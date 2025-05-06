from flask import Flask, render_template, session, redirect, url_for, request
from flask_babel import Babel, gettext, lazy_gettext
import time
import json
import os
import numpy as np
import concurrent.futures

_ = gettext
_l = lazy_gettext

app = Flask(__name__)
app.secret_key = os.urandom(24)

NUM_RUNS = 10

app.config['LANGUAGES'] = {
    'tr': 'Türkçe',
    'en': 'English'
}
app.config['BABEL_DEFAULT_LOCALE'] = 'tr'

babel = Babel()


def get_locale():
    language = session.get('language')
    if language in app.config['LANGUAGES']:
        return language
    return app.config['BABEL_DEFAULT_LOCALE']


babel.init_app(app, locale_selector=get_locale)


@app.route('/language/<lang_code>')
def set_language(lang_code):
    if lang_code in app.config['LANGUAGES']:
        session['language'] = lang_code
    referrer = request.referrer or url_for('index')
    return redirect(referrer)


def measure_time(func, *args, **kwargs):
    """Fonksiyonu NUM_RUNS kez eş zamanlı çalıştırıp, ortalama ve std hesaplar."""
    def run_once():
        start = time.perf_counter()
        func(*args, **kwargs)
        end = time.perf_counter()
        return end - start
    with concurrent.futures.ThreadPoolExecutor(max_workers=NUM_RUNS) as executor:
        futures = [executor.submit(run_once) for _ in range(NUM_RUNS)]
        times = [future.result() for future in futures]
    avg_time = np.mean(times)
    std_time = np.std(times)
    if np.isnan(avg_time) or np.isinf(avg_time):
        avg_time = None
    if np.isnan(std_time) or np.isinf(std_time):
        std_time = None
    return avg_time, std_time


def analyze_rsa():
    try:
        from Crypto.PublicKey import RSA
        from Crypto.Cipher import PKCS1_OAEP
    except ImportError:
        return [{"algorithm": "RSA", "configuration": "N/A", "security": _l("Kütüphane eksik"),
                 "performance_avg": None, "performance_std": None}]
    results = []
    for key_size in [1024, 2048, 4096]:
        def rsa_test():
            key = RSA.generate(key_size)
            cipher = PKCS1_OAEP.new(key)
            message = b"Test message for RSA encryption"
            result = cipher.encrypt(message)
        avg_time, std_time = measure_time(rsa_test)
        results.append({
            "algorithm": "RSA",
            "configuration": f"Key Size: {key_size}",
            "security": key_size,
            "performance_avg": avg_time,
            "performance_std": std_time
        })
    return results


def analyze_aes():
    try:
        from Crypto.Cipher import AES
        from Crypto.Util.Padding import pad
    except ImportError:
        return [{"algorithm": "AES", "configuration": "N/A", "security": _l("Kütüphane eksik"),
                 "performance_avg": None, "performance_std": None}]
    results = []
    for key_len, key_bits in [(16, 128), (24, 192), (32, 256)]:
        key = b'A' * key_len
        iv = b'B' * 16
        for msg_size in [100, 1000, 10000]:
            message = b'A' * msg_size
            def aes_test():
                cipher = AES.new(key, AES.MODE_CBC, iv)
                padded_message = pad(message, AES.block_size)
                result = cipher.encrypt(padded_message)
            avg_time, std_time = measure_time(aes_test)
            config_desc = f"Key: {key_bits}-bit, Msg: {msg_size}B"
            results.append({
                "algorithm": "AES",
                "configuration": config_desc,
                "security": key_bits,
                "performance_avg": avg_time,
                "performance_std": std_time
            })
    return results


def analyze_des():
    try:
        from Crypto.Cipher import DES
        from Crypto.Util.Padding import pad
    except ImportError:
        return [{"algorithm": "DES", "configuration": "N/A", "security": _l("Kütüphane eksik"),
                 "performance_avg": None, "performance_std": None}]
    results = []
    key = b'8bytekey'
    iv = b'8byteiv!'
    for msg_size in [100, 1000, 10000]:
        message = b'A' * msg_size
        def des_test():
            cipher = DES.new(key, DES.MODE_CBC, iv)
            padded_message = pad(message, DES.block_size)
            result = cipher.encrypt(padded_message)
        avg_time, std_time = measure_time(des_test)
        config_desc = f"Msg: {msg_size}B"
        results.append({
            "algorithm": "DES",
            "configuration": config_desc,
            "security": 56,
            "performance_avg": avg_time,
            "performance_std": std_time
        })
    return results


def analyze_blowfish():
    try:
        from Crypto.Cipher import Blowfish
        from Crypto.Util.Padding import pad
    except ImportError:
        return [{"algorithm": "Blowfish", "configuration": "N/A", "security": _l("Kütüphane eksik"),
                 "performance_avg": None, "performance_std": None}]
    results = []
    key = b'blowfishkey'
    iv = b'8byteiv!'
    for msg_size in [100, 1000, 10000]:
        message = b'A' * msg_size
        def blowfish_test():
            cipher = Blowfish.new(key, Blowfish.MODE_CBC, iv)
            padded_message = pad(message, Blowfish.block_size)
            result = cipher.encrypt(padded_message)
        avg_time, std_time = measure_time(blowfish_test)
        config_desc = f"Msg: {msg_size}B"
        results.append({
            "algorithm": "Blowfish",
            "configuration": config_desc,
            "security": 128,
            "performance_avg": avg_time,
            "performance_std": std_time
        })
    return results


def analyze_ecc():
    try:
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.hazmat.primitives import hashes
    except ImportError:
        return [{"algorithm": "ECC", "configuration": "N/A", "security": _l("Kütüphane eksik"),
                 "performance_avg": None, "performance_std": None}]
    results = []
    for curve, sec in [(ec.SECP256R1(), 128), (ec.SECP384R1(), 192)]:
        def ecc_test():
            private_key = ec.generate_private_key(curve)
            message = b"Test message for ECC signing"
            signature = private_key.sign(message, ec.ECDSA(hashes.SHA256()))
        avg_time, std_time = measure_time(ecc_test)
        try:
            curve_name = curve.name if hasattr(curve, 'name') else str(curve)
        except AttributeError:
             curve_name = str(curve)

        config_desc = f"Curve: {curve_name}"
        results.append({
            "algorithm": "ECC",
            "configuration": config_desc,
            "security": sec,
            "performance_avg": avg_time,
            "performance_std": std_time
        })
    return results


def analyze_hashes():
    try:
        import hashlib
    except ImportError:
        return [{"algorithm": "Hashing", "configuration": "N/A", "security": _l("Kütüphane eksik"),
                 "performance_avg": None, "performance_std": None}]
    results = []
    hash_algos = [
        ("MD5", hashlib.md5),
        ("SHA-1", hashlib.sha1),
        ("SHA-256", hashlib.sha256),
        ("SHA3-256", hashlib.sha3_256)
    ]
    for msg_size in [100, 10000]:
        message = b'A' * msg_size
        for algo_name, algo_func in hash_algos:
            def hash_test():
                h = algo_func()
                h.update(message)
                digest = h.digest()
            avg_time, std_time = measure_time(hash_test)
            config_desc = f"{algo_name}, Msg: {msg_size}B"
            security_map = {"MD5": 0, "SHA-1": 0, "SHA-256": 256, "SHA3-256": 256}
            security = security_map.get(algo_name, 0)
            results.append({
                "algorithm": "Hashing",
                "configuration": config_desc,
                "security": security,
                "performance_avg": avg_time,
                "performance_std": std_time
            })
    return results


def get_summary(results):
    summary = {}
    for res in results:
        if isinstance(res["security"], str) or res["performance_avg"] is None:
            continue
        alg = res["algorithm"]
        if alg not in summary or res["performance_avg"] < summary[alg]["performance_avg"]:
            summary[alg] = res
    return list(summary.values())


def get_algo_details():
    details = [
        {"name": "RSA", "amac": _l("Asimetrik şifreleme ve dijital imza"),"tarihce": _l("1977'de Ronald Rivest, Adi Shamir ve Leonard Adleman tarafından geliştirildi."),"neden": _l("Güvenli anahtar değişimi ve dijital imzaların gerekliliği nedeniyle geliştirilmiştir."),"kullanim": _l("Web güvenliği (TLS/SSL), dijital imza, sertifika altyapıları, vb."),"mantik": _l("Büyük asal sayıları çarpanlara ayırmanın zorluğuna dayanır."),"guvenlik": _l("Anahtar boyutu (örn. 2048, 4096 bit) arttıkça güvenlik de artar."),"performans": _l("Diğer asimetrik yöntemlere göre hesaplama maliyeti yüksektir."),"degisken": _l("Anahtar boyutu arttıkça güvenlik artar ancak performans düşer.")},
        {"name": "AES", "amac": _l("Simetrik şifreleme (gizlilik sağlama)"),"tarihce": _l("NIST yarışmasında Rijndael algoritması seçilerek 2001'de AES standardı oldu."),"neden": _l("DES'in yetersiz kalmaya başlaması ve daha hızlı, güvenli bir standarda ihtiyaç duyulması."),"kullanim": _l("Finans, devlet kurumları, disk şifreleme, Wi-Fi (WPA2), vs."),"mantik": _l("Substitution-Permutation Network yapısına sahiptir, blok bazlı şifreleme yapar."),"guvenlik": _l("128, 192 veya 256 bit anahtar ile yüksek güvenlik sağlar."),"performans": _l("Yazılım ve donanımda oldukça hızlı ve verimli çalışır."),"degisken": _l("Anahtar boyutu ve blok şifreleme modu (CBC, GCM, vb.) performansı etkiler.")},
        {"name": "DES", "amac": _l("Erken dönem simetrik şifreleme standardı"),"tarihce": _l("1970'lerde IBM tarafından geliştirildi, 1977'de ABD hükümeti standardı oldu."),"neden": _l("Dijital iletişimin yaygınlaşmasıyla gizlilik ihtiyacını karşılamak üzere."),"kullanim": _l("Tarihi önemi vardır; günümüzde çoğunlukla legacy sistemlerde görülebilir."),"mantik": _l("Feistel tabanlı yapı, 56 bit efektif anahtar kullanır."),"guvenlik": _l("56 bit anahtar günümüz için zayıf kabul edilir, kolay brute-force edilebilir."),"performans": _l("Hızlı çalışabilir ancak güvenlik yeterli değildir."),"degisken": _l("Sabit blok boyutu (64 bit) ve 56 bit anahtar nedeniyle esnekliği azdır.")},
        {"name": "Blowfish", "amac": _l("Hızlı, özgürce kullanılabilir simetrik şifreleme"),"tarihce": _l("Bruce Schneier tarafından 1993'te geliştirildi."),"neden": _l("DES'e alternatif, daha esnek anahtar boyutu ve ücretsiz kullanım ihtiyacı."),"kullanim": _l("Açık kaynak projeler, yazılım tabanlı şifreleme gereksinimleri, bazı VPN çözümleri."),"mantik": _l("Feistel tabanlı, 32 ile 448 bit arasında değişen anahtar uzunluğu."),"guvenlik": _l("AES kadar yaygın olmasa da güvenlidir."),"performans": _l("Yazılımda hızlı çalışır, özellikle kısa mesajlar için optimizasyonu bulunur."),"degisken": _l("Anahtar uzunluğu ve tur sayısı performansı etkiler.")},
        {"name": "ECC", "amac": _l("Asimetrik şifreleme ve dijital imza, düşük anahtar boyutuyla yüksek güvenlik"),"tarihce": _l("Eliptik eğri matematiği 1980-90'larda kriptografiye uyarlandı."),"neden": _l("RSA ve benzeri algoritmalara alternatif, daha küçük anahtarlarla benzer güvenlik sunma ihtiyacı."),"kullanim": _l("Mobil cihazlar, IoT, blockchain, düşük güç tüketimi gereken uygulamalar."),"mantik": _l("Eliptik eğriler üzerinde nokta hesaplarına dayalıdır."),"guvenlik": _l("Seçilen eğri ve anahtar boyutuna göre değişir."),"performans": _l("RSA'ya göre daha hızlı anahtar üretimi ve imzalama sunar."),"degisken": _l("Eğri seçimi ve anahtar boyutu performansı belirler.")},
        {"name": "Hashing (MD5, SHA-1, SHA-2, SHA-3)", "amac": _l("Veri bütünlüğü kontrolü, parola saklama, dijital imza öncesi özet çıkarma"),"tarihce": _l("MD5 ve SHA-1 eski, SHA-2 ve SHA-3 daha güncel standartlardır."),"neden": _l("Verinin doğruluğunu hızlı kontrol etmek ve parolaları güvenli saklamak için."),"kullanim": _l("Dosya bütünlüğü, parola saklama, dijital imza sistemleri."),"mantik": _l("Veriyi sabit uzunlukta özet değere dönüştürür."),"guvenlik": _l("Algoritmaya göre çarpışma ve bulma saldırılarına direnç değişir."),"performans": _l("Genellikle simetrik şifreleme işlemlerinden daha hızlıdır."),"degisken": _l("Mesaj uzunluğu arttıkça işlem süresi uzar.")}
    ]
    return details


def get_test_methodology():
    methodology = [
        {"name": _l("RSA Algoritması Testi"), "details": _l("RSA algoritması için 1024, 2048 ve 4096 bit anahtar boyutları kullanılarak testler gerçekleştirilmektedir. Her testte belirtilen bit uzunluğunda bir anahtar üretilip, PKCS1_OAEP protokolüyle rastgele mesaj şifrelenir. Testler eş zamanlı (10 paralel işlem) olarak çalıştırılır ve ortalama süre ile standart sapma hesaplanır.")},
        {"name": _l("AES Algoritması Testi"), "details": _l("AES testlerinde 128, 192 ve 256 bit anahtarlar ve 100B, 1000B, 10000B mesajlar kullanılarak CBC modunda şifreleme yapılır. Padding işlemi de dahil edilerek, eş zamanlı testler sonucunda performans ölçümleri alınır.")},
        {"name": _l("DES Algoritması Testi"), "details": _l("DES algoritmasında 56-bit anahtar ve farklı mesaj boyutları kullanılarak CBC modunda şifreleme gerçekleştirilir. Testler 10 paralel işlem ile yürütülür ve sonuçlar ortalama süre ile standart sapma olarak raporlanır.")},
        {"name": _l("Blowfish Algoritması Testi"), "details": _l("Blowfish testlerinde 128-bit anahtar kullanılarak, farklı mesaj boyutlarıyla CBC modunda şifreleme yapılır. Padding işlemi de gerçekleştirilip, eş zamanlı testlerle performans ölçümleri elde edilir.")},
        {"name": _l("ECC Algoritması Testi"), "details": _l("ECC testlerinde SECP256R1 ve SECP384R1 eğrileriyle eş zamanlı olarak ECDSA imzalama işlemi gerçekleştirilir. Her eğri için ortalama imzalama süresi ve standart sapma ölçülür.")},
        {"name": _l("Hashing Fonksiyonları Testi"), "details": _l("Hash testlerinde MD5, SHA-1, SHA-256 ve SHA3-256 algoritmaları kullanılarak, farklı mesaj uzunluklarında veri özeti hesaplanır. Eş zamanlı testlerle ortalama süre ve standart sapma değerleri elde edilir.")}
    ]
    return methodology


def compute_all_results():
    results = []
    results.extend(analyze_rsa())
    results.extend(analyze_aes())
    results.extend(analyze_des())
    results.extend(analyze_blowfish())
    results.extend(analyze_ecc())
    results.extend(analyze_hashes())
    return results


@app.route("/")
def index():
    current_locale = get_locale()
    cache_filename = f"cache_{current_locale}.json"
    CACHE_FILE_LOC = os.path.join(os.path.dirname(__file__), cache_filename)
    results = None

    if os.path.exists(CACHE_FILE_LOC):
        try:
            with open(CACHE_FILE_LOC, "r", encoding="utf-8") as f:
                results = json.load(f)
        except (json.JSONDecodeError, IOError):
            results = None

    if results is None:
        results = compute_all_results()
        try:
            clean_results = []
            for res in results:
                res_copy = res.copy()
                if isinstance(res_copy.get("performance_avg"), float) and np.isnan(res_copy["performance_avg"]):
                    res_copy["performance_avg"] = None
                if isinstance(res_copy.get("performance_std"), float) and np.isnan(res_copy["performance_std"]):
                    res_copy["performance_std"] = None
                clean_results.append(res_copy)
            results = clean_results

            with open(CACHE_FILE_LOC, "w", encoding="utf-8") as f:
                 json.dump(results, f, ensure_ascii=False, indent=4)
        except IOError:
            pass

    summary = get_summary(results)
    algo_details = get_algo_details()
    test_methodology = get_test_methodology()

    js_translations = {
        "avgPerfLabel": _("Ortalama Performans (saniye)"),
        "durationAxisLabel": _("Süre (s) - Logaritmik Ölçek"),
        "simRunsLabel": _("Tahmini Çalışma Sayısı"),
        "simRunsLabelWithTime": _("Tahmini Çalışma Sayısı ({duration} saniyede)"),
        "simRunsUnit": _("kez"),
        "invalidDurationError": _("Lütfen geçerli pozitif bir süre giriniz."),
        "noPerfDataError": _("Performans verisi yok veya geçersiz."),
        "libraryMissingError": _("Kütüphane eksik, hesaplanamadı."),
        "infiniteRunsWarning": _("Sonsuz (performans süresi sıfır)."),
        "negativePerfError": _("Geçersiz performans verisi (negatif)."),
        "noCalculableData": _("Hesaplanabilir performans verisi bulunamadı."),
        "noAlgoData": _("Karşılaştırılacak algoritma verisi bulunamadı."),
        "enterDurationPrompt": _("Süre girip 'Hesapla' butonuna basınız veya sekmeyi aktifleştiriniz."),
        "switchToSimTabPrompt": _("İlgili sekmeye geçerek simülasyonu başlatın."),
        "summaryChartTitle": _("Özet Veriler: En Hızlı Konfigürasyonlar"),
        "allConfigChartTitle": _("Tüm Konfigürasyonların Karşılaştırması"),
        "logScaleNote": _("Not: Grafiklerdeki süre eksenleri logaritmik ölçektedir. Bu, çok farklı büyüklükteki değerlerin (örneğin RSA ve AES süreleri) aynı grafikte anlamlı bir şekilde karşılaştırılabilmesini sağlar."),
        "calculateButton": _("Hesapla"),
        "simResultsTitle": _("Simülasyon Sonuçları:"),
        "simDurationLabel": _("Simülasyon Süresi (saniye cinsinden):"),
        "algoColumn": _("Algoritma"),
        "configColumn": _("Konfigürasyon"),
        "securityColumn": _("Güvenlik (Bit)"),
        "avgPerfColumn": _("Ort. Performans (s)"),
        "stdDevColumn": _("Std. Sapma (s)"),
        "fastestConfigColumn": _("En Hızlı Konfigürasyon"),
    }

    return render_template(
        "index.html",
        results=results,
        summary=summary,
        algo_details=algo_details,
        test_methodology=test_methodology,
        js_translations=json.dumps(js_translations, ensure_ascii=False)
    )


if __name__ == '__main__':
    app.run(debug=True)