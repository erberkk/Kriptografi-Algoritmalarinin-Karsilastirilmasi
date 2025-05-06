from flask import Flask, render_template
import time, json, os
import numpy as np
import concurrent.futures

app = Flask(__name__)
CACHE_FILE = os.path.join(os.path.dirname(__file__), "cache.json")
NUM_RUNS = 10


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
    return avg_time, std_time


def analyze_rsa():
    try:
        from Crypto.PublicKey import RSA
        from Crypto.Cipher import PKCS1_OAEP
    except ImportError:
        return [{"algorithm": "RSA", "configuration": "N/A", "security": "Kütüphane eksik",
                 "performance_avg": None, "performance_std": None}]
    results = []
    for key_size in [1024, 2048, 4096]:
        def rsa_test():
            key = RSA.generate(key_size)
            cipher = PKCS1_OAEP.new(key)
            message = b"Test message for RSA encryption"
            _ = cipher.encrypt(message)
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
        return [{"algorithm": "AES", "configuration": "N/A", "security": "Kütüphane eksik",
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
                _ = cipher.encrypt(padded_message)
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
        return [{"algorithm": "DES", "configuration": "N/A", "security": "Kütüphane eksik",
                 "performance_avg": None, "performance_std": None}]
    results = []
    key = b'8bytekey'
    iv = b'8byteiv!'
    for msg_size in [100, 1000, 10000]:
        message = b'A' * msg_size
        def des_test():
            cipher = DES.new(key, DES.MODE_CBC, iv)
            padded_message = pad(message, DES.block_size)
            _ = cipher.encrypt(padded_message)
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
        return [{"algorithm": "Blowfish", "configuration": "N/A", "security": "Kütüphane eksik",
                 "performance_avg": None, "performance_std": None}]
    results = []
    key = b'blowfishkey'
    iv = b'8byteiv!'
    for msg_size in [100, 1000, 10000]:
        message = b'A' * msg_size
        def blowfish_test():
            cipher = Blowfish.new(key, Blowfish.MODE_CBC, iv)
            padded_message = pad(message, Blowfish.block_size)
            _ = cipher.encrypt(padded_message)
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
        return [{"algorithm": "ECC", "configuration": "N/A", "security": "Kütüphane eksik",
                 "performance_avg": None, "performance_std": None}]
    results = []
    for curve, sec in [(ec.SECP256R1(), 128), (ec.SECP384R1(), 192)]:
        def ecc_test():
            private_key = ec.generate_private_key(curve)
            message = b"Test message for ECC signing"
            _ = private_key.sign(message, ec.ECDSA(hashes.SHA256()))
        avg_time, std_time = measure_time(ecc_test)
        curve_name = curve.name if hasattr(curve, "name") else str(curve)
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
        return [{"algorithm": "Hashing", "configuration": "N/A", "security": "Kütüphane eksik",
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
                _ = h.digest()
            avg_time, std_time = measure_time(hash_test)
            config_desc = f"{algo_name}, Msg: {msg_size}B"
            security = {"MD5":128, "SHA-1":160, "SHA-256":256, "SHA3-256":256}[algo_name]
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
        if res["performance_avg"] is None:
            continue
        alg = res["algorithm"]
        if alg not in summary or res["performance_avg"] < summary[alg]["performance_avg"]:
            summary[alg] = res
    return list(summary.values())


def get_algo_details():
    details = [
        {
            "name": "RSA",
            "amac": "Asimetrik şifreleme ve dijital imza",
            "tarihce": "1977'de Ronald Rivest, Adi Shamir ve Leonard Adleman tarafından geliştirildi.",
            "neden": "Güvenli anahtar değişimi ve dijital imzaların gerekliliği nedeniyle geliştirilmiştir.",
            "kullanim": "Web güvenliği (TLS/SSL), dijital imza, sertifika altyapıları, vb.",
            "mantik": "Büyük asal sayıları çarpanlara ayırmanın zorluğuna dayanır.",
            "guvenlik": "Anahtar boyutu (örn. 2048, 4096 bit) arttıkça güvenlik de artar.",
            "performans": "Diğer asimetrik yöntemlere göre hesaplama maliyeti yüksektir.",
            "degisken": "Anahtar boyutu arttıkça güvenlik artar ancak performans düşer."
        },
        {
            "name": "AES",
            "amac": "Simetrik şifreleme (gizlilik sağlama)",
            "tarihce": "NIST yarışmasında Rijndael algoritması seçilerek 2001'de AES standardı oldu.",
            "neden": "DES'in yetersiz kalmaya başlaması ve daha hızlı, güvenli bir standarda ihtiyaç duyulması.",
            "kullanim": "Finans, devlet kurumları, disk şifreleme, Wi-Fi (WPA2), vs.",
            "mantik": "Substitution-Permutation Network yapısına sahiptir, blok bazlı şifreleme yapar.",
            "guvenlik": "128, 192 veya 256 bit anahtar ile yüksek güvenlik sağlar.",
            "performans": "Yazılım ve donanımda oldukça hızlı ve verimli çalışır.",
            "degisken": "Anahtar boyutu ve blok şifreleme modu (CBC, GCM, vb.) performansı etkiler."
        },
        {
            "name": "DES",
            "amac": "Erken dönem simetrik şifreleme standardı",
            "tarihce": "1970'lerde IBM tarafından geliştirildi, 1977'de ABD hükümeti standardı oldu.",
            "neden": "Dijital iletişimin yaygınlaşmasıyla gizlilik ihtiyacını karşılamak üzere.",
            "kullanim": "Tarihi önemi vardır; günümüzde çoğunlukla legacy sistemlerde görülebilir.",
            "mantik": "Feistel tabanlı yapı, 56 bit efektif anahtar kullanır.",
            "guvenlik": "56 bit anahtar günümüz için zayıf kabul edilir, kolay brute-force edilebilir.",
            "performans": "Hızlı çalışabilir ancak güvenlik yeterli değildir.",
            "degisken": "Sabit blok boyutu (64 bit) ve 56 bit anahtar nedeniyle esnekliği azdır."
        },
        {
            "name": "Blowfish",
            "amac": "Hızlı, özgürce kullanılabilir simetrik şifreleme",
            "tarihce": "Bruce Schneier tarafından 1993'te geliştirildi.",
            "neden": "DES'e alternatif, daha esnek anahtar boyutu ve ücretsiz kullanım ihtiyacı.",
            "kullanim": "Açık kaynak projeler, yazılım tabanlı şifreleme gereksinimleri, bazı VPN çözümleri.",
            "mantik": "Feistel tabanlı, 32 ile 448 bit arasında değişen anahtar uzunluğu.",
            "guvenlik": "AES kadar yaygın olmasa da güvenlidir.",
            "performans": "Yazılımda hızlı çalışır, özellikle kısa mesajlar için optimizasyonu bulunur.",
            "degisken": "Anahtar uzunluğu ve tur sayısı performansı etkiler."
        },
        {
            "name": "ECC",
            "amac": "Asimetrik şifreleme ve dijital imza, düşük anahtar boyutuyla yüksek güvenlik",
            "tarihce": "Eliptik eğri matematiği 1980-90'larda kriptografiye uyarlandı.",
            "neden": "RSA ve benzeri algoritmalara alternatif, daha küçük anahtarlarla benzer güvenlik sunma ihtiyacı.",
            "kullanim": "Mobil cihazlar, IoT, blockchain, düşük güç tüketimi gereken uygulamalar.",
            "mantik": "Eliptik eğriler üzerinde nokta hesaplarına dayalıdır.",
            "guvenlik": "Seçilen eğri ve anahtar boyutuna göre değişir.",
            "performans": "RSA'ya göre daha hızlı anahtar üretimi ve imzalama sunar.",
            "degisken": "Eğri seçimi ve anahtar boyutu performansı belirler."
        },
        {
            "name": "Hashing (MD5, SHA-1, SHA-2, SHA-3)",
            "amac": "Veri bütünlüğü kontrolü, parola saklama, dijital imza öncesi özet çıkarma",
            "tarihce": "MD5 ve SHA-1 eski, SHA-2 ve SHA-3 daha güncel standartlardır.",
            "neden": "Verinin doğruluğunu hızlı kontrol etmek ve parolaları güvenli saklamak için.",
            "kullanim": "Dosya bütünlüğü, parola saklama, dijital imza sistemleri.",
            "mantik": "Veriyi sabit uzunlukta özet değere dönüştürür.",
            "guvenlik": "Algoritmaya göre çarpışma ve bulma saldırılarına direnç değişir.",
            "performans": "Genellikle simetrik şifreleme işlemlerinden daha hızlıdır.",
            "degisken": "Mesaj uzunluğu arttıkça işlem süresi uzar."
        }
    ]
    return details


def get_test_methodology():
    methodology = [
        {
            "name": "RSA Algoritması Testi",
            "details": (
                "RSA algoritması için 1024, 2048 ve 4096 bit anahtar boyutları kullanılarak testler gerçekleştirilmektedir. "
                "Her testte belirtilen bit uzunluğunda bir anahtar üretilip, PKCS1_OAEP protokolüyle rastgele mesaj şifrelenir. "
                "Testler eş zamanlı (10 paralel işlem) olarak çalıştırılır ve ortalama süre ile standart sapma hesaplanır."
            )
        },
        {
            "name": "AES Algoritması Testi",
            "details": (
                "AES testlerinde 128, 192 ve 256 bit anahtarlar ve 100B, 1000B, 10000B mesajlar kullanılarak CBC modunda şifreleme yapılır. "
                "Padding işlemi de dahil edilerek, eş zamanlı testler sonucunda performans ölçümleri alınır."
            )
        },
        {
            "name": "DES Algoritması Testi",
            "details": (
                "DES algoritmasında 56-bit anahtar ve farklı mesaj boyutları kullanılarak CBC modunda şifreleme gerçekleştirilir. "
                "Testler 10 paralel işlem ile yürütülür ve sonuçlar ortalama süre ile standart sapma olarak raporlanır."
            )
        },
        {
            "name": "Blowfish Algoritması Testi",
            "details": (
                "Blowfish testlerinde 128-bit anahtar kullanılarak, farklı mesaj boyutlarıyla CBC modunda şifreleme yapılır. "
                "Padding işlemi de gerçekleştirilip, eş zamanlı testlerle performans ölçümleri elde edilir."
            )
        },
        {
            "name": "ECC Algoritması Testi",
            "details": (
                "ECC testlerinde SECP256R1 ve SECP384R1 eğrileriyle eş zamanlı olarak ECDSA imzalama işlemi gerçekleştirilir. "
                "Her eğri için ortalama imzalama süresi ve standart sapma ölçülür."
            )
        },
        {
            "name": "Hashing Fonksiyonları Testi",
            "details": (
                "Hash testlerinde MD5, SHA-1, SHA-256 ve SHA3-256 algoritmaları kullanılarak, farklı mesaj uzunluklarında veri özeti hesaplanır. "
                "Eş zamanlı testlerle ortalama süre ve standart sapma değerleri elde edilir."
            )
        }
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
    if os.path.exists(CACHE_FILE):
        with open(CACHE_FILE, "r") as f:
            results = json.load(f)
    else:
        results = compute_all_results()
        with open(CACHE_FILE, "w") as f:
            json.dump(results, f)
    summary = get_summary(results)
    algo_details = get_algo_details()
    test_methodology = get_test_methodology()
    return render_template(
        "index.html",
        results=results,
        summary=summary,
        algo_details=algo_details,
        test_methodology=test_methodology
    )


if __name__ == '__main__':
    app.run(debug=True)
