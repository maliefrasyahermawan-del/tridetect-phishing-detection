#!/usr/bin/env python3
"""
Generate 5000 synthetic Indonesian SMS samples for smishing classifier training.
Output: tridetect/data/sms_synthetic.csv
"""

import csv
import random
from pathlib import Path

random.seed(42)

OUTPUT_PATH = Path(__file__).parent.parent / "tridetect" / "data" / "sms_synthetic.csv"

BANKS = ["BCA", "Mandiri", "BNI", "BRI", "CIMB", "BTN", "Bank Jago"]
EWALLETS = ["GoPay", "OVO", "Dana", "ShopeePay", "LinkAja"]
SHOPS = ["Shopee", "Tokopedia", "Lazada", "Bukalapak"]
LOGISTIC = ["JNE", "J&T", "SiCepat", "Anteraja", "GoSend"]
SUSPURLS = [
    "bit.ly/3xAbc1", "cutt.ly/bca-login", "g0pay-verify.tk/check",
    "shopee-id.ml/promo", "mandiri-secure.xyz/login",
    "jne-tracking.ml/id", "bca-mobile.ga/update",
    "t.co/9fXhZ", "tokopedia-hadiah.cf/klaim",
]


def rurl():
    return random.choice(SUSPURLS)


def rbank():
    return random.choice(BANKS)


def rewallet():
    return random.choice(EWALLETS)


def rshop():
    return random.choice(SHOPS)


def rlogistic():
    return random.choice(LOGISTIC)


SMISHING_TEMPLATES = [
    # Banking
    lambda: f"AKUN {rbank()} ANDA AKAN DIBEKUKAN. Verifikasi sekarang: {rurl()}",
    lambda: f"[{rbank()}] Rekening Anda terdeteksi aktivitas mencurigakan. Konfirmasi: {rurl()}",
    lambda: f"Penting! {rbank()} Mobile Banking Anda akan dinonaktifkan. Aktifkan: {rurl()}",
    lambda: f"[PEMBERITAHUAN {rbank().upper()}] PIN internet banking Anda akan kedaluwarsa. Perbarui: {rurl()}",
    lambda: f"Selamat! Anda menerima hadiah Rp {random.randint(5,100)*1_000_000:,} dari {rbank()}. Konfirmasi: {rurl()}",
    lambda: f"Transfer ke rekening Anda sebesar Rp {random.randint(1,50)*500_000:,} menunggu konfirmasi. Klik: {rurl()}",

    # E-wallet
    lambda: f"AKUN {rewallet().upper()} ANDA AKAN DIBEKUKAN. Verifikasi sekarang: {rurl()}",
    lambda: f"[{rewallet()}] Saldo Rp {random.randint(1,5)*100_000:,} akan hangus. Klaim: {rurl()}",
    lambda: f"Selamat! {rewallet()} memberikan bonus cashback Rp {random.randint(5,50)*10_000:,}. Klaim: {rurl()}",
    lambda: f"Akun {rewallet()} Anda terindikasi penyalahgunaan. Verifikasi segera: {rurl()}",

    # E-commerce
    lambda: f"Pesanan Anda di {rshop()} senilai Rp {random.randint(1,5)*100_000:,} menunggu pembayaran. Bayar: {rurl()}",
    lambda: f"[{rshop().upper()}] Anda memenangkan voucher Rp {random.randint(1,10)*100_000:,}! Klaim sebelum habis: {rurl()}",
    lambda: f"SELAMAT! Anda terpilih sebagai pemenang {rshop()} Flash Sale. Klaim hadiah: {rurl()}",

    # Logistics
    lambda: f"Paket Anda dari {rlogistic()} gagal dikirim. Alamat tidak valid. Update: {rurl()}",
    lambda: f"[{rlogistic().upper()}] Paket Anda tertahan di gudang. Konfirmasi alamat: {rurl()}",
    lambda: f"Pengiriman paket Anda memerlukan biaya tambahan Rp {random.randint(1,5)*10_000:,}. Bayar: {rurl()}",

    # Generic
    lambda: f"Anda memenangkan undian berhadiah Rp {random.randint(10,500)*1_000_000:,}. Klaim sekarang: {rurl()}",
    lambda: f"PENTING: Data pribadi Anda bocor. Lindungi akun Anda sekarang: {rurl()}",
    lambda: f"Pinjaman cepat cair Rp {random.randint(1,50)*1_000_000:,} tanpa jaminan. Daftar: {rurl()}",
    lambda: f"Tagihan listrik Anda menunggak. Bayar sekarang atau akan diputus: {rurl()}",
    lambda: f"[BPJS] Kartu BPJS Anda akan dinonaktifkan. Perpanjang: {rurl()}",
]

BENIGN_TEMPLATES = [
    # OTP
    lambda: f"[{rbank()}] Kode OTP Anda adalah: {random.randint(100000,999999)}. Berlaku 5 menit. Jangan bagikan kode ini kepada siapapun.",
    lambda: f"Kode verifikasi {rewallet()} Anda: {random.randint(100000,999999)}. JANGAN berikan kode ini ke siapapun termasuk pihak {rewallet()}.",
    lambda: f"[{rshop()}] Kode OTP login: {random.randint(100000,999999)}. Valid 10 menit.",

    # Transfer notifications
    lambda: f"[{rbank()}] Transfer masuk Rp {random.randint(1,50)*100_000:,} dari rekening xxxx{random.randint(1000,9999)}. {random.choice(['Berita: Gaji', 'Berita: Pembayaran', 'Berita: Transfer'])}",
    lambda: f"[{rbank()}] Transaksi berhasil. Pembayaran Rp {random.randint(1,5)*50_000:,} ke {random.choice(['PLN','Indosat','Telkomsel'])} berhasil.",
    lambda: f"[{rewallet()}] Pembayaran Rp {random.randint(1,10)*25_000:,} ke {random.choice(['Alfamart','Indomaret','merchant'])} berhasil. Saldo: Rp {random.randint(10,500)*1_000:,}",

    # Promo legitimate
    lambda: f"[{rshop()}] Flash sale dimulai! Diskon hingga 90% untuk produk pilihan. Cek di aplikasi resmi.",
    lambda: f"[{rewallet()}] Promo cashback 20% untuk transaksi minimal Rp 50.000. Berlaku s/d {random.randint(1,28)}/{random.randint(1,12)}.",
    lambda: f"[{rbank()}] Nikmati cicilan 0% untuk pembelian di merchant pilihan. Info lengkap di kantor cabang atau aplikasi kami.",

    # Informational
    lambda: f"Halo, ini Budi dari PT ABC. Apakah kita bisa diskusi project besok jam 10 pagi?",
    lambda: f"Reminder: Meeting tim besok jam 09.00 WIB di ruang rapat lantai 3.",
    lambda: f"Terima kasih telah berbelanja di {rshop()}. Pesanan Anda sedang diproses.",
    lambda: f"[{rlogistic()}] Paket Anda dengan nomor resi {random.randint(10**14, 10**15-1)} dalam proses pengiriman.",
    lambda: f"Selamat ulang tahun! Semoga sukses dan sehat selalu.",
    lambda: f"Info: Tarif parkir area Mall ABC mulai {random.randint(1,28)}/{random.randint(1,12)} berubah menjadi Rp 3.000/jam.",
    lambda: f"[PLN] Tagihan listrik Anda bulan ini: Rp {random.randint(50,500)*1_000:,}. Bayar sebelum tanggal 20.",
    lambda: f"Rekap transaksi {rbank()} hari ini: Debit Rp {random.randint(1,10)*50_000:,}, Kredit Rp {random.randint(1,10)*50_000:,}.",
    lambda: f"[Telkomsel] Paket internet 10GB Anda akan habis pada {random.randint(1,28)}/{random.randint(1,12)}. Top up di aplikasi MyTelkomsel.",
    lambda: f"Undangan: Kami mengundang Bapak/Ibu untuk hadir dalam acara seminar keamanan siber pada Sabtu, {random.randint(1,28)}/{random.randint(1,12)}.",
    lambda: f"Pengumuman: Libur nasional tanggal {random.randint(1,28)}/{random.randint(1,12)} kantor tutup.",
]


def generate() -> list[dict]:
    rows = []

    for _ in range(2500):
        template = random.choice(SMISHING_TEMPLATES)
        rows.append({"text": template(), "label": "smishing", "source": "synthetic_smishing"})

    for _ in range(2500):
        template = random.choice(BENIGN_TEMPLATES)
        rows.append({"text": template(), "label": "benign", "source": "synthetic_benign"})

    random.shuffle(rows)
    return rows


def main():
    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    rows = generate()

    with open(OUTPUT_PATH, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["text", "label", "source"])
        writer.writeheader()
        writer.writerows(rows)

    smishing_count = sum(1 for r in rows if r["label"] == "smishing")
    benign_count = sum(1 for r in rows if r["label"] == "benign")

    print(f"Generated {len(rows)} SMS samples:")
    print(f"  Smishing : {smishing_count}")
    print(f"  Benign   : {benign_count}")
    print(f"  Saved to : {OUTPUT_PATH}")


if __name__ == "__main__":
    main()
