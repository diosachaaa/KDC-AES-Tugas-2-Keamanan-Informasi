# KDC + AES - Key Distribution Scenario

Tugas mata kuliah Keamanan Informasi.

Implementasi Key Distribution Scenario dengan tiga entitas (KDC, Alice, Bob) di tiga IP address berbeda. Setelah handshake 5 langkah, Alice dan Bob berkomunikasi dua arah menggunakan AES yang diimplementasikan manual.

## Anggota

| Nama | NRP | Bagian |
|---|---|---|
| Muhammad Abdul Rafi | 5025231093 | AES |
| Dionysus Sacha Uistean Vladilen | 5025231228 | KDC & jaringan |

## Skenario

| Step | Arah | Isi |
|---|---|---|
| 1 | Alice → KDC | `ID_A ‖ ID_B ‖ N1` |
| 2 | KDC → Alice | `E(Ka, [Ks ‖ ID_A ‖ ID_B ‖ N1]) ‖ E(Kb, [Ks ‖ ID_A])` |
| 3 | Alice → Bob | `E(Kb, [Ks ‖ ID_A])` |
| 4 | Bob → Alice | `E(Ks, N2)` |
| 5 | Alice → Bob | `E(Ks, f(N2))`, dengan `f(N2) = N2 + 1` |
| 6+ | Alice ⇄ Bob | chat terenkripsi AES dengan `Ks` |

- **Ka, Kb**: master key Alice dan Bob, masing-masing 16 karakter ASCII, hanya diketahui pemiliknya dan KDC.
- **Ks**: session key 16 karakter ASCII acak, dibuat baru oleh KDC untuk setiap permintaan.
- **N1, N2**: nonce acak 64-bit. N1 mencegah replay balasan KDC; N2 membuktikan bahwa Alice benar-benar memegang Ks.

## Struktur

```
crypto/   implementasi AES, mode operasi, dan API enkripsi
net/      framing pesan dan sesi chat dua arah
kdc.py    Key Distribution Center
alice.py  inisiator
bob.py    responder
tests/    unit test
```

## Kebutuhan

- Python 3.10 atau lebih baru
- Tidak ada library tambahan (hanya standard library; AES diimplementasikan sendiri)

## Cara menjalankan

Jalankan dari folder root repo, dengan urutan **KDC → Bob → Alice**. Setiap program meminta master key (16 karakter ASCII) saat dijalankan.

### Di satu komputer (tiga terminal)

```bash
# Terminal 1
python kdc.py

# Terminal 2
python bob.py

# Terminal 3
python alice.py --kdc 127.0.0.1:5000 --bob 127.0.0.1:6000
```

### Di tiga komputer (tiga IP berbeda)

Ketiga komputer harus berada di jaringan yang sama (misalnya hotspot HP). Contoh IP:

| Komputer | IP | Perintah |
|---|---|---|
| KDC | `192.168.43.10` | `python kdc.py` |
| Bob | `192.168.43.12` | `python bob.py` |
| Alice | `192.168.43.11` | `python alice.py --kdc 192.168.43.10:5000 --bob 192.168.43.12:6000` |

- Cek IP dengan `ipconfig` (Windows) atau `ip a` / `ifconfig` (Linux/macOS).
- Di komputer KDC dan Bob, izinkan koneksi masuk ke port 5000 dan 6000 di firewall.
- KDC dan Bob mendengarkan di `0.0.0.0` secara default. Port bisa diubah dengan `--port`.

### Argumen

| Program | Argumen | Default |
|---|---|---|
| `kdc.py` | `--host`, `--port` | `0.0.0.0`, `5000` |
| `bob.py` | `--host`, `--port` | `0.0.0.0`, `6000` |
| `alice.py` | `--kdc HOST:PORT`, `--bob HOST:PORT` | wajib diisi |

## Perintah interaktif

Semua key bisa diganti **tanpa menjalankan ulang program**. Di Alice dan Bob, teks biasa dikirim sebagai pesan chat terenkripsi; baris yang diawali `/` adalah perintah.

| Perintah | KDC | Alice | Bob | Fungsi |
|---|:-:|:-:|:-:|---|
| `/setkey alice\|bob <key>` | ✓ | | | ganti Ka atau Kb yang disimpan KDC |
| `/setkey <key>` | | ✓ | ✓ | ganti master key sendiri |
| `/handshake` | | ✓ | | jalankan ulang step 1–5, dapatkan Ks baru |
| `/status` | ✓ | ✓ | ✓ | tampilkan key, alamat, sesi, dan Ks aktif |
| `/verbose on\|off` | | ✓ | ✓ | tampilkan ciphertext hex setiap pesan |
| `/help` | ✓ | ✓ | ✓ | daftar perintah |
| `/quit` | ✓ | ✓ | ✓ | keluar |

Key boleh mengandung spasi, misalnya `/setkey Thats my Kung Fu`.

Mengganti master key **tidak memutus sesi yang sedang berjalan**, karena chat dienkripsi dengan Ks. Key baru berlaku di handshake berikutnya.

## Contoh skenario uji

Mulai dengan Ka = `Thats my Kung Fu` dan Kb = `kunciBobRahasia1` di KDC, Alice, dan Bob.

| # | Langkah | Hasil yang diharapkan |
|---|---|---|
| 1 | Jalankan ketiga program dengan key yang sama | Handshake sukses, Ks di Alice dan Bob sama, chat dua arah jalan |
| 2 | Alice: `/setkey kunciAliceSALAH1`, lalu `/handshake` | Ditolak di Alice: `for_a tidak bisa didekripsi (Ka salah ...)` |
| 3 | Bob: `/setkey kunci Bob Baru 1`, lalu Alice: `/handshake` | Ditolak di Bob: `Ticket tidak bisa didekripsi (Kb salah ...)` |
| 4 | KDC: `/setkey bob kunci Bob Baru 1`, lalu Alice: `/handshake` | Sukses dengan Ks baru |
| 5 | Alice dan Bob: `/verbose on`, lalu saling kirim pesan | Ciphertext hex tampil di pengirim dan penerima (sama dengan yang terlihat di Wireshark) |
| 6 | Tutup terminal Alice | Bob: `[SESI] Alice terputus`, Bob tetap berjalan |
| 7 | Alice: `/quit` | Bob: `[SESI] Alice menutup sesi` |

## Format pesan

Setiap pesan dikirim lewat TCP sebagai `[panjang 4 byte, big-endian][JSON UTF-8]`.

| Pesan | Isi |
|---|---|
| Step 1 | `{"step": 1, "id_a", "id_b", "n1"}` (plaintext) |
| Step 2 | `{"step": 2, "for_a": E(Ka, ...), "ticket_b": E(Kb, ...)}` |
| Step 3 | `{"step": 3, "ticket_b"}` |
| Step 4 | `{"step": 4, "n2": E(Ks, N2)}` |
| Step 5 | `{"step": 5, "fn2": E(Ks, N2+1)}` |
| Chat | `{"type": "chat", "ct": E(Ks, pesan)}` |
| Error | `{"type": "error", "message": "..."}` |
| Tutup sesi | `{"type": "bye"}` |

Semua ciphertext berupa string hex dari `IV ‖ ciphertext` (AES-128-CBC, padding PKCS#7).

## Wireshark

- Pilih interface yang terhubung ke jaringan yang dipakai (Wi-Fi/hotspot), bukan loopback.
- Filter: `tcp.port == 5000 || tcp.port == 6000`
- Klik kanan paket → **Follow → TCP Stream** untuk melihat isi pesan.
- Step 1 terlihat dalam plaintext (sesuai skenario). Step 2–5 dan chat hanya berisi hex.

## Menjalankan test

```bash
python -m unittest
```

## Catatan keamanan

- **Step 1 tidak dienkripsi**, sesuai skenario. Modifikasi `id_b` di step 1 terdeteksi karena KDC mengembalikan ID di dalam `for_a` yang dikunci Ka.
- **Replay ticket lama** (step 3) dicegah oleh tantangan N2 di step 4–5, selama Ks lama tidak bocor. Kalau Ks lama bocor, ticket lama bisa diputar ulang (Denning–Sacco); umumnya diatasi dengan timestamp.
- **AES-CBC hanya menjamin kerahasiaan**, bukan keutuhan pesan. Untuk integritas dibutuhkan MAC (misalnya HMAC).
- **Ks terdiri dari 16 karakter alfanumerik** (sekitar 2⁹⁵ kemungkinan), lebih kecil dari 2¹²⁸ karena dibatasi format ASCII, tetapi tetap jauh di luar jangkauan brute force.
