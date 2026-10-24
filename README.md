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
| 5 | Alice → Bob | `E(Ks, f(N2))` |
| 6+ | Alice ⇄ Bob | chat terenkripsi AES dengan `Ks` |

## Struktur

```
crypto/   implementasi AES, mode operasi, dan API enkripsi
net/      framing pesan dan sesi chat dua arah
kdc.py    Key Distribution Center
alice.py  inisiator
bob.py    responder
tests/    unit test
docs/     panduan pengerjaan
```
