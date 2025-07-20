# Epoch-Seal

Projek untuk Quals Schematics NPC CTF 2025

Main Idea :
Challange Reverse Engineering dalam bentuk aplikasi android.
Pemain diharuskan menjawab 6 digit pin dengan benar untuk mendapatkan FLAG.

PIN dihitung secara dinamis dari waktu EPOCH saat ini melalui suatu algoritma (yang akan di kembangkan), namun pin di refresh setiap 5 menit untuk memberikan kesempatan.
Program ini menggunakan anti debug (detect ptrace/TracerPid), anti bruteforce (delay dan limit attempt)

Peserta tidak diperkenankan untuk menggunakan debugging runtime/patching, karena di harapkan untuk melakukan reverse engineering secara analisis statik.
Dengan cara merekonstruksi algoritma yang sudah ditetapkan untuk mendapatkan hasil PIN yang valid.

