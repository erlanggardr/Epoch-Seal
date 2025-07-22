# Epoch-Seal

Projek untuk Quals Schematics NPC CTF 2025

Main Idea :
Challange Reverse Engineering dalam bentuk aplikasi android.
Pemain diharuskan menjawab 6 digit pin dengan benar untuk mendapatkan FLAG.

PIN dihitung dari waktu EPOCH saat build time melalui suatu algoritma (yang akan di kembangkan).
Program ini menggunakan anti debug (detect ptrace/TracerPid), anti bruteforce (delay dan limit attempt).

Peserta tidak diperkenankan untuk menggunakan debugging runtime/patching, karena di harapkan untuk melakukan reverse engineering secara analisis statik.
Dengan cara merekonstruksi algoritma yang sudah ditetapkan untuk mendapatkan hasil PIN yang valid.

