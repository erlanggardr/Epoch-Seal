# Epoch-Seal

An Android-based reverse engineering challenge developed for the **Schematics NPC CTF 2025 Qualification Round**.

## Challenge Description
> March 2025. As the peak of the lunar eclipse arrived, Pisi panicked because he could not live without sunlight. He locked his application right at the peak of the eclipse, then fled to parts unknown. All that remains is a locked Android application.
> The app is locked by a number. Legend has it that this number is related to the time Pisi left behind.

* **Category:** Reverse Engineering
* **Difficulty:** Easy / Medium
* **Target SHA-256:** `a8e74a3ad4f11012d59cb97027842d7ad9dece2fbd6dd66ee26271f92341f62b`

---

## Design & Implementation Details

This project is implemented as an Android application using **Kotlin** for the frontend and **C++ (JNI / Android NDK)** for the core verification logic to deter trivial reverse engineering.

### Key Features
1. **Dynamic PIN Generation**: 
   * The valid PIN is calculated dynamically based on a specific build-time Epoch timestamp (March 14, 2025, 06:58:44 UTC $\rightarrow$ `1741935524`).
   * To prevent compilers or decompilers (like Jadx or Ghidra) from optimizing or displaying the epoch as a literal constant, the timestamp is reconstructed at runtime through time structure conversion (`tm` struct).
   * The validation algorithm performs decimal digit division and reverse operations.

2. **Advanced Cryptography (RC4 & Key Stretching)**:
   * Instead of a simple XOR, the decryption key is derived from the user-entered PIN using FNV-1a hashing mixed with a public salt (`0x5F3977DE13C78A42`).
   * The key is stretched through **300,000 rounds** of the `SplitMix64` algorithm to prevent efficient offline brute-forcing of the 6-digit PIN.
   * If the correct PIN is derived, it initializes the RC4 state to decrypt the embedded flag ciphertext.

3. **Anti-Debugging & Tamper Protections**:
   * **ptrace/TracerPid Detection**: Standard Linux anti-debugging that detects if a debugger is attached to the process.
   * **Delayed Execution Penalty**: If debugging or tampering is detected, the JNI layer sleeps for `69` seconds and returns a fake flag (`SCH25{UthinkSO?_=P}`), frustrating dynamic analysis attempts and standard runtime script automation.
   * Forces analysts to rely on **static analysis** and manual algorithm reconstruction.

---

## CTF Hints & Solution Outline
1. **Hint 1:** The peak of the Lunar Eclipse in March is March 14, 2025, 6:58:44 UTC.
2. **Hint 2:** Epoch timestamp is `1741935524`.
3. **Hint 3:** Analyze the JNI library `native-lib` to reconstruct the PIN generation algorithm. Inputting the correct epoch time into the reconstructed logic yields the valid 6-digit PIN. Entering this PIN in the app decrypts the flag.

---

## Bahasa Indonesia (Indonesian Version)

### Deskripsi Tantangan
> Maret 2025. Pada detik puncak gerhana bulan tiba, si Pisi panik, karena ia tak bisa hidup tanpa cahaya matahari. Ia mengunci aplikasinya tepat di momen puncak gerhana, lalu kabur melarikan diri entah kemana. Yang tersisa hanyalah sebuah aplikasi android yang terkunci.
> Aplikasi itu terkunci oleh angka. Konon, angka ini berhubungan dengan waktu yang di tinggalkan si Pisi.

* **Kategori:** Reverse Engineering
* **Kesulitan:** Mudah / Sedang
* **Target SHA-256:** `a8e74a3ad4f11012d59cb97027842d7ad9dece2fbd6dd66ee26271f92341f62b`

### Detail Desain & Implementasi
Proyek ini diimplementasikan sebagai aplikasi Android menggunakan **Kotlin** pada sisi frontend dan **C++ (JNI / Android NDK)** untuk logika verifikasi inti guna mencegah analisis balik yang sepele.

#### Fitur Utama
1. **Pembuatan PIN Dinamis**: PIN yang valid dihitung secara dinamis berdasarkan waktu Epoch saat proses kompilasi (14 Maret 2025, 06:58:44 UTC $\rightarrow$ `1741935524`).
2. **Kriptografi Lanjut (RC4 & Key Stretching)**: Kunci dekripsi diturunkan dari PIN menggunakan hashing FNV-1a dan salt statik (`0x5F3977DE13C78A42`), lalu di-stretch sebanyak **300.000 putaran** `SplitMix64`.
3. **Anti-Debugging & Proteksi Modifikasi**: Menggunakan deteksi ptrace/TracerPid dan penalti delay waktu eksekusi selama **69 detik** dengan mengembalikan *fake flag* jika terdeteksi adanya debugger.

### Petunjuk CTF & Alur Solusi
1. **Hint 1:** Puncak Gerhana Bulan Maret adalah 14 Maret 2025, 6:58:44.5 UTC.
2. **Hint 2:** Waktu Epoch adalah `1741935524`.
3. **Hint 3:** Rekonstruksi algoritma pembuatan PIN dari file library JNI `native-lib`.

---

## Flag
The flag for this challenge is:
```text
SCH25{wah_kau_benar-benar_REVERSE_chall_ini!-0_o}
```
