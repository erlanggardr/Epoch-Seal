#include <jni.h>
#include <cstdint>
#include <string>
#include <cstring>
#include <cstdio>
#include <unistd.h>
#include <cstdlib>
#include <time.h>
#include <ctime>

#if defined(__clang__)
#define NOINLINE __attribute__((noinline, optnone))
#elif defined(__GNUC__)
#define NOINLINE __attribute__((noinline))
  #define NOIPA __attribute__((noipa))
#else
#define NOINLINE
  #define NOIPA
#endif

auto fekFLAG = "SCH25{UthinkSO?_=P}";
//const static int EPOCH_TIME = 1741935524;

// START ANTI-DEBUGGER
bool C_F() {
    FILE *fp = fopen("/proc/self/maps", "r");
    if (!fp) return false;

    char line[512];
    while (fgets(line, sizeof(line), fp)) {
        if (strstr(line, "frida") != nullptr || strstr(line, "gum-js-loop") != nullptr) {
            fclose(fp);
            return true;
        }
    }
    fclose(fp);
    return false;
}

bool C_D() {
    FILE *status_file = fopen("/proc/self/status", "r");
    if (!status_file) return false;

    char line[256];
    bool debugger_found = false;

    while (fgets(line, sizeof(line), status_file)) {
        if (strstr(line, "TracerPid:") != nullptr) {
            char* pid_str = strchr(line, ':');
            if (pid_str != nullptr) {
                int tracer_pid = atoi(pid_str + 1);
                if (tracer_pid != 0) debugger_found = true;
            }
            break;
        }
    }
    fclose(status_file);
    return debugger_found;
}
// END ANTI-DEBUGGER

// ======================= Util & OP_x (Pendekatan A) =======================
/*
   load_epoch_runtime()  : bangun epoch dari tanggal UTC (tanpa menyimpan epoch literal)
   OP_3  : bagi 2 dalam domain desimal (string) → hindari munculnya epoch/2 literal
   OP_1  : reverse digit desimal (in-place, string)
   OP_2  : /1000 (buang 3 digit terakhir, hasil u32)
   GEN   : PIN = OP_2(OP_1(OP_3(to_string(load_epoch_runtime()))))
*/

// PIN runtime helpers
static NOINLINE uint64_t load_epoch_runtime() {
    // Bangun waktu UTC dari hint: 14 Mar 2025 06:58:44 UTC
    // (tanpa menyimpan epoch sebagai angka)
    struct tm tmv{};
    tmv.tm_year = 120 + 5;   // 2025 - 1900 = 125
    tmv.tm_mon  = 1 + 1;     // March = 2 (0-based)
    tmv.tm_mday = 7 + 7;     // 14
    tmv.tm_hour = 3 + 3;     // 6
    tmv.tm_min  = 60 - 2;    // 58
    tmv.tm_sec  = 45 - 1;    // 44
    // Konversi ke epoch (UTC)
    time_t t = timegm(&tmv);
    // Barrier kecil agar compiler/decompiler tidak “mengakali”
    asm volatile("" :: "r"(t) : "memory");
    return (uint64_t)t;
}

// reverse desimal dari val
// OP_3: pembagian 2 berbasis string (desimal) → tidak memunculkan half sebagai konstanta
static NOINLINE std::string OP_3(const std::string& s) {
    std::string out; out.reserve(s.size());
    int carry = 0;
    for (char c : s) {
        int d = (c - '0') + carry * 10;
        out.push_back(char('0' + (d / 2)));
        carry = d % 2;
    }
    size_t p = out.find_first_not_of('0');
    return (p == std::string::npos) ? std::string("0") : out.substr(p);
}

// OP_1: reverse digit desimal (in-place, string)
static NOINLINE void OP_1(std::string& s) {
    size_t i = 0, j = s.size();
    while (i < j) { std::swap(s[i++], s[--j]); }
}

// OP_2: bagi 1000 → ambil bagian ribuan ke atas (hasil u32)
static NOINLINE uint32_t OP_2(const std::string& s) {
    if (s.size() <= 3) return 0;
    std::string t = s.substr(0, s.size() - 3);
    return static_cast<uint32_t>(std::stoul(t)); // muat untuk timestamp normal
}

// GEN: (EPOCH/2 via OP_3) → reverse → /1000
static NOINLINE uint32_t GEN() {
    uint64_t epoch = load_epoch_runtime();                 // runtime, bukan konstanta
    std::string sepoch = std::to_string(epoch);
    std::string shalf  = OP_3(sepoch);       // desimal-bagi-2 (tanpa literal half)
    OP_1(shalf);                             // reverse digit
    uint32_t pin = OP_2(shalf);              // /1000 -> u32
    asm volatile("" :: "r"(pin) : "memory");
    return pin;
}

// operasi dekripsi xor untuk flag
std::string D_X(const uint8_t* ciphertext_bytes, size_t ciphertext_size, const std::string& key) {
    if (key.empty()) return "Error: Key cannot be empty.";

    std::string decrypted_text(ciphertext_size, '\0');
    const size_t key_length = key.length();

    for (size_t i = 0; i < ciphertext_size; ++i) {
        decrypted_text[i] = static_cast<char>(ciphertext_bytes[i] ^ key[i % key_length]);
    }
    return decrypted_text;
}

// encrypted flag bytes
uint8_t enkbyte[] = {
        0x61, 0x75, 0x7f, 0x05, 0x03, 0x42, 0x45, 0x57, 0x5f, 0x68, 0x5d, 0x58,
        0x47, 0x69, 0x55, 0x52, 0x58, 0x58, 0x40, 0x1b, 0x55, 0x52, 0x58, 0x58,
        0x40, 0x69, 0x65, 0x72, 0x60, 0x7c, 0x60, 0x65, 0x72, 0x68, 0x55, 0x51,
        0x53, 0x5a, 0x5b, 0x68, 0x5f, 0x57, 0x5b, 0x17, 0x1a, 0x07, 0x69, 0x56,
        0x4f
};

extern "C"
JNIEXPORT jstring JNICALL
Java_com_schematics_epochseal_MainActivity_checkPinNative(
        JNIEnv* env,
        jobject /* this */,
        jint pin) {

    if (C_F()) {
        sleep(2);
        return env->NewStringUTF(fekFLAG);
    }

    if (C_D()) {
        return env->NewStringUTF(fekFLAG);
    }

    const uint32_t correct_pin = GEN();

    if (static_cast<uint32_t>(pin) == correct_pin) {
        std::string key = std::to_string(correct_pin);
        const size_t flag_size = sizeof(enkbyte);
        std::string decrypted = D_X(enkbyte, flag_size, key);
        return env->NewStringUTF(decrypted.c_str());
    } else {
        return env->NewStringUTF("Try again");
    }
}
