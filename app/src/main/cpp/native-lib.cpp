#include <jni.h>
#include <cstdint>
#include <string>
#include <cstring>
#include <cstdio>
#include <unistd.h>
#include <cstdlib>
#include <time.h>

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
const static int EPOCH_TIME = 1741935524;

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

// PIN runtime helpers
static NOINLINE uint64_t load_epoch_runtime() {
    // Ambil nilai EPOCH_TIME yang memang visible sebagai clue
    volatile const int* p = &EPOCH_TIME;   // paksa runtime load
    int v = *p;

    // Tambahkan dependensi runtime yang dibatalkan (hasil tetap v)
    // Tujuannya cuma memutus constant folding.
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    int noise = (int)ts.tv_nsec;   // nilai runtime
    v = (v ^ noise) ^ noise;       // kembali ke v

    asm volatile("" :: "r"(v) : "memory"); // barrier kecil
    return (uint64_t)v;
}

// reverse desimal dari val
uint64_t OP_1(uint64_t val) {
    uint64_t r = 0;
    while (val) {
        r = r * 10 + (val % 10);
        val /= 10;
    }
    return r;
}

// bagi 1000
uint32_t OP_2(uint64_t val) {
    return static_cast<uint32_t>(val / 1000);
}

// generate pin
// (EPOCH_TIME/2) -> reverse -> /1000
static NOINLINE uint32_t GEN() {
    using op1_t = uint64_t(*)(uint64_t);
    using op2_t = uint32_t(*)(uint64_t);

    volatile op1_t f1 = OP_1;  // indirect call cegah inlining/IPA
    volatile op2_t f2 = OP_2;

    uint64_t half = load_epoch_runtime() / 2ULL;
    uint64_t rev  = ((op1_t)f1)(half);
    uint32_t pin  = ((op2_t)f2)(rev);

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
