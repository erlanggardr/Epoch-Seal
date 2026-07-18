#include <jni.h>
#include <cstdint>
#include <string>
#include <cstring>
#include <cstdio>
#include <unistd.h>
#include <cstdlib>
#include <time.h>
#include <ctime>
#include <memory>

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

// ======================= Util & OP_x  =======================
/*
   load_epoch_runtime()  : bangun epoch dari tanggal UTC 
   OP_3  : bagi 2 dalam domain desimal (string) 
   OP_1  : reverse digit desimal (in-place, string)
   OP_2  : /1000 (buang 3 digit terakhir, hasil u32)
   GEN   : PIN = OP_2(OP_1(OP_3(to_string(load_epoch_runtime()))))
*/

// PIN runtime helpers
static NOINLINE uint64_t load_epoch_runtime() {
    struct tm tmv{};
    tmv.tm_year = 120 + 5;   // 2025 - 1900 = 125
    tmv.tm_mon  = 1 + 1;     // March = 2 (0-based)
    tmv.tm_mday = 7 + 7;     // 14
    tmv.tm_hour = 3 + 3;     // 6
    tmv.tm_min  = 60 - 2;    // 58
    tmv.tm_sec  = 45 - 1;    // 44
    // Konversi ke epoch
    time_t t = timegm(&tmv);
    asm volatile("" :: "r"(t) : "memory");
    return (uint64_t)t;
}

// reverse desimal dari val
// OP_3: pembagian 2 berbasis string (desimal) 
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

// OP_1: reverse digit desimal
static NOINLINE void OP_1(std::string& s) {
    size_t i = 0, j = s.size();
    while (i < j) { std::swap(s[i++], s[--j]); }
}

// OP_2: bagi 1000 → ambil bagian ribuan ke atas (hasil u32)
static NOINLINE uint32_t OP_2(const std::string& s) {
    if (s.size() <= 3) return 0;
    std::string t = s.substr(0, s.size() - 3);
    return static_cast<uint32_t>(std::stoul(t));
}

// GEN: (EPOCH/2 via OP_3) → reverse → /1000
static NOINLINE uint32_t GEN() {
    uint64_t epoch = load_epoch_runtime();
    std::string sepoch = std::to_string(epoch);
    std::string shalf  = OP_3(sepoch);       // desimal-bagi-2
    OP_1(shalf);                             // reverse digit
    uint32_t pin = OP_2(shalf);              // /1000 -> u32
    asm volatile("" :: "r"(pin) : "memory");
    return pin;
}

// ===== RC4 (KSA + PRGA) =====
// ===== Key-stretching (derive 32B RC4 key from PIN) =====
//  splitmix64_once = SM64_O
//  FNV_OFFSET = FNV_O
//  rc4_key_from_pin_stretched = RC4_P_S
//  rc4_ksa = KSA
//  rc4_xor = ROX
static inline uint64_t SM64_O(uint64_t x){
    x += 0x9e3779b97f4a7c15ULL;
    uint64_t z = x;
    z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9ULL;
    z = (z ^ (z >> 27)) * 0x94d049bb133111ebULL;
    return z ^ (z >> 31);
}

static inline uint64_t fnv1a64_update(uint64_t h, const uint8_t* p, size_t n){
    const uint64_t FNV_PRIME = 1099511628211ULL;
    for (size_t i = 0; i < n; ++i) { h ^= p[i]; h *= FNV_PRIME; }
    return h;
}

#ifndef STRETCH_ROUNDS
#define STRETCH_ROUNDS 300000
#endif

static const uint64_t FNV_O = 1469598103934665603ULL;
static const uint64_t KS_NONCE64 = 0x5F3977DE13C78A42ULL; // "salt" publik (64-bit)

static void RC4_P_S(const std::string& pin, uint8_t out_key[32]){
    // seed awal = FNV1a(pin) ^ nonce
    uint64_t seed = fnv1a64_update(FNV_O,
                                   reinterpret_cast<const uint8_t*>(pin.data()), pin.size()) ^ KS_NONCE64;

    // stretching
    uint64_t s = seed;
    for (int i = 0; i < STRETCH_ROUNDS; ++i) s = SM64_O(s);

    // emit 32 byte kunci (4 x uint64_t, little-endian)
    uint64_t b0 = SM64_O(s); s = SM64_O(s);
    uint64_t b1 = SM64_O(s); s = SM64_O(s);
    memcpy(out_key + 0,  &b0, 8);
    memcpy(out_key + 8,  &s,  8);
    memcpy(out_key + 16, &b1, 8);
    uint64_t b3 = SM64_O(s);
    memcpy(out_key + 24, &b3, 8);
}

static inline void KSA(uint8_t S[256], const uint8_t* key, size_t keylen) {
    for (int i = 0; i < 256; ++i) S[i] = (uint8_t)i;
    uint8_t j = 0;
    for (int i = 0; i < 256; ++i) {
        j = (uint8_t)(j + S[i] + key[i % keylen]);
        uint8_t tmp = S[i]; S[i] = S[j]; S[j] = tmp;
    }
}

static inline void ROX(uint8_t S[256], const uint8_t* in, uint8_t* out, size_t n) {
    uint8_t i = 0, j = 0;
    for (size_t k = 0; k < n; ++k) {
        i = (uint8_t)(i + 1);
        j = (uint8_t)(j + S[i]);
        uint8_t tmp = S[i]; S[i] = S[j]; S[j] = tmp;
        uint8_t K = S[(uint8_t)(S[i] + S[j])];
        out[k] = (uint8_t)(in[k] ^ K);
    }
}

static std::string D_X(const uint8_t* ciphertext, size_t n, const std::string& pin) {
    if (pin.empty()) return "Error: Key cannot be empty.";
    uint8_t key[32];
    RC4_P_S(pin, key);
    uint8_t S[256]; KSA(S, key, sizeof(key));
    std::string out(n, '\0');
    ROX(S, ciphertext, reinterpret_cast<uint8_t*>(&out[0]), n);
    return out;
}


uint8_t enkbyte[] = {
        0x89,    0xd1,    0x54,    0xbc,    0xcc,    0x07,    0x03,    0x32,    0x2e,    0x5b,    0x2f,    0xb9,
        0xf6,    0xca,    0x1a,    0x51,    0xcd,    0x38,    0xcd,    0x28,    0x77,    0xe0,    0x0d,    0xfc,
        0xb0,    0x18,    0x2a,    0xb5,    0x0e,    0x04,    0x51,    0x78,    0x95,    0x5a,    0x20,    0x5c,
        0x07,    0x8f,    0x52,    0x99,    0xdd,    0x7b,    0xc5,    0xc9,    0xee,    0xf1,    0xae,    0xb7,
        0x73
};

extern "C"
JNIEXPORT jstring JNICALL
Java_com_schematics_epochseal_MainActivity_checkPinNative(
        JNIEnv* env,
        jobject /* this */,
        jint pin) {

    auto flag = "SCH25{android_Reverse_is_easy}"; //fek fleg #2
    auto PIN = 123456; //fek pin

    if(C_D() || C_F()){
        sleep(69);
        return env->NewStringUTF(fekFLAG);
    };

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
