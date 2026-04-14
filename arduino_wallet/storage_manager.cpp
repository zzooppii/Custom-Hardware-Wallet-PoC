/**
 * storage_manager.cpp — ESP32 NVS 암호화 저장/복호화 구현
 *
 * AES-256-GCM 암호화 흐름:
 *   1. enc_salt(16바이트) 랜덤 생성
 *   2. AES 키 파생: PBKDF2-HMAC-SHA256(pin, enc_salt, 10000) → 32바이트
 *   3. IV(12바이트) 랜덤 생성
 *   4. mbedtls_gcm_crypt_and_tag()로 니모닉 암호화
 *   5. enc_salt, iv, tag, ciphertext 모두 NVS에 저장
 *
 * 복호화 흐름:
 *   1. NVS에서 enc_salt, iv, tag, ciphertext 읽기
 *   2. PBKDF2로 AES 키 재파생
 *   3. mbedtls_gcm_auth_decrypt()로 복호화 + GCM 인증
 *   4. 인증 실패 시 false 반환 (잘못된 PIN 또는 데이터 변조)
 */

#include "storage_manager.h"
#include <Preferences.h>
#include <string.h>
#include <stdio.h>

// mbedtls
#include "mbedtls/gcm.h"
#include "mbedtls/md.h"
#include "mbedtls/pkcs5.h"
#include "mbedtls/platform_util.h"

// ESP32 RNG
#ifdef ESP32
#include <esp_random.h>
#endif

// NVS 네임스페이스
static const char* NVS_NS = "hwwallet";

// ── 내부 유틸 ─────────────────────────────────────────────────────────────────

static void bytes_to_hex(const uint8_t* in, size_t len, char* out) {
    for (size_t i = 0; i < len; i++) {
        snprintf(out + i*2, 3, "%02x", in[i]);
    }
    out[len*2] = '\0';
}

static bool hex_to_bytes(const char* hex, uint8_t* out, size_t expectedLen) {
    size_t hexLen = strlen(hex);
    if (hexLen != expectedLen * 2) return false;
    for (size_t i = 0; i < expectedLen; i++) {
        char hi = hex[i*2], lo = hex[i*2+1];
        auto nib = [](char c) -> int {
            if (c >= '0' && c <= '9') return c - '0';
            if (c >= 'a' && c <= 'f') return c - 'a' + 10;
            if (c >= 'A' && c <= 'F') return c - 'A' + 10;
            return -1;
        };
        int hn = nib(hi), ln = nib(lo);
        if (hn < 0 || ln < 0) return false;
        out[i] = (uint8_t)((hn << 4) | ln);
    }
    return true;
}

static void gen_random_bytes(uint8_t* buf, size_t len) {
#ifdef ESP32
    for (size_t i = 0; i < len; i += 4) {
        uint32_t r = esp_random();
        for (size_t j = 0; j < 4 && (i+j) < len; j++) {
            buf[i+j] = (r >> (j*8)) & 0xFF;
        }
    }
#else
    // 테스트 환경 폴백 (절대 실사용 금지)
    for (size_t i = 0; i < len; i++) buf[i] = (uint8_t)i;
#endif
}

// PBKDF2-HMAC-SHA256: PIN → 32바이트 AES 키
static bool derive_aes_key(const char* pin, const uint8_t* enc_salt, uint8_t aes_key[32]) {
    const mbedtls_md_info_t* md = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    mbedtls_md_context_t ctx;
    mbedtls_md_init(&ctx);
    int ret = mbedtls_md_setup(&ctx, md, 1);
    if (ret != 0) { mbedtls_md_free(&ctx); return false; }

    ret = mbedtls_pkcs5_pbkdf2_hmac(
        &ctx,
        (const uint8_t*)pin, strlen(pin),  // password = PIN
        enc_salt, 16,                       // salt
        10000,                              // iterations
        32,                                 // dkLen = 32바이트 (AES-256)
        aes_key
    );
    mbedtls_md_free(&ctx);
    return ret == 0;
}

// ── 공개 API 구현 ─────────────────────────────────────────────────────────────

bool storage_is_initialized() {
    Preferences prefs;
    prefs.begin(NVS_NS, true);
    bool val = prefs.getBool("init", false);
    prefs.end();
    return val;
}

void storage_set_initialized(bool val) {
    Preferences prefs;
    prefs.begin(NVS_NS, false);
    prefs.putBool("init", val);
    prefs.end();
}

bool storage_set_pin(const char* pin_hash_hex, const char* pin_salt_hex) {
    Preferences prefs;
    prefs.begin(NVS_NS, false);
    prefs.putString("pinHash", pin_hash_hex);
    prefs.putString("pinSalt", pin_salt_hex);
    prefs.end();
    return true;
}

bool storage_get_pin(char* pin_hash_hex_out, char* pin_salt_hex_out) {
    Preferences prefs;
    prefs.begin(NVS_NS, true);
    String h = prefs.getString("pinHash", "");
    String s = prefs.getString("pinSalt", "");
    prefs.end();
    if (h.length() != 64 || s.length() != 32) return false;
    strncpy(pin_hash_hex_out, h.c_str(), 65);
    strncpy(pin_salt_hex_out, s.c_str(), 33);
    return true;
}

int storage_get_fail_count() {
    Preferences prefs;
    prefs.begin(NVS_NS, true);
    int val = prefs.getInt("failCount", 0);
    prefs.end();
    return val;
}

void storage_set_fail_count(int count) {
    Preferences prefs;
    prefs.begin(NVS_NS, false);
    prefs.putInt("failCount", count);
    prefs.end();
}

uint32_t storage_get_locked_until() {
    Preferences prefs;
    prefs.begin(NVS_NS, true);
    uint32_t val = prefs.getUInt("lockedUnt", 0);
    prefs.end();
    return val;
}

void storage_set_locked_until(uint32_t millis_ts) {
    Preferences prefs;
    prefs.begin(NVS_NS, false);
    prefs.putUInt("lockedUnt", millis_ts);
    prefs.end();
}

bool storage_encrypt_and_save_mnemonic(const char* mnemonic, const char* pin) {
    size_t mnemonicLen = strlen(mnemonic);
    if (mnemonicLen == 0 || mnemonicLen > 200) return false;

    // 랜덤 salt(16바이트), IV(12바이트) 생성
    uint8_t enc_salt[16], iv[12];
    gen_random_bytes(enc_salt, 16);
    gen_random_bytes(iv, 12);

    // PBKDF2로 AES-256 키 파생
    uint8_t aes_key[32];
    if (!derive_aes_key(pin, enc_salt, aes_key)) return false;

    // AES-256-GCM 암호화
    uint8_t ciphertext[200];
    uint8_t tag[16];

    mbedtls_gcm_context gcm;
    mbedtls_gcm_init(&gcm);
    int ret = mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, aes_key, 256);
    if (ret == 0) {
        ret = mbedtls_gcm_crypt_and_tag(
            &gcm, MBEDTLS_GCM_ENCRYPT,
            mnemonicLen,
            iv, 12,
            nullptr, 0,  // AAD 없음
            (const uint8_t*)mnemonic, ciphertext,
            16, tag
        );
    }
    mbedtls_gcm_free(&gcm);
    mbedtls_platform_zeroize(aes_key, sizeof(aes_key));
    if (ret != 0) return false;

    // hex 문자열로 변환하여 NVS 저장
    char enc_salt_hex[33], iv_hex[25], tag_hex[33];
    char cipher_hex[401];  // 최대 200바이트 → 400자 hex

    bytes_to_hex(enc_salt, 16, enc_salt_hex);
    bytes_to_hex(iv, 12, iv_hex);
    bytes_to_hex(tag, 16, tag_hex);
    bytes_to_hex(ciphertext, mnemonicLen, cipher_hex);

    Preferences prefs;
    prefs.begin(NVS_NS, false);
    prefs.putString("encSalt", enc_salt_hex);
    prefs.putString("encIv",   iv_hex);
    prefs.putString("encTag",  tag_hex);
    prefs.putString("encData", cipher_hex);
    prefs.end();

    // 민감 데이터 제로화
    mbedtls_platform_zeroize(enc_salt, sizeof(enc_salt));
    mbedtls_platform_zeroize(iv, sizeof(iv));
    mbedtls_platform_zeroize(tag, sizeof(tag));
    mbedtls_platform_zeroize(ciphertext, sizeof(ciphertext));

    return true;
}

bool storage_decrypt_mnemonic(const char* pin, char* mnemonic_out) {
    Preferences prefs;
    prefs.begin(NVS_NS, true);
    String enc_salt_str = prefs.getString("encSalt", "");
    String iv_str       = prefs.getString("encIv",   "");
    String tag_str      = prefs.getString("encTag",  "");
    String data_str     = prefs.getString("encData", "");
    prefs.end();

    if (enc_salt_str.length() != 32 || iv_str.length() != 24 ||
        tag_str.length() != 32 || data_str.length() == 0) {
        return false;
    }

    // hex → 바이트 변환
    uint8_t enc_salt[16], iv[12], tag[16];
    if (!hex_to_bytes(enc_salt_str.c_str(), enc_salt, 16)) return false;
    if (!hex_to_bytes(iv_str.c_str(),       iv,       12)) return false;
    if (!hex_to_bytes(tag_str.c_str(),       tag,      16)) return false;

    size_t cipherLen = data_str.length() / 2;
    uint8_t ciphertext[200];
    if (!hex_to_bytes(data_str.c_str(), ciphertext, cipherLen)) return false;

    // PBKDF2로 AES-256 키 파생
    uint8_t aes_key[32];
    if (!derive_aes_key(pin, enc_salt, aes_key)) return false;

    // AES-256-GCM 복호화 + GCM 인증 태그 검증
    uint8_t plaintext[200];
    mbedtls_gcm_context gcm;
    mbedtls_gcm_init(&gcm);
    int ret = mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, aes_key, 256);
    if (ret == 0) {
        ret = mbedtls_gcm_auth_decrypt(
            &gcm, cipherLen,
            iv, 12,
            nullptr, 0,  // AAD 없음
            tag, 16,     // GCM auth tag (검증됨)
            ciphertext, plaintext
        );
    }
    mbedtls_gcm_free(&gcm);
    mbedtls_platform_zeroize(aes_key, sizeof(aes_key));
    mbedtls_platform_zeroize(ciphertext, sizeof(ciphertext));

    if (ret != 0) {
        // GCM 인증 실패 = 잘못된 PIN 또는 데이터 변조
        mbedtls_platform_zeroize(plaintext, sizeof(plaintext));
        return false;
    }

    memcpy(mnemonic_out, plaintext, cipherLen);
    mnemonic_out[cipherLen] = '\0';

    mbedtls_platform_zeroize(plaintext, sizeof(plaintext));
    mbedtls_platform_zeroize(enc_salt, sizeof(enc_salt));
    mbedtls_platform_zeroize(iv, sizeof(iv));
    mbedtls_platform_zeroize(tag, sizeof(tag));

    return true;
}

void storage_wipe_all() {
    Preferences prefs;
    prefs.begin(NVS_NS, false);
    prefs.clear();
    prefs.end();
}
