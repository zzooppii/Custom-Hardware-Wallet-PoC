/**
 * crypto_utils.cpp — BIP39 생성 / BIP32 HD 키 파생
 *
 * 구현 세부사항:
 *   - PBKDF2-HMAC-SHA512: mbedtls_pkcs5_pbkdf2_hmac() 사용
 *   - HMAC-SHA512:        mbedtls MD API 사용
 *   - 256비트 모듈러 덧셈: secp256k1 곡선 위수(n)에 대한 직접 구현
 *   - 공개키 압축:         micro-ecc uECC_compute_public_key() + y 홀짝 확인
 */

#include "crypto_utils.h"
#include "bip39_english.h"   // PROGMEM 단어 배열
#include <string.h>
#include <stdio.h>

// mbedtls
#include "mbedtls/sha256.h"
#include "mbedtls/sha512.h"
#include "mbedtls/md.h"
#include "mbedtls/pkcs5.h"
#include "mbedtls/platform_util.h"

// micro-ecc (공개키 연산)
#include <uECC.h>

// ESP32 하드웨어 RNG
#ifdef ESP32
#include <esp_random.h>
#endif

// ── secp256k1 곡선 위수 n ────────────────────────────────────────────────────
// n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
const uint8_t SECP256K1_N[32] = {
    0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
    0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFE,
    0xBA,0xAE,0xDC,0xE6,0xAF,0x48,0xA0,0x3B,
    0xBF,0xD2,0x5E,0x8C,0xD0,0x36,0x41,0x41,
};

// ── 256비트 빅엔디언 모듈러 덧셈: (a + b) mod n ──────────────────────────────
// BIP32 child key: child = (parse256(IL) + parent) mod n
static void mod_add_n(const uint8_t a[32], const uint8_t b[32], uint8_t out[32]) {
    uint16_t carry = 0;
    for (int i = 31; i >= 0; i--) {
        uint16_t sum = (uint16_t)a[i] + b[i] + carry;
        out[i] = (uint8_t)(sum & 0xFF);
        carry  = sum >> 8;
    }
    // 결과가 n 이상이면 n을 뺌 (조건부 감산)
    // 비교: out >= SECP256K1_N?
    bool geq = false;
    for (int i = 0; i < 32; i++) {
        if (out[i] > SECP256K1_N[i]) { geq = true;  break; }
        if (out[i] < SECP256K1_N[i]) { geq = false; break; }
        if (i == 31)                 { geq = true;          }  // 완전히 같음
    }
    if (carry || geq) {
        int16_t borrow = 0;
        for (int i = 31; i >= 0; i--) {
            int16_t diff = (int16_t)out[i] - SECP256K1_N[i] - borrow;
            if (diff < 0) { out[i] = (uint8_t)(diff + 256); borrow = 1; }
            else          { out[i] = (uint8_t)diff;          borrow = 0; }
        }
    }
}

// ── 공개키 압축 (65바이트 uncompressed → 33바이트 compressed) ─────────────────
// uncompressed: 0x04 || x(32) || y(32)  또는  x(32) || y(32) (micro-ecc 형식)
static void compress_pubkey(const uint8_t uncompressed[64], uint8_t compressed[33]) {
    // micro-ecc는 0x04 prefix 없이 x||y 64바이트 반환
    compressed[0] = (uncompressed[63] & 1) ? 0x03 : 0x02;  // y 홀짝
    memcpy(compressed + 1, uncompressed, 32);                // x 좌표
}

// ── HMAC-SHA512 ───────────────────────────────────────────────────────────────
static void hmac_sha512(const uint8_t* key, size_t key_len,
                        const uint8_t* data, size_t data_len,
                        uint8_t out[64]) {
    const mbedtls_md_info_t* md = mbedtls_md_info_from_type(MBEDTLS_MD_SHA512);
    mbedtls_md_context_t ctx;
    mbedtls_md_init(&ctx);
    mbedtls_md_setup(&ctx, md, 1);  // 1 = HMAC
    mbedtls_md_hmac_starts(&ctx, key, key_len);
    mbedtls_md_hmac_update(&ctx, data, data_len);
    mbedtls_md_hmac_finish(&ctx, out);
    mbedtls_md_free(&ctx);
}

// ── BIP39: 니모닉 생성 ────────────────────────────────────────────────────────

bool generate_mnemonic(char* output, size_t maxLen) {
#ifdef ESP32
    // 128비트(16바이트) 엔트로피 생성 (esp_random은 32비트씩 반환)
    uint8_t entropy[16];
    for (int i = 0; i < 4; i++) {
        uint32_t r = esp_random();
        entropy[i*4+0] = (r >> 24) & 0xFF;
        entropy[i*4+1] = (r >> 16) & 0xFF;
        entropy[i*4+2] = (r >>  8) & 0xFF;
        entropy[i*4+3] = (r      ) & 0xFF;
    }
#else
    // 테스트 환경 (비 ESP32): 고정값 사용 (절대 실사용 금지)
    uint8_t entropy[16] = {
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    };
#endif

    // SHA-256 체크섬 (첫 4비트만 사용)
    uint8_t hash[32];
    mbedtls_sha256(entropy, 16, hash, 0);
    uint8_t checksum = (hash[0] >> 4) & 0x0F;  // 상위 4비트

    // 132비트 = 128비트 엔트로피 + 4비트 체크섬
    // 11비트씩 12그룹으로 분할하여 단어 인덱스 추출
    uint8_t bits[17];
    memcpy(bits, entropy, 16);
    bits[16] = checksum << 4;  // 체크섬을 상위 비트에 배치

    size_t outLen = 0;
    for (int w = 0; w < 12; w++) {
        // 비트 위치: w * 11
        int bitPos   = w * 11;
        int byteIdx  = bitPos / 8;
        int bitShift = bitPos % 8;

        uint16_t idx = 0;
        idx  = (uint16_t)(bits[byteIdx]   & (0xFF >> bitShift)) << (3 + bitShift);
        idx |= (uint16_t)(bits[byteIdx+1])                      >> (5 - bitShift);
        if (bitShift > 5)
            idx |= (uint16_t)(bits[byteIdx+2]) >> (13 - bitShift);
        idx &= 0x7FF;  // 11비트 마스크

        // PROGMEM에서 단어 읽기
        const char* wordPtr = (const char*)pgm_read_ptr(&bip39_english[idx]);
        char word[12];
        strncpy_P(word, wordPtr, 11);
        word[11] = '\0';

        if (w > 0 && outLen < maxLen - 1) {
            output[outLen++] = ' ';
        }
        size_t wlen = strlen(word);
        if (outLen + wlen < maxLen) {
            memcpy(output + outLen, word, wlen);
            outLen += wlen;
        }
    }
    output[outLen] = '\0';

    // 민감 데이터 제로화
    mbedtls_platform_zeroize(entropy, sizeof(entropy));
    mbedtls_platform_zeroize(hash, sizeof(hash));

    return outLen > 0;
}

// ── BIP39 단어 이진 탐색 (단어목록은 알파벳 순 정렬) ─────────────────────────
// 반환값: 0-2047 인덱스, 없으면 -1
static int bip39_find_word(const char* word) {
    int lo = 0, hi = 2047;
    while (lo <= hi) {
        int mid = (lo + hi) / 2;
        const char* wordPtr = (const char*)pgm_read_ptr(&bip39_english[mid]);
        int cmp = strcmp_P(word, wordPtr);
        if (cmp == 0) return mid;
        else if (cmp < 0) hi = mid - 1;
        else lo = mid + 1;
    }
    return -1;
}

bool validate_mnemonic(const char* mnemonic) {
    // 1. 입력 복사 후 공백으로 분리 (strtok는 원본 수정)
    char buf[256];
    strncpy(buf, mnemonic, sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = '\0';

    char* words[13];  // 13개까지 탐지 (12개 초과 방지)
    int count = 0;
    char* tok = strtok(buf, " ");
    while (tok && count < 13) {
        words[count++] = tok;
        tok = strtok(NULL, " ");
    }
    if (count != 12) return false;  // 정확히 12단어여야 함

    // 2. 각 단어 BIP39 단어목록 검색 → 인덱스 추출
    uint16_t indices[12];
    for (int i = 0; i < 12; i++) {
        int idx = bip39_find_word(words[i]);
        if (idx < 0) return false;  // 목록에 없는 단어
        indices[i] = (uint16_t)idx;
    }

    // 3. 132비트 비트 패킹 (11비트씩, MSB 우선)
    uint8_t bits[17];
    memset(bits, 0, sizeof(bits));
    for (int i = 0; i < 12; i++) {
        uint16_t idx = indices[i];
        int bitStart = i * 11;
        for (int b = 0; b < 11; b++) {
            int bit = (idx >> (10 - b)) & 1;
            int pos = bitStart + b;
            if (bit) bits[pos / 8] |= (uint8_t)(1 << (7 - (pos % 8)));
        }
    }

    // 4. 체크섬 검증: SHA-256(bits[0..15])[0] 상위 4비트 == bits[16] 상위 4비트
    uint8_t hash[32];
    mbedtls_sha256(bits, 16, hash, 0);
    bool ok = ((hash[0] >> 4) == (bits[16] >> 4));
    mbedtls_platform_zeroize(hash, sizeof(hash));
    return ok;
}

// ── BIP39 → 시드 ──────────────────────────────────────────────────────────────

void mnemonic_to_seed(const char* mnemonic, uint8_t seed[64]) {
    // PBKDF2-HMAC-SHA512(password=mnemonic, salt="mnemonic", iterations=2048, dklen=64)
    const mbedtls_md_info_t* md = mbedtls_md_info_from_type(MBEDTLS_MD_SHA512);
    mbedtls_md_context_t ctx;
    mbedtls_md_init(&ctx);
    mbedtls_md_setup(&ctx, md, 1);

    const uint8_t* salt = (const uint8_t*)"mnemonic";
    mbedtls_pkcs5_pbkdf2_hmac(
        &ctx,
        (const uint8_t*)mnemonic, strlen(mnemonic),  // password
        salt, 8,                                       // salt = "mnemonic"
        2048,                                          // iterations (BIP39 표준)
        64,                                            // dkLen = 64바이트
        seed
    );

    mbedtls_md_free(&ctx);
}

// ── BIP32 마스터 키 ───────────────────────────────────────────────────────────

void seed_to_master(const uint8_t seed[64],
                    uint8_t master_key[32], uint8_t master_chain[32]) {
    uint8_t I[64];
    const uint8_t key[] = "Bitcoin seed";
    hmac_sha512(key, 12, seed, 64, I);

    memcpy(master_key,   I,      32);  // IL = 마스터 프라이빗 키
    memcpy(master_chain, I + 32, 32);  // IR = 마스터 체인코드

    mbedtls_platform_zeroize(I, sizeof(I));
}

// ── BIP32 Hardened 자식 키 파생 ───────────────────────────────────────────────

void derive_child_hardened(const uint8_t parent_key[32],
                           const uint8_t parent_chain[32],
                           uint32_t index,
                           uint8_t child_key[32],
                           uint8_t child_chain[32]) {
    // 인덱스는 반드시 0x80000000 이상 (hardened)
    uint32_t idx = index | 0x80000000;

    // 데이터: 0x00 || parent_key(32) || index(4바이트 big-endian)
    uint8_t data[37];
    data[0] = 0x00;
    memcpy(data + 1, parent_key, 32);
    data[33] = (idx >> 24) & 0xFF;
    data[34] = (idx >> 16) & 0xFF;
    data[35] = (idx >>  8) & 0xFF;
    data[36] = (idx      ) & 0xFF;

    uint8_t I[64];
    hmac_sha512(parent_chain, 32, data, 37, I);

    // child_key = (parse256(IL) + parent_key) mod n
    mod_add_n(I, parent_key, child_key);
    memcpy(child_chain, I + 32, 32);

    mbedtls_platform_zeroize(I, sizeof(I));
    mbedtls_platform_zeroize(data, sizeof(data));
}

// ── BIP32 Normal 자식 키 파생 ─────────────────────────────────────────────────

void derive_child_normal(const uint8_t parent_key[32],
                         const uint8_t parent_chain[32],
                         uint32_t index,
                         uint8_t child_key[32],
                         uint8_t child_chain[32]) {
    // 부모 공개키 계산 (micro-ecc: 64바이트 비압축)
    uint8_t pub_uncompressed[64];
    const struct uECC_Curve_t* curve = uECC_secp256k1();
    uECC_compute_public_key(parent_key, pub_uncompressed, curve);

    // 압축 공개키 (33바이트)
    uint8_t pub_compressed[33];
    compress_pubkey(pub_uncompressed, pub_compressed);

    // 데이터: compressed_pubkey(33) || index(4바이트 big-endian)
    uint8_t data[37];
    memcpy(data, pub_compressed, 33);
    data[33] = (index >> 24) & 0xFF;
    data[34] = (index >> 16) & 0xFF;
    data[35] = (index >>  8) & 0xFF;
    data[36] = (index      ) & 0xFF;

    uint8_t I[64];
    hmac_sha512(parent_chain, 32, data, 37, I);

    // child_key = (parse256(IL) + parent_key) mod n
    mod_add_n(I, parent_key, child_key);
    memcpy(child_chain, I + 32, 32);

    mbedtls_platform_zeroize(I, sizeof(I));
    mbedtls_platform_zeroize(pub_uncompressed, sizeof(pub_uncompressed));
}

// ── 전체 경로 파생: m/44'/60'/0'/0/{accountIndex} ────────────────────────────

bool derive_eth_privkey(const char* mnemonic, uint32_t accountIndex,
                        uint8_t privkey_out[32]) {
    // 1. 니모닉 → 64바이트 시드
    uint8_t seed[64];
    mnemonic_to_seed(mnemonic, seed);  // ~2-4초 (PBKDF2 2048회)

    // 2. 시드 → 마스터 키 + 체인코드
    uint8_t key[32], chain[32];
    seed_to_master(seed, key, chain);
    mbedtls_platform_zeroize(seed, sizeof(seed));

    // 3. m / 44' (hardened)
    uint8_t k2[32], c2[32];
    derive_child_hardened(key, chain, 44, k2, c2);

    // 4. / 60' (hardened)
    uint8_t k3[32], c3[32];
    derive_child_hardened(k2, c2, 60, k3, c3);
    mbedtls_platform_zeroize(k2, 32);
    mbedtls_platform_zeroize(c2, 32);

    // 5. / 0' (hardened)
    uint8_t k4[32], c4[32];
    derive_child_hardened(k3, c3, 0, k4, c4);
    mbedtls_platform_zeroize(k3, 32);
    mbedtls_platform_zeroize(c3, 32);

    // 6. / 0 (normal)
    uint8_t k5[32], c5[32];
    derive_child_normal(k4, c4, 0, k5, c5);
    mbedtls_platform_zeroize(k4, 32);
    mbedtls_platform_zeroize(c4, 32);

    // 7. / accountIndex (normal)
    derive_child_normal(k5, c5, accountIndex, privkey_out, c5);
    mbedtls_platform_zeroize(k5, 32);
    mbedtls_platform_zeroize(c5, 32);

    // 모든 중간 키 제로화 (보안)
    mbedtls_platform_zeroize(key, sizeof(key));
    mbedtls_platform_zeroize(chain, sizeof(chain));

    return true;
}
