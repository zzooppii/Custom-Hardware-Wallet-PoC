/**
 * secp256k1_signer.cpp — ECDSA 서명 구현
 *
 * ▶ EIP-2 Low-S 정규화:
 *   secp256k1 서명은 (r, s)와 (r, n-s)가 모두 유효하지만,
 *   이더리움 Homestead(EIP-2)는 s <= n/2인 정규형만 허용합니다.
 *   sign_hash()는 서명 후 s > n/2이면 자동으로 s = n - s로 교체하고 v를 반전합니다.
 *
 * ▶ V값 복구:
 *   uECC_recover()로 recovery_id 0, 1을 시도하여 알려진 공개키와 비교합니다.
 *   이 기능은 micro-ecc recovery 지원 버전이 필요합니다.
 *
 * ▶ RFC 6979 결정론적 서명:
 *   uECC_sign_deterministic()은 k값을 HMAC-DRBG로 결정론적으로 생성합니다.
 */

#include "secp256k1_signer.h"
#include "crypto_utils.h"  // SECP256K1_N 공유
#include <uECC.h>
#include <string.h>

// ── ESP32 하드웨어 RNG ────────────────────────────────────────────────────────
#ifdef ESP32
#include <esp_random.h>
static int esp32_rng(uint8_t* dest, unsigned size) {
    uint32_t val;
    for (unsigned i = 0; i < size; i++) {
        if (i % 4 == 0) val = esp_random();
        dest[i] = (uint8_t)(val >> (8 * (i % 4)));
    }
    return 1;
}
#endif

// ── mbedtls SHA-256 래퍼 (RFC 6979 결정론적 서명용) ──────────────────────────
#include "mbedtls/sha256.h"
#include "mbedtls/md.h"

typedef struct {
    uECC_HashContext uECC;
    mbedtls_sha256_context ctx;
    uint8_t tmp[2 * 32 + 64];
} SHA256_HashContext;

static void _sha256_init(const uECC_HashContext* base) {
    SHA256_HashContext* ctx = (SHA256_HashContext*)base;
    mbedtls_sha256_init(&ctx->ctx);
    mbedtls_sha256_starts(&ctx->ctx, 0);
}

static void _sha256_update(const uECC_HashContext* base,
                           const uint8_t* msg, unsigned len) {
    SHA256_HashContext* ctx = (SHA256_HashContext*)base;
    mbedtls_sha256_update(&ctx->ctx, msg, len);
}

static void _sha256_finish(const uECC_HashContext* base, uint8_t* out) {
    SHA256_HashContext* ctx = (SHA256_HashContext*)base;
    mbedtls_sha256_finish(&ctx->ctx, out);
}

// ── EIP-2 Low-S 정규화 ────────────────────────────────────────────────────────

// secp256k1 n/2 = 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0
static const uint8_t SECP256K1_N_HALF[32] = {
    0x7F,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
    0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
    0x5D,0x57,0x6E,0x73,0x57,0xA4,0x50,0x1D,
    0xDF,0xE9,0x2F,0x46,0x68,0x1B,0x20,0xA0,
};

// 32바이트 빅엔디언 비교: a < b → -1, a == b → 0, a > b → 1
static int bn_cmp(const uint8_t a[32], const uint8_t b[32]) {
    for (int i = 0; i < 32; i++) {
        if (a[i] < b[i]) return -1;
        if (a[i] > b[i]) return  1;
    }
    return 0;
}

// s > n/2이면 s = n - s 로 교체하고 v 반전 (EIP-2)
static void normalize_s(ECDSASignature* sig) {
    if (bn_cmp(sig->s, SECP256K1_N_HALF) <= 0) return;  // 이미 정규형

    // s = n - s (256비트 빼기)
    int16_t borrow = 0;
    for (int i = 31; i >= 0; i--) {
        int16_t diff = (int16_t)SECP256K1_N[i] - (int16_t)sig->s[i] - borrow;
        if (diff < 0) {
            sig->s[i] = (uint8_t)(diff + 256);
            borrow = 1;
        } else {
            sig->s[i] = (uint8_t)diff;
            borrow = 0;
        }
    }

    // v 반전: 27 ↔ 28
    sig->v = (sig->v == 27) ? 28 : 27;
}

// ── 공개 API 구현 ─────────────────────────────────────────────────────────────

bool compute_pubkey(const uint8_t privkey[32], uint8_t pubkey[64]) {
#ifdef ESP32
    uECC_set_rng(esp32_rng);
#endif
    const struct uECC_Curve_t* curve = uECC_secp256k1();
    return uECC_compute_public_key(privkey, pubkey, curve) == 1;
}

bool sign_hash(const uint8_t privkey[32], const uint8_t hash[32], ECDSASignature* sig) {
#ifdef ESP32
    uECC_set_rng(esp32_rng);
#endif
    const struct uECC_Curve_t* curve = uECC_secp256k1();

    SHA256_HashContext ctx = {
        { &_sha256_init, &_sha256_update, &_sha256_finish, 32, 64, ctx.tmp },
        {}, {}
    };

    // (r, s) 서명 생성
    uint8_t rs[64];
    int result = uECC_sign_deterministic(
        privkey, hash, 32,
        &ctx.uECC,
        rs, curve
    );
    if (result != 1) return false;

    memcpy(sig->r, rs,      32);
    memcpy(sig->s, rs + 32, 32);

    // ── V값 복구 ──────────────────────────────────────────────────────────────
    uint8_t known_pubkey[64];
    if (!compute_pubkey(privkey, known_pubkey)) return false;

    sig->v = 0;  // 초기화

    for (int rec_id = 0; rec_id < 2; rec_id++) {
        uint8_t recovered[64];

#ifdef uECC_SUPPORTS_RECOVERY
        if (uECC_recover(hash, rs, rec_id, recovered, curve) != 1) continue;
        if (memcmp(recovered, known_pubkey, 64) == 0) {
            sig->v = 27 + (uint8_t)rec_id;
            break;
        }
#else
        // micro-ecc recovery 미지원: 컴파일 오류로 조기 경고
        // 이 코드에 도달했다면 recovery를 지원하는 micro-ecc 포크를 설치해야 합니다.
        // 예: https://github.com/kmackay/micro-ecc (최신 버전의 uECC_recover 확인)
        #error "uECC_recover() is required for correct v-value recovery. \
Install a micro-ecc build that defines uECC_SUPPORTS_RECOVERY."
#endif
    }

    if (sig->v == 0) {
        // 복구 실패 — 서명은 유효하지만 v를 결정할 수 없음
        return false;
    }

    // ── EIP-2: Low-S 정규화 ───────────────────────────────────────────────────
    normalize_s(sig);

    return true;
}

bool recover_pubkey(const uint8_t hash[32], const ECDSASignature* sig,
                    const uint8_t expected_pubkey[64], bool* match) {
#ifdef uECC_SUPPORTS_RECOVERY
    const struct uECC_Curve_t* curve = uECC_secp256k1();
    uint8_t rs[64];
    memcpy(rs,      sig->r, 32);
    memcpy(rs + 32, sig->s, 32);

    uint8_t recovered[64];
    int rec_id = sig->v - 27;
    if (rec_id < 0 || rec_id > 1) { *match = false; return false; }
    if (uECC_recover(hash, rs, rec_id, recovered, curve) != 1) {
        *match = false;
        return false;
    }
    *match = (memcmp(recovered, expected_pubkey, 64) == 0);
    return true;
#else
    #error "uECC_recover() is required. Install a micro-ecc build that defines uECC_SUPPORTS_RECOVERY."
    *match = false;
    return false;
#endif
}
