/**
 * keccak256.cpp — Ethereum Keccak-256 구현
 *
 * Keccak sponge function (200바이트 state, 1088비트 rate, 512비트 capacity)
 * 출처: 공개 도메인 Keccak 레퍼런스 구현 기반, MIT 라이선스 재작성
 */

#include "keccak256.h"
#include <string.h>

// ── Keccak 상수 ───────────────────────────────────────────────────────────────

static const uint64_t KECCAK_RC[24] = {
    0x0000000000000001ULL, 0x0000000000008082ULL,
    0x800000000000808AULL, 0x8000000080008000ULL,
    0x000000000000808BULL, 0x0000000080000001ULL,
    0x8000000080008081ULL, 0x8000000000008009ULL,
    0x000000000000008AULL, 0x0000000000000088ULL,
    0x0000000080008009ULL, 0x000000008000000AULL,
    0x000000008000808BULL, 0x800000000000008BULL,
    0x8000000000008089ULL, 0x8000000000008003ULL,
    0x8000000000008002ULL, 0x8000000000000080ULL,
    0x000000000000800AULL, 0x800000008000000AULL,
    0x8000000080008081ULL, 0x8000000000008080ULL,
    0x0000000080000001ULL, 0x8000000080008008ULL,
};

static const int RHO[24] = {
     1,  3,  6, 10, 15, 21, 28, 36, 45, 55,  2, 14,
    27, 41, 56,  8, 25, 43, 62, 18, 39, 61, 20, 44,
};

static const int PI[24] = {
    10,  7, 11, 17, 18,  3,  5, 16,  8, 21, 24,  4,
    15, 23, 19, 13, 12,  2, 20, 14, 22,  9,  6,  1,
};

// ── 헬퍼 ───────────────────────────────────────────────────────────────────────

static inline uint64_t rotl64(uint64_t x, int n) {
    return (x << n) | (x >> (64 - n));
}

// ── Keccak-f[1600] 순열 ───────────────────────────────────────────────────────

static void keccakf(uint64_t st[25]) {
    uint64_t t, bc[5];

    for (int r = 0; r < 24; r++) {
        // Theta
        for (int i = 0; i < 5; i++)
            bc[i] = st[i] ^ st[i+5] ^ st[i+10] ^ st[i+15] ^ st[i+20];
        for (int i = 0; i < 5; i++) {
            t = bc[(i+4) % 5] ^ rotl64(bc[(i+1) % 5], 1);
            for (int j = 0; j < 25; j += 5) st[j+i] ^= t;
        }

        // Rho & Pi
        t = st[1];
        for (int i = 0; i < 24; i++) {
            int j   = PI[i];
            bc[0]   = st[j];
            st[j]   = rotl64(t, RHO[i]);
            t       = bc[0];
        }

        // Chi
        for (int j = 0; j < 25; j += 5) {
            for (int i = 0; i < 5; i++) bc[i] = st[j+i];
            for (int i = 0; i < 5; i++)
                st[j+i] ^= (~bc[(i+1)%5]) & bc[(i+2)%5];
        }

        // Iota
        st[0] ^= KECCAK_RC[r];
    }
}

// ── 공개 API ───────────────────────────────────────────────────────────────────

void keccak256(const uint8_t* input, size_t len, uint8_t* output) {
    // rate = 1088비트 = 136바이트 (capacity = 512비트, Keccak-256)
    const size_t RATE = 136;

    uint64_t st[25];
    memset(st, 0, sizeof(st));

    // 흡수 (absorb) 단계
    size_t offset = 0;
    while (len - offset >= RATE) {
        for (size_t i = 0; i < RATE / 8; i++) {
            uint64_t lane = 0;
            for (int b = 0; b < 8; b++)
                lane |= (uint64_t)(input[offset + i*8 + b]) << (8*b);
            st[i] ^= lane;
        }
        keccakf(st);
        offset += RATE;
    }

    // 패딩 블록 준비
    uint8_t block[136];
    memset(block, 0, RATE);
    size_t rem = len - offset;
    memcpy(block, input + offset, rem);

    // Keccak 패딩: 0x01 ... 0x80
    // (SHA3는 0x06을 사용하지만 Ethereum Keccak은 0x01 사용)
    block[rem]        = 0x01;
    block[RATE - 1]  |= 0x80;

    for (size_t i = 0; i < RATE / 8; i++) {
        uint64_t lane = 0;
        for (int b = 0; b < 8; b++)
            lane |= (uint64_t)(block[i*8 + b]) << (8*b);
        st[i] ^= lane;
    }
    keccakf(st);

    // 짜내기 (squeeze) 단계: 32바이트 출력
    for (int i = 0; i < 4; i++) {
        uint64_t lane = st[i];
        for (int b = 0; b < 8; b++)
            output[i*8 + b] = (uint8_t)(lane >> (8*b));
    }
}
