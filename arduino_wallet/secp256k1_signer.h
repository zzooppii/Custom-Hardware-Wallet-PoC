#pragma once
#include <stdint.h>
#include <stdbool.h>

/**
 * secp256k1_signer.h — ECDSA 서명 + Ethereum v값 복구
 *
 * 의존성: micro-ecc (Arduino Library Manager에서 "micro-ecc" 설치)
 *
 * 사용법:
 *   uint8_t privkey[32] = { ... };
 *   uint8_t hash[32]    = { ... };  // keccak256 결과
 *   ECDSASignature sig;
 *   if (sign_hash(privkey, hash, &sig)) {
 *       // sig.r, sig.s: 각 32바이트
 *       // sig.v: 27 또는 28 (Ethereum 형식)
 *   }
 */

struct ECDSASignature {
    uint8_t r[32];
    uint8_t s[32];
    uint8_t v;  // 27 또는 28
};

/**
 * 32바이트 해시를 secp256k1 개인키로 서명합니다.
 * RFC 6979 결정론적 서명 (동일 입력 → 항상 동일 출력).
 *
 * @param privkey  32바이트 개인키
 * @param hash     32바이트 메시지 해시 (keccak256 결과)
 * @param sig      결과 서명 (r, s, v)
 * @return true = 성공, false = 실패
 */
bool sign_hash(const uint8_t privkey[32], const uint8_t hash[32], ECDSASignature* sig);

/**
 * 서명에서 공개키를 복구하여 예상 공개키와 비교합니다.
 * (내부적으로 v값 결정에 사용)
 */
bool recover_pubkey(const uint8_t hash[32], const ECDSASignature* sig,
                    const uint8_t expected_pubkey[64], bool* match);

/**
 * 개인키로부터 압축되지 않은 64바이트 공개키를 계산합니다.
 * (x 32바이트 || y 32바이트)
 */
bool compute_pubkey(const uint8_t privkey[32], uint8_t pubkey[64]);
