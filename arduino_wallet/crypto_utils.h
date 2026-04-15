#pragma once
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

/**
 * crypto_utils.h — BIP39 생성 / BIP32 HD 키 파생
 *
 * 의존성:
 *   - mbedtls (ESP32 Arduino 코어 내장): PBKDF2, HMAC-SHA512, SHA-256
 *   - micro-ecc: 공개키 연산 (normal child derivation용)
 *   - bip39_english.h: 2048 영단어 PROGMEM 배열
 *
 * 주요 함수:
 *   generate_mnemonic()   — 첫 부팅: ESP32 TRNG으로 12단어 생성
 *   derive_path()         — 니모닉 → m/44'/60'/0'/0/{index} 프라이빗 키
 */

// ── secp256k1 곡선 위수 (secp256k1_signer.cpp와 공유) ────────────────────────
extern const uint8_t SECP256K1_N[32];

// ── BIP39 ─────────────────────────────────────────────────────────────────────

/**
 * ESP32 하드웨어 RNG(esp_random())으로 BIP39 12단어 니모닉을 생성합니다.
 * @param output  출력 버퍼 (최소 200바이트 권장)
 * @param maxLen  출력 버퍼 크기
 * @return true = 성공
 */
bool generate_mnemonic(char* output, size_t maxLen);

/**
 * 니모닉 문자열이 유효한 BIP39 단어들로 구성되어 있는지 확인합니다.
 * @param mnemonic  공백으로 구분된 12단어 문자열
 * @return true = 유효
 */
bool validate_mnemonic(const char* mnemonic);

// ── BIP39 → 시드 변환 ────────────────────────────────────────────────────────

/**
 * BIP39 니모닉 → 512비트(64바이트) 시드 (PBKDF2-HMAC-SHA512, 2048회)
 * @param mnemonic  12단어 니모닉 (UTF-8)
 * @param seed      출력 버퍼 64바이트
 */
void mnemonic_to_seed(const char* mnemonic, uint8_t seed[64]);

// ── BIP32 마스터 키 파생 ──────────────────────────────────────────────────────

/**
 * 시드 → BIP32 마스터 키 + 체인코드
 * HMAC-SHA512("Bitcoin seed", seed) → 왼쪽 32바이트=키, 오른쪽 32바이트=체인코드
 */
void seed_to_master(const uint8_t seed[64],
                    uint8_t master_key[32], uint8_t master_chain[32]);

// ── BIP32 자식 키 파생 ────────────────────────────────────────────────────────

/**
 * Hardened 자식 키 파생 (인덱스 >= 0x80000000)
 * 데이터: 0x00 || parent_key || index(4바이트 big-endian)
 */
void derive_child_hardened(const uint8_t parent_key[32],
                           const uint8_t parent_chain[32],
                           uint32_t index,
                           uint8_t child_key[32],
                           uint8_t child_chain[32]);

/**
 * Normal 자식 키 파생 (인덱스 < 0x80000000)
 * 데이터: compressed_pubkey(33바이트) || index(4바이트 big-endian)
 */
void derive_child_normal(const uint8_t parent_key[32],
                         const uint8_t parent_chain[32],
                         uint32_t index,
                         uint8_t child_key[32],
                         uint8_t child_chain[32]);

// ── 최종 편의 함수 ────────────────────────────────────────────────────────────

/**
 * 니모닉에서 m/44'/60'/0'/0/{accountIndex} 경로의 프라이빗 키를 파생합니다.
 * 내부적으로 mnemonic_to_seed → seed_to_master → 경로 파생을 순차 수행합니다.
 *
 * @param mnemonic      12단어 BIP39 니모닉
 * @param accountIndex  계정 인덱스 (0, 1, 2, ...)
 * @param privkey_out   결과 32바이트 프라이빗 키
 * @return true = 성공
 */
bool derive_eth_privkey(const char* mnemonic, uint32_t accountIndex,
                        uint8_t privkey_out[32]);
