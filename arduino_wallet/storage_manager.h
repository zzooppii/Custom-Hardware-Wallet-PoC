#pragma once
#include <stdint.h>
#include <stdbool.h>

/**
 * storage_manager.h — ESP32 NVS 암호화 저장/복호화
 *
 * Preferences.h (ESP32 Arduino)를 통해 NVS(Non-Volatile Storage)에
 * 지갑 상태를 저장합니다.
 *
 * NVS 키 레이아웃:
 *   "init"      (bool)    — 지갑 초기화 여부
 *   "pinHash"   (String)  — SHA-256(pin + pinSalt) hex 64자
 *   "pinSalt"   (String)  — 16바이트 salt hex 32자
 *   "encSalt"   (String)  — PBKDF2용 salt hex 32자
 *   "encIv"     (String)  — AES-GCM IV hex 24자 (12바이트)
 *   "encTag"    (String)  — AES-GCM auth tag hex 32자 (16바이트)
 *   "encData"   (String)  — 암호화된 니모닉 hex
 *   "failCount" (int)     — PIN 실패 횟수
 *   "lockedUnt" (uint32)  — 잠금 해제 millis() 타임스탬프
 */

// ── 초기화 ────────────────────────────────────────────────────────────────────
bool storage_is_initialized();
void storage_set_initialized(bool val);

// ── PIN 관련 ──────────────────────────────────────────────────────────────────
bool storage_set_pin(const char* pin_hash_hex, const char* pin_salt_hex);
bool storage_get_pin(char* pin_hash_hex_out, char* pin_salt_hex_out);

// ── 실패 카운터 / 잠금 ────────────────────────────────────────────────────────
int      storage_get_fail_count();
void     storage_set_fail_count(int count);
uint32_t storage_get_locked_until();
void     storage_set_locked_until(uint32_t millis_ts);

// ── 암호화된 니모닉 저장/읽기 ─────────────────────────────────────────────────
/**
 * 니모닉을 AES-256-GCM으로 암호화하여 NVS에 저장합니다.
 * 암호화 키: PBKDF2-HMAC-SHA256(pin, enc_salt, 10000)
 *
 * @param mnemonic  평문 니모닉
 * @param pin       사용자 PIN
 * @return true = 성공
 */
bool storage_encrypt_and_save_mnemonic(const char* mnemonic, const char* pin);

/**
 * NVS에서 암호화된 니모닉을 읽어 복호화합니다.
 * GCM 인증 태그 검증 실패 시 (잘못된 PIN, 데이터 변조) false를 반환합니다.
 *
 * @param pin          사용자 PIN
 * @param mnemonic_out 복호화된 니모닉 출력 버퍼 (최소 200바이트)
 * @return true = 성공 (GCM 인증 통과)
 */
bool storage_decrypt_mnemonic(const char* pin, char* mnemonic_out);

// ── 전체 삭제 (자폭) ──────────────────────────────────────────────────────────
void storage_wipe_all();
