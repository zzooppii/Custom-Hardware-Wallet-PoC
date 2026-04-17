#pragma once
#include <stdint.h>
#include <stdbool.h>
#include <M5Stack.h>

/**
 * pin_manager.h — 3버튼 PIN 입력 UI + 보안 검증
 *
 * 버튼 매핑 (M5Stack):
 *   BtnA (왼쪽)  — 현재 자릿수 올림 (0→1→...→9→0)
 *   BtnC (오른쪽) — 현재 자릿수 내림 (0→9→...→1→0)
 *   BtnB (가운데) — 현재 자릿수 확정, 다음 자릿수로 이동
 *
 * 잠금 정책:
 *   3회 실패  → 경고 표시
 *   5회 실패  → 30초 잠금
 *   10회 실패 → NVS 전체 삭제 (자폭)
 */

// ── 상수 ──────────────────────────────────────────────────────────────────────
#define PIN_LENGTH      6     // 6자리: 1,000,000 조합 (4자리 10,000보다 100배 강함)
#define WARN_AFTER      3
#define LOCK_AFTER      5
#define WIPE_AFTER      10
#define LOCK_SECONDS    30

// ── PIN 입력 상태 ─────────────────────────────────────────────────────────────
enum PinEntryState {
    PIN_ENTRY_DIGIT_0 = 0,
    PIN_ENTRY_DIGIT_1,
    PIN_ENTRY_DIGIT_2,
    PIN_ENTRY_DIGIT_3,
    PIN_ENTRY_DIGIT_4,
    PIN_ENTRY_DIGIT_5,
    PIN_ENTRY_COMPLETE,
};

// ── 공개 API ──────────────────────────────────────────────────────────────────

/**
 * PIN 입력 UI를 초기화하고 화면을 표시합니다.
 * 새 PIN 입력이 시작될 때마다 호출하세요.
 */
void pin_start_entry(const char* promptMsg = "Enter PIN:");

/**
 * loop()에서 매 프레임 호출하여 버튼 입력을 처리합니다.
 * @return true = 4자리 입력 완료
 */
bool pin_handle_buttons();

/**
 * 입력 완료 후 입력된 PIN 문자열을 반환합니다 (4자리 숫자).
 * pin_handle_buttons()가 true를 반환한 후에만 호출하세요.
 */
const char* pin_get_entered();

/**
 * 입력된 PIN이 저장된 해시와 일치하는지 검증합니다.
 * 내부적으로 실패 카운터를 관리하고 잠금 정책을 적용합니다.
 *
 * @param entered_pin  4자리 PIN 문자열
 * @return  1 = 성공,  0 = 실패,  -1 = 잠금 상태,  -2 = 자폭(지갑 삭제됨)
 */
int pin_verify(const char* entered_pin);

/**
 * 새 PIN을 설정합니다 (첫 부팅 시 사용).
 * SHA-256(pin + salt) 해시를 계산하여 NVS에 저장합니다.
 * @return true = 성공
 */
bool pin_setup(const char* new_pin);

/**
 * 현재 잠금까지 남은 시간(초)을 반환합니다. 잠금 상태가 아니면 0.
 */
uint32_t pin_lock_remaining_seconds();
