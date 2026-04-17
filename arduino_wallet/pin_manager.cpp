/**
 * pin_manager.cpp — 3버튼 PIN 입력 UI 및 보안 검증 구현
 *
 * 보안 변경사항:
 *   - PIN 길이 4 → 6자리 (1,000,000 조합)
 *   - PIN 해시: SHA-256 1회 → PBKDF2-HMAC-SHA256 100,000회
 *   - PIN 비교: strcmp → 상수시간 비교 (타이밍 사이드채널 차단)
 *   - 잠금 타이머: millis() 기반 → fail_count 기반 (재부팅 우회 방지)
 */

#include "pin_manager.h"
#include "storage_manager.h"
#include "mbedtls/sha256.h"
#include "mbedtls/md.h"
#include "mbedtls/pkcs5.h"
#include "mbedtls/platform_util.h"
#include <string.h>
#include <stdio.h>

// ── 내부 상태 ────────────────────────────────────────────────────────────────
static PinEntryState s_state         = PIN_ENTRY_DIGIT_0;
static uint8_t       s_digits[6]     = {0};
static char          s_entered[7]    = {0};  // 6자리 + null
static const char*   s_prompt_msg    = "Enter PIN:";

// ── PIN 해싱: PBKDF2-HMAC-SHA256 (100,000회) ─────────────────────────────────
// SHA-256 1회 대비 오프라인 브루트포스 비용 100,000배 증가
// ESP32에서 약 2-3초 소요 (허용 가능한 UX)
static bool hash_pin(const char* pin, const char* salt_hex, char* out_hex64) {
    // salt_hex (32자) → 바이트
    uint8_t salt[16];
    for (int i = 0; i < 16; i++) {
        char hi = salt_hex[i*2], lo = salt_hex[i*2+1];
        auto nib = [](char c) -> uint8_t {
            if (c >= '0' && c <= '9') return c - '0';
            if (c >= 'a' && c <= 'f') return c - 'a' + 10;
            if (c >= 'A' && c <= 'F') return c - 'A' + 10;
            return 0;
        };
        salt[i] = (nib(hi) << 4) | nib(lo);
    }

    // PBKDF2-HMAC-SHA256: 100,000 iterations → 32바이트 해시
    uint8_t hash[32];
    const mbedtls_md_info_t* md = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    mbedtls_md_context_t ctx;
    mbedtls_md_init(&ctx);
    int ret = mbedtls_md_setup(&ctx, md, 1);
    if (ret == 0) {
        ret = mbedtls_pkcs5_pbkdf2_hmac(
            &ctx,
            (const uint8_t*)pin, strlen(pin),
            salt, 16,
            100000,  // iterations — 브루트포스 비용 핵심
            32, hash
        );
    }
    mbedtls_md_free(&ctx);

    if (ret != 0) {
        mbedtls_platform_zeroize(salt, sizeof(salt));
        return false;
    }

    for (int i = 0; i < 32; i++) {
        snprintf(out_hex64 + i*2, 3, "%02x", hash[i]);
    }
    out_hex64[64] = '\0';

    mbedtls_platform_zeroize(salt, sizeof(salt));
    mbedtls_platform_zeroize(hash, sizeof(hash));
    return true;
}

// ── 상수시간 문자열 비교 (타이밍 사이드채널 방지) ────────────────────────────
static bool constant_time_eq(const char* a, const char* b, size_t len) {
    volatile uint8_t diff = 0;
    for (size_t i = 0; i < len; i++) {
        diff |= (uint8_t)((unsigned char)a[i] ^ (unsigned char)b[i]);
    }
    return diff == 0;
}

// ── LCD PIN UI 헬퍼 ───────────────────────────────────────────────────────────

static void _draw_pin_ui(const char* prompt) {
    M5.Lcd.clear();
    M5.Lcd.setTextSize(2);
    M5.Lcd.setCursor(0, 0);
    M5.Lcd.setTextColor(YELLOW);
    M5.Lcd.println(prompt);
    M5.Lcd.setTextColor(WHITE);

    // 자릿수 표시: 확정됨=[*], 현재편집=[숫자], 미입력=[_]
    M5.Lcd.setCursor(10, 60);
    M5.Lcd.setTextSize(2);
    for (int i = 0; i < PIN_LENGTH; i++) {
        M5.Lcd.print(" ");
        if ((int)s_state > i) {
            M5.Lcd.setTextColor(GREEN);
            M5.Lcd.print("*");
        } else if ((int)s_state == i) {
            M5.Lcd.setTextColor(CYAN);
            M5.Lcd.print(s_digits[i]);
        } else {
            M5.Lcd.setTextColor(DARKGREY);
            M5.Lcd.print("_");
        }
        M5.Lcd.setTextColor(WHITE);
    }

    // 버튼 안내
    M5.Lcd.setTextSize(1);
    M5.Lcd.setCursor(0, 180);
    M5.Lcd.setTextColor(CYAN);
    M5.Lcd.print("[A]+  ");
    M5.Lcd.setTextColor(GREEN);
    M5.Lcd.print("[B]OK  ");
    M5.Lcd.setTextColor(CYAN);
    M5.Lcd.print("[C]-");
    M5.Lcd.setTextColor(WHITE);
}

// ── 공개 API 구현 ─────────────────────────────────────────────────────────────

void pin_start_entry(const char* promptMsg) {
    s_prompt_msg = promptMsg;
    s_state = PIN_ENTRY_DIGIT_0;
    memset(s_digits, 0, sizeof(s_digits));
    memset(s_entered, 0, sizeof(s_entered));
    _draw_pin_ui(promptMsg);
}

bool pin_handle_buttons() {
    if (s_state == PIN_ENTRY_COMPLETE) return true;

    int idx = (int)s_state;
    bool redraw = false;

    if (M5.BtnA.wasPressed()) {
        s_digits[idx] = (s_digits[idx] + 1) % 10;
        redraw = true;
    }
    if (M5.BtnC.wasPressed()) {
        s_digits[idx] = (s_digits[idx] + 9) % 10;  // +9 mod 10 = -1 mod 10
        redraw = true;
    }
    if (M5.BtnB.wasPressed()) {
        s_state = (PinEntryState)(idx + 1);
        if (s_state == PIN_ENTRY_COMPLETE) {
            for (int i = 0; i < PIN_LENGTH; i++) {
                s_entered[i] = '0' + s_digits[i];
            }
            s_entered[PIN_LENGTH] = '\0';
            return true;
        }
        redraw = true;
    }

    if (redraw) {
        _draw_pin_ui(s_prompt_msg);
    }
    return false;
}

const char* pin_get_entered() {
    return s_entered;
}

bool pin_setup(const char* new_pin) {
    // 새 salt 생성
    uint8_t salt_bytes[16];
#ifdef ESP32
    for (int i = 0; i < 4; i++) {
        uint32_t r = esp_random();
        salt_bytes[i*4+0] = (r >> 24) & 0xFF;
        salt_bytes[i*4+1] = (r >> 16) & 0xFF;
        salt_bytes[i*4+2] = (r >>  8) & 0xFF;
        salt_bytes[i*4+3] = (r      ) & 0xFF;
    }
#else
    memset(salt_bytes, 0xAB, 16);
#endif

    char salt_hex[33];
    for (int i = 0; i < 16; i++) {
        snprintf(salt_hex + i*2, 3, "%02x", salt_bytes[i]);
    }
    salt_hex[32] = '\0';

    // PBKDF2 PIN 해시 계산
    char pin_hash[65];
    bool ok = hash_pin(new_pin, salt_hex, pin_hash);
    if (!ok) {
        mbedtls_platform_zeroize(salt_bytes, sizeof(salt_bytes));
        return false;
    }

    ok = storage_set_pin(pin_hash, salt_hex);

    mbedtls_platform_zeroize(salt_bytes, sizeof(salt_bytes));
    mbedtls_platform_zeroize(pin_hash, sizeof(pin_hash));

    return ok;
}

int pin_verify(const char* entered_pin) {
    // 잠금 상태 확인
    uint32_t remaining = pin_lock_remaining_seconds();
    if (remaining > 0) return -1;

    char stored_hash[65];
    char stored_salt[33];
    if (!storage_get_pin(stored_hash, stored_salt)) return 0;

    // PBKDF2 해싱 (~2-3초)
    char input_hash[65];
    if (!hash_pin(entered_pin, stored_salt, input_hash)) {
        return 0;
    }

    // 상수시간 비교 (타이밍 사이드채널 방지)
    bool match = constant_time_eq(input_hash, stored_hash, 64);

    mbedtls_platform_zeroize(input_hash, sizeof(input_hash));

    if (match) {
        storage_set_fail_count(0);
        storage_set_locked_until(0);
        return 1;
    }

    // 실패 처리
    int fails = storage_get_fail_count() + 1;
    storage_set_fail_count(fails);

    if (fails >= WIPE_AFTER) {
        storage_wipe_all();
        return -2;
    }

    if (fails >= LOCK_AFTER) {
        // 잠금 시각 갱신 (재부팅 우회 방지: pin_lock_remaining_seconds에서 재설정됨)
        uint32_t unlock_at = millis() + (uint32_t)LOCK_SECONDS * 1000;
        storage_set_locked_until(unlock_at);
    }

    return 0;
}

uint32_t pin_lock_remaining_seconds() {
    int fails = storage_get_fail_count();
    if (fails < LOCK_AFTER) return 0;

    uint32_t locked_until = storage_get_locked_until();

    // 재부팅 후 잠금 상태: millis()가 0에서 재시작되어 locked_until이 미래처럼 보임
    // → fail_count >= LOCK_AFTER이면 잠금이 활성 상태임을 보장
    if (locked_until == 0) {
        // 재부팅으로 잠금 타이머가 지워진 경우 → 잠금 재설정
        locked_until = millis() + (uint32_t)LOCK_SECONDS * 1000;
        storage_set_locked_until(locked_until);
    }

    uint32_t now = millis();
    if (now >= locked_until) {
        storage_set_locked_until(0);
        return 0;
    }
    return (locked_until - now) / 1000 + 1;
}
