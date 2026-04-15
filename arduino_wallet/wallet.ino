/**
 * wallet.ino — Custom Hardware Wallet Firmware (최종 통합)
 *
 * ──────────────────────────────────────────────
 * 빌드 환경: Arduino IDE + M5Stack ESP32 보드
 * 필수 라이브러리 (Arduino Library Manager):
 *   - M5Stack
 *   - ArduinoJson (>= 6.x)
 *   - micro-ecc (by Kenneth MacKay)
 * ──────────────────────────────────────────────
 *
 * 동작 구조:
 *   [첫 부팅]  → 니모닉 생성 → 화면 표시 → PIN 설정 → 암호화 저장
 *   [일반 부팅] → PIN 입력 → PBKDF2 복호화 → 키 파생 → 대기
 *   [TX 수신]  → 해시 독립 검증 → 화면 표시 → 승인/거절
 *   [승인]     → PIN 재입력 → 키 파생 → ECDSA 서명 → 전송
 *
 * 통신 프로토콜 (JSON over Serial 115200baud):
 *   PC → 기기: { txHash, accountIndex, rawFields: {to, value, nonce, ...} }
 *   기기 → PC: { status:"success", signature:{r,s,v} }
 *              또는 { status:"rejected", reason:"..." }
 */

#include <M5Stack.h>
#include <ArduinoJson.h>
#include <WiFi.h>
#include "esp_bt.h"

#include "crypto_utils.h"
#include "secp256k1_signer.h"
#include "keccak256.h"
#include "rlp_encoder.h"
#include "pin_manager.h"
#include "storage_manager.h"
#include "mbedtls/platform_util.h"

// ── 상태 머신 ─────────────────────────────────────────────────────────────────
enum WalletState {
    STATE_FIRST_BOOT_GENERATE,    // 첫 부팅: 니모닉 생성
    STATE_FIRST_BOOT_SHOW_WORDS,  // 12단어 화면 표시
    STATE_FIRST_BOOT_SET_PIN,     // 새 PIN 설정 (첫 입력)
    STATE_FIRST_BOOT_CONFIRM_PIN, // 새 PIN 확인 (두 번째 입력)
    STATE_BOOT_ENTER_PIN,         // 일반 부팅: PIN 입력
    STATE_UNLOCKED_IDLE,          // 잠금 해제 대기
    STATE_REVIEW_TX,              // 트랜잭션 검토
    STATE_ENTER_PIN_FOR_TX,       // 서명용 PIN 입력
    STATE_SIGNING,                // 키 파생 + 서명
    STATE_LOCKED_OUT,             // 브루트포스 잠금
};

// ── 전역 상태 ─────────────────────────────────────────────────────────────────
static WalletState  g_state           = STATE_FIRST_BOOT_GENERATE;
static char         g_mnemonic[200]   = {0};  // RAM에 상주 (전원 차단 시 소멸)
static char         g_pending_hash[67]= {0};  // 서명 대기 중인 txHash
static uint32_t     g_account_index   = 0;
static char         g_first_pin[8]    = {0};  // 첫 PIN 설정 시 임시 저장 (PIN_LENGTH=6 + null + 여유)

// 첫 부팅 단어 표시 상태
static int  g_word_page = 0;   // 0=1-4단어, 1=5-8단어, 2=9-12단어

// ── 유틸: 바이트 배열 → "0x..." hex 문자열 ────────────────────────────────────
static void bytes_to_hex_str(const uint8_t* data, size_t len, char* out) {
    out[0] = '0'; out[1] = 'x';
    for (size_t i = 0; i < len; i++) {
        snprintf(out + 2 + i*2, 3, "%02x", data[i]);
    }
    out[2 + len*2] = '\0';
}

// ── hex 문자열 유효성 검사 ────────────────────────────────────────────────────
static bool is_valid_hex_str(const char* h, size_t expected_bytes) {
    for (size_t i = 0; i < expected_bytes * 2; i++) {
        char c = h[i];
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')))
            return false;
    }
    return true;
}

// ── 거절 전송 ─────────────────────────────────────────────────────────────────
static void send_rejection(const char* reason) {
    StaticJsonDocument<200> resp;
    resp["status"] = "rejected";
    resp["reason"] = reason;
    serializeJson(resp, Serial);
    Serial.println();
    memset(g_pending_hash, 0, sizeof(g_pending_hash));
}

// ── 첫 부팅: 단어 화면 표시 ───────────────────────────────────────────────────
static void show_mnemonic_page(int page) {
    M5.Lcd.clear();
    M5.Lcd.setCursor(0, 0);
    M5.Lcd.setTextSize(2);
    M5.Lcd.setTextColor(YELLOW);
    M5.Lcd.printf("Recovery Phrase\n(%d/3)\n\n", page + 1);
    M5.Lcd.setTextColor(WHITE);

    // 공백으로 단어 분리
    char words[12][12] = {};
    int wcount = 0;
    char tmp[200];
    strncpy(tmp, g_mnemonic, sizeof(tmp) - 1);
    char* tok = strtok(tmp, " ");
    while (tok && wcount < 12) {
        strncpy(words[wcount++], tok, 11);
        tok = strtok(nullptr, " ");
    }

    // 4단어씩 표시
    for (int i = page * 4; i < page * 4 + 4 && i < 12; i++) {
        M5.Lcd.printf("%2d. %s\n", i + 1, words[i]);
    }

    M5.Lcd.setTextSize(1);
    M5.Lcd.setCursor(0, 210);
    if (page < 2) {
        M5.Lcd.setTextColor(GREEN);
        M5.Lcd.print("[B] Next page");
    } else {
        M5.Lcd.setTextColor(GREEN);
        M5.Lcd.print("[A] Backed up!   ");
        M5.Lcd.setTextColor(CYAN);
        M5.Lcd.print("[C] Show again");
    }
    M5.Lcd.setTextColor(WHITE);
}

// ── setup ───────────────────────────────────────────────────────────────────
void setup() {
    M5.begin();

    // 에어갭: Wi-Fi와 Bluetooth를 완전히 비활성화
    WiFi.mode(WIFI_OFF);
    WiFi.disconnect(true);
    btStop();

    Serial.begin(115200);
    M5.Lcd.setTextSize(2);

    if (storage_is_initialized()) {
        // 일반 부팅
        g_state = STATE_BOOT_ENTER_PIN;
        pin_start_entry("Unlock Wallet:");
    } else {
        // 첫 부팅
        g_state = STATE_FIRST_BOOT_GENERATE;
        M5.Lcd.clear();
        M5.Lcd.setTextColor(CYAN);
        M5.Lcd.println("Generating\nnew wallet...");
        M5.Lcd.setTextColor(WHITE);
    }
}

// ── loop ────────────────────────────────────────────────────────────────────
void loop() {
    M5.update();

    switch (g_state) {

    // ── 첫 부팅: 니모닉 생성 ─────────────────────────────────────────────────
    case STATE_FIRST_BOOT_GENERATE: {
        if (!generate_mnemonic(g_mnemonic, sizeof(g_mnemonic))) {
            M5.Lcd.setTextColor(RED);
            M5.Lcd.println("Mnemonic gen failed!");
            delay(3000);
            ESP.restart();
        }
        g_word_page = 0;
        g_state = STATE_FIRST_BOOT_SHOW_WORDS;
        show_mnemonic_page(0);
        break;
    }

    // ── 첫 부팅: 12단어 화면 표시 ────────────────────────────────────────────
    case STATE_FIRST_BOOT_SHOW_WORDS: {
        if (g_word_page < 2) {
            if (M5.BtnB.wasPressed()) {
                g_word_page++;
                show_mnemonic_page(g_word_page);
            }
        } else {
            // 마지막 페이지
            if (M5.BtnA.wasPressed()) {
                // 백업 완료 확인 → PIN 설정으로
                g_state = STATE_FIRST_BOOT_SET_PIN;
                pin_start_entry("Set new PIN:");
            } else if (M5.BtnC.wasPressed()) {
                // 처음부터 다시 보기
                g_word_page = 0;
                show_mnemonic_page(0);
            }
        }
        break;
    }

    // ── 첫 부팅: 새 PIN 설정 (첫 번째 입력) ──────────────────────────────────
    case STATE_FIRST_BOOT_SET_PIN: {
        if (pin_handle_buttons()) {
            strncpy(g_first_pin, pin_get_entered(), PIN_LENGTH + 1);
            g_state = STATE_FIRST_BOOT_CONFIRM_PIN;
            pin_start_entry("Confirm PIN:");
        }
        break;
    }

    // ── 첫 부팅: 새 PIN 확인 (두 번째 입력) ──────────────────────────────────
    case STATE_FIRST_BOOT_CONFIRM_PIN: {
        if (pin_handle_buttons()) {
            if (strcmp(g_first_pin, pin_get_entered()) == 0) {
                // PIN 일치 → 저장 및 암호화
                M5.Lcd.clear();
                M5.Lcd.setTextColor(YELLOW);
                M5.Lcd.println("Saving wallet...");
                M5.Lcd.println("(~5 seconds)");
                M5.Lcd.setTextColor(WHITE);

                pin_setup(g_first_pin);
                storage_encrypt_and_save_mnemonic(g_mnemonic, g_first_pin);
                storage_set_initialized(true);

                mbedtls_platform_zeroize(g_first_pin, sizeof(g_first_pin));

                M5.Lcd.clear();
                M5.Lcd.setTextColor(GREEN);
                M5.Lcd.println("Wallet created!");
                M5.Lcd.setTextColor(WHITE);
                M5.Lcd.println("Waiting for PC...");

                g_state = STATE_UNLOCKED_IDLE;
            } else {
                // PIN 불일치 → 다시 설정
                M5.Lcd.clear();
                M5.Lcd.setTextColor(RED);
                M5.Lcd.println("PIN mismatch!\nTry again.");
                delay(1500);
                mbedtls_platform_zeroize(g_first_pin, sizeof(g_first_pin));
                g_state = STATE_FIRST_BOOT_SET_PIN;
                pin_start_entry("Set new PIN:");
            }
        }
        break;
    }

    // ── 일반 부팅: PIN 입력으로 잠금 해제 ────────────────────────────────────
    case STATE_BOOT_ENTER_PIN: {
        uint32_t remaining = pin_lock_remaining_seconds();
        if (remaining > 0) {
            // 잠금 중 → 잠금 해제 상태 표시
            static uint32_t last_draw = 0;
            if (millis() - last_draw > 1000) {
                last_draw = millis();
                M5.Lcd.clear();
                M5.Lcd.setTextColor(RED);
                M5.Lcd.setCursor(0, 60);
                M5.Lcd.printf("Locked: %ds\n", remaining);
                M5.Lcd.setTextColor(WHITE);
            }
            break;
        }

        if (pin_handle_buttons()) {
            M5.Lcd.clear();
            M5.Lcd.setTextColor(YELLOW);
            M5.Lcd.println("Decrypting...\n(~5 seconds)");
            M5.Lcd.setTextColor(WHITE);

            // PIN 검증
            int result = pin_verify(pin_get_entered());
            if (result == 1) {
                // 성공 → 니모닉 복호화
                if (storage_decrypt_mnemonic(pin_get_entered(), g_mnemonic)) {
                    M5.Lcd.clear();
                    M5.Lcd.setTextColor(GREEN);
                    M5.Lcd.println("Unlocked!");
                    M5.Lcd.setTextColor(WHITE);
                    M5.Lcd.println("\nWaiting for PC...");
                    g_state = STATE_UNLOCKED_IDLE;
                } else {
                    M5.Lcd.clear();
                    M5.Lcd.setTextColor(RED);
                    M5.Lcd.println("Decrypt failed!");
                    delay(2000);
                    pin_start_entry("Unlock Wallet:");
                }
            } else if (result == -2) {
                // 자폭: 지갑 삭제됨
                M5.Lcd.clear();
                M5.Lcd.setTextColor(RED);
                M5.Lcd.println("WIPE! Max PIN\nfailures.");
                delay(3000);
                ESP.restart();
            } else if (result == -1) {
                // 잠금 상태
                M5.Lcd.clear();
                M5.Lcd.setTextColor(RED);
                M5.Lcd.printf("Locked: %ds\n", pin_lock_remaining_seconds());
                delay(1000);
                pin_start_entry("Unlock Wallet:");
            } else {
                // 오류 PIN
                int fails = storage_get_fail_count();
                M5.Lcd.clear();
                M5.Lcd.setTextColor(RED);
                M5.Lcd.printf("Wrong PIN!\n%d fails\n", fails);
                if (fails >= WARN_AFTER) {
                    M5.Lcd.setTextColor(ORANGE);
                    M5.Lcd.printf("%d left before\nwipe!\n", WIPE_AFTER - fails);
                }
                M5.Lcd.setTextColor(WHITE);
                delay(2000);
                pin_start_entry("Unlock Wallet:");
            }
        }
        break;
    }

    // ── 잠금 해제 대기: Serial에서 TX 수신 ───────────────────────────────────
    case STATE_UNLOCKED_IDLE: {
        if (!Serial.available()) break;

        String payload = Serial.readStringUntil('\n');
        payload.trim();
        if (payload.length() == 0) break;
        if (payload.length() > 2048) {
            send_rejection("Payload too large");
            break;
        }

        StaticJsonDocument<1024> doc;
        DeserializationError err = deserializeJson(doc, payload);
        if (err) {
            send_rejection("JSON parse error");
            break;
        }

        const char* txHash = doc["txHash"] | "";
        if (strlen(txHash) != 66) {  // "0x" + 64 hex
            send_rejection("Invalid txHash");
            break;
        }

        g_account_index = doc["accountIndex"] | 0;

        // accountIndex 상한 검사 (임의 키 파생 방지)
        if (g_account_index > 99) {
            send_rejection("Account index out of range (max 99)");
            break;
        }

        // ── 독립 txHash 검증 (Step 6) ──────────────────────────────────────
        if (doc.containsKey("rawFields")) {
            JsonObject rawFields = doc["rawFields"].as<JsonObject>();
            uint8_t computed_hash[32];
            compute_eip1559_hash(rawFields, computed_hash);

            // computed hash를 hex 문자열로 변환하여 비교
            char computed_hex[67];
            bytes_to_hex_str(computed_hash, 32, computed_hex);

            if (strcmp(computed_hex, txHash) != 0) {
                M5.Lcd.clear();
                M5.Lcd.setTextColor(RED);
                M5.Lcd.println("HASH MISMATCH!");
                M5.Lcd.println("Possible tamper.");
                M5.Lcd.setTextColor(WHITE);
                M5.Lcd.println(computed_hex);
                delay(3000);
                send_rejection("txHash mismatch - tampering detected");
                M5.Lcd.clear();
                M5.Lcd.setTextColor(WHITE);
                M5.Lcd.println("Waiting for PC...");
                break;
            }

            // 검증 통과 → 트랜잭션 표시
            M5.Lcd.clear();
            M5.Lcd.setCursor(0, 0);
            M5.Lcd.setTextColor(YELLOW);
            M5.Lcd.println("Review TX (OK)");
            M5.Lcd.setTextColor(WHITE);
            M5.Lcd.printf("Acct: #%d\n", g_account_index);
            M5.Lcd.print("To: ");
            String toAddr = rawFields["to"].as<String>();
            M5.Lcd.println(toAddr.substring(0, 12) + "...");
            // value는 wei → 표시 (간략)
            M5.Lcd.print("Val: ");
            M5.Lcd.println(rawFields["value"].as<String>() + " wei");
            M5.Lcd.print("Gas: ");
            M5.Lcd.println(rawFields["maxFeePerGas"].as<String>() + " wei");
            M5.Lcd.print("Net: ");
            M5.Lcd.println(rawFields["chainId"].as<String>());
        } else {
            // rawFields 없음 (하위 호환)
            M5.Lcd.clear();
            M5.Lcd.setTextColor(YELLOW);
            M5.Lcd.println("Review TX");
            M5.Lcd.setTextColor(WHITE);
            M5.Lcd.println(txHash);
        }

        M5.Lcd.setTextSize(1);
        M5.Lcd.setCursor(0, 210);
        M5.Lcd.setTextColor(GREEN);
        M5.Lcd.print("[A] APPROVE  ");
        M5.Lcd.setTextColor(RED);
        M5.Lcd.print("[C] REJECT");
        M5.Lcd.setTextColor(WHITE);
        M5.Lcd.setTextSize(2);

        strncpy(g_pending_hash, txHash, sizeof(g_pending_hash) - 1);
        g_state = STATE_REVIEW_TX;
        break;
    }

    // ── 트랜잭션 검토: 승인/거절 ─────────────────────────────────────────────
    case STATE_REVIEW_TX: {
        if (M5.BtnA.wasPressed()) {
            g_state = STATE_ENTER_PIN_FOR_TX;
            pin_start_entry("PIN to Sign:");
        } else if (M5.BtnC.wasPressed()) {
            send_rejection("User Rejected");
            g_state = STATE_UNLOCKED_IDLE;
            M5.Lcd.clear();
            M5.Lcd.setTextColor(WHITE);
            M5.Lcd.println("Rejected.\nWaiting for PC...");
        }
        break;
    }

    // ── 서명용 PIN 입력 ───────────────────────────────────────────────────────
    case STATE_ENTER_PIN_FOR_TX: {
        uint32_t remaining = pin_lock_remaining_seconds();
        if (remaining > 0) {
            static uint32_t last_draw2 = 0;
            if (millis() - last_draw2 > 1000) {
                last_draw2 = millis();
                M5.Lcd.clear();
                M5.Lcd.setTextColor(RED);
                M5.Lcd.setCursor(0, 60);
                M5.Lcd.printf("Locked: %ds\n", remaining);
                M5.Lcd.setTextColor(WHITE);
            }
            break;
        }

        if (pin_handle_buttons()) {
            int result = pin_verify(pin_get_entered());
            if (result == 1) {
                g_state = STATE_SIGNING;
            } else if (result == -2) {
                M5.Lcd.clear();
                M5.Lcd.setTextColor(RED);
                M5.Lcd.println("WIPE! Max PIN\nfailures.");
                mbedtls_platform_zeroize(g_mnemonic, sizeof(g_mnemonic));
                send_rejection("Device wiped");
                delay(3000);
                ESP.restart();
            } else {
                int fails = storage_get_fail_count();
                M5.Lcd.clear();
                M5.Lcd.setTextColor(RED);
                M5.Lcd.printf("Wrong PIN!\n%d fails\n", fails);
                M5.Lcd.setTextColor(WHITE);
                delay(2000);
                send_rejection("Invalid PIN");
                g_state = STATE_UNLOCKED_IDLE;
                M5.Lcd.clear();
                M5.Lcd.println("Waiting for PC...");
            }
        }
        break;
    }

    // ── 서명 수행 ─────────────────────────────────────────────────────────────
    case STATE_SIGNING: {
        M5.Lcd.clear();
        M5.Lcd.setTextColor(YELLOW);
        M5.Lcd.println("Deriving key...\n(~3 seconds)");
        M5.Lcd.setTextColor(WHITE);

        // 1. 니모닉 → 프라이빗 키 파생
        uint8_t privkey[32];
        if (!derive_eth_privkey(g_mnemonic, g_account_index, privkey)) {
            send_rejection("Key derivation failed");
            g_state = STATE_UNLOCKED_IDLE;
            break;
        }

        // 2. txHash hex → 32바이트 (유효성 검사 포함)
        const char* h = (g_pending_hash[1] == 'x') ? g_pending_hash + 2 : g_pending_hash;
        if (!is_valid_hex_str(h, 32)) {
            mbedtls_platform_zeroize(privkey, 32);
            send_rejection("Invalid hex in txHash");
            g_state = STATE_UNLOCKED_IDLE;
            M5.Lcd.clear();
            M5.Lcd.println("Waiting for PC...");
            break;
        }
        uint8_t hash_bytes[32];
        for (int i = 0; i < 32; i++) {
            int hi = 0, lo = 0;
            char hc = h[i*2], lc = h[i*2+1];
            if (hc >= '0' && hc <= '9') hi = hc - '0';
            else if (hc >= 'a' && hc <= 'f') hi = hc - 'a' + 10;
            else if (hc >= 'A' && hc <= 'F') hi = hc - 'A' + 10;
            if (lc >= '0' && lc <= '9') lo = lc - '0';
            else if (lc >= 'a' && lc <= 'f') lo = lc - 'a' + 10;
            else if (lc >= 'A' && lc <= 'F') lo = lc - 'A' + 10;
            hash_bytes[i] = (uint8_t)((hi << 4) | lo);
        }

        M5.Lcd.println("Signing...");

        // 3. secp256k1 ECDSA 서명
        ECDSASignature sig;
        if (!sign_hash(privkey, hash_bytes, &sig)) {
            mbedtls_platform_zeroize(privkey, 32);
            send_rejection("Signing failed");
            g_state = STATE_UNLOCKED_IDLE;
            break;
        }

        // 서명 즉시 제로화
        mbedtls_platform_zeroize(privkey, 32);

        // 4. 결과 전송
        char r_hex[67], s_hex[67];
        bytes_to_hex_str(sig.r, 32, r_hex);
        bytes_to_hex_str(sig.s, 32, s_hex);

        StaticJsonDocument<512> response;
        response["status"] = "success";
        JsonObject signature = response.createNestedObject("signature");
        signature["r"] = r_hex;
        signature["s"] = s_hex;
        signature["v"] = sig.v;

        serializeJson(response, Serial);
        Serial.println();

        M5.Lcd.clear();
        M5.Lcd.setTextColor(GREEN);
        M5.Lcd.println("Signed!");
        M5.Lcd.setTextColor(WHITE);
        M5.Lcd.println("Sent to PC.\n\nWaiting for PC...");

        memset(g_pending_hash, 0, sizeof(g_pending_hash));
        g_state = STATE_UNLOCKED_IDLE;
        break;
    }

    // ── 브루트포스 잠금 표시 ─────────────────────────────────────────────────
    case STATE_LOCKED_OUT: {
        uint32_t remaining = pin_lock_remaining_seconds();
        if (remaining == 0) {
            pin_start_entry("Unlock Wallet:");
            g_state = STATE_BOOT_ENTER_PIN;
        } else {
            static uint32_t last_draw3 = 0;
            if (millis() - last_draw3 > 1000) {
                last_draw3 = millis();
                M5.Lcd.clear();
                M5.Lcd.setTextColor(RED);
                M5.Lcd.setCursor(20, 80);
                M5.Lcd.setTextSize(3);
                M5.Lcd.printf("%ds\n", remaining);
                M5.Lcd.setTextSize(2);
                M5.Lcd.setTextColor(WHITE);
                M5.Lcd.println("Locked");
            }
        }
        break;
    }

    } // switch end
}
