#include <M5Stack.h>
#include <ArduinoJson.h>

// [가상의 보안 영역 - 이 키는 탈취할 수 없는 메모리(Secure Element)에 존재한다고 가정]
const String SECURE_PRIVATE_KEY = "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef";

String pendingTransaction = "";
bool waitingForApproval = false;

void setup() {
  M5.begin();
  Serial.begin(115200); // PC와 USB 통신만 엽니다. (Wi-Fi 모듈 비활성화)
  
  M5.Lcd.setTextSize(2);
  M5.Lcd.println("Hardware Wallet PoC");
  M5.Lcd.println("Status: Locked");
  M5.Lcd.println("Waiting for PC...");
}

void loop() {
  M5.update(); // 물리 버튼 상태 업데이트

  // 1. PC에서 USB 시리얼을 통해 서명 요청이 들어오면
  if (Serial.available()) {
    String payload = Serial.readStringUntil('\n');

    // JSON 파싱 (목적지, 금액 등을 받음)
    StaticJsonDocument<200> doc;
    DeserializationError error = deserializeJson(doc, payload);
    if (!error) {
      pendingTransaction = payload;
      waitingForApproval = true;

      // 2. 물리적 화면(OLED)에만 출력. (아직 서명 안함)
      M5.Lcd.clear();
      M5.Lcd.setCursor(0, 0);
      M5.Lcd.setTextColor(YELLOW);
      M5.Lcd.println("Review Transaction!");
      M5.Lcd.setTextColor(WHITE);
      M5.Lcd.print("To: ");
      M5.Lcd.println(doc["to"].as<String>().substring(0, 10) + "...");
      M5.Lcd.print("Amount: ");
      M5.Lcd.println(doc["amount"].as<String>());
      
      M5.Lcd.setTextColor(GREEN);
      M5.Lcd.println("\nPress [Btn A] to SIGN");
      M5.Lcd.setTextColor(RED);
      M5.Lcd.println("Press [Btn C] to REJECT");
    }
  }

  // 3. 서명 대기 상태
  if (waitingForApproval) {
    if (M5.BtnA.wasPressed()) {
      // 4. [보안의 핵심] 기기 내부에서만 ECDSA 서명을 수행 (이 PoC에서는 가상 로직)
      // 실제로는 uBitcoin이나 trezor-crypto의 secp256k1 로직 호출
      
      M5.Lcd.clear();
      M5.Lcd.setTextColor(GREEN);
      M5.Lcd.setCursor(0, 50);
      M5.Lcd.println("Signing in SE...");
      
      delay(1000); // 연산 시뮬레이션
      
      String signature = "0xabcd_signed_by_hardware_" + String(random(1000, 9999));
      
      StaticJsonDocument<200> response;
      response["status"] = "success";
      response["signature"] = signature;
      
      // 서명값(영수증)만 PC(USB)로 뱉어냄
      serializeJson(response, Serial);
      Serial.println();
      
      M5.Lcd.println("Done! Sent to PC.");
      waitingForApproval = false;
      pendingTransaction = "";
    } 
    else if (M5.BtnC.wasPressed()) {
      // 사용자가 해킹 시도로 간주하고 거절
      M5.Lcd.clear();
      M5.Lcd.setTextColor(RED);
      M5.Lcd.setCursor(0, 50);
      M5.Lcd.println("Rejected by User.");
      
      StaticJsonDocument<200> response;
      response["status"] = "rejected";
      serializeJson(response, Serial);
      Serial.println();
      
      waitingForApproval = false;
      pendingTransaction = "";
    }
  }
}
