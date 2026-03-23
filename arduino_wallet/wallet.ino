#include <M5Stack.h>
#include <ArduinoJson.h>

// [가상의 보안 영역 - 이 키는 탈취할 수 없는 메모리(Secure Element)에 존재한다고 가정]
// v2: HD Wallet (BIP39 Mnemonic Seed Base)
const String MNEMONIC_SEED = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
// 실제 구현 시 trezor-crypto의 hdnode 파이프라인 이용:
// hdnode_from_seed(...) -> hdnode_private_ckd("m/44'/60'/0'/0/0")

String pendingTxHash = "";
bool waitingForApproval = false;
bool awaitingPin = false;

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

    // JSON 파싱 (목적지, 금액, 해시 등을 받음)
    StaticJsonDocument<500> doc;
    DeserializationError error = deserializeJson(doc, payload);
    if (!error) {
      pendingTxHash = doc["txHash"].as<String>();
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
      M5.Lcd.println(doc["amount"].as<String>() + " ETH");
      M5.Lcd.print("GasFee: ");
      M5.Lcd.println(doc["maxFeePerGas"].as<String>() + " Gwei");
      M5.Lcd.print("ChainID:");
      M5.Lcd.println(doc["chainId"].as<String>());
      
      M5.Lcd.setTextColor(GREEN);
      M5.Lcd.println("\nPress [Btn A] to APPROVE");
      M5.Lcd.setTextColor(RED);
      M5.Lcd.println("Press [Btn C] to REJECT");
    }
  }

  // 3. 서명 대기 상태
  if (waitingForApproval && !awaitingPin) {
    if (M5.BtnA.wasPressed()) {
      // 바로 서명하지 않고 PIN 화면으로 넘어갑니다.
      awaitingPin = true;
      M5.Lcd.clear();
      M5.Lcd.setTextColor(YELLOW);
      M5.Lcd.setCursor(0, 20);
      M5.Lcd.println("Enter PIN to Sign");
      M5.Lcd.setTextColor(WHITE);
      M5.Lcd.println("Press [Btn B] as 1234");
      M5.Lcd.println("(Dummy correct PIN)\n");
      M5.Lcd.setTextColor(RED);
      M5.Lcd.println("Press [Btn C] to Cancel");
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
      pendingTxHash = "";
    }
  }

  // 4. PIN 인증 및 서명 파트
  if (awaitingPin) {
    if (M5.BtnB.wasPressed()) {
      // 올바른 PIN(1234 등)이 들어왔다고 가정
      M5.Lcd.clear();
      M5.Lcd.setTextColor(GREEN);
      M5.Lcd.setCursor(0, 20);
      M5.Lcd.println("PIN Correct!");
      
      // 5. [보안의 핵심] 기기 내부에서만 ECDSA 서명을 수행 
      // 실제 구현 시: hdnode_private_ckd 로 도출된 키와 ecdsa_sign_digest 연동
      
      M5.Lcd.println("Signing in SE (HD Wallet)...");
      
      delay(1000); // 연산 시뮬레이션
      
      // PoC 목적으로 하드웨어 펌웨어에서는 더미 포맷의 r, s, v 반환
      StaticJsonDocument<200> response;
      response["status"] = "success";
      
      JsonObject sig = response.createNestedObject("signature");
      sig["r"] = "0x1111111111111111111111111111111111111111111111111111111111111111"; // 더미
      sig["s"] = "0x2222222222222222222222222222222222222222222222222222222222222222"; // 더미
      sig["v"] = 27; // 더미
      
      // 서명값(영수증)만 PC(USB)로 뱉어냄
      serializeJson(response, Serial);
      Serial.println();
      
      M5.Lcd.println("Done! Sent to PC.");
      waitingForApproval = false;
      awaitingPin = false;
      pendingTxHash = "";
    } 
    else if (M5.BtnC.wasPressed()) {
      M5.Lcd.clear();
      M5.Lcd.setTextColor(RED);
      M5.Lcd.setCursor(0, 50);
      M5.Lcd.println("PIN Cancelled.");
      
      StaticJsonDocument<200> response;
      response["status"] = "rejected";
      serializeJson(response, Serial);
      Serial.println();
      
      waitingForApproval = false;
      awaitingPin = false;
      pendingTxHash = "";
    }
  }
}
