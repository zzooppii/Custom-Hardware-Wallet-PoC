# Custom Hardware Wallet PoC

RWA 및 고가치 자산 보안을 위한 **오프라인 에어갭 콜드월렛**의 동작 원리를 구현한 PoC(Proof of Concept)입니다.

USB 시리얼 통신을 통해 인터넷이 차단된 기기 내부에서 트랜잭션을 서명하며, 실제 Ledger/Trezor 수준의 암호학 표준을 C++과 Node.js로 완전 구현했습니다.

---

## 아키텍처 개요

```
┌──────────────────────────────┐       USB Serial        ┌─────────────────────────────┐
│  PC Client (pc_client/)      │ ←──────────────────────→ │  Hardware Wallet            │
│  Node.js + ethers v6         │    JSON (115200 baud)    │  M5Stack ESP32 (arduino_wallet/) │
│                              │                          │                             │
│  • TX 생성 (EIP-1559)        │  → {txHash, rawFields}  │  • PIN 인증                 │
│  • 서명 결과로 TX 조립        │  ← {r, s, v}            │  • RLP 독립 검증             │
│  • Sepolia 브로드캐스트       │                          │  • HD 키 파생               │
└──────────────────────────────┘                          │  • secp256k1 ECDSA 서명     │
                                                          └─────────────────────────────┘
```

**에어갭 보장**: 기기는 `WiFi.mode(WIFI_OFF)` + `btStop()`으로 무선 통신을 완전 차단하며, USB 시리얼만 열려 있습니다.

---

## 디렉토리 구조

```
Custom-Hardware-Wallet-PoC/
├── arduino_wallet/          ← ESP32 M5Stack 펌웨어 (C++)
│   ├── wallet.ino           — 상태 머신 기반 메인 루프
│   ├── secp256k1_signer.h/.cpp  — ECDSA 서명 + EIP-2 Low-S 정규화
│   ├── crypto_utils.h/.cpp  — BIP39 생성 / BIP32 HD 키 파생
│   ├── keccak256.h/.cpp     — Ethereum Keccak-256
│   ├── rlp_encoder.h/.cpp   — EIP-1559 RLP 인코더 + txHash 독립 검증
│   ├── pin_manager.h/.cpp   — 3버튼 PIN UI (6자리, PBKDF2 100,000회)
│   ├── storage_manager.h/.cpp — AES-256-GCM NVS 암호화 저장
│   └── bip39_english.h      — 2048 BIP39 영단어 PROGMEM 배열
└── pc_client/               ← PC 소프트웨어 (Node.js)
    ├── index.js             — 실제 하드웨어 연결 클라이언트
    ├── simulate.js          — 하드웨어 없이 전체 플로우 시뮬레이터
    ├── virtual_arduino.js   — 가상 기기 (펌웨어 동작 Node.js 재현)
    └── verify_firmware.js   — 펌웨어 암호화 값 크로스체크 스크립트
```

---

## 전체 동작 플로우

### 첫 부팅 (지갑 생성)
```
전원 ON
  ↓
ESP32 TRNG → 128비트 엔트로피
  ↓
BIP39: 12단어 니모닉 생성
  ↓
LCD에 4단어씩 3페이지 표시 → [B] 다음 / [A] 백업 완료
  ↓
6자리 PIN 설정 (2회 입력 확인)
  ↓
PBKDF2-HMAC-SHA256(pin, salt, 100,000) → AES-256 키
  ↓
AES-256-GCM으로 니모닉 암호화 → ESP32 NVS 저장
```

### 일반 부팅 (잠금 해제)
```
전원 ON → NVS 확인 → initialized?
  ↓ Yes
6자리 PIN 입력 (3버튼 UI)
  ↓
PBKDF2-HMAC-SHA256으로 PIN 검증 (~3초)
  ↓
AES-256-GCM 복호화 + GCM 인증 태그 검증
  ↓
니모닉 복호화 성공 → "Waiting for PC..."
```

### 트랜잭션 서명
```
PC → 기기: { txHash, accountIndex, rawFields: {...} }
  ↓
기기: rawFields로 EIP-1559 해시 직접 재계산
      keccak256(0x02 || RLP([chainId, nonce, ..., []]))
  ↓
PC 해시 ≠ 재계산 해시 → 즉시 거부 (변조 감지)
  ↓
LCD에 수신자/금액/가스비/체인ID 표시
  ↓
[A] APPROVE → PIN 재입력 → PBKDF2 검증
  ↓
m/44'/60'/0'/0/{accountIndex} 경로 HD 키 파생
  ↓
secp256k1 ECDSA 서명 (RFC 6979 결정론적)
EIP-2 Low-S 정규화 적용
  ↓
기기 → PC: { status: "success", signature: { r, s, v } }
  ↓
PC: Transaction.from({...fields, signature}) → Sepolia 브로드캐스트
```

---

## 구현된 암호화 스택

| 기능 | 알고리즘 / 라이브러리 |
|------|---------------------|
| secp256k1 ECDSA | micro-ecc (uECC_sign_deterministic, RFC 6979) |
| EIP-2 Low-S 정규화 | 직접 구현 (n - s when s > n/2) |
| Keccak-256 | 자체 구현 (keccak256.cpp, Ethereum padding 0x01) |
| BIP39 니모닉 생성 | ESP32 TRNG + SHA-256 체크섬 |
| BIP32 HD 파생 | HMAC-SHA512 + 256비트 모듈러 덧셈 |
| 니모닉 → 시드 | PBKDF2-HMAC-SHA512 (2,048회) |
| EIP-1559 RLP 인코딩 | 자체 구현 (rlp_encoder.cpp) |
| PIN 해시 | PBKDF2-HMAC-SHA256 (100,000회) |
| 니모닉 암호화 | AES-256-GCM (mbedtls) |
| 암호화 키 파생 | PBKDF2-HMAC-SHA256 (10,000회) |
| 난수 생성 | esp_random() (ESP32 하드웨어 TRNG) |

---

## 보안 설계

### PIN 보안
- **6자리 숫자 PIN** — 1,000,000 가지 조합 (4자리 대비 100배)
- **PBKDF2 100,000회** — 오프라인 브루트포스 비용 100,000배 증가 (ESP32에서 ~3초)
- **상수시간 비교** — `mbedtls_ct_memcmp` 기반으로 타이밍 사이드채널 차단
- **잠금 정책**: 3회 실패 → 경고 / 5회 → 30초 잠금 / 10회 → NVS 전체 삭제(자폭)
- **잠금 재부팅 우회 방지** — fail_count가 NVS에 영구 저장되므로 전원 재시작으로 우회 불가

### 키 관리
- **에어갭**: `WiFi.mode(WIFI_OFF)` + `btStop()` — 무선 인터페이스 완전 차단
- **민감 데이터 제로화**: `mbedtls_platform_zeroize()` — 컴파일러 최적화 우회, 프라이빗 키/시드/체인코드 모두 사용 후 즉시 소거
- **니모닉 RAM 상주** — 복호화 후 RAM에만 존재, 전원 차단 시 자동 소멸

### 트랜잭션 검증
- **독립 txHash 재계산** — PC가 보낸 해시를 rawFields로 직접 재계산하여 비교 (변조 불가)
- **EIP-2 Low-S 정규화** — 서명 후 `s > n/2`이면 `s = n - s`, v 반전 적용
- **accountIndex 상한** — 0-99 범위만 허용

### 저장소 보안
- **AES-256-GCM 인증 암호화** — GCM 태그로 데이터 변조 자동 감지
- **NVS 레이아웃** (키/값 저장):

| NVS 키 | 내용 |
|--------|------|
| `init` | 초기화 여부 |
| `pinHash` | PBKDF2(PIN, pinSalt, 100000) 해시 |
| `pinSalt` | PIN 해시용 16바이트 랜덤 salt |
| `encSalt` | 암호화 키 파생용 16바이트 랜덤 salt |
| `encIv` | AES-GCM 12바이트 IV |
| `encTag` | AES-GCM 16바이트 인증 태그 |
| `encData` | 암호화된 니모닉 (hex) |
| `failCount` | PIN 실패 횟수 |
| `lockedUnt` | 잠금 해제 타임스탬프 |

---

## 시뮬레이터 사용법 (하드웨어 없이 테스트)

### 설치
```bash
cd pc_client
npm install
```

### 첫 실행 (새 지갑 생성)
```bash
node simulate.js
```
- 새 BIP39 니모닉이 생성되어 `wallet_state.json`에 AES-256-GCM 암호화 저장됩니다.
- 기본 PIN: `123456`

### 지갑 초기화 후 재생성
```bash
node simulate.js --wipe
```

### 대화형 테스트
```
[터미널 출력 예시]
===========================================
[📱 HW 기기] 트랜잭션 수신 완료! (해시 검증 OK ✅)
 - To      : 0xAb5801a7...
 - Amount  : 0.1 ETH
 - Chain ID: 11155111
===========================================
🤔 이 송금을 승인하시겠습니까? (y = 승인 / n = 거절)
```
- `y` + Enter: 승인
- `n` + Enter: 거절
- PIN 입력 (`123456` + Enter): 서명 진행

### 니모닉 확인 (개발용)
```bash
DEBUG_MNEMONIC=1 node simulate.js --wipe
```

### 펌웨어 크로스체크 (레퍼런스 값 확인)
```bash
node verify_firmware.js
```
M5Stack에 플래시 후 Serial 출력값과 비교할 기준값(서명 r, s, v / BIP32 파생 키 / keccak256 벡터)을 출력합니다.

---

## 실물 하드웨어 연동 방법

### 1. 필수 라이브러리 설치 (Arduino IDE)
- **M5Stack** (보드 패키지)
- **ArduinoJson** (>=6.x)
- **micro-ecc** by Kenneth MacKay — **recovery 지원 버전 필수**

> micro-ecc의 표준 릴리즈는 `uECC_recover()`가 없을 수 있습니다. v-값 복구를 위해 `uECC_SUPPORTS_RECOVERY`가 정의된 빌드가 필요합니다.

### 2. 펌웨어 업로드
```
arduino_wallet/ 폴더를 Arduino IDE로 열기
→ 보드: "M5Stack-Core-ESP32" 선택
→ 포트 선택 후 업로드
```

### 3. 첫 부팅 플로우
1. 기기가 자동으로 12단어 니모닉 생성
2. LCD에 4단어씩 3페이지 표시 — 종이에 기록
3. [A] 버튼으로 백업 완료 확인
4. 6자리 PIN 설정 (BtnA=+1, BtnC=-1, BtnB=확정)
5. 완료 시 "Waiting for PC..." 표시

### 4. PC 클라이언트 연결
```bash
cd pc_client
npm install
```
`index.js`의 `PORT_NAME`을 실제 시리얼 포트로 수정:
```js
const PORT_NAME = '/dev/tty.usbserial-XXXX'; // Mac
// const PORT_NAME = 'COM3';  // Windows
```
```bash
node index.js
```

### 5. 트랜잭션 승인 (하드웨어 버튼)
| 버튼 | 역할 |
|------|------|
| BtnA (왼쪽) | 숫자 +1 / 트랜잭션 승인 |
| BtnB (가운데) | PIN 자릿수 확정 |
| BtnC (오른쪽) | 숫자 -1 / 트랜잭션 거절 |

---

## 통신 프로토콜 (JSON over Serial, 115200 baud)

**PC → 기기**:
```json
{
  "txHash": "0x8f8db57f...",
  "accountIndex": 0,
  "rawFields": {
    "to": "0xAb5801a7...",
    "value": "100000000000000000",
    "nonce": 42,
    "gasLimit": "21000",
    "maxPriorityFeePerGas": "1000000000",
    "maxFeePerGas": "20000000000",
    "chainId": "11155111",
    "data": "0x"
  }
}
```

**기기 → PC (성공)**:
```json
{
  "status": "success",
  "signature": { "r": "0x...", "s": "0x...", "v": 28 }
}
```

**기기 → PC (거절)**:
```json
{
  "status": "rejected",
  "reason": "User Rejected"
}
```

---

## 버전 이력

### v1 — 기본 구조
- USB 시리얼 에어갭 아키텍처
- 더미 서명 반환 (테스트 목적)

### v2 — ethers.js 통합
- EIP-1559 트랜잭션 포맷 및 32바이트 해시 계산
- 실제 secp256k1 서명 (시뮬레이터)

### v2.1 — HD 지갑 + PIN
- BIP39 HD 지갑 (ethers.HDNodeWallet 기반 시뮬레이터)
- 4자리 PIN 인증 추가

### v3 — 펌웨어 실제 암호화 구현
모든 암호화 연산을 ESP32 C++로 구현:
- **keccak256.cpp**: Ethereum Keccak-256 (0x01 패딩, NIST SHA3 아님)
- **secp256k1_signer.cpp**: micro-ecc ECDSA + v값 복구
- **crypto_utils.cpp**: BIP39 생성 + BIP32/BIP44 HD 파생 전체 경로
- **rlp_encoder.cpp**: EIP-1559 RLP 인코더 + txHash 독립 재계산
- **pin_manager.cpp**: 3버튼 PIN UI + 브루트포스 잠금
- **storage_manager.cpp**: AES-256-GCM NVS 암호화 저장
- **wallet.ino**: 9개 상태의 상태 머신 전면 재작성
- **virtual_arduino.js**: PC 시뮬레이터에 BIP39/BIP32/AES-GCM/PIN 완전 구현

### v3.1 — 보안 감사 및 취약점 수정
전체 코드베이스 보안 감사 후 Critical/High 취약점 수정:

| 심각도 | 수정 항목 |
|--------|---------|
| Critical | EIP-2 Low-S 정규화 추가 (미적용 시 ~50% 서명 거부) |
| Critical | V값 복구 브로큰 코드 → 컴파일 오류로 명시 (`#error`) |
| Critical | PIN 길이 4 → **6자리** (조합 수 100배 증가) |
| Critical | PIN 해시 SHA-256 1회 → **PBKDF2 100,000회** |
| High | PIN 비교 `strcmp` → **상수시간 비교** (타이밍 사이드채널 방지) |
| High | 잠금 타이머 reboot 우회 → **fail_count 기반으로 방지** |
| High | BIP32 중간 체인코드(c2, c3, c4) **메모리 제로화** 추가 |
| High | accountIndex **0-99 범위 제한** |
| Medium | RLP 버퍼 오버플로우 방지 (512바이트 상한 + pos 경계 검사) |
| Medium | hexnib() 반환값 검증 (무효한 hex 입력 차단) |
| Medium | txHash hex 유효성 검사 추가 |
| Medium | Serial 페이로드 최대 2048바이트 제한 |
| Medium | JSON.parse try-catch 래핑 (크래시 방지) |
| Medium | wallet_state.json 파일 권한 **0600** (소유자 전용) |
| Low | 데드코드 제거 (`_runtimePin`, hmac 스텁 함수) |
| Low | 니모닉 콘솔 출력 → **`DEBUG_MNEMONIC=1`** 환경변수 게이팅 |
| Low | 의존성 버전 정확히 고정 (`^` 제거) |

> **Breaking Change**: v3.1에서 PIN 해시 알고리즘이 변경되어 기존 `wallet_state.json` 및 NVS 데이터와 호환되지 않습니다. 기존 지갑이 있다면 `node simulate.js --wipe`로 재초기화하세요.

---

## 향후 고려 사항

- **ESP32 Flash Encryption** — eFuse 기반 플래시 전체 암호화 (비가역적, 프로덕션 기기용)
- **JTAG 비활성화** — eFuse 기반 디버그 포트 영구 차단
- **BIP39 패스프레이즈** — "25번째 단어" 지원으로 추가 보호 레이어
- **트랜잭션 리플레이 감지** — 최근 서명 해시 링버퍼로 중복 서명 경고
