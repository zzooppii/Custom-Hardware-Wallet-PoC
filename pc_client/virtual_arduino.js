/**
 * VirtualArduino - 하드웨어 기기(M5Stack/ESP32) 시뮬레이터
 *
 * 실제 펌웨어(wallet.ino)가 수행하는 동작을 Node.js로 모의 구현합니다.
 * - BIP39 니모닉 동적 생성 (첫 부팅)
 * - 파생된 HD 지갑으로 실제 secp256k1 ECDSA 서명
 * - 하드코딩된 PIN 대신 SHA-256 해싱 + 브루트포스 잠금
 * - AES-256-GCM으로 니모닉 암호화 저장 (wallet_state.json = 가상 NVS)
 * - PC가 보낸 txHash를 직접 재계산하여 독립 검증
 */

const readline = require('readline');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { ethers } = require('ethers');

// 가상 NVS (Non-Volatile Storage) 파일 경로
const WALLET_STATE_PATH = path.join(__dirname, 'wallet_state.json');

// 브루트포스 잠금 정책
const PIN_POLICY = {
    WARN_AFTER: 3,       // 3회 실패 시 경고
    LOCKOUT_AFTER: 5,    // 5회 실패 시 30초 잠금
    WIPE_AFTER: 10,      // 10회 실패 시 니모닉 삭제
    LOCKOUT_SECONDS: 30,
};

// ──────────────────────────────────────────────
// 암호화 유틸리티 (AES-256-GCM + PBKDF2)
// ──────────────────────────────────────────────

/**
 * PIN + salt로 AES-256 키 파생 (PBKDF2-SHA256, 100,000 iterations)
 * 실제 ESP32에서는 mbedTLS의 pbkdf2_hmac()을 사용합니다.
 */
function deriveKey(pin, saltHex) {
    const salt = Buffer.from(saltHex, 'hex');
    return crypto.pbkdf2Sync(pin, salt, 100_000, 32, 'sha256');
}

/**
 * 니모닉을 AES-256-GCM으로 암호화합니다.
 * 반환값: { iv, authTag, ciphertext } (모두 hex 문자열)
 */
function encryptMnemonic(mnemonic, pin, saltHex) {
    const key = deriveKey(pin, saltHex);
    const iv = crypto.randomBytes(12); // GCM 표준 96비트 IV
    const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
    const encrypted = Buffer.concat([cipher.update(mnemonic, 'utf8'), cipher.final()]);
    return {
        iv: iv.toString('hex'),
        authTag: cipher.getAuthTag().toString('hex'),
        ciphertext: encrypted.toString('hex'),
    };
}

/**
 * AES-256-GCM으로 암호화된 니모닉을 복호화합니다.
 * PIN이 틀리거나 데이터가 변조된 경우 예외를 던집니다.
 */
function decryptMnemonic(encrypted, pin, saltHex) {
    const key = deriveKey(pin, saltHex);
    const decipher = crypto.createDecipheriv(
        'aes-256-gcm',
        key,
        Buffer.from(encrypted.iv, 'hex')
    );
    decipher.setAuthTag(Buffer.from(encrypted.authTag, 'hex'));
    try {
        const decrypted = Buffer.concat([
            decipher.update(Buffer.from(encrypted.ciphertext, 'hex')),
            decipher.final(),
        ]);
        return decrypted.toString('utf8');
    } catch {
        throw new Error('GCM 인증 실패 — 잘못된 PIN이거나 데이터가 변조되었습니다.');
    }
}

/**
 * PIN을 PBKDF2-HMAC-SHA256(100,000회)으로 해싱합니다.
 * SHA-256 1회 대비 오프라인 브루트포스 비용 100,000배 증가.
 * 펌웨어(pin_manager.cpp)와 동일한 파라미터 사용.
 */
function hashPin(pin, saltHex) {
    const salt = Buffer.from(saltHex, 'hex');
    return crypto.pbkdf2Sync(pin, salt, 100_000, 32, 'sha256').toString('hex');
}

// ──────────────────────────────────────────────
// 가상 NVS (wallet_state.json) 관리
// ──────────────────────────────────────────────

function loadWalletState() {
    if (!fs.existsSync(WALLET_STATE_PATH)) return null;
    return JSON.parse(fs.readFileSync(WALLET_STATE_PATH, 'utf8'));
}

function saveWalletState(state) {
    fs.writeFileSync(WALLET_STATE_PATH, JSON.stringify(state, null, 2), { encoding: 'utf8', mode: 0o600 });
}

function wipeWalletState() {
    if (fs.existsSync(WALLET_STATE_PATH)) fs.unlinkSync(WALLET_STATE_PATH);
}

// ──────────────────────────────────────────────
// EIP-1559 트랜잭션 해시 독립 계산
// 실제 펌웨어에서는 RLP 인코딩 + keccak256을 C++로 직접 구현합니다.
// 시뮬레이터에서는 ethers.js의 Transaction.from().unsignedHash를 사용합니다.
// ──────────────────────────────────────────────

function computeUnsignedHash(rawFields) {
    const tx = ethers.Transaction.from({
        type: 2,
        to: rawFields.to,
        value: BigInt(rawFields.value),
        nonce: rawFields.nonce,
        gasLimit: BigInt(rawFields.gasLimit),
        maxPriorityFeePerGas: BigInt(rawFields.maxPriorityFeePerGas),
        maxFeePerGas: BigInt(rawFields.maxFeePerGas),
        chainId: BigInt(rawFields.chainId),
        data: rawFields.data || '0x',
    });
    return tx.unsignedHash;
}

// ──────────────────────────────────────────────
// VirtualArduino 메인 클래스
// ──────────────────────────────────────────────

class VirtualArduino {
    constructor(cable) {
        this.cable = cable;
        this.pendingTxHash = null;
        this.awaitingPin = false;
        this.signingKey = null;
        this.mnemonic = null;    // 복호화된 니모닉 (accountIndex별 동적 파생에 사용)
        this.pendingAccountIndex = 0;

        // PC에서 서명 요청이 들어오면 실행
        this.cable.on('data_to_device', (data) => this._onTxReceived(data));
    }

    // ── 부팅 시 초기화 ──────────────────────────────
    async boot(initialPin) {
        let state = loadWalletState();

        if (!state) {
            // [첫 부팅] 니모닉 생성 및 PIN 설정
            console.log('\n[📱 HW 기기] 저장된 지갑 없음 — 새 지갑을 생성합니다...');
            state = await this._provisionNewWallet(initialPin);
            console.log('[📱 HW 기기] 지갑 생성 완료. wallet_state.json에 암호화 저장됨.');
        } else {
            // [일반 부팅] PIN으로 복호화
            console.log('\n[📱 HW 기기] 저장된 지갑 발견. PIN으로 잠금 해제 중...');
            this._unlockWithPin(state, initialPin);
        }

        console.log(`[📱 HW 기기] ✅ 지갑 잠금 해제 완료.`);
        console.log(`[📱 HW 기기] 계정 주소 (m/44'/60'/0'/0/0): ${this.walletAddress}`);
        console.log('[📱 HW 기기] Waiting for transaction...\n');
    }

    // ── 첫 부팅: 새 지갑 프로비저닝 ─────────────────
    async _provisionNewWallet(pin) {
        // 1. 하드웨어 RNG(시뮬레이션)으로 128비트 엔트로피 → BIP39 니모닉
        const mnemonic = ethers.Mnemonic.entropyToPhrase(ethers.randomBytes(16));
        // 니모닉은 터미널 히스토리에 남으므로 DEBUG_MNEMONIC=1 환경변수가 있을 때만 출력
        // 실제 기기에서는 LCD 화면에만 표시되고 절대 직렬 전송되지 않음
        if (process.env.DEBUG_MNEMONIC) {
            console.log('\n[📱 HW 기기] ── 복구 구문 (아래 12단어를 안전한 곳에 보관하세요) ──');
            mnemonic.split(' ').forEach((word, i) => {
                process.stdout.write(`  ${String(i + 1).padStart(2, ' ')}. ${word.padEnd(12)}`);
                if ((i + 1) % 4 === 0) process.stdout.write('\n');
            });
            console.log('[📱 HW 기기] ─────────────────────────────────────────────────\n');
        } else {
            console.log('\n[📱 HW 기기] 복구 구문 생성 완료. (출력하려면 DEBUG_MNEMONIC=1 환경변수 설정)');
        }

        // 2. PIN 해싱용 salt 생성
        const pinSalt = crypto.randomBytes(16).toString('hex');
        const pinHash = hashPin(pin, pinSalt);

        // 3. 니모닉 암호화용 salt 생성 후 AES-256-GCM 암호화
        const encSalt = crypto.randomBytes(16).toString('hex');
        const encryptedMnemonic = encryptMnemonic(mnemonic, pin, encSalt);

        const state = {
            version: 1,
            pinHash,
            pinSalt,
            encSalt,
            encryptedMnemonic,
            failedAttempts: 0,
            lockedUntil: null,
        };
        saveWalletState(state);

        // 4. 니모닉 보관 및 기본 계정(0) 키 파생
        this.mnemonic = mnemonic;
        this._deriveSigningKey(mnemonic, 0);
        return state;
    }

    // ── 일반 부팅: PIN으로 잠금 해제 ─────────────────
    _unlockWithPin(state, pin) {
        // 잠금 상태 확인
        if (state.lockedUntil && Date.now() < state.lockedUntil) {
            const remaining = Math.ceil((state.lockedUntil - Date.now()) / 1000);
            throw new Error(`기기가 잠금 상태입니다. ${remaining}초 후에 다시 시도하세요.`);
        }

        // PIN 검증 (타이밍 사이드채널 방지)
        const inputHash = hashPin(pin, state.pinSalt);
        const inputBuf  = Buffer.from(inputHash, 'hex');
        const storedBuf = Buffer.from(state.pinHash, 'hex');
        if (!crypto.timingSafeEqual(inputBuf, storedBuf)) {
            state.failedAttempts = (state.failedAttempts || 0) + 1;

            if (state.failedAttempts >= PIN_POLICY.WIPE_AFTER) {
                wipeWalletState();
                throw new Error('❌ PIN 10회 오류 — 보안 정책에 따라 지갑이 삭제되었습니다.');
            }

            if (state.failedAttempts >= PIN_POLICY.LOCKOUT_AFTER) {
                state.lockedUntil = Date.now() + PIN_POLICY.LOCKOUT_SECONDS * 1000;
                saveWalletState(state);
                throw new Error(`❌ PIN ${state.failedAttempts}회 오류 — ${PIN_POLICY.LOCKOUT_SECONDS}초 잠금.`);
            }

            saveWalletState(state);
            const remaining = PIN_POLICY.WIPE_AFTER - state.failedAttempts;
            throw new Error(`❌ 잘못된 PIN. (${state.failedAttempts}회 실패, ${remaining}회 남음)`);
        }

        // PIN 성공 → 실패 카운터 초기화
        state.failedAttempts = 0;
        state.lockedUntil = null;
        saveWalletState(state);

        // 니모닉 복호화 (GCM 인증 포함)
        const mnemonic = decryptMnemonic(state.encryptedMnemonic, pin, state.encSalt);

        // 니모닉 보관 및 기본 계정(0) 키 파생
        this.mnemonic = mnemonic;
        this._deriveSigningKey(mnemonic, 0);
    }

    // ── HD 지갑 키 파생 ────────────────────────────────
    _deriveSigningKey(mnemonic, accountIndex) {
        const path = `m/44'/60'/0'/0/${accountIndex}`;
        const wallet = ethers.HDNodeWallet.fromPhrase(mnemonic, undefined, path);
        this.signingKey = wallet.signingKey;
        this.walletAddress = wallet.address;
    }

    // ── 트랜잭션 수신 처리 ─────────────────────────────
    _onTxReceived(data) {
        let tx;
        try {
            tx = JSON.parse(data);
        } catch (e) {
            const response = JSON.stringify({ status: 'rejected', reason: 'Invalid JSON' });
            this.cable.writeToPC(response);
            return;
        }

        // accountIndex 범위 검증 (0-99만 허용)
        const accountIndex = tx.accountIndex ?? 0;
        if (!Number.isInteger(accountIndex) || accountIndex < 0 || accountIndex > 99) {
            const response = JSON.stringify({ status: 'rejected', reason: 'Account index out of range (0-99)' });
            this.cable.writeToPC(response);
            return;
        }

        // [보안] PC가 보낸 txHash를 raw 필드로 독립 재계산하여 검증
        let computedHash;
        try {
            computedHash = computeUnsignedHash(tx.rawFields);
        } catch (e) {
            const response = JSON.stringify({ status: 'rejected', reason: 'Invalid rawFields' });
            this.cable.writeToPC(response);
            return;
        }
        if (computedHash !== tx.txHash) {
            console.log(`\n[📱 HW 기기] ⚠️  경고: txHash 불일치!`);
            console.log(`[📱 HW 기기] 🚫 변조된 트랜잭션입니다. 서명을 거부합니다.\n`);
            const response = JSON.stringify({ status: 'rejected', reason: 'txHash mismatch — possible tampering detected' });
            this.cable.writeToPC(response);
            return;
        }

        this.pendingTxHash = tx.txHash;
        this.pendingAccountIndex = accountIndex;

        const derivPath = `m/44'/60'/0'/0/${this.pendingAccountIndex}`;
        console.log(`\n===========================================`);
        console.log(`[📱 HW 기기] 트랜잭션 수신 완료! (해시 검증 OK ✅)`);
        console.log(` - 계정     : Account #${this.pendingAccountIndex} (${derivPath})`);
        console.log(` - To      : ${tx.rawFields.to}`);
        console.log(` - Amount  : ${ethers.formatEther(tx.rawFields.value)} ETH`);
        console.log(` - Gas Fee : ${ethers.formatUnits(tx.rawFields.maxFeePerGas, 'gwei')} Gwei (Max)`);
        console.log(` - Chain ID: ${tx.rawFields.chainId}`);
        console.log(` - TxHash  : ${tx.txHash}`);
        console.log(`===========================================`);
        console.log(`🤔 이 송금을 승인하시겠습니까? (y = 승인 / n = 거절)`);
    }

    // ── 터미널 입력 처리 (물리 버튼 시뮬레이션) ──────────
    startInputListener(pin) {
        const rl = readline.createInterface({ input: process.stdin, output: process.stdout });

        rl.on('line', (input) => {
            const trimmed = input.trim();

            if (this.awaitingPin) {
                this._handlePinInput(trimmed);
                return;
            }

            if (trimmed === 'y' && this.pendingTxHash) {
                console.log(`[📱 HW 기기] 👉 승인됨. PIN을 입력하세요:`);
                this.awaitingPin = true;
            } else if (trimmed === 'n') {
                console.log(`[📱 HW 기기] ❌ 사용자가 거절했습니다.`);
                this._sendRejection('User Rejected');
            }
        });

        // (실제 기기에서는 PIN을 매번 버튼으로 입력받음)
    }

    // ── PIN 입력 처리 ────────────────────────────────────
    _handlePinInput(input) {
        const state = loadWalletState();

        // 잠금 상태 확인
        if (state.lockedUntil && Date.now() < state.lockedUntil) {
            const remaining = Math.ceil((state.lockedUntil - Date.now()) / 1000);
            console.log(`[📱 HW 기기] 🔒 잠금 중. ${remaining}초 후 재시도 가능.`);
            return;
        }

        const inputHash  = hashPin(input, state.pinSalt);
        const inputBuf2  = Buffer.from(inputHash, 'hex');
        const storedBuf2 = Buffer.from(state.pinHash, 'hex');

        if (!crypto.timingSafeEqual(inputBuf2, storedBuf2)) {
            state.failedAttempts = (state.failedAttempts || 0) + 1;

            if (state.failedAttempts >= PIN_POLICY.WIPE_AFTER) {
                wipeWalletState();
                console.log('[📱 HW 기기] 💥 PIN 10회 오류 — 지갑이 삭제되었습니다. 프로그램을 종료합니다.');
                process.exit(1);
            }

            if (state.failedAttempts >= PIN_POLICY.LOCKOUT_AFTER) {
                state.lockedUntil = Date.now() + PIN_POLICY.LOCKOUT_SECONDS * 1000;
                saveWalletState(state);
                console.log(`[📱 HW 기기] 🔒 ${state.failedAttempts}회 오류 — ${PIN_POLICY.LOCKOUT_SECONDS}초 잠금.`);
            } else {
                saveWalletState(state);
                const remaining = PIN_POLICY.WIPE_AFTER - state.failedAttempts;
                console.log(`[📱 HW 기기] ❌ 잘못된 PIN. (${state.failedAttempts}회 실패, ${remaining}회 남음)`);
            }

            this.awaitingPin = false;
            this._sendRejection('Invalid PIN');
            return;
        }

        // PIN 성공 → 카운터 초기화
        state.failedAttempts = 0;
        state.lockedUntil = null;
        saveWalletState(state);

        console.log(`[📱 HW 기기] ✅ PIN 인증 성공! secp256k1 서명 중...`);
        this.awaitingPin = false;

        setTimeout(() => {
            // 요청된 accountIndex로 키 동적 파생 후 서명
            this._deriveSigningKey(this.mnemonic, this.pendingAccountIndex);
            const signature = this.signingKey.sign(this.pendingTxHash);
            const response = JSON.stringify({
                status: 'success',
                signature: { r: signature.r, s: signature.s, v: signature.v },
            });
            this.cable.writeToPC(response);
            this.pendingTxHash = null;
        }, 500);
    }

    _sendRejection(reason) {
        const response = JSON.stringify({ status: 'rejected', reason });
        this.cable.writeToPC(response);
        this.pendingTxHash = null;
    }
}

module.exports = { VirtualArduino };
