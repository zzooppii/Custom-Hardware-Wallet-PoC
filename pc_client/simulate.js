/**
 * simulate.js — 하드웨어 월렛 전체 플로우 시뮬레이터
 *
 * 실물 M5Stack 없이 터미널에서 PC ↔ 기기 간 통신을 완전 모의합니다.
 *
 * 실행:
 *   node simulate.js            (첫 실행: 새 지갑 생성, PIN 설정)
 *   node simulate.js --wipe     (wallet_state.json 삭제 후 재생성)
 *
 * 사용:
 *   y + Enter → 트랜잭션 승인
 *   n + Enter → 트랜잭션 거절
 *   PIN 입력 후 Enter → 서명 진행
 */

const EventEmitter = require('events');
const { ethers } = require('ethers');
const { VirtualArduino } = require('./virtual_arduino');
const fs = require('fs');
const path = require('path');

// ──────────────────────────────────────────────
// 1. 가상 USB 케이블 (MockUsbCable)
// ──────────────────────────────────────────────
class MockUsbCable extends EventEmitter {
    writeToDevice(data) { this.emit('data_to_device', data); }
    writeToPC(data)     { this.emit('data_to_pc', data); }
}

// ──────────────────────────────────────────────
// 2. PC 클라이언트 (MetaMask 역할)
// ──────────────────────────────────────────────
class PcClient {
    constructor(cable) {
        this.cable = cable;
        this.pendingTx = null;
        this.cable.on('data_to_pc', this.onResponseFromHardware.bind(this));
    }

    onResponseFromHardware(data) {
        const parsed = JSON.parse(data);

        if (parsed.status === 'success') {
            console.log(`\n[💻 PC] ✅ 기기로부터 서명값 수신!`);
            console.log(`   r : ${parsed.signature.r}`);
            console.log(`   s : ${parsed.signature.s}`);
            console.log(`   v : ${parsed.signature.v}`);

            if (this.pendingTx) {
                // ethers v6: Transaction은 불변 → 서명 포함해 새로 생성
                const signedTx = ethers.Transaction.from({
                    type: 2,
                    to: this.pendingTx.to,
                    value: this.pendingTx.value,
                    nonce: this.pendingTx.nonce,
                    gasLimit: this.pendingTx.gasLimit,
                    maxPriorityFeePerGas: this.pendingTx.maxPriorityFeePerGas,
                    maxFeePerGas: this.pendingTx.maxFeePerGas,
                    chainId: this.pendingTx.chainId,
                    signature: {
                        r: parsed.signature.r,
                        s: parsed.signature.s,
                        v: parsed.signature.v,
                    },
                });

                console.log(`\n🚀 완성된 Signed Raw Transaction:`);
                console.log(`   ${signedTx.serialized}`);
                console.log(`\n   서명자 주소 (from): ${signedTx.from}`);
                console.log(`\n🚀 이더리움 테스트넷(Sepolia)으로 Broadcast 가능!\n`);
            }
        } else {
            console.log(`\n[💻 PC] ❌ 트랜잭션 취소됨 — 사유: ${parsed.reason}\n`);
        }

        process.exit(0);
    }

    requestSignature(txRequest, originalTx) {
        console.log(`[💻 PC] 하드웨어 월렛으로 서명 요청 전송 중...`);
        this.pendingTx = originalTx;
        this.cable.writeToDevice(JSON.stringify(txRequest));
    }
}

// ──────────────────────────────────────────────
// 실행
// ──────────────────────────────────────────────
async function main() {
    // --wipe 플래그로 지갑 상태 초기화
    if (process.argv.includes('--wipe')) {
        const statePath = path.join(__dirname, 'wallet_state.json');
        if (fs.existsSync(statePath)) {
            fs.unlinkSync(statePath);
            console.log('wallet_state.json 삭제 완료. 재생성합니다.\n');
        }
    }

    console.log('─────────────────────────────────────────');
    console.log('  하드웨어 월렛(Cold Wallet) 시뮬레이터');
    console.log('─────────────────────────────────────────\n');

    const usbCable = new MockUsbCable();

    // 시뮬레이터 PIN (실제 기기에서는 6자리 버튼으로 입력)
    const DEVICE_PIN = '123456';

    // 기기 부팅 (첫 실행 시 지갑 생성, 이후 PIN으로 복호화)
    const arduino = new VirtualArduino(usbCable);
    try {
        await arduino.boot(DEVICE_PIN);
    } catch (err) {
        console.error(`[📱 HW 기기] 부팅 실패: ${err.message}`);
        process.exit(1);
    }

    // 터미널 입력 리스너 시작 (물리 버튼 시뮬레이션)
    arduino.startInputListener(DEVICE_PIN);

    // PC 클라이언트 초기화
    const pc = new PcClient(usbCable);

    // 2초 뒤 트랜잭션 요청 (MetaMask 역할)
    setTimeout(() => {
        // 사용할 계정 인덱스 (0 = 첫 번째 계정, 1 = 두 번째 계정, ...)
        const ACCOUNT_INDEX = 0;

        // 서명할 트랜잭션 생성
        const tx = ethers.Transaction.from({
            type: 2,
            to: '0xAb5801a7D398351b8bE11C439e05C5B3259aeC9B',
            value: ethers.parseEther('0.1'),
            nonce: 42,
            gasLimit: 21000n,
            maxPriorityFeePerGas: ethers.parseUnits('1', 'gwei'),
            maxFeePerGas: ethers.parseUnits('20', 'gwei'),
            chainId: 11155111n, // Sepolia
        });

        // PC → 기기 페이로드: txHash + raw 필드 + accountIndex
        const txRequest = {
            txHash: tx.unsignedHash,
            accountIndex: ACCOUNT_INDEX,
            rawFields: {
                to: tx.to,
                value: tx.value.toString(),
                nonce: tx.nonce,
                gasLimit: tx.gasLimit.toString(),
                maxPriorityFeePerGas: tx.maxPriorityFeePerGas.toString(),
                maxFeePerGas: tx.maxFeePerGas.toString(),
                chainId: tx.chainId.toString(),
                data: '0x',
            },
        };

        pc.requestSignature(txRequest, tx);
    }, 2000);
}

main().catch(console.error);
