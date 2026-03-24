const readline = require('readline');
const EventEmitter = require('events');
const { ethers } = require('ethers');

// ======================================
// 1. 가상 USB 케이블 (EventEmitter로 Mocking)
// ======================================
// SerialPort를 모방하여 PC와 기기가 서로 데이터를 주고받게 해줍니다.
class MockUsbCable extends EventEmitter {
    writeToDevice(data) {
        this.emit('data_to_device', data);
    }
    writeToPC(data) {
        this.emit('data_to_pc', data);
    }
}
const usbCable = new MockUsbCable();

// ======================================
// 2. 가상의 아두이노(하드웨어) 기기 프로그램
// ======================================
class VirtualArduino {
    constructor(cable) {
        this.cable = cable;
        
        // [보안의 핵심] 기기 내부에 분리 보관된 12개 단어 니모닉(BIP39 Mnemonic Seed)
        const mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        const wallet = ethers.HDNodeWallet.fromPhrase(mnemonic);
        this.signingKey = wallet.signingKey; // 기본 파생 경로 m/44'/60'/0'/0/0 에서 추출
        
        this.pendingTxHash = null;
        this.devicePin = "1234"; // 오프라인 하드웨어 잠금/서명 PIN
        this.awaitingPin = false;

        // PC에서 USB(가상)로 서명 요청이 들어오면 실행
        this.cable.on('data_to_device', (data) => {
            const tx = JSON.parse(data);
            this.pendingTxHash = tx.txHash; // 서명할 해시 보관
            
            console.log(`\n===========================================`);
            console.log(`[📱 HW 디바이스 화면] 트랜잭션 수신 완료!`);
            console.log(` - To: ${tx.to.substring(0, 10)}...`);
            console.log(` - Amount: ${tx.amount} ETH`);
            console.log(` - Gas Fee: ${tx.maxFeePerGas} Gwei (Max)`);
            console.log(` - Chain ID: ${tx.chainId}`);
            console.log(` - TxHash: ${tx.txHash}`);
            console.log(`===========================================`);
            console.log(`🤔 이 송금을 승인하시겠습니까? (터미널에 'y' 입력 후 엔터 : 서명 진행 / 'n' 입력 : 거절)`);
        });

        // 🌟 터미널에서 사용자 입력(물리 버튼 클릭 및 PIN)을 감지합니다.
        const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
        rl.on('line', (input) => {
            if (this.awaitingPin) {
                if (input.trim() === this.devicePin) {
                    console.log(`[📱 HW 디바이스] ✅ PIN 인증 성공! HD 지갑 파생 경로(m/44'/60'/0'/0/0)를 통해 ECDSA 보안 서명 중...`);
                    this.awaitingPin = false;
                    setTimeout(() => {
                        // 기기 내부에서 계층적 결정적 지갑(HD Wallet)의 실제 secp256k1 타원곡선 서명 수행
                        const signature = this.signingKey.sign(this.pendingTxHash);
                        
                        const response = JSON.stringify({ 
                            status: "success", 
                            signature: {
                                r: signature.r,
                                s: signature.s,
                                v: signature.v
                            } 
                        });
                        this.cable.writeToPC(response); // 서명값을 PC로 전송
                        this.pendingTxHash = null;
                    }, 1000); // 1초 연산 딜레이
                } else {
                    console.log(`[📱 HW 디바이스] ❌ PIN 번호가 틀렸습니다! 해킹 시도 차단을 위해 서명을 즉시 취소합니다.`);
                    this.awaitingPin = false;
                    const response = JSON.stringify({ status: "rejected", reason: "Invalid PIN" });
                    this.cable.writeToPC(response);
                    this.pendingTxHash = null;
                }
                return;
            }

            if (input.trim() === 'y' && this.pendingTxHash) {
                console.log(`[📱 HW 디바이스] 👉 송금이 승인되었습니다. 서명을 위해 기기 PIN 번호 4자리를 입력하세요 (예: 1234).`);
                this.awaitingPin = true;
            } else if (input.trim() === 'n') {
                console.log(`[📱 HW 디바이스] ❌ 거절 버튼 클릭됨!`);
                const response = JSON.stringify({ status: "rejected", reason: "User Rejected" });
                this.cable.writeToPC(response);
                this.pendingTxHash = null;
            }
        });
    }
}

// ======================================
// 3. PC 클라이언트 (MetaMask 역할) 프로그램
// ======================================
class PcClient {
    constructor(cable) {
        this.cable = cable;
        this.cable.on('data_to_pc', this.onResponseFromHardware.bind(this));
    }

    onResponseFromHardware(data) {
        const parsed = JSON.parse(data);
        if (parsed.status === 'success') {
            console.log(`\n[💻 PC 소프트웨어] ✅ 기기로부터 서명값을 받았습니다!`);
            console.log(`   수신된 r : ${parsed.signature.r}`);
            console.log(`   수신된 s : ${parsed.signature.s}`);
            console.log(`   수신된 v : ${parsed.signature.v}`);
            
            // 서명된 트랜잭션 조립
            if (this.pendingTx) {
                this.pendingTx.signature = parsed.signature;
                console.log(`\n🚀 완성된 Signed Raw Transaction : `);
                console.log(`   ${this.pendingTx.serialized}\n`);
                console.log(`🚀 이제 이더리움 테스트넷(RPC)으로 Broadcast 합니다!! 🚀\n`);
            }
            process.exit(0);
        } else {
            console.log(`\n[💻 PC 소프트웨어] ❌ 기기에서 사용자가 거절했습니다. 송금이 취소됩니다.\n`);
            process.exit(0);
        }
    }

    requestSignature(txRequest, originalTx) {
        console.log(`[💻 PC 소프트웨어] 하드웨어 월렛으로 트랜잭션 해시 서명 요청 전송중...`);
        this.pendingTx = originalTx; // 반환받은 서명을 합치기 위해 원본 트랜잭션 기억
        const payload = JSON.stringify(txRequest);
        this.cable.writeToDevice(payload);
    }
}

// ======================================
// 🚀 실행 (Simulation)
// ======================================
console.log("-----------------------------------------");
console.log("   하드웨어 월렛(Cold Wallet) PoC 시뮬레이터");
console.log("   (Ethers.js 실제 ECDSA 서명 적용 버전)");
console.log("-----------------------------------------\n");

// 1. 기기 전원을 켬 (Virtual Arduino 시작)
new VirtualArduino(usbCable);

// 2. PC 클라이언트 켬 
const pc = new PcClient(usbCable);

// 3. 2초 뒤에 메타마스크가 결제를 요청함
setTimeout(() => {
    // 실제 이더리움 트랜잭션 객체 생성
    const tx = ethers.Transaction.from({
        to: "0xAb5801a7D398351b8bE11C439e05C5B3259aeC9B",
        value: ethers.parseEther("0.1"),
        nonce: 42,
        gasLimit: 21000,
        maxPriorityFeePerGas: ethers.parseUnits("1", "gwei"),
        maxFeePerGas: ethers.parseUnits("20", "gwei"),
        chainId: 11155111 // Sepolia 체인 ID
    });
    
    // 이더리움 규격에 따른 서명 대상 해시(Keccak256) 추출
    const txHash = tx.unsignedHash;
    
    // 하드웨어 기기로 보낼 확장 페이로드 (Gas 및 Network 정보 포함)
    const txRequest = {
        txHash: txHash,
        to: tx.to,
        amount: ethers.formatEther(tx.value),
        gasLimit: tx.gasLimit.toString(),
        maxFeePerGas: ethers.formatUnits(tx.maxFeePerGas, "gwei"),
        chainId: tx.chainId.toString()
    };
    
    pc.requestSignature(txRequest, tx);
}, 2000);
