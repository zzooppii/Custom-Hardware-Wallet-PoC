const { SerialPort } = require('serialport');
const { ReadlineParser } = require('@serialport/parser-readline');
const { ethers } = require('ethers');

// ** Mac/Window의 실제 포트를 지정해야 합니다. (예: COM3 또는 /dev/tty.usbmodem...) **
const PORT_NAME = '/dev/tty.SLAB_USBtoUART'; // Arduino 시리얼 포트 경로 (에시)
const BAUD_RATE = 115200;

class HardwareWalletClient {
    constructor(portPath, baudRate) {
        console.log(`📡 Connecting to Hardware Wallet on ${portPath}...`);
        this.port = new SerialPort({ path: portPath, baudRate: baudRate });
        this.parser = this.port.pipe(new ReadlineParser({ delimiter: '\n' }));

        this.parser.on('data', this.onDataReceived.bind(this));
        this.pendingResolve = null;
        this.pendingReject = null;
    }

    // 데이터 수신 콜백
    onDataReceived(data) {
        try {
            const parsed = JSON.parse(data.trim());
            if (parsed.status === 'success') {
                console.log(`\n✅ [SUCCESS] Hardware Wallet Signed! Signature r: ${parsed.signature.r.substring(0, 10)}...`);
                // 서명된 트랜잭션 조립
                if (this.pendingTx) {
                    this.pendingTx.signature = parsed.signature;
                    if (this.pendingResolve) this.pendingResolve(this.pendingTx.serialized);
                } else {
                    if (this.pendingResolve) this.pendingResolve(parsed.signature);
                }
            } else if (parsed.status === 'rejected') {
                console.log(`\n❌ [REJECTED] User pressed cancel on the device.`);
                if (this.pendingReject) this.pendingReject(new Error("User Rejected on Device"));
            } else {
                console.log(`[DEVICE DBG] ${data}`);
            }
        } catch (e) {
            // 일반적인 디버깅 로그
            console.log(`[DEVICE LOG] ${data}`);
        }
    }

    // 서명 요청 (MetaMask가 하드웨어로 던지는 역할)
    async requestSignature(txRequest, originalTx) {
        console.log(`\n📤 Sending Transaction Hash to HW Wallet for Approval...`);
        console.log(`>> To: ${txRequest.to} | Amount: ${txRequest.amount} ETH | Gas Fee: ${txRequest.maxFeePerGas} Gwei`);
        this.pendingTx = originalTx; // 원본 트랜잭션 객체 저장

        return new Promise((resolve, reject) => {
            this.pendingResolve = resolve;
            this.pendingReject = reject;

            const payload = JSON.stringify(txRequest) + '\n';
            this.port.write(payload, (err) => {
                if (err) {
                    console.error("Failed to send data to wallet:", err.message);
                    return reject(err);
                }
                console.log("   (Waiting for physical button press...)");
            });
        });
    }
}

// ======================================
// 메인 실험 코드 (Mocha Test 느낌)
// ======================================
async function runDemo() {
    try {
        const hwWallet = new HardwareWalletClient(PORT_NAME, BAUD_RATE);

        // 연결 안정화를 위해 2초 대기
        setTimeout(async () => {
            console.log("\n=================================");
            console.log(" 🏦 RWA Token Transfer Request");
            console.log("=================================");

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
            
            const txRequest = {
                txHash: tx.unsignedHash,
                to: tx.to,
                amount: ethers.formatEther(tx.value),
                gasLimit: tx.gasLimit.toString(),
                maxFeePerGas: ethers.formatUnits(tx.maxFeePerGas, "gwei"),
                chainId: tx.chainId.toString()
            };

            try {
                // 원본 tx 객체도 함께 넘겨 v,r,s 를 주입받을 수 있도록 함
                const signedTxRaw = await hwWallet.requestSignature(txRequest, tx);
                console.log(`\n🔗 Now Broadcasting to Ethereum Network...`);
                console.log(`[Signed Tx Formatted: ${signedTxRaw}]`);
                console.log(`Broadcast can be done via: new ethers.JsonRpcProvider(URL).broadcastTransaction(signedTxRaw)`);
            } catch (err) {
                console.error("Transaction Aborted.");
            }
        }, 2000);

    } catch (error) {
        console.error("Could not find hardware wallet. (Check PORT_NAME in index.js)");
    }
}

runDemo();
