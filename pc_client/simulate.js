const readline = require('readline');
const EventEmitter = require('events');

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

        // PC에서 USB(가상)로 서명 요청이 들어오면 실행
        this.cable.on('data_to_device', (data) => {
            const tx = JSON.parse(data);
            console.log(`\n===========================================`);
            console.log(`[📱 HW 디바이스 화면] 트랜잭션 수신 완료!`);
            console.log(` - To: ${tx.to.substring(0, 10)}...`);
            console.log(` - Amount: ${tx.amount}`);
            console.log(`===========================================`);
            console.log(`🤔 물리 버튼을 누르시겠습니까? (터미널에 'y' 입력 후 엔터 : 서명 승인 / 'n' 입력 : 거절)`);
        });

        // 🌟 터미널에서 사용자 입력(물리 버튼 클릭)을 감지합니다.
        const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
        rl.on('line', (input) => {
            if (input.trim() === 'y') {
                console.log(`[📱 HW 디바이스] ✅ 승인 버튼 클릭됨! 내부 칩에서 보안 서명 중...`);
                setTimeout(() => {
                    const fakeSignature = "0xabcd_securely_signed_by_hardware_chip_9999";
                    const response = JSON.stringify({ status: "success", signature: fakeSignature });
                    this.cable.writeToPC(response); // 서명값을 PC로 USB(가상)를 통해 전송
                }, 1000); // 1초 연산 딜레이
            } else if (input.trim() === 'n') {
                console.log(`[📱 HW 디바이스] ❌ 거절 버튼 클릭됨!`);
                const response = JSON.stringify({ status: "rejected" });
                this.cable.writeToPC(response);
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
            console.log(`   받은 서명 영수증 : ${parsed.signature}`);
            console.log(`🚀 이제 이더리움 메인넷으로 전송(Broadcast) 합니다!! 🚀\n`);
            process.exit(0);
        } else {
            console.log(`\n[💻 PC 소프트웨어] ❌ 기기에서 사용자가 거절했습니다. 송금이 취소됩니다.\n`);
            process.exit(0);
        }
    }

    requestSignature(txData) {
        console.log(`[💻 PC 소프트웨어] 하드웨어 월렛으로 서명 요청을 전송합니다 (USB 케이블 연결 중...)`);
        const payload = JSON.stringify(txData);
        this.cable.writeToDevice(payload);
    }
}

// ======================================
// 🚀 실행 (Simulation)
// ======================================
console.log("-----------------------------------------");
console.log("   하드웨어 월렛(Cold Wallet) PoC 시뮬레이터");
console.log("-----------------------------------------\n");

// 1. 기기 전원을 켬 (Virtual Arduino 시작)
new VirtualArduino(usbCable);

// 2. PC 클라이언트 켬 
const pc = new PcClient(usbCable);

// 3. 2초 뒤에 메타마스크가 결제를 요청함
setTimeout(() => {
    const txRequest = {
        to: "0xAb5801a7D398351b8bE11C439e05C5B3259aeC9B",
        amount: "10,000 RWA-Token",
        chainId: 1
    };
    pc.requestSignature(txRequest);
}, 2000);
