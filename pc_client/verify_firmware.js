/**
 * verify_firmware.js — 펌웨어 암호화 로직 크로스체크
 *
 * 기기 없이 펌웨어 C++ 코드의 정확성을 검증합니다.
 * ethers.js를 레퍼런스로 삼아 기대값을 계산하고,
 * 기기를 연결한 뒤 실제 출력과 비교하는 테스트 가이드를 제공합니다.
 *
 * 실행: node verify_firmware.js
 */

const { ethers } = require('ethers');

console.log('═══════════════════════════════════════════════════');
console.log('  펌웨어 암호화 로직 크로스체크 (레퍼런스 값 생성)');
console.log('═══════════════════════════════════════════════════\n');

// ── Step 1 검증: secp256k1 서명 ─────────────────────────────────────────────
console.log('── Step 1: secp256k1 서명 검증 ──────────────────────\n');

const TEST_MNEMONIC = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';
const wallet = ethers.HDNodeWallet.fromPhrase(TEST_MNEMONIC, undefined, "m/44'/60'/0'/0/0");

console.log('[레퍼런스] 테스트 니모닉:', TEST_MNEMONIC);
console.log('[레퍼런스] 파생 경로:    m/44\'/60\'/0\'/0/0');
console.log('[레퍼런스] 프라이빗 키:', wallet.privateKey);
console.log('[레퍼런스] 지갑 주소:   ', wallet.address);
console.log('');
console.log('▶ wallet.ino의 TEST_PRIVKEY 배열이 이 값과 일치해야 합니다:');
const pkBytes = wallet.privateKey.slice(2);
let cArrayStr = 'static const uint8_t TEST_PRIVKEY[32] = {\n   ';
for (let i = 0; i < 32; i++) {
    cArrayStr += ' 0x' + pkBytes.slice(i*2, i*2+2) + ',';
    if ((i + 1) % 8 === 0 && i < 31) cArrayStr += '\n   ';
}
cArrayStr += '\n};';
console.log(cArrayStr);
console.log('');

// ── 테스트 트랜잭션 해시 ────────────────────────────────────────────────────
const tx = ethers.Transaction.from({
    type: 2,
    to: '0xAb5801a7D398351b8bE11C439e05C5B3259aeC9B',
    value: ethers.parseEther('0.1'),
    nonce: 42,
    gasLimit: 21000n,
    maxPriorityFeePerGas: ethers.parseUnits('1', 'gwei'),
    maxFeePerGas: ethers.parseUnits('20', 'gwei'),
    chainId: 11155111n,
});

const txHash = tx.unsignedHash;
console.log('[레퍼런스] 테스트 TX unsignedHash:', txHash);
console.log('');

// ── 서명 생성 ───────────────────────────────────────────────────────────────
const signature = wallet.signingKey.sign(txHash);
console.log('[레퍼런스] 서명 결과 (ethers.js):');
console.log('  r:', signature.r);
console.log('  s:', signature.s);
console.log('  v:', signature.v);
console.log('');

// 서명 검증: signedTx.from이 올바른 주소인지 확인
const signedTx = ethers.Transaction.from({
    type: 2,
    to: tx.to,
    value: tx.value,
    nonce: tx.nonce,
    gasLimit: tx.gasLimit,
    maxPriorityFeePerGas: tx.maxPriorityFeePerGas,
    maxFeePerGas: tx.maxFeePerGas,
    chainId: tx.chainId,
    signature: { r: signature.r, s: signature.s, v: signature.v },
});
console.log('[레퍼런스] 서명된 TX from:', signedTx.from);
console.log('[검증]', signedTx.from === wallet.address ? '✅ from 주소 일치' : '❌ from 주소 불일치!');
console.log('');

// ── Step 2 검증: BIP32 경로별 키 파생 ──────────────────────────────────────
console.log('── Step 2: BIP32 HD 키 파생 검증 ────────────────────\n');
const paths = [
    "m/44'/60'/0'/0/0",
    "m/44'/60'/0'/0/1",
    "m/44'/60'/0'/0/2",
];
paths.forEach(p => {
    const w = ethers.HDNodeWallet.fromPhrase(TEST_MNEMONIC, undefined, p);
    console.log(`  ${p}`);
    console.log(`    privkey: ${w.privateKey}`);
    console.log(`    address: ${w.address}`);
});
console.log('');
console.log('▶ firmware의 derive_path()가 각 경로에서 동일한 privkey를 출력해야 합니다.');
console.log('  (Serial.println으로 #ifdef DEBUG 아래에서 출력하여 확인)');
console.log('');

// ── Step 6 검증: RLP 인코딩 + keccak256 ────────────────────────────────────
console.log('── Step 6: 독립 txHash 검증 ──────────────────────────\n');
console.log('[레퍼런스] rawFields:');
console.log(JSON.stringify({
    to: tx.to,
    value: tx.value.toString(),
    nonce: tx.nonce,
    gasLimit: tx.gasLimit.toString(),
    maxPriorityFeePerGas: tx.maxPriorityFeePerGas.toString(),
    maxFeePerGas: tx.maxFeePerGas.toString(),
    chainId: tx.chainId.toString(),
    data: '0x',
}, null, 2));
console.log('');
console.log('[레퍼런스] 예상 unsignedHash:', txHash);
console.log('▶ firmware의 compute_eip1559_hash(rawFields) 결과가 이 값과 일치해야 합니다.');
console.log('');

// ── keccak256 단위 테스트 벡터 ──────────────────────────────────────────────
console.log('── keccak256.cpp 단위 테스트 벡터 ───────────────────\n');
const vectors = [
    { input: Buffer.alloc(0),                label: '빈 입력' },
    { input: Buffer.from('abc'),             label: '"abc"' },
    { input: Buffer.from('Hello, World!'),   label: '"Hello, World!"' },
];
vectors.forEach(({ input, label }) => {
    const hash = ethers.keccak256(input);
    console.log(`  ${label}:`);
    console.log(`    입력(hex): ${input.toString('hex') || '(empty)'}`);
    console.log(`    keccak256: ${hash}`);
});
console.log('');
console.log('▶ firmware의 keccak256()이 동일한 출력을 생성해야 합니다.');
console.log('  (Serial.println으로 #ifdef DEBUG 아래에서 출력하여 확인)');
console.log('');
console.log('═══════════════════════════════════════════════════');
console.log('  기기 연결 후 테스트 방법:');
console.log('  1. wallet.ino를 M5Stack에 플래시');
console.log('  2. node index.js 실행 (시리얼 포트 연결 확인)');
console.log('  3. M5Stack에서 BtnA → BtnB 눌러 서명 승인');
console.log('  4. 출력된 "서명자 주소 (from)"이 아래와 일치하는지 확인:');
console.log(`     ${wallet.address}`);
console.log('═══════════════════════════════════════════════════');
