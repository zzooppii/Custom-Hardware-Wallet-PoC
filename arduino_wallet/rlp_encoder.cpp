/**
 * rlp_encoder.cpp — EIP-1559 트랜잭션 RLP 인코딩 구현
 *
 * RLP 규칙 요약:
 *   - 단일 바이트 0x00-0x7f: 그대로 인코딩
 *   - 빈 바이트열: 0x80
 *   - 1-55바이트 문자열: (0x80+length) || data
 *   - 55바이트 초과 문자열: (0xb7+len_of_len) || length_bytes || data
 *   - 0-55바이트 항목의 리스트: (0xc0+total_len) || items
 *   - 55바이트 초과 리스트: (0xf7+len_of_len) || length_bytes || items
 *   - 정수: big-endian, no leading zeros, 0 = 빈 바이트열(0x80)
 *
 * EIP-1559 unsigned tx 필드 순서:
 *   [chainId, nonce, maxPriorityFeePerGas, maxFeePerGas,
 *    gasLimit, to, value, data, accessList(=[]))]
 */

#include "rlp_encoder.h"
#include "keccak256.h"
#include <string.h>
#include <stdlib.h>
#include <stdint.h>

// ── 내부 유틸 ─────────────────────────────────────────────────────────────────

// 최소 바이트 수로 표현 가능한 uint의 바이트 길이
static size_t uint_byte_len(uint64_t val) {
    if (val == 0)         return 0;
    if (val <= 0xFF)      return 1;
    if (val <= 0xFFFF)    return 2;
    if (val <= 0xFFFFFF)  return 3;
    if (val <= 0xFFFFFFFF)return 4;
    if (val <= 0xFFFFFFFFFFULL) return 5;
    if (val <= 0xFFFFFFFFFFFFULL) return 6;
    if (val <= 0xFFFFFFFFFFFFFFULL) return 7;
    return 8;
}

// 10진수 문자열 → uint64_t (최대 18자리)
// 큰 wei 값은 uint64_t 오버플로우 가능성 있으므로 big-number 경로 필요
// 실용적 범위(0.1 ETH = 1e17 wei)는 uint64_t로 처리 가능
static uint64_t decimal_to_u64(const char* s) {
    uint64_t val = 0;
    while (*s >= '0' && *s <= '9') {
        val = val * 10 + (*s - '0');
        s++;
    }
    return val;
}

// 대형 정수(wei 값 등) 처리: 10진수 → 최소 big-endian 바이트 배열
// 최대 32바이트 (256비트) 지원
static size_t decimal_to_bigendian(const char* decimal, uint8_t* out, size_t maxLen) {
    // 단순 구현: 10진수를 반복 나눗셈으로 바이트 배열로 변환
    // 임시 배열에 역순으로 저장 후 뒤집기
    uint8_t tmp[32];
    size_t len = 0;

    // 문자열을 임시 배열에 복사 (최대 78자리)
    char buf[80];
    size_t slen = strlen(decimal);
    if (slen >= sizeof(buf)) slen = sizeof(buf) - 1;
    memcpy(buf, decimal, slen);
    buf[slen] = '\0';

    // "0" 처리
    if (slen == 1 && buf[0] == '0') return 0;

    // 반복 나눗셈: 256으로 나누어 나머지를 바이트로 저장
    while (slen > 0) {
        // buf[] / 256, 나머지를 tmp[len++]에 저장
        uint32_t rem = 0;
        int nonzero_start = -1;
        for (size_t i = 0; i < slen; i++) {
            uint32_t cur = rem * 10 + (buf[i] - '0');
            buf[i] = '0' + (cur / 256);
            rem = cur % 256;
            if (buf[i] != '0' && nonzero_start < 0) nonzero_start = (int)i;
        }
        if (len < maxLen) tmp[len++] = (uint8_t)rem;

        // 앞의 0 제거
        if (nonzero_start < 0) {
            slen = 0;
        } else if (nonzero_start > 0) {
            memmove(buf, buf + nonzero_start, slen - nonzero_start);
            slen -= nonzero_start;
        }
        // 마지막 자리가 '0'이면 제거
        while (slen > 1 && buf[0] == '0') {
            memmove(buf, buf + 1, --slen);
        }
        if (slen == 1 && buf[0] == '0') slen = 0;
    }

    if (len == 0 || len > maxLen) return 0;

    // 뒤집기 (big-endian)
    for (size_t i = 0; i < len; i++) out[i] = tmp[len - 1 - i];
    return len;
}

// hex 문자 → 4비트 값
static int hexnib(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

// ── RLP 바이트열 인코딩 (길이 접두어) ────────────────────────────────────────

static size_t rlp_bytes(const uint8_t* data, size_t data_len, uint8_t* out) {
    size_t pos = 0;
    if (data_len == 1 && data[0] < 0x80) {
        // 단일 바이트 0x00-0x7f: 그대로
        out[pos++] = data[0];
    } else if (data_len <= 55) {
        out[pos++] = (uint8_t)(0x80 + data_len);
        memcpy(out + pos, data, data_len);
        pos += data_len;
    } else {
        // 길이 자체를 바이트로 표현
        uint8_t lenBytes[8];
        size_t ll = uint_byte_len(data_len);
        for (size_t i = 0; i < ll; i++)
            lenBytes[ll - 1 - i] = (uint8_t)(data_len >> (8 * i));
        out[pos++] = (uint8_t)(0xb7 + ll);
        memcpy(out + pos, lenBytes, ll);
        pos += ll;
        memcpy(out + pos, data, data_len);
        pos += data_len;
    }
    return pos;
}

// ── 공개 API ─────────────────────────────────────────────────────────────────

size_t rlp_encode_decimal_uint(const char* decimal_str, uint8_t* buf) {
    uint8_t valBytes[32];
    size_t vlen = decimal_to_bigendian(decimal_str, valBytes, 32);
    // 0이면 RLP empty string = 0x80
    if (vlen == 0) { buf[0] = 0x80; return 1; }
    return rlp_bytes(valBytes, vlen, buf);
}

size_t rlp_encode_address(const char* hex_addr, uint8_t* buf) {
    // "0x" 접두어 제거
    const char* h = (hex_addr[0] == '0' && hex_addr[1] == 'x') ? hex_addr + 2 : hex_addr;
    if (strlen(h) != 40) { buf[0] = 0x80; return 1; }

    uint8_t addr[20];
    for (int i = 0; i < 20; i++) {
        int hi = hexnib(h[i*2]), lo = hexnib(h[i*2+1]);
        if (hi < 0 || lo < 0) { buf[0] = 0x80; return 1; }  // 유효하지 않은 hex
        addr[i] = (uint8_t)((hi << 4) | lo);
    }
    // 주소는 항상 20바이트 → 0x94(=0x80+20) prefix
    buf[0] = 0x94;
    memcpy(buf + 1, addr, 20);
    return 21;
}

size_t rlp_encode_data(const char* hex_data, uint8_t* buf) {
    // "0x" 또는 "" → 빈 바이트열 = 0x80
    if (!hex_data || strlen(hex_data) == 0 ||
        (hex_data[0] == '0' && hex_data[1] == 'x' && hex_data[2] == '\0')) {
        buf[0] = 0x80;
        return 1;
    }
    const char* h = (hex_data[0] == '0' && hex_data[1] == 'x') ? hex_data + 2 : hex_data;
    size_t hexLen = strlen(h);
    if (hexLen % 2 != 0 || hexLen == 0) { buf[0] = 0x80; return 1; }

    uint8_t data[512];
    size_t dataLen = hexLen / 2;
    if (dataLen > sizeof(data)) { buf[0] = 0x80; return 1; }  // 버퍼 오버플로우 방지
    for (size_t i = 0; i < dataLen; i++) {
        int hi = hexnib(h[i*2]), lo = hexnib(h[i*2+1]);
        if (hi < 0 || lo < 0) { buf[0] = 0x80; return 1; }  // 유효하지 않은 hex
        data[i] = (uint8_t)((hi << 4) | lo);
    }
    return rlp_bytes(data, dataLen, buf);
}

size_t rlp_encode_list(const uint8_t* items, size_t items_len, uint8_t* buf) {
    size_t pos = 0;
    if (items_len <= 55) {
        buf[pos++] = (uint8_t)(0xc0 + items_len);
    } else {
        uint8_t lenBytes[8];
        size_t ll = uint_byte_len(items_len);
        for (size_t i = 0; i < ll; i++)
            lenBytes[ll - 1 - i] = (uint8_t)(items_len >> (8 * i));
        buf[pos++] = (uint8_t)(0xf7 + ll);
        memcpy(buf + pos, lenBytes, ll);
        pos += ll;
    }
    memcpy(buf + pos, items, items_len);
    pos += items_len;
    return pos;
}

// ── EIP-1559 unsigned transaction 해시 계산 ──────────────────────────────────

bool compute_eip1559_hash(const JsonObject& rawFields, uint8_t hash_out[32]) {
    // 필드 읽기
    const char* chainId    = rawFields["chainId"]            | "0";
    const char* nonce_s    = nullptr;
    int nonce_i            = rawFields["nonce"]              | 0;
    const char* maxPrio    = rawFields["maxPriorityFeePerGas"]| "0";
    const char* maxFee     = rawFields["maxFeePerGas"]       | "0";
    const char* gasLimit   = rawFields["gasLimit"]           | "0";
    const char* to         = rawFields["to"]                 | "";
    const char* value      = rawFields["value"]              | "0";
    const char* data       = rawFields["data"]               | "0x";

    // nonce는 정수로 저장됨 → 문자열 변환
    char nonce_buf[20];
    snprintf(nonce_buf, sizeof(nonce_buf), "%d", nonce_i);
    nonce_s = nonce_buf;

    // 각 필드를 RLP 인코딩 (순서: EIP-1559 스펙)
    uint8_t enc[1024];
    size_t  pos = 0;

    uint8_t tmp[256];
    size_t  n;

#define SAFE_APPEND(buf, pos, tmp, n) \
    do { if ((pos) + (n) > sizeof(buf)) return false; \
         memcpy((buf)+(pos), (tmp), (n)); (pos) += (n); } while(0)

    n = rlp_encode_decimal_uint(chainId,  tmp); SAFE_APPEND(enc, pos, tmp, n);
    n = rlp_encode_decimal_uint(nonce_s,  tmp); SAFE_APPEND(enc, pos, tmp, n);
    n = rlp_encode_decimal_uint(maxPrio,  tmp); SAFE_APPEND(enc, pos, tmp, n);
    n = rlp_encode_decimal_uint(maxFee,   tmp); SAFE_APPEND(enc, pos, tmp, n);
    n = rlp_encode_decimal_uint(gasLimit, tmp); SAFE_APPEND(enc, pos, tmp, n);
    n = rlp_encode_address(to,            tmp); SAFE_APPEND(enc, pos, tmp, n);
    n = rlp_encode_decimal_uint(value,    tmp); SAFE_APPEND(enc, pos, tmp, n);
    n = rlp_encode_data(data,             tmp); SAFE_APPEND(enc, pos, tmp, n);

    // accessList = [] (빈 리스트)
    tmp[0] = 0xc0;  // RLP empty list
    SAFE_APPEND(enc, pos, tmp, 1);

    // RLP 리스트로 래핑
    uint8_t rlp_list[1100];
    size_t listLen = rlp_encode_list(enc, pos, rlp_list);

    // EIP-1559 type prefix(0x02) + RLP list
    uint8_t typed_tx[1101];
    typed_tx[0] = 0x02;
    memcpy(typed_tx + 1, rlp_list, listLen);

    // keccak256 해시
    keccak256(typed_tx, 1 + listLen, hash_out);
    return true;
}
