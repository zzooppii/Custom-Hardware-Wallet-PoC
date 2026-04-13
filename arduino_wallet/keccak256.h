#pragma once
#include <stdint.h>
#include <stddef.h>

/**
 * keccak256.h — Ethereum Keccak-256 해시
 *
 * NOTE: Ethereum은 NIST SHA3-256이 아닌 원본 Keccak-256을 사용합니다.
 *       (padding byte 0x01 대신 0x01을 사용하며, SHA3는 0x06 사용)
 *
 * 인터페이스:
 *   keccak256(input, len, output)  — output은 32바이트 버퍼
 */

void keccak256(const uint8_t* input, size_t len, uint8_t* output);
