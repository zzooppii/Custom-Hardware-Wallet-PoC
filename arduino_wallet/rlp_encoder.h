#pragma once
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <ArduinoJson.h>

/**
 * rlp_encoder.h — EIP-1559 트랜잭션 전용 최소 RLP 인코더
 *
 * EIP-1559 unsigned transaction 해시 계산:
 *   keccak256( 0x02 || RLP([chainId, nonce, maxPriorityFeePerGas,
 *                            maxFeePerGas, gasLimit, to, value, data, []]) )
 *
 * 참고: accessList는 항상 빈 리스트 []
 */

/**
 * rawFields JSON 객체로부터 EIP-1559 unsigned transaction 해시를 계산합니다.
 *
 * @param rawFields  ArduinoJson JsonObject (to, value, nonce, gasLimit,
 *                   maxPriorityFeePerGas, maxFeePerGas, chainId, data 포함)
 * @param hash_out   결과 32바이트 keccak256 해시
 * @return true = 성공
 */
bool compute_eip1559_hash(const JsonObject& rawFields, uint8_t hash_out[32]);

// ── 저수준 RLP 함수 (단위 테스트용) ──────────────────────────────────────────

/**
 * 10진수 문자열 정수를 RLP로 인코딩합니다.
 * 예: "42" → 0x2a (1바이트)
 * @return 인코딩된 바이트 수
 */
size_t rlp_encode_decimal_uint(const char* decimal_str, uint8_t* buf);

/**
 * "0x..." hex 문자열 주소(20바이트)를 RLP로 인코딩합니다.
 * @return 인코딩된 바이트 수 (항상 21: 0x94 prefix + 20바이트)
 */
size_t rlp_encode_address(const char* hex_addr, uint8_t* buf);

/**
 * "0x" 또는 빈 문자열 데이터를 RLP로 인코딩합니다.
 * @return 인코딩된 바이트 수
 */
size_t rlp_encode_data(const char* hex_data, uint8_t* buf);

/**
 * 이미 RLP 인코딩된 항목들의 배열을 RLP 리스트로 래핑합니다.
 * @return 인코딩된 바이트 수
 */
size_t rlp_encode_list(const uint8_t* items, size_t items_len, uint8_t* buf);
