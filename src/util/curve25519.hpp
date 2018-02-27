#pragma once

#include <stdint.h>

int ED25519_sign(uint8_t *out_sig, const uint8_t *message, size_t message_len,
	const uint8_t public_key[32], const uint8_t private_key[32]);
int ED25519_verify(const uint8_t *message, size_t message_len,
	const uint8_t signature[64], const uint8_t public_key[32]);
void ED25519_public_from_private(uint8_t out_public_key[32],
	const uint8_t private_key[32]);

int X25519(uint8_t out_shared_key[32], const uint8_t private_key[32],
	const uint8_t peer_public_value[32]);
void X25519_public_from_private(uint8_t out_public_value[32],
	const uint8_t private_key[32]);
