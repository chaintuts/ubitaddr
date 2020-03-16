/* This file contains the underlying implementation for BitAddr functions
*
* Author: Josh McIntyre
*/
#include <string.h>
//#include "py/runtime.h"
#include "sha2.h"
#include "sha3.h"
#include "ripemd160.h"
#include "secp256k1.h"
#include "ecdsa.h"
#include "rand.h"
#include "base58.h"
#include "cash_addr.h"

#include <stdio.h>

// Some size definitions we'll need to implement the pubkey -> address conversion
size_t RAW_ADDRESS_NOCHECK_LENGTH = 21;
size_t RAW_ADDRESS_CHECK_LENGTH = 25;
size_t PUBKEY_65_LENGTH = 65;
size_t CHECKSUM_LENGTH = 4;
size_t ADDRESS_LENGTH = 40;
size_t ETH_PUBKEY_LENGTH = 64;
size_t RAW_ETH_ADDRESS_LENGTH = 20;
size_t ETH_ADDRESS_LENGTH = 42;
size_t RAW_PRIVKEY_NOCHECK_LENGTH = 33;
size_t RAW_PRIVKEY_CHECK_LENGTH = 37;
size_t PRIVKEY_WIF_LENGTH = 70;
size_t PRIVKEY_HEX_LENGTH = 66;

// Version bit data
// The defines are taken from Trezor examples
#define CASHADDR_P2PKH_BITS (0)
#define CASHADDR_RIPEMD160_BITS (0)
unsigned char BTC_ADDR_PREFIX = 0x0;
unsigned char BTC_WIF_PREFIX = 0x80;
unsigned char LTC_ADDR_PREFIX = 0x30;
unsigned char LTC_WIF_PREFIX = 0xB0;
unsigned char DGB_ADDR_PREFIX = 0x1E;
unsigned char DGB_WIF_PREFIX = 0x80;

// Define helper functions that aren't directly accessible to Python

// Convert a byte to hex format and write directly to the buffer
// This is a substitute for sprintf on a microcontroller platform
void byte_to_hex(unsigned char byte, unsigned char* buffer)
{
	char hex_chars[16] = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f' };
	unsigned char left_mask = 0xF0;
	unsigned char right_mask = 0xF;

	// First, calculate the character for the first nibble (4 bits)
	// Mask off the last 4 bits, then right shift 4 bytes
	// This will be the index used to get the right character from hex_chars
	unsigned char left_index = byte & left_mask;
	left_index = left_index >> 4;
	*buffer = hex_chars[left_index];

	unsigned char right_index = byte & right_mask;
	*(buffer + 1) = hex_chars[right_index];
}

// Calculate the secp256k1 public key from the private key
void pubkey_from_privkey(unsigned char privkey[SHA256_DIGEST_LENGTH],  unsigned char pubkey[PUBKEY_65_LENGTH])
{
	 ecdsa_get_public_key65(&secp256k1, (uint8_t*) privkey,
                            (uint8_t*) pubkey);
}

// Generate a private key from some entropy
void privkey_from_entropy(const char* entropy, unsigned char privkey[SHA256_DIGEST_LENGTH])
{
	sha256_Raw((uint8_t*) entropy, strlen(entropy), (uint8_t*) privkey);
}

// Generate address from pubkey
void address_from_pubkey(const unsigned char pubkey[PUBKEY_65_LENGTH], unsigned char version_prefix, unsigned char address[ADDRESS_LENGTH])
{
	// First, "double hash" the public key
	unsigned char round_1[SHA256_DIGEST_LENGTH];
	unsigned char round_2[RIPEMD160_DIGEST_LENGTH];

	sha256_Raw((uint8_t*) pubkey, PUBKEY_65_LENGTH, (uint8_t*) round_1);
	ripemd160((uint8_t*) round_1, SHA256_DIGEST_LENGTH, (uint8_t*) round_2);

	// Add the version specifier
	unsigned char raw_address_nocheck[RAW_ADDRESS_NOCHECK_LENGTH];
	raw_address_nocheck[0] = version_prefix;
	memcpy(raw_address_nocheck + 1, round_2, RIPEMD160_DIGEST_LENGTH);

	// Generate a checksum
	unsigned char check_round_1[SHA256_DIGEST_LENGTH];
	unsigned char check_round_2[SHA256_DIGEST_LENGTH];
	unsigned char checksum[CHECKSUM_LENGTH];

	sha256_Raw((uint8_t*) raw_address_nocheck, RAW_ADDRESS_NOCHECK_LENGTH, check_round_1);
	sha256_Raw((uint8_t*) check_round_1, SHA256_DIGEST_LENGTH, check_round_2);
	memcpy(checksum, check_round_2, CHECKSUM_LENGTH);


	// Finalize the raw address
	// 1 byte for the version string
	// 20 bytes for the pubkey hash
	// 4 bytes for the checksum
	unsigned char raw_address_check[RAW_ADDRESS_CHECK_LENGTH];
	memcpy(raw_address_check, raw_address_nocheck, RAW_ADDRESS_NOCHECK_LENGTH);
	memcpy(raw_address_check + RAW_ADDRESS_NOCHECK_LENGTH, checksum, CHECKSUM_LENGTH);

	// Base58 encode
	b58enc((char*) address, &ADDRESS_LENGTH, raw_address_check, RAW_ADDRESS_CHECK_LENGTH);
}

// Generate address from pubkey
void eth_address_from_pubkey(const unsigned char pubkey[PUBKEY_65_LENGTH], unsigned char address[ETH_ADDRESS_LENGTH])
{
	// First, hash the public key without the 04 uncompressed pubkey indicator byte at the front
	unsigned char round_1[SHA3_256_DIGEST_LENGTH];

	keccak_256(pubkey + 1, ETH_PUBKEY_LENGTH, round_1);

	unsigned char raw_address[RAW_ETH_ADDRESS_LENGTH];
	memcpy(raw_address, round_1 + 12, RIPEMD160_DIGEST_LENGTH);
	
	address[0] = '0';
	address[1] = 'x';
	int c = 2;
	for (int i = 0; i < RIPEMD160_DIGEST_LENGTH; i++)
	{
		byte_to_hex(raw_address[i], &address[c]);
		c += 2;
	}
}

// Generate address from pubkey
void cash_address_from_pubkey(const unsigned char pubkey[PUBKEY_65_LENGTH], unsigned char address[ADDRESS_LENGTH])
{
	// First, "double hash" the public key
	unsigned char round_1[SHA256_DIGEST_LENGTH];
	unsigned char round_2[RIPEMD160_DIGEST_LENGTH];

	sha256_Raw((uint8_t*) pubkey, PUBKEY_65_LENGTH, (uint8_t*) round_1);
	ripemd160((uint8_t*) round_1, SHA256_DIGEST_LENGTH, (uint8_t*) round_2);

	// Add the version specifier
	unsigned char raw_address_nocheck[RAW_ADDRESS_NOCHECK_LENGTH];
	raw_address_nocheck[0] = CASHADDR_P2PKH_BITS | CASHADDR_RIPEMD160_BITS;
	memcpy(raw_address_nocheck + 1, round_2, RIPEMD160_DIGEST_LENGTH);

	// Cashaddr  encode
	cash_addr_encode((char*) address, "bitcoincash", raw_address_nocheck, RAW_ADDRESS_NOCHECK_LENGTH);
}

void privkey_hex_from_raw(unsigned char* privkey_raw, unsigned char* privkey)
{
	privkey[0] = '0';
	privkey[1] = 'x';
	int c = 2;
	for (int i = 0; i < SHA256_DIGEST_LENGTH; i++)
	{
		byte_to_hex(privkey_raw[i], &privkey[c]);
		c += 2;
	}
}

void privkey_wif_from_raw(unsigned char* privkey_raw, unsigned char version_prefix, unsigned char* privkey)
{
	
	// Add the version specifierd
	unsigned char raw_privkey_nocheck[RAW_PRIVKEY_NOCHECK_LENGTH];
	raw_privkey_nocheck[0] = version_prefix;
	memcpy(raw_privkey_nocheck + 1, privkey_raw, SHA256_DIGEST_LENGTH);

	// Generate a checksum
	unsigned char check_round_1[SHA256_DIGEST_LENGTH];
	unsigned char check_round_2[SHA256_DIGEST_LENGTH];
	unsigned char checksum[CHECKSUM_LENGTH];

	sha256_Raw((uint8_t*) raw_privkey_nocheck, RAW_PRIVKEY_NOCHECK_LENGTH, check_round_1);
	sha256_Raw((uint8_t*) check_round_1, SHA256_DIGEST_LENGTH, check_round_2);
	memcpy(checksum, check_round_2, CHECKSUM_LENGTH);


	// Finalize the raw WIF format privkey
	// 1 byte for the version string - 0x80 for mainneti BTC/BCH
	// 32 bytes for the raw private key data
	// 4 bytes for the checksum
	unsigned char raw_privkey_check[RAW_PRIVKEY_CHECK_LENGTH];
	memcpy(raw_privkey_check, raw_privkey_nocheck, RAW_PRIVKEY_NOCHECK_LENGTH);
	memcpy(raw_privkey_check + RAW_PRIVKEY_NOCHECK_LENGTH, checksum, CHECKSUM_LENGTH);

	// Base58 encode
	b58enc((char*) privkey, &PRIVKEY_WIF_LENGTH, raw_privkey_check, RAW_PRIVKEY_CHECK_LENGTH);
}


// Define functions that implement the Python API

// The default API get_address_privkey returns a keypair for Bitcoin (BTC) and/or Bitcoin Cash (BCH)
// The bch flag can be set to use CashAddr format instead of the cross-compatible/legacy base58check format
void shared_modules_bitaddr_get_address_privkey(unsigned char* address, unsigned char* privkey, const char* entropy_privkey, const char* entropy_ecdsa, int bch)
{
	// Init the random32 for rand.h and ecdsa.h functions
	// The random function is only needed for curve_to_jacobian - needs a random k value
	// It will only be called once for address generation, so we'll use true entropy
	// To "seed" random32's PRNG without causing problems
	unsigned char seed_entropy[SHA256_DIGEST_LENGTH];
	sha256_Raw((uint8_t*) entropy_ecdsa, strlen(entropy_ecdsa), (uint8_t*) seed_entropy);
	init_random32(seed_entropy);

	// Generate the private key from some entropy
	// Then generate the public key from the private key
	unsigned char privkey_raw[SHA256_DIGEST_LENGTH];
	privkey_from_entropy(entropy_privkey, privkey_raw);

	unsigned char pubkey[PUBKEY_65_LENGTH];
	pubkey_from_privkey(privkey_raw, pubkey);

	// Generate the address from the public key
	// This address can use the legacy base58check encoding valid
	// in both BTC and BCH, or BCH cashaddr
	if (bch)
	{
		cash_address_from_pubkey(pubkey, address);
	}
	else
	{
		address_from_pubkey(pubkey, BTC_ADDR_PREFIX, address);
	}

	// Convert the private key to WIF format for export
	privkey_wif_from_raw(privkey_raw, BTC_WIF_PREFIX, privkey);
}

// This function generates a keypair for Litecoin, with the same steps as BTC. The only difference is the address version prefix and WIF privkey version prefix
// Although this code is copy-pasted from above and could be refactored, I want to have a one-to-one mapping from the Python API to the underlying module code here
void shared_modules_bitaddr_get_address_privkey_ltc(unsigned char* address, unsigned char* privkey, const char* entropy_privkey, const char* entropy_ecdsa)
{
	// Init the random32 for rand.h and ecdsa.h functions
	// The random function is only needed for curve_to_jacobian - needs a random k value
	// It will only be called once for address generation, so we'll use true entropy
	// To "seed" random32's PRNG without causing problems
	unsigned char seed_entropy[SHA256_DIGEST_LENGTH];
	sha256_Raw((uint8_t*) entropy_ecdsa, strlen(entropy_ecdsa), (uint8_t*) seed_entropy);
	init_random32(seed_entropy);

	// Generate the private key from some entropy
	// Then generate the public key from the private key
	unsigned char privkey_raw[SHA256_DIGEST_LENGTH];
	privkey_from_entropy(entropy_privkey, privkey_raw);

	unsigned char pubkey[PUBKEY_65_LENGTH];
	pubkey_from_privkey(privkey_raw, pubkey);

	address_from_pubkey(pubkey, LTC_ADDR_PREFIX, address);

	// Convert the private key to WIF format for export
	privkey_wif_from_raw(privkey_raw, LTC_WIF_PREFIX, privkey);
}


// This function generates a keypair for Digibyte, with the same steps as BTC. The only difference is the address version prefix and WIF privkey version prefix
void shared_modules_bitaddr_get_address_privkey_dgb(unsigned char* address, unsigned char* privkey, const char* entropy_privkey, const char* entropy_ecdsa)
{
	// Init the random32 for rand.h and ecdsa.h functions
	// The random function is only needed for curve_to_jacobian - needs a random k value
	// It will only be called once for address generation, so we'll use true entropy
	// To "seed" random32's PRNG without causing problems
	unsigned char seed_entropy[SHA256_DIGEST_LENGTH];
	sha256_Raw((uint8_t*) entropy_ecdsa, strlen(entropy_ecdsa), (uint8_t*) seed_entropy);
	init_random32(seed_entropy);

	// Generate the private key from some entropy
	// Then generate the public key from the private key
	unsigned char privkey_raw[SHA256_DIGEST_LENGTH];
	privkey_from_entropy(entropy_privkey, privkey_raw);

	unsigned char pubkey[PUBKEY_65_LENGTH];
	pubkey_from_privkey(privkey_raw, pubkey);

	address_from_pubkey(pubkey, DGB_ADDR_PREFIX, address);

	// Convert the private key to WIF format for export
	privkey_wif_from_raw(privkey_raw, DGB_WIF_PREFIX, privkey);
}

// This function generates a keypair for Ethereum
void shared_modules_bitaddr_get_address_privkey_eth(unsigned char* address, unsigned char* privkey, const char* entropy_privkey, const char* entropy_ecdsa)
{
	// Init the random32 for rand.h and ecdsa.h functions
	// The random function is only needed for curve_to_jacobian - needs a random k value
	// It will only be called once for address generation, so we'll use true entropy
	// To "seed" random32's PRNG without causing problems
	unsigned char seed_entropy[SHA256_DIGEST_LENGTH];
	sha256_Raw((uint8_t*) entropy_ecdsa, strlen(entropy_ecdsa), (uint8_t*) seed_entropy);
	init_random32(seed_entropy);

	// Generate the private key from some entropy
	// Then generate the public key from the private key
	unsigned char privkey_raw[SHA256_DIGEST_LENGTH];
	privkey_from_entropy(entropy_privkey, privkey_raw);

	unsigned char pubkey[PUBKEY_65_LENGTH];
	pubkey_from_privkey(privkey_raw, pubkey);

	eth_address_from_pubkey(pubkey, address);

	// Convert the private key to hex format for export
	privkey_hex_from_raw(privkey_raw, privkey);
}

