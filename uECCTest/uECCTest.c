#include "stdafx.h"
#include "uECC.h"
#include <time.h>
#include <stdlib.h>
#include <string.h>
#include "sha256.h"

void PrintBytes(unsigned char *bytes, int len)
{
	for (int i = 0; i < len; i++)
	{
		if (i > 0) printf(":");
		printf("%02X", bytes[i]);
	}
	printf("\n");
}

static int RNG(uint8_t *dest, unsigned size) 
{
	while (size) 
	{
		uint8_t val = 0;
		for (unsigned i = 0; i < 8; ++i) 
		{
			int init = rand();
			int count = 0;
			while (rand() == init) 
				++count;
	
			if (count == 0) 
				val = (val << 1) | (init & 0x01);
			else 
				val = (val << 1) | (count & 0x01);
		}
		*dest = val;
		++dest;
		--size;
	}
	return 1;
}

void GenKeys(unsigned char *shared, int len)
{
	const struct uECC_Curve_t * curve = uECC_secp256r1();
	uint8_t private1[32] = { 0 };
	uint8_t private2[32] = { 0 };
	uint8_t public1[64] = { 0 };
	uint8_t public2[64] = { 0 };
	uint8_t secret1[32] = { 0 };
	uint8_t secret2[32] = { 0 };

	uECC_make_key(public1, private1, curve);
	puts("Public 1:");
	PrintBytes(public1, sizeof(public1));
	puts("Private 1:");
	PrintBytes(private1, sizeof(private1));
	
	uECC_make_key(public2, private2, curve);
	puts("Public 2:");
	PrintBytes(public2, sizeof(public2));
	puts("Private 2:");
	PrintBytes(private2, sizeof(private2));

	int r = uECC_shared_secret(public2, private1, secret1, curve);
	puts("Shared Secret from private1 and public2:");
	PrintBytes(secret1, sizeof(secret1));

	r = uECC_shared_secret(public1, private2, secret2, curve);
	puts("Shared Secret from private2 and public1:");
	PrintBytes(secret2, sizeof(secret2));
	int result = memcmp(secret1, secret2, sizeof(secret2));
	printf("Shared secrets should match. %s\n", !result? "They Do!" : "They Don't!");
	memcpy(shared, secret2, sizeof(secret2));
	
}

int main()
{
	const struct uECC_Curve_t * curve = uECC_secp160r1();
	uint8_t private1[32] = { 0 };
	uint8_t private2[32] = { 0 };
	uint8_t public1[64] = { 0 };
	uint8_t public2[64] = { 0 };
	uint8_t secret1[32] = { 0 };
	uint8_t secret2[32] = { 0 };
	uint8_t hash[SHA256_BYTES];

	srand(time(NULL));  // seed the RNG
	puts("Testing ecc\n");
	char sharedSecret[33+1] = { 0 };
	GenKeys(sharedSecret, 32);

	sha256(sharedSecret, sizeof(sharedSecret), hash);
	printf("input = '%s'\nresult: ", sharedSecret);
	puts("Hashed Shared Key\n");
	PrintBytes(hash, sizeof(hash));
    return 0;
}

