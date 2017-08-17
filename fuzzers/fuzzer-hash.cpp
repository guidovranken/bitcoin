#include "fuzzer.h"
#include "crypto/ripemd160.h"
#include "crypto/sha1.h"
#include "crypto/sha256.h"
#include "crypto/sha512.h"
#include <openssl/ripemd.h>
#include <openssl/sha.h>

/* Differential fuzzing of Bitcoin's own implementations of the following
 * hash functions:
 *  - RIPEMD160
 *  - SHA1
 *  - SHA256
 *  - SHA512
 *
 *  against OpenSSL's output for the same data
 */

void test_ripemd160(const uint8_t *data, size_t size)
{
    unsigned char hash_ripemd160_bc[160];
    unsigned char hash_ripemd160_openssl[160];

    memset(hash_ripemd160_bc, 0, sizeof(hash_ripemd160_bc));
    memset(hash_ripemd160_openssl, 0, sizeof(hash_ripemd160_openssl));

    CRIPEMD160().Write(data, size).Finalize(hash_ripemd160_bc);
    RIPEMD160(data, size, hash_ripemd160_openssl);

    if ( memcmp(hash_ripemd160_bc, hash_ripemd160_openssl, 160) ) {
        printf("ripemd160 mismatch\n"); fflush(stdout);
        abort();
    }
}

void test_sha1(const uint8_t *data, size_t size)
{
    unsigned char hash_sha1_bc[160];
    unsigned char hash_sha1_openssl[160];

    memset(hash_sha1_bc, 0, sizeof(hash_sha1_bc));
    memset(hash_sha1_openssl, 0, sizeof(hash_sha1_openssl));

    CSHA1().Write(data, size).Finalize(hash_sha1_bc);
    SHA1(data, size, hash_sha1_openssl);

    if ( memcmp(hash_sha1_bc, hash_sha1_openssl, 160) ) {
        printf("sha1 mismatch\n"); fflush(stdout);
        abort();
    }
}

void test_sha256(const uint8_t *data, size_t size)
{
    unsigned char hash_sha256_bc[160];
    unsigned char hash_sha256_openssl[160];

    memset(hash_sha256_bc, 0, sizeof(hash_sha256_bc));
    memset(hash_sha256_openssl, 0, sizeof(hash_sha256_openssl));

    CSHA256().Write(data, size).Finalize(hash_sha256_bc);
    SHA256(data, size, hash_sha256_openssl);

    if ( memcmp(hash_sha256_bc, hash_sha256_openssl, 160) ) {
        printf("sha256 mismatch\n"); fflush(stdout);
        abort();
    }
}

void test_sha512(const uint8_t *data, size_t size)
{
    unsigned char hash_sha512_bc[160];
    unsigned char hash_sha512_openssl[160];

    memset(hash_sha512_bc, 0, sizeof(hash_sha512_bc));
    memset(hash_sha512_openssl, 0, sizeof(hash_sha512_openssl));

    CSHA512().Write(data, size).Finalize(hash_sha512_bc);
    SHA512(data, size, hash_sha512_openssl);

    if ( memcmp(hash_sha512_bc, hash_sha512_openssl, 160) ) {
        printf("sha512 mismatch\n"); fflush(stdout);
        abort();
    }
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    test_ripemd160(data, size);
    test_sha1(data, size);
    test_sha256(data, size);
    test_sha512(data, size);
    return 0;
}
