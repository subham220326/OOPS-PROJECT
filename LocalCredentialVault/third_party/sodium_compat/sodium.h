#ifndef LOCAL_CREDENTIAL_VAULT_SODIUM_COMPAT_H
#define LOCAL_CREDENTIAL_VAULT_SODIUM_COMPAT_H

/*
 * Minimal libsodium 1.0.18 ABI-compatible header for environments where the
 * libsodium shared library (e.g., libsodium.so.23) is present without the
 * development header package. If a system-wide <sodium.h> is installed, CMake
 * uses the system header first.
 */

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Library initialization and secure memory cleanup */
int sodium_init(void);
void sodium_memzero(void * const pnt, const size_t len);

/* Cryptographically secure pseudorandom number generator */
void randombytes_buf(void * const buf, const size_t size);

/* Argon2id Password-Based Key Derivation (crypto_pwhash) */
#define crypto_pwhash_ALG_ARGON2ID13 2
#define crypto_pwhash_SALTBYTES 16U
#define crypto_pwhash_OPSLIMIT_INTERACTIVE 2ULL
#define crypto_pwhash_MEMLIMIT_INTERACTIVE 67108864ULL
#define crypto_pwhash_OPSLIMIT_MIN 1ULL
#define crypto_pwhash_MEMLIMIT_MIN 8192ULL

int crypto_pwhash(unsigned char * const out,
                  unsigned long long outlen,
                  const char * const passwd,
                  unsigned long long passwdlen,
                  const unsigned char * const salt,
                  unsigned long long opslimit,
                  size_t memlimit,
                  int alg);

/* XChaCha20-Poly1305 IETF Authenticated Encryption with Associated Data */
#define crypto_aead_xchacha20poly1305_ietf_KEYBYTES 32U
#define crypto_aead_xchacha20poly1305_ietf_NPUBBYTES 24U
#define crypto_aead_xchacha20poly1305_ietf_ABYTES 16U

int crypto_aead_xchacha20poly1305_ietf_encrypt(
    unsigned char *c,
    unsigned long long *clen_p,
    const unsigned char *m,
    unsigned long long mlen,
    const unsigned char *ad,
    unsigned long long adlen,
    const unsigned char *nsec,
    const unsigned char *npub,
    const unsigned char *k);

int crypto_aead_xchacha20poly1305_ietf_decrypt(
    unsigned char *m,
    unsigned long long *mlen_p,
    unsigned char *nsec,
    const unsigned char *c,
    unsigned long long clen,
    const unsigned char *ad,
    unsigned long long adlen,
    const unsigned char *npub,
    const unsigned char *k);

#ifdef __cplusplus
}
#endif

#endif /* LOCAL_CREDENTIAL_VAULT_SODIUM_COMPAT_H */
