/* SPDX-License-Identifier: MIT */
/* mbedTLS 3.6 overlay for camtls (docs/PLAN-TLS.md §B): included after Debian's mbedtls_config.h
 * (MBEDTLS_USER_CONFIG_FILE), it switches off what an HTTPS front end for a browser never needs.
 * camtls narrows the rest at run time (versions 1.2/1.3, ECDHE-ECDSA suites with ChaCha20-Poly1305
 * first, groups X25519 + P-256, ECDSA-SHA256). scripts/build-camtls.sh refuses a name here that
 * isn't an option of the source's mbedtls_config.h, so a typo can't silently keep something on. */

/* no RSA or finite-field DH anywhere: our keys and every browser key share are ECC */
#undef MBEDTLS_RSA_C
#undef MBEDTLS_PKCS1_V15
#undef MBEDTLS_PKCS1_V21
#undef MBEDTLS_X509_RSASSA_PSS_SUPPORT
#undef MBEDTLS_GENPRIME
#undef MBEDTLS_DHM_C
#undef MBEDTLS_KEY_EXCHANGE_RSA_ENABLED
#undef MBEDTLS_KEY_EXCHANGE_DHE_RSA_ENABLED
#undef MBEDTLS_KEY_EXCHANGE_ECDHE_RSA_ENABLED
#undef MBEDTLS_KEY_EXCHANGE_ECDH_RSA_ENABLED
#undef MBEDTLS_KEY_EXCHANGE_ECDH_ECDSA_ENABLED
#undef MBEDTLS_KEY_EXCHANGE_RSA_PSK_ENABLED
#undef MBEDTLS_KEY_EXCHANGE_DHE_PSK_ENABLED
#undef MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED
#undef MBEDTLS_KEY_EXCHANGE_PSK_ENABLED
/* TLS 1.3: a resumed session still does ECDHE (psk_dhe_ke, what browsers use); never PSK alone */
#undef MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_PSK_ENABLED

/* no CBC suites (and nothing that only exists for them), no legacy ciphers */
#undef MBEDTLS_CIPHER_MODE_CBC
#undef MBEDTLS_SSL_ENCRYPT_THEN_MAC
#undef MBEDTLS_PKCS5_C
#undef MBEDTLS_PKCS12_C
#undef MBEDTLS_DES_C
#undef MBEDTLS_CAMELLIA_C
#undef MBEDTLS_ARIA_C
#undef MBEDTLS_CCM_C

/* curves: P-256 (our certificates, a browser key share) and X25519 (the other key share) */
#undef MBEDTLS_ECP_DP_SECP192R1_ENABLED
#undef MBEDTLS_ECP_DP_SECP224R1_ENABLED
#undef MBEDTLS_ECP_DP_SECP384R1_ENABLED
#undef MBEDTLS_ECP_DP_SECP521R1_ENABLED
#undef MBEDTLS_ECP_DP_SECP192K1_ENABLED
#undef MBEDTLS_ECP_DP_SECP224K1_ENABLED
#undef MBEDTLS_ECP_DP_SECP256K1_ENABLED
#undef MBEDTLS_ECP_DP_BP256R1_ENABLED
#undef MBEDTLS_ECP_DP_BP384R1_ENABLED
#undef MBEDTLS_ECP_DP_BP512R1_ENABLED
#undef MBEDTLS_ECP_DP_CURVE448_ENABLED

/* protocol features a one-request-per-connection HTTPS server doesn't use */
#undef MBEDTLS_SSL_PROTO_DTLS
#undef MBEDTLS_SSL_DTLS_ANTI_REPLAY
#undef MBEDTLS_SSL_DTLS_HELLO_VERIFY
#undef MBEDTLS_SSL_DTLS_CLIENT_PORT_REUSE
#undef MBEDTLS_SSL_COOKIE_C
#undef MBEDTLS_SSL_RENEGOTIATION
#undef MBEDTLS_SSL_ALPN
#undef MBEDTLS_SSL_SERVER_NAME_INDICATION
#undef MBEDTLS_SSL_MAX_FRAGMENT_LENGTH
#undef MBEDTLS_SSL_CONTEXT_SERIALIZATION
#undef MBEDTLS_SSL_CACHE_C
/* records out of camtls can be small (browsers accept any size); in, a browser may send 16 KiB */
#define MBEDTLS_SSL_OUT_CONTENT_LEN 4096

/* no PSA key storage on disk (keys are ours, in files camcfg writes), no threads, no sockets
 * layer (camtls does its own), no debug strings */
#undef MBEDTLS_PSA_CRYPTO_STORAGE_C
#undef MBEDTLS_PSA_ITS_FILE_C
#undef MBEDTLS_THREADING_C
#undef MBEDTLS_THREADING_PTHREAD
#undef MBEDTLS_NET_C
#undef MBEDTLS_DEBUG_C
