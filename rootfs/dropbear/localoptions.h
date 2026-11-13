/* SPDX-License-Identifier: MIT */
/* Dropbear build options for the camera (#76): server only, public keys only, no forwarding.
 * scripts/build-dropbear.sh copies this into the source tree and fails if any name below is
 * not in that version's default_options.h (so a typo can't silently drop a setting). */

/* auth: public keys only (incl. FIDO security keys); no passwords, no PAM */
#define DROPBEAR_SVR_PASSWORD_AUTH 0
#define DROPBEAR_SVR_PAM_AUTH 0
#define DROPBEAR_SVR_PUBKEY_AUTH 1
#define DROPBEAR_SVR_PUBKEY_OPTIONS 1
#define MAX_AUTH_TRIES 3
#define MAX_UNAUTH_PER_IP 3
#define MAX_UNAUTH_CLIENTS 6

/* no forwarding of any kind */
#define DROPBEAR_X11FWD 0
#define DROPBEAR_SVR_AGENTFWD 0
#define DROPBEAR_SVR_LOCALTCPFWD 0
#define DROPBEAR_SVR_REMOTETCPFWD 0

/* key types: ed25519 host key; clients may use ed25519, ecdsa, rsa (SHA-2 only), -sk keys */
#define DROPBEAR_ED25519 1
#define DROPBEAR_ECDSA 1
#define DROPBEAR_RSA 1
#define DROPBEAR_RSA_SHA1 0
#define DROPBEAR_DSS 0
#define DROPBEAR_SK_KEYS 1

/* key exchange, ciphers, MACs: no SHA-1, no CBC, no 3DES */
#define DROPBEAR_CURVE25519 1
/* post-quantum hybrids with x25519 (Gate 3): recorded sessions stay safe from a future quantum
 * computer; clients that know them (OpenSSH 9.0+/9.9+) pick them first */
#define DROPBEAR_MLKEM768 1
#define DROPBEAR_SNTRUP761 1
#define DROPBEAR_ECDH 1
#define DROPBEAR_DH_GROUP14_SHA256 1
#define DROPBEAR_DH_GROUP14_SHA1 0
#define DROPBEAR_DH_GROUP16 0
#define DROPBEAR_DH_GROUP1 0
#define DROPBEAR_AES128 1
#define DROPBEAR_AES256 1
#define DROPBEAR_3DES 0
#define DROPBEAR_CHACHA20POLY1305 1
#define DROPBEAR_ENABLE_CTR_MODE 1
#define DROPBEAR_ENABLE_CBC_MODE 0
#define DROPBEAR_ENABLE_GCM_MODE 1
#define DROPBEAR_SHA1_HMAC 0
#define DROPBEAR_SHA1_96_HMAC 0
#define DROPBEAR_SHA2_256_HMAC 1
#define DROPBEAR_SHA2_512_HMAC 1

/* misc */
#define DO_MOTD 0
#define DROPBEAR_SFTPSERVER 0
#define DROPBEAR_SMALL_CODE 1
#define DEFAULT_ROOT_PATH "/usr/sbin:/usr/bin:/sbin:/bin"
