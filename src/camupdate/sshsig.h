/* SPDX-License-Identifier: MIT */
/*
 * sshsig.h: OpenSSH signature (SSHSIG, `ssh-keygen -Y sign`) verification, shared by camupdate
 * (firmware packages, namespace "cam-firmware") and camcfg's signed recovery (namespace
 * "cam-recover", docs/PLAN-DATA-LOCK.md Part 3). Keys: ssh-ed25519, and sk-ssh-ed25519@openssh.com
 * with the user-presence and user-verified (PIN) flags. Trusted keys are OpenSSH public key lines
 * (the image's /etc/cam/update-keys). Needs libsodium (sodium.h) and the C library only; every
 * name here starts with ss_ or sshsig_.
 */
#ifndef SSHSIG_H
#define SSHSIG_H
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sodium.h>

/* ---- base64 and SSH wire strings ------------------------------------------------------ */

static int ss_b64(const char *in, size_t n, uint8_t *out, size_t cap)
{
	uint32_t acc = 0;
	int bits = 0;
	size_t o = 0, pad = 0;
	for (size_t i = 0; i < n; i++) {
		char c = in[i];
		int v;
		if (c >= 'A' && c <= 'Z') v = c - 'A';
		else if (c >= 'a' && c <= 'z') v = c - 'a' + 26;
		else if (c >= '0' && c <= '9') v = c - '0' + 52;
		else if (c == '+') v = 62;
		else if (c == '/') v = 63;
		else if (c == '=') { pad++; continue; }
		else if (c == '\n' || c == '\r') continue;
		else return -1;
		if (pad) return -1;                                      /* data after padding */
		acc = acc << 6 | (uint32_t)v;
		bits += 6;
		if (bits >= 8) {
			bits -= 8;
			if (o >= cap) return -1;
			out[o++] = (uint8_t)(acc >> bits);
		}
	}
	return pad > 2 ? -1 : (int)o;
}

struct ss_rd { const uint8_t *p; size_t n; };

static int ss_u32(struct ss_rd *r, uint32_t *v)
{
	if (r->n < 4) return -1;
	*v = (uint32_t)r->p[0] << 24 | (uint32_t)r->p[1] << 16 | (uint32_t)r->p[2] << 8 | r->p[3];
	r->p += 4; r->n -= 4;
	return 0;
}

static int ss_str(struct ss_rd *r, struct ss_rd *s)
{
	uint32_t l;
	if (ss_u32(r, &l) || l > r->n) return -1;
	s->p = r->p; s->n = l;
	r->p += l; r->n -= l;
	return 0;
}

static int ss_is(const struct ss_rd *s, const char *lit)
{
	return s->n == strlen(lit) && !memcmp(s->p, lit, s->n);
}

/* Append an SSH string to out[cap] at *o; -1 (nothing written) if it doesn't fit. */
static int ss_put(uint8_t *out, size_t cap, size_t *o, const void *d, size_t n)
{
	if (*o > cap || cap - *o < 4 || cap - *o - 4 < n) return -1;
	out[(*o)++] = (uint8_t)(n >> 24); out[(*o)++] = (uint8_t)(n >> 16);
	out[(*o)++] = (uint8_t)(n >> 8); out[(*o)++] = (uint8_t)n;
	memcpy(out + *o, d, n);
	*o += n;
	return 0;
}

/* ---- trusted keys and sshsig ---------------------------------------------------------- */

/* Is the public-key blob `pk` one of the trusted keys (OpenSSH public key lines in keys_path)? */
static int ss_key_trusted(const char *keys_path, const struct ss_rd *pk, char *comment, size_t ccap)
{
	FILE *f = fopen(keys_path, "r");
	char line[1024];
	uint8_t blob[512];
	int ok = 0;
	if (!f) return 0;
	while (!ok && fgets(line, sizeof line, f)) {
		char *t = strtok(line, " \t\r\n"), *b = t ? strtok(NULL, " \t\r\n") : NULL, *c;
		if (!t || *t == '#' || !b) continue;
		int n = ss_b64(b, strlen(b), blob, sizeof blob);
		if (n > 0 && (size_t)n == pk->n && !memcmp(blob, pk->p, pk->n)) {
			ok = 1;
			c = strtok(NULL, "\r\n");
			snprintf(comment, ccap, "%s", c ? c : t);
		}
	}
	fclose(f);
	return ok;
}

/* Verify an armored SSH signature over msg (namespace ns, sha512) by a key in keys_path. 0 if
 * good, with the key's comment in signer; else -1 and *why. */
static int sshsig_verify(const char *armor, size_t alen, const uint8_t *msg, size_t mlen, const char *ns_want,
			 const char *keys_path, char *signer, size_t scap, const char **why)
{
	static const char beg[] = "-----BEGIN SSH SIGNATURE-----", end[] = "-----END SSH SIGNATURE-----";
	const char *b = memmem(armor, alen, beg, sizeof beg - 1), *e;
	if (!b) { *why = "no signature block"; return -1; }
	b += sizeof beg - 1;
	e = memmem(b, alen - (size_t)(b - armor), end, sizeof end - 1);
	if (!e) { *why = "unterminated signature block"; return -1; }
	static uint8_t blob[4096];
	int bn = ss_b64(b, (size_t)(e - b), blob, sizeof blob);
	if (bn < 6 || memcmp(blob, "SSHSIG", 6)) { *why = "not an SSHSIG"; return -1; }
	struct ss_rd r = { blob + 6, (size_t)bn - 6 }, pk, ns, res, halg, sig, sigtype, sigbytes;
	uint32_t ver;
	if (ss_u32(&r, &ver) || ver != 1 || ss_str(&r, &pk) || ss_str(&r, &ns) || ss_str(&r, &res) ||
	    ss_str(&r, &halg) || ss_str(&r, &sig) || r.n) {
		*why = "malformed SSHSIG";
		return -1;
	}
	if (!ss_is(&ns, ns_want)) { *why = "wrong signature namespace"; return -1; }
	if (!ss_is(&halg, "sha512")) { *why = "hash must be sha512"; return -1; }
	/* OpenSSH always writes an empty reserved field; anything in it is not ours (and it went
	 * unbounded into sd[] below before, Gate 3 review) */
	if (res.n) { *why = "SSHSIG reserved field is not empty"; return -1; }
	if (!ss_key_trusted(keys_path, &pk, signer, scap)) { *why = "signed by an untrusted key"; return -1; }

	/* the signed blob: "SSHSIG" ns reserved hash_alg H(message); every field bounded by sd[] */
	uint8_t h[64], sd[256];
	size_t o = 6;
	crypto_hash_sha512(h, msg, mlen);
	memcpy(sd, "SSHSIG", 6);
	if (ss_put(sd, sizeof sd, &o, ns.p, ns.n) || ss_put(sd, sizeof sd, &o, res.p, res.n) ||
	    ss_put(sd, sizeof sd, &o, halg.p, halg.n) || ss_put(sd, sizeof sd, &o, h, sizeof h)) {
		*why = "signed data too long";
		return -1;
	}

	struct ss_rd kr = pk, ktype, kpub, app, sr = sig;
	if (ss_str(&kr, &ktype) || ss_str(&kr, &kpub) || kpub.n != 32) {
		*why = "malformed public key";
		return -1;
	}
	if (ss_str(&sr, &sigtype) || sigtype.n != ktype.n || memcmp(sigtype.p, ktype.p, ktype.n) ||
	    ss_str(&sr, &sigbytes) || sigbytes.n != 64) {
		*why = "malformed signature";
		return -1;
	}
	if (ss_is(&ktype, "ssh-ed25519")) {
		if (kr.n || sr.n) { *why = "trailing data in key or signature"; return -1; }
		if (crypto_sign_ed25519_verify_detached(sigbytes.p, sd, o, kpub.p)) { *why = "bad signature"; return -1; }
		return 0;
	}
	if (ss_is(&ktype, "sk-ssh-ed25519@openssh.com")) {
		/* key: type pub application; signature: type sig flags(1) counter(4); the authenticator
		 * signed SHA256(application) || flags || counter || SHA256(signed blob) */
		if (ss_str(&kr, &app) || kr.n || sr.n != 5) { *why = "malformed sk key/signature"; return -1; }
		uint8_t flags = sr.p[0], m[69];
		if (!(flags & 0x01)) { *why = "sk signature without user presence"; return -1; }
		/* the owner's keys are verify-required (PIN): insist on it, so a stolen YubiKey alone
		 * can't sign (owner, 2026-10-23) */
		if (!(flags & 0x04)) { *why = "sk signature without user verification (PIN)"; return -1; }
		crypto_hash_sha256(m, app.p, app.n);
		m[32] = flags;
		memcpy(m + 33, sr.p + 1, 4);
		crypto_hash_sha256(m + 37, sd, o);
		if (crypto_sign_ed25519_verify_detached(sigbytes.p, m, sizeof m, kpub.p)) { *why = "bad signature"; return -1; }
		return 0;
	}
	*why = "unsupported key type (ssh-ed25519 or sk-ssh-ed25519 only)";
	return -1;
}

#endif
