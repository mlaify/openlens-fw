/* SPDX-License-Identifier: MIT */
/*
 * camupdate: install an owner-signed rootfs into mtd2 (#104; design in docs/UPDATE-PATH.md).
 *
 *   camupdate [--check] [FILE|-]        read a .camfw package (stdin by default)
 *
 * Package: header text (key=value lines, ending with an empty line), the OpenSSH signature of
 * exactly those header bytes (armored "SSH SIGNATURE", namespace "cam-firmware", made with
 * `ssh-keygen -Y sign`), then the payload (`size` bytes, a squashfs). Checks, all before anything is
 * written: header keys and values, the signature against /etc/cam/update-keys (ssh-ed25519 or
 * sk-ssh-ed25519@openssh.com; sk signatures need the user-presence and user-verified flags), device (/etc/cam/device),
 * part, payload SHA-256 and squashfs magic, size within mtd "rootfs", and the version: newer than
 * /etc/cam/version unless the signed header has allow-downgrade=1 (a missing or malformed
 * /etc/cam/version is refused the same way: no downgrade rule, no install). --check stops there.
 * Bench images (#128): build-rootfs.sh --bench embeds the builder's credentials and appends a
 * trailer ("... BENCH IMAGE ...") after the squashfs. The payload must end at the squashfs's
 * bytes_used (superblock, u64 LE at 40) rounded up to 4 KiB, as mksquashfs pads it, so a bench
 * image (or anything else after the filesystem) is refused, even one packaged by an older
 * make-update.sh. Looking inside the xz-compressed squashfs for /etc/cam/bench would need an xz
 * and squashfs reader here; the trailer check needs neither.
 *
 * Install: the running rootfs IS mtd2, so before erasing it camupdate re-executes from a tmpfs copy
 * (a fresh 0700 directory under /tmp), stops every other process except init and its own ancestors
 * (SIGSTOP: nothing exits, so init respawns nothing from the flash being rewritten), takes over the
 * watchdog from BusyBox's feeder, erases and writes mtd2 in 64 KiB steps while feeding it, reads
 * back and compares, then syncs and reboots. If the watchdog can't be taken, everything is resumed,
 * the feeder restarted, and nothing is written. Once the erase has begun camupdate never just exits:
 * a failed erase, write or read-back is retried from the in-RAM payload (3 passes), and if all fail
 * it syncs and reboots. A power cut during it, or 3 failed passes, needs the CH341A (Gate 1) or
 * U-Boot TFTP.
 */
#define _GNU_SOURCE
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/reboot.h>
#include <sys/stat.h>
#include <unistd.h>
#ifdef __linux__
#include <linux/watchdog.h>
#include <mtd/mtd-user.h>
#endif
#ifdef __APPLE__
#include <mach-o/dyld.h>            /* host test: _NSGetExecutablePath, macOS has no /proc */
#endif

#include <sodium.h>                 /* Ubuntu libsodium-dev:armhf (static); Homebrew on the Mac */

#define PKG_MAX (14u << 20)             /* > mtd2 (0xCB0000) + header + signature */
#define SQ_SUPER 96                     /* squashfs 4.0 superblock */
#define SQ_PAD 4096                     /* mksquashfs pads the image to this */
#define BENCH_MARK "BENCH IMAGE"        /* in build-rootfs.sh --bench's trailer */
#define HDR_MAX 2048
#define NAMESPACE "cam-firmware"

static const char *keys_path = "/etc/cam/update-keys", *device_path = "/etc/cam/device",
		  *version_path = "/etc/cam/version";

#define LOG(...) fprintf(stderr, __VA_ARGS__)

/* ---- SHA-256 (FIPS 180-4) ------------------------------------------------------------- */

struct sha256 { uint32_t h[8]; uint64_t len; uint8_t buf[64]; };

static const uint32_t K256[64] = {
	0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
	0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
	0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
	0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
	0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
	0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
	0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
	0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
};

#define ROR(x, n) ((x) >> (n) | (x) << (32 - (n)))

static void sha256_block(struct sha256 *s, const uint8_t *p)
{
	uint32_t w[64], a, b, c, d, e, f, g, h;
	for (int i = 0; i < 16; i++)
		w[i] = (uint32_t)p[4 * i] << 24 | (uint32_t)p[4 * i + 1] << 16 | (uint32_t)p[4 * i + 2] << 8 | p[4 * i + 3];
	for (int i = 16; i < 64; i++) {
		uint32_t s0 = ROR(w[i - 15], 7) ^ ROR(w[i - 15], 18) ^ (w[i - 15] >> 3);
		uint32_t s1 = ROR(w[i - 2], 17) ^ ROR(w[i - 2], 19) ^ (w[i - 2] >> 10);
		w[i] = w[i - 16] + s0 + w[i - 7] + s1;
	}
	a = s->h[0]; b = s->h[1]; c = s->h[2]; d = s->h[3]; e = s->h[4]; f = s->h[5]; g = s->h[6]; h = s->h[7];
	for (int i = 0; i < 64; i++) {
		uint32_t t1 = h + (ROR(e, 6) ^ ROR(e, 11) ^ ROR(e, 25)) + ((e & f) ^ (~e & g)) + K256[i] + w[i];
		uint32_t t2 = (ROR(a, 2) ^ ROR(a, 13) ^ ROR(a, 22)) + ((a & b) ^ (a & c) ^ (b & c));
		h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
	}
	s->h[0] += a; s->h[1] += b; s->h[2] += c; s->h[3] += d;
	s->h[4] += e; s->h[5] += f; s->h[6] += g; s->h[7] += h;
}

static void sha256_init(struct sha256 *s)
{
	static const uint32_t iv[8] = { 0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
					0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19 };
	memcpy(s->h, iv, sizeof iv);
	s->len = 0;
}

static void sha256_update(struct sha256 *s, const void *data, size_t n)
{
	const uint8_t *p = data;
	size_t have = (size_t)(s->len & 63);
	s->len += n;
	while (n) {
		size_t k = 64 - have < n ? 64 - have : n;
		memcpy(s->buf + have, p, k);
		have += k; p += k; n -= k;
		if (have == 64) { sha256_block(s, s->buf); have = 0; }
	}
}

static void sha256_final(struct sha256 *s, uint8_t out[32])
{
	uint64_t bits = s->len * 8;
	uint8_t pad = 0x80, z = 0, l[8];
	sha256_update(s, &pad, 1);
	while ((s->len & 63) != 56) sha256_update(s, &z, 1);
	for (int i = 0; i < 8; i++) l[i] = (uint8_t)(bits >> (56 - 8 * i));
	sha256_update(s, l, 8);
	for (int i = 0; i < 32; i++) out[i] = (uint8_t)(s->h[i / 4] >> (24 - 8 * (i % 4)));
}

static void sha256(const void *d, size_t n, uint8_t out[32])
{
	struct sha256 s;
	sha256_init(&s);
	sha256_update(&s, d, n);
	sha256_final(&s, out);
}

#include "sshsig.h"                 /* the verifier, shared with camcfg (#176) */

/* ---- header ---------------------------------------------------------------------------- */

struct hdr {
	char device[64], part[16], version[32], sha[65];
	unsigned long size;
	int downgrade;
};

static int valid_version(const char *v)
{
	/* YYYYMMDD.N */
	size_t n = strlen(v), d = strspn(v, "0123456789");
	return d == 8 && n > 9 && n <= 16 && v[8] == '.' && strspn(v + 9, "0123456789") == n - 9;
}

/* Parse header lines [h, h+len) (the empty line excluded). 0 or -1 with *why. */
static int hdr_parse(const char *h, size_t len, struct hdr *o, const char **why)
{
	char line[256];
	int seen = 0;
	memset(o, 0, sizeof *o);
	o->downgrade = -1;
	for (size_t i = 0; i < len;) {
		size_t e = i;
		while (e < len && h[e] != '\n') e++;
		if (e - i >= sizeof line) { *why = "header line too long"; return -1; }
		memcpy(line, h + i, e - i);
		line[e - i] = 0;
		i = e + 1;
		char *eq = strchr(line, '=');
		if (!eq) { *why = "header line without '='"; return -1; }
		*eq++ = 0;
		for (char *p = eq; *p; p++)
			if (!isgraph((unsigned char)*p)) { *why = "bad character in header value"; return -1; }
		int bit;
		if (!strcmp(line, "magic")) { if (strcmp(eq, "camfw1")) { *why = "not a camfw1 package"; return -1; } bit = 1; }
		else if (!strcmp(line, "device")) { if (strlen(eq) >= sizeof o->device) goto bad; strcpy(o->device, eq); bit = 2; }
		else if (!strcmp(line, "part")) { if (strlen(eq) >= sizeof o->part) goto bad; strcpy(o->part, eq); bit = 4; }
		else if (!strcmp(line, "version")) { if (!valid_version(eq)) goto bad; strcpy(o->version, eq); bit = 8; }
		else if (!strcmp(line, "size")) {
			if (strspn(eq, "0123456789") != strlen(eq) || strlen(eq) > 9) goto bad;
			o->size = strtoul(eq, NULL, 10);
			bit = 16;
		} else if (!strcmp(line, "sha256")) {
			if (strlen(eq) != 64 || strspn(eq, "0123456789abcdef") != 64) goto bad;
			strcpy(o->sha, eq);
			bit = 32;
		} else if (!strcmp(line, "allow-downgrade")) {
			if (strcmp(eq, "0") && strcmp(eq, "1")) goto bad;
			o->downgrade = eq[0] == '1';
			bit = 64;
		} else { *why = "unknown header key"; return -1; }
		if (seen & bit) { *why = "duplicate header key"; return -1; }
		seen |= bit;
	}
	if (seen != 127) { *why = "header incomplete"; return -1; }
	return 0;
bad:
	*why = "bad header value";
	return -1;
}

/* versions YYYYMMDD.N: <0, 0, >0 */
static int vcmp(const char *a, const char *b)
{
	unsigned long ad = strtoul(a, NULL, 10), bd = strtoul(b, NULL, 10);
	if (ad != bd) return ad < bd ? -1 : 1;
	unsigned long an = strtoul(strchr(a, '.') + 1, NULL, 10), bn = strtoul(strchr(b, '.') + 1, NULL, 10);
	return an < bn ? -1 : an > bn;
}

static int read_line_file(const char *path, char *out, size_t cap)
{
	FILE *f = fopen(path, "r");
	if (!f) return -1;
	int ok = fgets(out, (int)cap, f) != NULL;
	fclose(f);
	if (!ok) return -1;
	out[strcspn(out, "\r\n")] = 0;
	return 0;
}

/* ---- the package ----------------------------------------------------------------------- */

struct pkg {
	uint8_t *buf;
	size_t len, hlen;                  /* header bytes incl. the empty line */
	const uint8_t *payload;
	struct hdr h;
	char signer[128];
};

/* Everything but the mtd size check. 0 or -1 with *why. */
static int pkg_check(struct pkg *p, const char **why)
{
	const uint8_t *eh = memmem(p->buf, p->len < HDR_MAX ? p->len : HDR_MAX, "\n\n", 2);
	if (!eh) { *why = "no header"; return -1; }
	p->hlen = (size_t)(eh - p->buf) + 2;
	if (hdr_parse((const char *)p->buf, p->hlen - 2, &p->h, why)) return -1;
	static const char endm[] = "-----END SSH SIGNATURE-----";
	const uint8_t *se = memmem(p->buf + p->hlen, p->len - p->hlen, endm, sizeof endm - 1);
	if (!se) { *why = "no signature"; return -1; }
	se += sizeof endm - 1;
	if (se < p->buf + p->len && *se == '\n') se++;
	if (sshsig_verify((const char *)p->buf + p->hlen, (size_t)(se - (p->buf + p->hlen)), p->buf,
			  p->hlen, NAMESPACE, keys_path, p->signer, sizeof p->signer, why))
		return -1;
	/* from here on the header is the owner's */
	p->payload = se;
	if ((size_t)(p->buf + p->len - se) != p->h.size) { *why = "payload size differs from the header"; return -1; }
	uint8_t d[32];
	char hex[65];
	sha256(p->payload, p->h.size, d);
	for (int i = 0; i < 32; i++) snprintf(hex + 2 * i, 3, "%02x", d[i]);
	if (strcmp(hex, p->h.sha)) { *why = "payload SHA-256 differs from the header"; return -1; }
	if (strcmp(p->h.part, "rootfs")) { *why = "only part=rootfs is supported"; return -1; }
	if (p->h.size < SQ_SUPER || memcmp(p->payload, "hsqs", 4)) { *why = "payload is not a squashfs"; return -1; }
	uint64_t used = 0;
	for (int i = 7; i >= 0; i--) used = used << 8 | p->payload[40 + i];
	if (used < SQ_SUPER || used > p->h.size) { *why = "squashfs bytes_used is out of range"; return -1; }
	uint64_t pad = (used + SQ_PAD - 1) / SQ_PAD * SQ_PAD;
	if (p->h.size > pad) {
		*why = memmem(p->payload + pad, p->h.size - pad, BENCH_MARK, sizeof BENCH_MARK - 1) ?
		       "a bench image (it carries the builder's credentials, #128): never installed" :
		       "payload has data after the squashfs";
		return -1;
	}
	char dev[64], ver[32];
	if (read_line_file(device_path, dev, sizeof dev) || strcmp(dev, p->h.device)) {
		*why = "package is for another device";
		return -1;
	}
	/* without a readable installed version there is nothing to compare: refuse (it was skipped
	 * before, Gate 3 review); allow-downgrade=1 still means "any version" */
	if (!p->h.downgrade) {
		if (read_line_file(version_path, ver, sizeof ver) || !valid_version(ver)) {
			*why = "installed version unknown (/etc/cam/version missing or not YYYYMMDD.N; no allow-downgrade)";
			return -1;
		}
		if (vcmp(p->h.version, ver) <= 0) {
			*why = "not newer than the installed version (no allow-downgrade)";
			return -1;
		}
	}
	return 0;
}

static int read_all(int fd, struct pkg *p)
{
	p->buf = malloc(PKG_MAX);
	if (!p->buf) return -1;
	p->len = 0;
	for (;;) {
		ssize_t n = read(fd, p->buf + p->len, PKG_MAX - p->len);
		if (n < 0) { if (errno == EINTR) continue; return -1; }
		if (n == 0) return 0;
		p->len += (size_t)n;
		if (p->len == PKG_MAX) return -1;                       /* too big */
	}
}

#ifndef CAMUPDATE_NO_MAIN
#if defined(__linux__) || defined(CAMUPDATE_TEST)
/* ---- installing ------------------------------------------------------------------------ */

/* A CAMUPDATE_TEST build never touches a real mtd, watchdog or process, and never reboots: the
 * flash is a regular file (CU_MTD), the watchdog one too (CU_WATCHDOG, each feed appends a byte),
 * /proc is a directory the test fills (CU_PROC) and /tmp is CU_TMP; main won't install without
 * all four. CU_FAIL_ERASE=N and CU_FAIL_VERIFY=N make the first N passes fail. */
static const char *proc_root = "/proc", *wdt_path = "/dev/watchdog", *tmp_base = "/tmp";
#ifdef CAMUPDATE_TEST
static int test_pass, test_fail_erase, test_fail_verify;
#endif

#define PASSES 3                        /* erase + write + read-back attempts from the RAM payload */

struct flash { int fd; size_t size, erasesize; char dev[32]; };

#ifndef CAMUPDATE_TEST
static int find_rootfs_mtd(char *dev, size_t cap)
{
	FILE *f = fopen("/proc/mtd", "r");
	char line[128];
	int found = -1;
	if (!f) return -1;
	while (found < 0 && fgets(line, sizeof line, f)) {
		int n;
		if (sscanf(line, "mtd%d:", &n) == 1 && strstr(line, "\"rootfs\"")) {
			snprintf(dev, cap, "/dev/mtd%d", n);
			found = n;
		}
	}
	fclose(f);
	return found;
}
#endif

/* Open mtd "rootfs": 0, -1 with errno, or -2 if there is none. */
static int flash_open(struct flash *f)
{
#ifdef CAMUPDATE_TEST
	struct stat st;
	snprintf(f->dev, sizeof f->dev, "CU_MTD");
	if ((f->fd = open(getenv("CU_MTD"), O_RDWR | O_CLOEXEC)) < 0 || fstat(f->fd, &st)) return -1;
	f->size = (size_t)st.st_size;
	f->erasesize = 65536;
	return 0;
#else
	struct mtd_info_user mi;
	if (find_rootfs_mtd(f->dev, sizeof f->dev) < 0) return -2;
	if ((f->fd = open(f->dev, O_RDWR | O_SYNC | O_CLOEXEC)) < 0 || ioctl(f->fd, MEMGETINFO, &mi)) return -1;
	f->size = mi.size;
	f->erasesize = mi.erasesize;
	return 0;
#endif
}

static int flash_erase(struct flash *f, size_t off)
{
#ifdef CAMUPDATE_TEST
	static uint8_t ff[65536];
	memset(ff, 0xff, sizeof ff);
	if (test_pass <= test_fail_erase && off == f->erasesize) { errno = EIO; return -1; }
	return pwrite(f->fd, ff, f->erasesize, (off_t)off) == (ssize_t)f->erasesize ? 0 : -1;
#else
	struct erase_info_user ei = { (uint32_t)off, (uint32_t)f->erasesize };
	return ioctl(f->fd, MEMERASE, &ei);
#endif
}

static int flash_write(struct flash *f, const uint8_t *d, size_t n, size_t off)
{
#ifdef CAMUPDATE_TEST
	if (test_pass <= test_fail_verify && off == 0) {         /* a bit that didn't program */
		uint8_t b = d[0] ^ 1;
		return pwrite(f->fd, &b, 1, 0) == 1 && pwrite(f->fd, d + 1, n - 1, 1) == (ssize_t)(n - 1) ? 0 : -1;
	}
#endif
	return pwrite(f->fd, d, n, (off_t)off) == (ssize_t)n ? 0 : -1;
}

static int wdt = -1;
static void wdt_feed(void)
{
#ifdef CAMUPDATE_TEST
	if (wdt >= 0 && write(wdt, "k", 1) != 1) LOG("camupdate: (test build) feed failed\n");
#else
	if (wdt >= 0) ioctl(wdt, WDIOC_KEEPALIVE, 0);
#endif
}

/* Sync and reboot; never returns. If the reboot fails, nobody feeds the watchdog any more. */
static void reboot_now(struct flash *f)
{
#ifdef CAMUPDATE_TEST
	fsync(f->fd);                       /* not sync(): the whole host's, it can block for minutes */
	close(f->fd);
	LOG("camupdate: (test build) reboot\n");
	exit(3);
#else
	close(f->fd);
	sync();
	reboot(RB_AUTOBOOT);
	LOG("camupdate: reboot: %s; the watchdog resets the camera\n", strerror(errno));
	for (;;) pause();
#endif
}

static int is_ancestor(pid_t pid)
{
	for (pid_t p = getppid(); p > 1;) {
		if (p == pid) return 1;
		char path[PATH_MAX], buf[512];
		snprintf(path, sizeof path, "%s/%d/stat", proc_root, (int)p);
		FILE *f = fopen(path, "r");
		if (!f) return 0;
		int ok = fgets(buf, sizeof buf, f) != NULL;
		fclose(f);
		char *rp = ok ? strrchr(buf, ')') : NULL;
		int pp;
		if (!rp || sscanf(rp + 2, "%*c %d", &pp) != 1) return 0;
		p = (pid_t)pp;
	}
	return 0;
}

/* BusyBox's watchdog feeder as signal_others found it (its executable and NUL-separated argv).
 * rcS starts it once (`watchdog -T 30 -t 5 /dev/watchdog`; inittab has no entry for it), so init
 * never respawns it: if we can't take the device after killing it, we start it again ourselves. */
static char feeder_exe[PATH_MAX], feeder_args[256];
static size_t feeder_n;

/* SIGSTOP: stop every user process except init, us and our ancestors, and kill the watchdog
 * feeder instead (/dev/watchdog is single-open: we take it over). SIGCONT: resume the same set. */
static void signal_others(int sig)
{
	DIR *d = opendir(proc_root);
	struct dirent *e;
	pid_t me = getpid();
	if (!d) return;
	while ((e = readdir(d))) {
		pid_t pid = (pid_t)atoi(e->d_name);
		if (pid <= 1 || pid == me || is_ancestor(pid)) continue;
		char path[PATH_MAX], args[256];
		snprintf(path, sizeof path, "%s/%d/cmdline", proc_root, (int)pid);
		FILE *f = fopen(path, "r");
		if (!f) continue;
		size_t n = fread(args, 1, sizeof args - 1, f);
		fclose(f);
		if (!n) continue;                                        /* kernel thread */
		args[n] = 0;
		if (sig != SIGSTOP || !strstr(args, "watchdog")) { kill(pid, sig); continue; }
		if (!feeder_exe[0]) {
			snprintf(path, sizeof path, "%s/%d/exe", proc_root, (int)pid);
			ssize_t l = readlink(path, feeder_exe, sizeof feeder_exe - 1);
			feeder_exe[l > 0 ? l : 0] = 0;
			memcpy(feeder_args, args, n + 1);
			feeder_n = n;
		}
		kill(pid, SIGKILL);
	}
	closedir(d);
}

static void restart_feeder(void)
{
	char *av[16];
	int ac = 0;
	if (!feeder_exe[0]) { LOG("camupdate: no watchdog feeder was running; none restarted\n"); return; }
	for (size_t i = 0; i < feeder_n && ac < 15; i += strlen(feeder_args + i) + 1) av[ac++] = feeder_args + i;
	av[ac] = NULL;
	pid_t pid = fork();
	if (pid == 0) {
		setsid();
		execv(feeder_exe, av);
		_exit(127);
	}
	if (pid < 0) LOG("camupdate: can't restart the watchdog feeder (%s): the watchdog will reset the camera\n",
			 strerror(errno));
	else LOG("camupdate: watchdog feeder restarted (%s %s)\n", feeder_exe, av[0]);
}

/* Erase, write and read back mtd2 from the in-RAM payload, feeding the watchdog. 0: it is the image. */
static int flash_pass(struct flash *f, const struct pkg *p)
{
	static uint8_t chk[65536];
	size_t span = ((p->h.size + f->erasesize - 1) / f->erasesize) * f->erasesize;
	for (size_t off = 0; off < span; off += f->erasesize) {
		if (flash_erase(f, off)) { LOG("camupdate: erase at %#zx: %s\n", off, strerror(errno)); return -1; }
		wdt_feed();
		if (off % 0x40000 == 0) LOG("camupdate: erased %zu%%\n", off * 100 / span);
	}
	for (size_t off = 0; off < p->h.size; off += sizeof chk) {
		size_t n = p->h.size - off < sizeof chk ? p->h.size - off : sizeof chk;
		if (flash_write(f, p->payload + off, n, off)) {
			LOG("camupdate: write at %#zx: %s\n", off, strerror(errno));
			return -1;
		}
		wdt_feed();
	}
	for (size_t off = 0; off < p->h.size; off += sizeof chk) {
		size_t n = p->h.size - off < sizeof chk ? p->h.size - off : sizeof chk;
		if (pread(f->fd, chk, n, (off_t)off) != (ssize_t)n || memcmp(chk, p->payload + off, n)) {
			LOG("camupdate: read-back differs at %#zx\n", off);
			return -1;
		}
		wdt_feed();
	}
	return 0;
}

static int install(struct pkg *p)
{
	struct flash f = { .fd = -1 };
	int r = flash_open(&f), err = 0;
	if (r == -2) { LOG("camupdate: no mtd \"rootfs\"\n"); return 1; }
	if (r) { LOG("camupdate: %s: %s\n", f.dev, strerror(errno)); return 1; }
	if (p->h.size > f.size) { LOG("camupdate: payload larger than %s\n", f.dev); return 1; }
	LOG("camupdate: installing %s (signed by %s) to %s; the camera reboots when done\n",
	    p->h.version, p->signer, f.dev);
	signal_others(SIGSTOP);
	usleep(300000);
	/* the feeder had to go first (single-open); taking the device is the last step that may fail,
	 * and it fails with nothing written: resume everything, restart the feeder, stop here */
	for (int i = 0; i < 20 && wdt < 0; i++) {
		wdt = open(wdt_path, O_WRONLY | O_CLOEXEC);
		if (wdt < 0) { err = errno; usleep(100000); }
	}
	if (wdt < 0) {
		restart_feeder();
		signal_others(SIGCONT);
		LOG("camupdate: can't take the watchdog (%s): nothing written, everything resumed\n", strerror(err));
		close(f.fd);
		return 1;
	}
	/* from the first erase on, never just exit: everything else is stopped and only we feed the
	 * watchdog. Retry from RAM; if no pass verifies, reboot (the CH341A is the way back). */
	for (int pass = 1; pass <= PASSES; pass++) {
#ifdef CAMUPDATE_TEST
		test_pass = pass;
#endif
		if (!flash_pass(&f, p)) {
			LOG("camupdate: written and verified; rebooting\n");
			reboot_now(&f);
		}
		wdt_feed();
		if (pass < PASSES) LOG("camupdate: pass %d of %d failed; erasing and writing again from RAM\n", pass, PASSES);
	}
	LOG("camupdate: INSTALL FAILED: mtd2 is not the image after %d passes. Rebooting; if the camera "
	    "doesn't come back, restore mtd2 with the CH341A (docs/UPDATE-PATH.md)\n", PASSES);
	reboot_now(&f);
	return 1;
}

/* Our executable's path, to tell whether we already run from the RAM copy. */
static int self_path(char *out, size_t cap)
{
#ifdef __APPLE__
	char t[PATH_MAX];
	uint32_t n = sizeof t;
	(void)cap;
	return _NSGetExecutablePath(t, &n) || !realpath(t, out) ? -1 : 0;   /* out: PATH_MAX */
#else
	ssize_t n = readlink("/proc/self/exe", out, cap - 1);
	if (n < 0) return -1;
	out[n] = 0;
	return 0;
#endif
}

/* The writer must not run from the flash it rewrites: copy ourselves to tmpfs and exec that. The
 * copy goes into a fresh 0700 directory (mkdtemp, then O_EXCL | O_NOFOLLOW), so nothing planted in
 * the world-writable /tmp is followed or truncated; once running, the copy removes itself (the
 * kernel keeps the running image), so failed runs leave nothing in RAM. */
static void reexec_from_ram(char **argv)
{
	static const char run[] = "/camupdate.run";
	static char buf[65536];
	char self[PATH_MAX] = "", dir[PATH_MAX], ram[PATH_MAX];
	const char *src = "/proc/self/exe";
	size_t tl = strlen(tmp_base);
	if (!self_path(self, sizeof self) && !strncmp(self, tmp_base, tl) && !strncmp(self + tl, "/camupdate.", 11) &&
	    strlen(self + tl) == 17 + sizeof run - 1 && !strcmp(self + tl + 17, run)) {
#ifdef CAMUPDATE_TEST
		struct stat fs, ds;
		char d[PATH_MAX];
		snprintf(d, sizeof d, "%.*s", (int)(tl + 17), self);
		if (!lstat(self, &fs) && !lstat(d, &ds))
			LOG("camupdate: (test build) running from %s (dir %o, file %o)\n", self,
			    (unsigned)(ds.st_mode & 07777), (unsigned)(fs.st_mode & 07777));
#endif
		unlink(self);
		self[tl + 17] = 0;
		rmdir(self);
		return;
	}
#ifdef __APPLE__
	src = self;
#endif
	if (snprintf(dir, sizeof dir, "%s/camupdate.XXXXXX", tmp_base) >= (int)sizeof dir || !mkdtemp(dir)) {
		LOG("camupdate: can't copy to %s: %s\n", tmp_base, strerror(errno));
		exit(1);
	}
	snprintf(ram, sizeof ram, "%s%s", dir, run);
	int in = open(src, O_RDONLY | O_CLOEXEC), out = open(ram, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0700);
	int ok = in >= 0 && out >= 0 && !fchmod(out, 0700);
	ssize_t n;
	while (ok && (n = read(in, buf, sizeof buf)) != 0)
		ok = n > 0 && write(out, buf, (size_t)n) == n;
	if (in >= 0) close(in);
	if (out >= 0 && close(out)) ok = 0;
	if (!ok) LOG("camupdate: can't copy to %s: %s\n", ram, strerror(errno));
	else {
		argv[0] = ram;
		execv(ram, argv);
		LOG("camupdate: exec %s: %s\n", ram, strerror(errno));
	}
	unlink(ram);
	rmdir(dir);
	exit(1);
}
#endif

int main(int argc, char **argv)
{
	int check = 0;
	const char *file = "-";
	if (sodium_init() < 0) { LOG("camupdate: libsodium init failed\n"); return 1; }
#ifdef CAMUPDATE_TEST
	if (getenv("CU_KEYS")) keys_path = getenv("CU_KEYS");       /* host test only */
	if (getenv("CU_DEVICE")) device_path = getenv("CU_DEVICE");
	if (getenv("CU_VERSION")) version_path = getenv("CU_VERSION");
	if (argc == 4 && !strcmp(argv[1], "--verify-sig")) {        /* sshsig vectors: HDR SIG */
		struct pkg h, g;
		char who[128];
		const char *w = "";
		int fh = open(argv[2], O_RDONLY), fg = open(argv[3], O_RDONLY);
		if (fh < 0 || fg < 0 || read_all(fh, &h) || read_all(fg, &g)) return 2;
		if (sshsig_verify((const char *)g.buf, g.len, h.buf, h.len, NAMESPACE, keys_path, who, sizeof who, &w)) {
			printf("REFUSED: %s\n", w);
			return 1;
		}
		printf("OK: signed by %s\n", who);
		return 0;
	}
#endif
	for (int i = 1; i < argc; i++) {
		if (!strcmp(argv[i], "--check")) check = 1;
		else if (argv[i][0] == '-' && argv[i][1] && strcmp(argv[i], "-")) {
			fprintf(stderr, "usage: %s [--check] [FILE|-]\n", argv[0]);
			return 2;
		} else file = argv[i];
	}
#ifdef CAMUPDATE_TEST
	if (!check) {                                               /* see "installing" */
		if (!getenv("CU_MTD") || !getenv("CU_PROC") || !getenv("CU_WATCHDOG") || !getenv("CU_TMP")) {
			LOG("camupdate: test build: installing needs CU_MTD, CU_PROC, CU_WATCHDOG and CU_TMP\n");
			return 1;
		}
		proc_root = getenv("CU_PROC");
		wdt_path = getenv("CU_WATCHDOG");
		tmp_base = getenv("CU_TMP");
		test_fail_erase = getenv("CU_FAIL_ERASE") ? atoi(getenv("CU_FAIL_ERASE")) : 0;
		test_fail_verify = getenv("CU_FAIL_VERIFY") ? atoi(getenv("CU_FAIL_VERIFY")) : 0;
	}
#endif
#if defined(__linux__) || defined(CAMUPDATE_TEST)
	if (!check) reexec_from_ram(argv);
#endif
	struct pkg p;
	const char *why = "";
	/* close-on-exec: a watchdog feeder we restart must not hold the package (or mtd2) open */
	int fd = strcmp(file, "-") ? open(file, O_RDONLY | O_CLOEXEC) : 0;
	if (fd < 0 || read_all(fd, &p)) { LOG("camupdate: can't read the package (or it's too big)\n"); return 1; }
	if (pkg_check(&p, &why)) { LOG("camupdate: REFUSED: %s\n", why); return 1; }
	printf("camupdate: OK: version %s for %s, %lu bytes, signed by %s%s\n", p.h.version, p.h.device,
	       p.h.size, p.signer, p.h.downgrade ? " (downgrade allowed)" : "");
	if (check) return 0;
#if defined(__linux__) || defined(CAMUPDATE_TEST)
	return install(&p);
#else
	LOG("camupdate: installing needs Linux\n");
	return 1;
#endif
}
#endif
