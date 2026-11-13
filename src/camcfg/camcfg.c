/* SPDX-License-Identifier: MIT */
/*
 * camcfg: the camera's persistent settings, user accounts and SSH keys (#72, #79).
 *
 * Files in DIR (default /mnt/nand/cam on DATA, mtd3 jffs2; -d DIR or $CAMCFG_DIR to override):
 *   cam.conf   key=value settings (keys [a-z0-9._-], values one line)
 *   users      name:role:password lines. Roles: admin, operator, viewer (ONVIF Administrator,
 *              Operator, User). Passwords are stored recoverably (owner decision 2026-10-23:
 *              ONVIF WS-UsernameToken digest needs them); the file is root-only (0600), like
 *              everything here. Every reader (camcfg, camhttpd) splits a line on its first two
 *              colons only, so a password may hold ':'.
 *   ssh/authorized_keys  root's SSH keys (/root/.ssh links to DIR/ssh, #76)
 *   recovery   the admin recovery code's slow hash (#128, docs/CLAIM.md): key=value lines algo
 *              (pbkdf2-sha256), iterations, salt (hex, 16 random bytes), hash (hex, 32 bytes) and
 *              user (the admin it was made for). The code itself is never stored.
 * Every change is written to a temp file, fsync'd and renamed over the old one under an flock,
 * so a power cut or a second writer can't leave a half-written file on the 1 MiB partition.
 *
 *   camcfg [-d DIR] get KEY | set KEY VALUE | unset KEY | list
 *   camcfg [-d DIR] user list | add NAME ROLE | passwd NAME | role NAME ROLE | del NAME
 *                   (add/passwd read the password from stdin: one line, nothing after it; the
 *                   last admin can't be deleted or given another role)
 *   camcfg [-d DIR] sshkey list | add | del N
 *                   list prints "N<TAB>type<TAB>SHA256:fingerprint<TAB>comment" per key, from 1
 *                   (# lines don't count); add reads one key line from stdin and prints its list
 *                   line; del N removes the Nth key
 *   camcfg [-d DIR] htdigest REALM OUTFILE   writes user:realm:MD5(user:realm:password) for
 *                                            every user (rtspd -a), 0600, atomically; run as
 *                                            root, owned by OUTFILE's directory's owner
 *                                            (/run/cam: rtspd, Gate 3)
 *   camcfg ctl COMMAND…                      send one line to rtspd's control socket and print
 *                                            the reply ("get", "set image.saturation 40", …);
 *                                            exit 0 when its last line is "ok" or "ok …" (the
 *                                            snapshot's "ok SIZE"), else 1
 * First-boot claim and admin recovery (#128, docs/CLAIM.md); camhttpd's /setup and /recover run
 * these, so camcfg stays the one writer of DIR:
 *   camcfg [-d DIR] claimed [--mark] exit 0 if the users file has an admin (the camera is
 *                                    claimed), else 1; rtspd-run and sshd-run wait for it.
 *                                    --mark: when it is claimed, also write DIR/claimed if it is
 *                                    missing (rcS's data-check, the first boot of this firmware)
 *   camcfg [-d DIR] claim NAME       the first admin: stdin is the password line and optionally an
 *                                    SSH public key line. Refused once an admin exists, and in
 *                                    lock mode (below). Makes a
 *                                    recovery code for NAME, adds the user (a power cut before it
 *                                    leaves the camera unclaimed), then the key (only once the
 *                                    admin is stored: a key that can't be added undoes the claim,
 *                                    so a failed claim never leaves a root key behind), and prints
 *                                    "recovery-code: XXXX-…" (shown once, never stored)
 *                                    The claim ends by writing DIR/claimed, a file of its own.
 * DATA lock (docs/PLAN-DATA-LOCK.md Part 2, #174): DIR/claimed says the camera was claimed. rcS's
 *   data-check locks the camera (/run/data-failed, $CAMCFG_DATA_FAILED in tests) when DATA doesn't
 *   mount, or when it holds that marker but no users file with an admin. Then claim and backup
 *   import are refused (and the marker alone refuses a claim too).
 *   camcfg unlock restore [-c CHALLENGE] FILE|-   (#176, lock mode only; the caller reboots)
 *   camcfg unlock erase [-c CHALLENGE]
 *   camcfg unlock info               prints "device ID" and "firmware VERSION" (camhttpd's challenge)
 *                                    stdin: restore's passphrase line; with -c, an SSH signature
 *                                    (armored, `ssh-keygen -Y sign -n cam-recover`) by a key in
 *                                    /etc/cam/update-keys over the lines "cam-recover 1",
 *                                    "challenge CHALLENGE", "device ID", "firmware VERSION",
 *                                    "action restore|erase", "backup SHA256-OF-FILE|none"; with
 *                                    FILE "-", then the backup. -c is camhttpd's lock page (it
 *                                    holds the one-time challenge); without it, root over the
 *                                    lock-mode SSH (update keys only). The signature (exit 3), the
 *                                    whole backup (exit 3 for its passphrase) and its device ID are
 *                                    checked before mtd3 is erased; restore then mounts it on
 *                                    /run/recover and writes the files and the marker. Tests:
 *                                    $CAMCFG_MTD3 (a file filled with 0xFF), $CAMCFG_RECOVER_DIR
 *                                    (a directory instead of the mount), $CAMCFG_UPDATE_KEYS.
 *   camcfg [-d DIR] recover [NAME]   stdin: the recovery code line, then the new password line.
 *                                    Resets admin NAME's password (no NAME: the admin the code
 *                                    was made for) and rotates the code: prints "admin: NAME"
 *                                    and the new code.
 *                                    Exit 3 for a wrong code (or none set), so the caller can
 *                                    count it as a failed login
 *   camcfg [-d DIR] recovery set | check
 *                                    set: store the code on stdin (keeps the file's user);
 *                                    check: exit 0 if the code on stdin matches, else 1
 * HTTPS (docs/PLAN-TLS.md §B): the camera's own CA and server certificate in DIR/tls (ca.key,
 * ca.crt, server.key, server.crt; all 0600, like everything here). camtls (/usr/sbin/camtls, or
 * $CAMCFG_CAMTLS for tests) makes them as a helper: run with a fixed argv, no shell, PATH as its
 * only environment, a 10 s limit, its output kept for the messages. camcfg moves its files in,
 * each fsync'd and renamed, under the lock, so camcfg stays the one writer of DIR:
 *   camcfg [-d DIR] tls init [IP]    first start: "exists" if DIR/tls/ca.crt is there; else
 *                                    camtls gen-ca and camtls issue for IP (default: eth0's IPv4)
 *                                    in a new 0700 directory in DIR/tls, then the files into
 *                                    DIR/tls with ca.crt last (a power cut before it: init again)
 *   camcfg [-d DIR] tls renew [IP]   a new server.crt for IP (default eth0's), server.key kept
 *   camcfg [-d DIR] tls show [IP]    camtls check DIR/tls [IP]: prints its line ("ok san=… ",
 *                                    "renew …", "bad …") and exits with its status (0, 1, 2)
 *   camtls refuses an IP outside CAM_NET (exit 2): init and renew then fail with its message.
 * Network (#80): cam.conf's net.mode (dhcp, the default, or static), net.address (A.B.C.D/PREFIX,
 * prefix 8..30, in CAM_NET like the certificate (src/camnet.h), not the subnet's network or broadcast
 * address), net.gateway (static: a host in that subnet, not the camera), net.dns (1-3 IPv4,
 * comma-separated; dhcp: instead of the lease's) and net.hostname (1-63 of a-z 0-9 -, no - at
 * either end; default the image's /etc/hostname). Only net set writes them (set/unset of these
 * keys is refused; net.plain is an ordinary setting), so a change is checked whole and can be
 * taken back: rcS's net-up applies it at the next boot and reverts it unless confirmed in 10 min.
 *   camcfg [-d DIR] net show         the settings as shell-friendly lines: mode, address, netmask,
 *                                    gateway, dns (space-separated), hostname, pending (0|1);
 *                                    exit 1 if cam.conf's are invalid (net-up then uses DHCP)
 *   camcfg [-d DIR] net set mode=dhcp|static [address=…] [gateway=…] [dns=…] [hostname=…]
 *                                    replaces all five (a key left out: its default). Unless a
 *                                    change already waits, the confirmed rows go to
 *                                    DIR/net-pending first; setting the confirmed values again
 *                                    removes it
 *   camcfg [-d DIR] net confirm      keeps the new settings (removes DIR/net-pending)
 *   camcfg [-d DIR] net revert       puts the confirmed rows back (exit 1 if nothing waits); the
 *                                    caller reboots
 * Settings backup (docs/PLAN-DATA-LOCK.md Part 1, #171): DIR in one encrypted file, which
 * restores only on the camera that made it:
 *   camcfg [-d DIR] backup export > FILE
 *                                    stdin's first line is the passphrase (12..256 bytes, no
 *                                    control characters; on a terminal it is asked for twice,
 *                                    unechoed); the backup goes to stdout (never a terminal).
 *                                    Refused on an unclaimed camera
 *   camcfg [-d DIR] backup import [FILE]
 *                                    stdin's first line is the passphrase; the backup is FILE or
 *                                    the rest of stdin. All of it is checked in memory first (the
 *                                    header, this camera's ID, the box, the file list, the users
 *                                    file has an admin); then each file is written, fsync'd and
 *                                    renamed under the lock, users last, and the files below that
 *                                    the backup doesn't hold are removed. Exit 3 for a wrong
 *                                    passphrase (or a changed file: the two look the same). Then
 *                                    DIR/claimed. Refused in lock mode. Reboot afterwards: the
 *                                    daemons read DIR when they start
 *   It holds cam.conf, users, recovery, ssh/authorized_keys, ssh/dropbear_ed25519_host_key and
 *   tls/ (ca.key too: owner decision 2026-10-26; all four files or none), so it is
 *   password-equivalent: the ONVIF passwords are in it in clear.
 *   Format (.cambak): a text header, the lines
 *     cam-backup 1 | device ID | firmware VERSION (/etc/cam/version or "unknown") |
 *     created UNIX-TIME (the camera's clock) | kdf argon2id OPS MEM SALT | nonce NONCE
 *   and an empty line; then libsodium's XChaCha20-Poly1305 over the archive, with the whole header
 *   as associated data (no line of it can be edited), keyed by Argon2id from the passphrase (OPS
 *   passes over MEM bytes, SALT 16 random bytes: 8 and 4 MiB here; import takes 1..32 and
 *   1..8 MiB). Archive: per file "file NAME SIZE\n", SIZE bytes, "\n"; then "end\n".
 *   The device ID is the first 16 bytes of SHA-256("cam-backup device 1\n" and eth0's MAC in lower
 *   case) in hex. The MAC comes from U-Boot's env (ethaddr, mtd0, read only, as rcS reads it;
 *   $CAMCFG_MTD0 in tests), so the ID survives a lost DATA; without a valid one, no backup or
 *   restore.
 *   Codes: 26 characters of A-Z 2-7 (base32, 130 random bits from /dev/urandom), shown in groups
 *   of 4; case, spaces and dashes don't matter when typed. Stored as PBKDF2-HMAC-SHA256 with a
 *   per-camera random salt and 100000 iterations (checks take the file's count, 1000..10000000),
 *   compared in constant time.
 * Passwords (#79): camcfg is the one place that checks them; the web UI shows its message.
 *   - 8..64 characters, never shortened: a longer line is refused, not cut;
 *   - printable ASCII only (space to '~'). Every symbol works (: " \ & < % + @ # '), but browsers,
 *     NVRs and ONVIF tools encode other bytes differently, so é or an emoji would log in from one
 *     client and not another;
 *   - no space at the start or end (clients trim them);
 *   - not the user name, in any case.
 * SSH keys (#79): "TYPE BASE64 [COMMENT]", TYPE one of ssh-ed25519, sk-ssh-ed25519@openssh.com,
 *   ecdsa-sha2-nistp256, sk-ecdsa-sha2-nistp256@openssh.com, ssh-rsa, with no options before it.
 *   The base64 must decode to exactly that type's fields, the first being the same type name;
 *   the comment is printable ASCII; at most 16 keys, no duplicates.
 * Settings checked here (as rtspd reads them): image.brightness|contrast|saturation|sharpness|
 *   exposure 0..100 (50 = stock); image.mirror, image.flip 0|1 (0 = stock's picture);
 *   image.shutter_day_max 0 (auto) or 100..1000000 us, image.shutter_night_max 0 or 100..50000 us;
 *   image.antiflicker 0|1, image.mains_hz 50|60; image.nr2d, nr3d, wdr, blc 0..255 (128 / 128 / 0 /
 *   0 = the IQ profile as tuned); image.night_tuning 0|1 (stock night tuning, default 0);
 *   image.exposure_night day|0..100 (day = as image.exposure, the default);
 *   image.isp_gain_day_max, image.isp_gain_night_max 1..4 (x; defaults 4 and 2, as stock);
 *   daynight.night_below < daynight.day_above (1..1000000 each; 15 / 1500); stream.*, motion.*,
 *   audio.*, osd.* (on-screen display; osd.title.text printable ASCII, at most 48) and the other
 *   daynight.* keys as their *_check functions say. time.tz: the time zone, a POSIX TZ string
 *   (src/rtspd/tz.h: e.g. CST6CDT,M3.2.0,M11.1.0 for US Central; at most 64 characters; default
 *   UTC0). The old osd.tz_offset is refused; "unset osd.tz_offset" still removes a leftover line.
 *   net.plain 1|0 (camhttpd: ONVIF and /snapshot.jpg on port 80, rtsp:// stream URIs; 0 = off while
 *   HTTPS is up, once SSS uses HTTPS and RTSPS; default 1).
 * Live effect (#73): set/unset of an image.*, daynight.*, motion.* or osd.* key or of time.tz is
 *   also sent to rtspd, and a user change
 * regenerates /run/cam/rtspd.htdigest and has rtspd reload it, when rtspd is running
 * ($CAMCTL_SOCK, default /run/camd.sock). Saving works either way. A set/unset of time.ntp also
 * updates ntpc's world-readable copy /run/ntp.conf when it exists (ntp_copy; ntpc isn't root).
 * Exit status 0 on success, 1 on a failed operation, 2 on usage errors.
 */
#define _GNU_SOURCE                    /* flock */
#include <arpa/inet.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/file.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <net/if.h>
#include <termios.h>
#include <time.h>
#include <unistd.h>

#include <sodium.h>                    /* the backup: Argon2id, XChaCha20-Poly1305 */
#include "sshsig.h"                    /* src/camupdate: the signed recovery's verifier */
#ifdef __linux__
#include <mtd/mtd-user.h>              /* MEMGETINFO, MEMERASE */
#include <sys/mount.h>
#endif

#include "auth.h"                      /* md5_hex */
#include "streamcfg.h"                 /* stream sizes, fps range */
#include "tz.h"                        /* tz_valid */
#include "../camnet.h"                 /* CAM_NET: NET_BASE, NET_MASK, CAM_NET_STR (a build setting) */

#define MAX_LINES 512
#define MAX_LINE 512
#define MAX_FILE (64 * 1024)           /* refuse to grow either file past this */

static const char *dir = "/mnt/nand/cam";
static char lines[MAX_LINES][MAX_LINE];
static int nlines;

static const char *ctl_sock = "/run/camd.sock";

/* rtspd's reply ends in a line "ok" ("get", "set", ...) or "ok DETAIL" ("snapshot": "ok <size>");
 * anything else ("err ...", nothing, a reply cut short) is a failure. 1 if it is an ok. */
static int ctl_reply_ok(const char *out)
{
	size_t n = strlen(out);
	if (n && out[n - 1] == '\n') n--;
	size_t start = n;
	while (start && out[start - 1] != '\n') start--;
	const char *last = out + start;
	size_t len = n - start;
	return (len == 2 && !strncmp(last, "ok", 2)) || (len > 3 && !strncmp(last, "ok ", 3));
}

/* Send one line to rtspd; print the reply if `show`. -1 if rtspd isn't there or doesn't end with ok. */
static int ctl_send(const char *line, int show)
{
	struct sockaddr_un a;
	int fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (fd < 0 || strlen(ctl_sock) >= sizeof a.sun_path) return -1;
	memset(&a, 0, sizeof a);
	a.sun_family = AF_UNIX;
	strcpy(a.sun_path, ctl_sock);
	if (connect(fd, (struct sockaddr *)&a, sizeof a)) { close(fd); return -1; }
	char out[4096];                 /* get: ~1.2 KiB with the motion mask */
	size_t got = 0;
	ssize_t n = write(fd, line, strlen(line));
	if (n == (ssize_t)strlen(line))
		while (got < sizeof out - 1 && (n = read(fd, out + got, sizeof out - 1 - got)) > 0)
			got += (size_t)n;
	close(fd);
	out[got] = 0;
	if (show) fputs(out, stdout);
	return ctl_reply_ok(out) ? 0 : -1;
}

static int fail(const char *fmt, const char *arg)
{
	fprintf(stderr, "camcfg: ");
	fprintf(stderr, fmt, arg);
	fputc('\n', stderr);
	return 1;
}

static void path_of(char *out, size_t cap, const char *name)
{
	snprintf(out, cap, "%s/%s", dir, name);
}

static int lock_dir(void)
{
	char p[512];
	path_of(p, sizeof p, ".lock");
	int fd = open(p, O_RDWR | O_CREAT | O_CLOEXEC, 0600);
	if (fd < 0 || flock(fd, LOCK_EX)) return -1;
	return fd;                                   /* released at exit */
}

static int load(const char *name)
{
	char p[512];
	path_of(p, sizeof p, name);
	nlines = 0;
	FILE *f = fopen(p, "r");
	if (!f) return errno == ENOENT ? 0 : -1;
	char buf[MAX_LINE + 2];
	while (fgets(buf, sizeof buf, f)) {
		size_t n = strcspn(buf, "\n");
		/* overlong: more than a row holds (MAX_LINE - 1 and its NUL), with or without a newline */
		if ((buf[n] != '\n' && !feof(f)) || n >= MAX_LINE) { fclose(f); return -1; }
		buf[n] = 0;
		if (!*buf) continue;
		if (nlines == MAX_LINES) { fclose(f); return -1; }
		memcpy(lines[nlines++], buf, n + 1);
	}
	fclose(f);
	return 0;
}

/* Atomically replace the file p (DIR/name or an absolute path) with n rows, `stride` apart, mode
 * 0600. owner (uid_t)-1: ours. Any other: the file is given to that user, and as the directory is
 * then someone else's (htdigest in /run/cam, which belongs to rtspd), the temp file is made new
 * (O_EXCL, O_NOFOLLOW): a name planted there can't make root write through a link. */
static int save_rows_as(const char *p, const char *rows, size_t stride, int n, uid_t owner)
{
	char tmp[600];
	size_t total = 0;
	for (int i = 0; i < n; i++) total += strlen(rows + (size_t)i * stride) + 1;
	if (total > MAX_FILE) return fail("%s would exceed the size limit", p);
	snprintf(tmp, sizeof tmp, "%s.tmp", p);
	int fd;
	if (owner == (uid_t)-1) {
		fd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
	} else {
		unlink(tmp);
		fd = open(tmp, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
		if (fd >= 0 && fchown(fd, owner, (gid_t)-1)) {
			close(fd);
			unlink(tmp);
			return fail("can't give %s to its directory's owner", tmp);
		}
	}
	if (fd < 0) return fail("can't write %s", tmp);
	FILE *f = fdopen(fd, "w");
	for (int i = 0; i < n; i++) fprintf(f, "%s\n", rows + (size_t)i * stride);
	if (fflush(f) || fsync(fd) || fclose(f) || rename(tmp, p)) {
		unlink(tmp);
		return fail("can't replace %s", p);
	}
	return 0;
}

static int save_rows(const char *p, const char *rows, size_t stride, int n)
{
	return save_rows_as(p, rows, stride, n, (uid_t)-1);
}

static int save_to(const char *p) { return save_rows(p, lines[0], MAX_LINE, nlines); }

static int save(const char *name)
{
	char p[512];
	path_of(p, sizeof p, name);
	return save_to(p);
}

static int valid_key(const char *k)
{
	if (!*k || strlen(k) > 64) return 0;
	for (const char *c = k; *c; c++)
		if (!((*c >= 'a' && *c <= 'z') || (*c >= '0' && *c <= '9') || *c == '.' || *c == '_' ||
		      *c == '-'))
			return 0;
	return 1;
}

static int valid_name(const char *n)
{
	if (!*n || strlen(n) > 32) return 0;
	for (const char *c = n; *c; c++)
		if (!((*c >= 'a' && *c <= 'z') || (*c >= 'A' && *c <= 'Z') || (*c >= '0' && *c <= '9') ||
		      *c == '.' || *c == '_' || *c == '-'))
			return 0;
	return 1;
}

static int valid_role(const char *r)
{
	return !strcmp(r, "admin") || !strcmp(r, "operator") || !strcmp(r, "viewer");
}

/* Index of the line whose first field (up to sep) equals key, or -1. */
static int find(const char *key, char sep)
{
	size_t kl = strlen(key);
	for (int i = 0; i < nlines; i++)
		if (!strncmp(lines[i], key, kl) && lines[i][kl] == sep) return i;
	return -1;
}

static void drop(int i)
{
	memmove(lines[i], lines[i + 1], (size_t)(nlines - i - 1) * MAX_LINE);
	nlines--;
}

static int is_admin(int i)                        /* lines[i] of the users file */
{
	char *a = strchr(lines[i], ':');
	return a && !strncmp(a + 1, "admin:", 6);
}

static int admins(void)
{
	int n = 0;
	for (int i = 0; i < nlines; i++) n += is_admin(i);
	return n;
}

#define PW_ASCII "password: letters, digits, symbols and spaces only (ASCII)"
#define PW_LONG "password must be at most 64 characters (a longer one is never shortened)"

/* The policy above for user `name`'s password buf[0..n) (n its real length: a NUL inside is
 * caught); copied to pw if it passes. 0, or 1 with the reason on stderr. */
static int pw_check(const char *name, const char *buf, size_t n, char *pw, size_t cap)
{
	int r = 0;
	memset(pw, 0, cap);
	if (memchr(buf, 0, n)) r = fail("%s", PW_ASCII);
	for (size_t i = 0; !r && i < n; i++)
		if ((unsigned char)buf[i] < 0x20 || (unsigned char)buf[i] > 0x7e) r = fail("%s", PW_ASCII);
	if (!r && n && (buf[0] == ' ' || buf[n - 1] == ' '))
		r = fail("%s", "password must not start or end with a space");
	if (!r && n < 8) r = fail("%s", "password must be at least 8 characters");
	if (!r && n > 64) r = fail("%s", PW_LONG);
	if (!r && !strcasecmp(buf, name)) r = fail("%s", "password must not be the user name");
	if (!r && n < cap) {
		memcpy(pw, buf, n);
		pw[n] = 0;
	} else if (!r) r = fail("%s", PW_LONG);
	return r;
}

/* User `name`'s new password from stdin, checked against the policy above. A line longer than
 * the buffer is refused, never cut; anything after the line too (a second line could otherwise
 * hide behind the first). 0, or 1 with the reason on stderr. */
static int read_password(const char *name, char *pw, size_t cap)
{
	char buf[258];                             /* well above 64, so a long line is seen whole */
	int r = 0;
	memset(pw, 0, cap);
	if (!fgets(buf, sizeof buf, stdin)) return fail("%s", "no password on stdin");
	size_t n = strlen(buf);
	int nl = n && buf[n - 1] == '\n';
	if (nl) buf[--n] = 0;
	if (n && buf[n - 1] == '\r') buf[--n] = 0;          /* a CRLF line */
	if (!nl && !feof(stdin)) r = fail("%s", PW_LONG);
	else if (!isatty(0) && getchar() != EOF) r = fail("%s", "password must be one line");
	else if (n != strlen(buf)) r = fail("%s", PW_ASCII);  /* a NUL inside */
	if (!r) r = pw_check(name, buf, n, pw, cap);
	memset(buf, 0, sizeof buf);
	return r;
}

/* ---- settings ------------------------------------------------------------------------ */

/* image.* keys are the ones rtspd knows (#73): the picture levels, whole numbers 0..100 (50 = stock),
 * and orientation, shutter limits and anti-flicker as rtspd's ix_value(), and the ISP tuning as its
 * tune_value(). 1 for a level key, 2 for the others, 0 if unknown. */
static int image_key_ok(const char *key)
{
	static const char *const keys[] = { "brightness", "contrast", "saturation", "sharpness",
	                                    "exposure", "mirror", "flip", "shutter_day_max",
	                                    "shutter_night_max", "antiflicker", "mains_hz", "nr2d", "nr3d",
	                                    "wdr", "blc", "night_tuning", "exposure_night", "isp_gain_day_max",
	                                    "isp_gain_night_max" };
	for (size_t i = 0; i < sizeof keys / sizeof keys[0]; i++)
		if (!strcmp(key + 6, keys[i])) return i < 5 ? 1 : 2;
	return 0;
}

/* image.mirror / flip: 0 or 1 (1 = mirrored left-right / upside down). Shutter limits in us, 0 =
 * auto: day 100..1000000 (longer than a frame acts as a frame), night 100..50000 (stock's 50 ms;
 * longer would lower the frame rate). image.antiflicker 0|1, image.mains_hz 50|60. ISP tuning
 * 0..255: image.nr2d / nr3d (128 = as tuned), image.wdr (0 = as tuned), image.blc (used with
 * image.wdr 0; 0 = as tuned). image.night_tuning 0|1 (stock's night IQ at night; default 0).
 * image.exposure_night: day (as image.exposure, the default) or 0..100 (30 suits a street-lit or
 * mostly dark scene). image.isp_gain_day_max / _night_max 1..4 (x; 4 / 2 = stock's, 1 = no ISP
 * gain). "" if fine, else the reason. */
static const char *image_other_check(const char *key, const char *v)
{
	size_t n = strlen(v);
	long x = n >= 1 && n <= 7 && strspn(v, "0123456789") == n && (n == 1 || v[0] != '0') ? atol(v) : -1;
	if (!strcmp(key, "image.mirror") || !strcmp(key, "image.flip"))
		return x == 0 || x == 1 ? "" : "image.mirror, image.flip: 0 (off) or 1 (on)";
	if (!strcmp(key, "image.exposure_night"))
		return !strcmp(v, "day") || (x >= 0 && x <= 100) ? "" :
			"image.exposure_night: day (the same as image.exposure) or 0..100 (50 = stock; 30 suits a "
			"street-lit or mostly dark scene)";
	if (!strcmp(key, "image.isp_gain_day_max") || !strcmp(key, "image.isp_gain_night_max"))
		return x >= 1 && x <= 4 ? "" : "image.isp_gain_day_max, isp_gain_night_max: 1..4 (x; stock 4 by day, "
					       "2 at night; 1 = no ISP gain)";
	if (!strcmp(key, "image.night_tuning"))
		return x == 0 || x == 1 ? "" : "image.night_tuning: 0 (off) or 1 (stock night tuning at night)";
	if (!strcmp(key, "image.antiflicker"))
		return x == 0 || x == 1 ? "" : "image.antiflicker: 0 (off) or 1 (on)";
	if (!strcmp(key, "image.mains_hz"))
		return x == 50 || x == 60 ? "" : "image.mains_hz: 50 or 60 (the mains frequency)";
	if (!strcmp(key, "image.nr2d") || !strcmp(key, "image.nr3d") || !strcmp(key, "image.wdr") ||
	    !strcmp(key, "image.blc"))
		return x >= 0 && x <= 255 ? "" : "image.nr2d, nr3d, wdr, blc: whole numbers 0..255 (nr2d/nr3d 128 "
						 "and wdr/blc 0 = as tuned)";
	if (!strcmp(key, "image.shutter_day_max"))
		return x == 0 || (x >= 100 && x <= 1000000) ? "" :
			"image.shutter_day_max: 0 (auto) or 100..1000000 microseconds";
	return x == 0 || (x >= 100 && x <= 50000) ? "" :
		"image.shutter_night_max: 0 (auto) or 100..50000 microseconds (50000 = stock's 1/20 s)";
}

/* What rtspd runs for an unset key of the kind above */
static const char *image_other_default(const char *key)
{
	return !strcmp(key, "image.mains_hz") ? "60" :
	       !strcmp(key, "image.nr2d") || !strcmp(key, "image.nr3d") ? "128" :
	       !strcmp(key, "image.exposure_night") ? "day" : !strcmp(key, "image.isp_gain_day_max") ? "4" :
	       !strcmp(key, "image.isp_gain_night_max") ? "2" : "0";
}

/* stream.* keys rtspd reads at start; same ranges as rtspd's stream_setting() (sizes and fps from
 * streamcfg.h). "" if fine, else the reason. A stream.sub.fps above the main's is saved: rtspd
 * runs the sub-stream at the main's rate. */
static const char *stream_check(const char *key, const char *v)
{
	int sub = !strncmp(key, "stream.sub.", 11);
	const char *k = key + (sub ? 11 : 12);
	size_t n = strlen(v);
	int num = n >= 1 && n <= 5 && strspn(v, "0123456789") == n, x = num ? atoi(v) : -1;
	if (!sub && strncmp(key, "stream.main.", 12)) return "stream keys: stream.main.* or stream.sub.*";
	if (!strcmp(k, "codec")) return !strcmp(v, "h264") || !strcmp(v, "h265") ? "" : "codec: h264 or h265";
	if (!strcmp(k, "kbps")) return x >= 64 && x <= 16384 ? "" : "kbps: 64..16384";
	if (!strcmp(k, "fps")) return x >= 1 && x <= STREAM_FPS_MAX ? "" : "fps: 1..30";
	if (!strcmp(k, "size"))
		return stream_size_find(sub, v) ? "" : sub ? "stream.sub.size: 640x360, 960x540 or 1280x720"
			: "stream.main.size: 2560x1440, 2304x1296, 1920x1080 or 1280x720";
	if (!strcmp(k, "gop")) return x >= 1 && x <= 1000 ? "" : "gop (keyframe interval, frames): 1..1000";
	if (!strcmp(k, "rc")) return !strcmp(v, "vbr") || !strcmp(v, "cbr") ? "" : "rc: vbr or cbr";
	if (!strcmp(k, "profile"))
		return !strcmp(v, "high") || !strcmp(v, "main") || !strcmp(v, "baseline") ? ""
			: "profile (H.264): high, main or baseline";
	if (sub && !strcmp(k, "enabled")) return !strcmp(v, "0") || !strcmp(v, "1") ? "" : "enabled: 0 or 1";
	return "stream keys: codec, kbps, fps, gop, rc, profile, size (and stream.sub.enabled)";
}

/* daynight.* (#30), as rtspd's daynight_setting(): "" if fine, else the reason */
static const char *daynight_check(const char *key, const char *v)
{
	size_t n = strlen(v);
	int x = n >= 1 && n <= 3 && strspn(v, "0123456789") == n ? atoi(v) : -1;
	if (!strcmp(key, "daynight.mode"))
		return !strcmp(v, "auto") || !strcmp(v, "day") || !strcmp(v, "night") ? "" : "mode: auto, day or night";
	if (!strcmp(key, "daynight.irled")) return x >= 0 && x <= 100 ? "" : "irled: IR LED % at night, 0..100";
	if (!strcmp(key, "daynight.invert")) return x == 0 || x == 1 ? "" : "invert: 0 or 1";
	if (!strcmp(key, "daynight.source"))
		return !strcmp(v, "image") || !strcmp(v, "sensor") ? "" : "source: image or sensor";
	if (!strcmp(key, "daynight.night_below") || !strcmp(key, "daynight.day_above")) {
		long t = n >= 1 && n <= 7 && strspn(v, "0123456789") == n ? atol(v) : -1;
		return t >= 1 && t <= 1000000 ? "" : "brightness score threshold: 1..1000000";
	}
	return "daynight keys: mode, irled, invert, source, night_below, day_above";
}

/* daynight.night_below must stay below daynight.day_above (rtspd keeps that hysteresis, and refuses
 * a live set that breaks it). With key set to v and the other as cam.conf has it (else its
 * default): "" if fine, else the reason. Call after load("cam.conf"). */
static const char *dn_pair_check(const char *key, const char *v)
{
	int below = !strcmp(key, "daynight.night_below");
	if (!below && strcmp(key, "daynight.day_above")) return "";
	const char *other = below ? "daynight.day_above" : "daynight.night_below";
	int i = find(other, '=');
	long o = i >= 0 ? atol(lines[i] + strlen(other) + 1) : below ? 1500 : 15, x = atol(v);
	if (below ? x < o : o < x) return "";
	static char why[160];
	snprintf(why, sizeof why, "daynight.night_below must be below daynight.day_above (%s is %ld)", other, o);
	return why;
}

/* motion.* (#77), as rtspd's motion_setting(): "" if fine, else the reason */
static const char *motion_check(const char *key, const char *v)
{
	size_t n = strlen(v);
	int x = n >= 1 && n <= 3 && strspn(v, "0123456789") == n ? atoi(v) : -1;
	if (!strcmp(key, "motion.enabled")) return x == 0 || x == 1 ? "" : "motion.enabled: 0 or 1";
	if (!strcmp(key, "motion.sensitivity")) return x >= 0 && x <= 100 ? "" : "motion.sensitivity: 0..100";
	if (!strcmp(key, "motion.mask"))         /* 32x32 cells, 1 bit each, row-major, MSB first */
		return n == 256 && strspn(v, "0123456789abcdefABCDEF") == 256 ? "" : "motion.mask: 256 hex digits";
	return "motion keys: motion.enabled, motion.sensitivity, motion.mask";
}

/* audio.* (#110), read by rtspd at start: "" if fine, else the reason */
static const char *audio_check(const char *key, const char *v)
{
	size_t n = strlen(v);
	int x = n >= 1 && n <= 2 && strspn(v, "0123456789") == n ? atoi(v) : -1;
	if (!strcmp(key, "audio.enabled")) return x == 0 || x == 1 ? "" : "audio.enabled: 0 or 1";
	if (!strcmp(key, "audio.gain")) return x >= 0 && x <= 19 ? "" : "audio.gain: 0..19 (mic gain; 14 = stock)";
	return "audio keys: audio.enabled, audio.gain";
}

/* osd.* (src/mi/osd.c), as rtspd's osd_set(): "" if fine, else the reason */
static const char *osd_check(const char *key, const char *v)
{
	static const char *const fmts[] = { "yyyy-MM-dd", "yyyy/MM/dd", "dd/MM/yyyy", "MM/dd/yyyy", "dd-MM-yyyy",
					    "MM-dd-yyyy" };
	const char *d = v + (*v == '-');
	size_t n = strlen(v), dn = strlen(d);
	int num = dn >= 1 && dn <= 4 && strspn(d, "0123456789") == dn && (dn == 1 || d[0] != '0') &&
		  !(*v == '-' && d[0] == '0');
	long x = num ? atol(v) : -1000000;
	int t = !strncmp(key, "osd.time.", 9), l = t || !strncmp(key, "osd.title.", 10);
	const char *f = key + (t ? 9 : 10);
	if (l && (!strcmp(f, "enabled") || (t && (!strcmp(f, "12h") || !strcmp(f, "weekday")))))
		return !strcmp(v, "0") || !strcmp(v, "1") ? "" : "osd.*.enabled, osd.time.12h, osd.time.weekday: 0 or 1";
	if (l && !strcmp(f, "pos"))
		return !strcmp(v, "ul") || !strcmp(v, "ur") || !strcmp(v, "ll") || !strcmp(v, "lr") || !strcmp(v, "custom")
			? "" : "osd position: ul, ur, ll, lr (corners) or custom (with .x and .y)";
	if (l && (!strcmp(f, "x") || !strcmp(f, "y")))
		return x >= 0 && x <= 100 ? "" : "osd .x, .y (custom position): 0..100 % of the room left";
	if (t && !strcmp(f, "format")) {
		for (size_t i = 0; i < sizeof fmts / sizeof fmts[0]; i++)
			if (!strcmp(v, fmts[i])) return "";
		return "osd.time.format: yyyy-MM-dd, yyyy/MM/dd, dd/MM/yyyy, MM/dd/yyyy, dd-MM-yyyy or MM-dd-yyyy";
	}
	if (l && !t && !strcmp(f, "text")) {
		for (size_t i = 0; i < n; i++)
			if ((unsigned char)v[i] < 0x20 || (unsigned char)v[i] > 0x7e) return "osd.title.text: printable ASCII only";
		return n <= 48 ? "" : "osd.title.text: at most 48 characters";
	}
	if (!strcmp(key, "osd.size"))
		return !strcmp(v, "small") || !strcmp(v, "medium") || !strcmp(v, "large") ? "" : "osd.size: small, medium or large";
	if (!strcmp(key, "osd.style"))
		return !strcmp(v, "border") || !strcmp(v, "black-on-white") || !strcmp(v, "white-on-black") ? ""
			: "osd.style: border, black-on-white or white-on-black";
	if (!strcmp(key, "osd.tz_offset"))
		return "osd.tz_offset is gone: set the time zone as time.tz (camcfg set time.tz CST6CDT,M3.2.0,M11.1.0)";
	return "osd keys: osd.time.{enabled,pos,x,y,format,12h,weekday}, osd.title.{enabled,pos,x,y,text}, "
	       "osd.size, osd.style";
}

/* time.tz (tz.h), as rtspd's tz_apply and camhttpd take it: "" if fine, else the reason */
static const char *tz_check(const char *v)
{
	return tz_valid(v) ? "" : "time.tz: a POSIX TZ string of at most 64 characters, e.g. CST6CDT,M3.2.0,M11.1.0 "
				  "(US Central), CET-1CEST,M3.5.0,M10.5.0/3, <+0530>-5:30 or UTC0; names of 3+ letters "
				  "or <+05>, offsets [+-]hh[:mm[:ss]] up to 24h (west is positive), rules Mm.w.d[/time], "
				  "Jn or n";
}

/* An osd.* key's default (what rtspd uses without the line), or NULL for an unknown key. */
static const char *osd_default(const char *key)
{
	static const char *const d[][2] = {
		{ "osd.time.enabled", "1" }, { "osd.time.pos", "ul" }, { "osd.time.x", "0" }, { "osd.time.y", "0" },
		{ "osd.time.format", "yyyy-MM-dd" }, { "osd.time.12h", "0" }, { "osd.time.weekday", "0" },
		{ "osd.title.enabled", "0" }, { "osd.title.pos", "ll" }, { "osd.title.x", "0" }, { "osd.title.y", "0" },
		{ "osd.title.text", "" }, { "osd.size", "small" }, { "osd.style", "border" } };
	for (size_t i = 0; i < sizeof d / sizeof d[0]; i++)
		if (!strcmp(key, d[i][0])) return d[i][1];
	return NULL;
}

static int image_value_ok(const char *v)
{
	size_t n = strlen(v);
	if (n < 1 || n > 3 || strspn(v, "0123456789") != n) return 0;
	return atoi(v) <= 100;
}

/* ntpc runs as its own user (Gate 3) and can't read DATA: ntpc-run makes /run/ntp.conf, a
 * world-readable copy of cam.conf's time.ntp line, at every start, and a set or unset of time.ntp
 * updates it here (value NULL: no line, ntpc's default), so ntpc sees it at its next poll as it
 * did with cam.conf. Only when the copy exists (ntpc-run made it) and DIR is the camera's;
 * $CAMCFG_NTP_COPY names another file (tests). A failure is reported; the setting stays saved. */
static void ntp_copy(const char *value)
{
	const char *p = getenv("CAMCFG_NTP_COPY");
	if (!p) {
		if (strcmp(dir, "/mnt/nand/cam")) return;
		p = "/run/ntp.conf";
	}
	if (access(p, F_OK)) return;
	char tmp[600];
	int ok = 0;
	snprintf(tmp, sizeof tmp, "%s.tmp", p);
	unlink(tmp);
	int fd = open(tmp, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0644);
	if (fd >= 0) {
		FILE *f = fdopen(fd, "w");
		if (!f) {
			close(fd);
		} else {
			ok = !fchmod(fd, 0644) && (!value || fprintf(f, "time.ntp=%s\n", value) > 0) && !fflush(f);
			if (fclose(f)) ok = 0;
			ok = ok && !rename(tmp, p);
		}
	}
	if (!ok) {
		unlink(tmp);
		fprintf(stderr, "camcfg: saved; %s not updated: ntpc keeps the old servers until it is restarted\n", p);
	}
}

static int cmd_conf(int argc, char **argv)
{
	const char *op = argv[0];
	if (!strcmp(op, "list") && argc == 1) {
		if (load("cam.conf")) return fail("%s", "can't read cam.conf");
		for (int i = 0; i < nlines; i++) puts(lines[i]);
		return 0;
	}
	if (argc < 2 || !valid_key(argv[1])) return 2;
	const char *key = argv[1];
	if (strcmp(op, "get") && !strncmp(key, "net.", 4) && strcmp(key, "net.plain"))
		return fail("%s", "network settings change with camcfg net set (each change waits for confirmation)");
	if (!strcmp(op, "get") && argc == 2) {
		if (load("cam.conf")) return fail("%s", "can't read cam.conf");
		int i = find(key, '=');
		if (i < 0) return 1;
		puts(lines[i] + strlen(key) + 1);
		return 0;
	}
	int image = !strncmp(key, "image.", 6), ikind = image ? image_key_ok(key) : 0;
	if (image && !ikind)
		return fail("%s", "image keys: image.brightness, contrast, saturation, sharpness, exposure, "
			    "mirror, flip, shutter_day_max, shutter_night_max, antiflicker, mains_hz, nr2d, nr3d, "
			    "wdr, blc, night_tuning, exposure_night, isp_gain_day_max, isp_gain_night_max");
	if (ikind == 1 && !strcmp(op, "set") && argc == 3 && !image_value_ok(argv[2]))
		return fail("%s", "image values are whole numbers 0..100 (50 = stock)");
	if (ikind == 2 && !strcmp(op, "set") && argc == 3 && *image_other_check(key, argv[2]))
		return fail("%s", image_other_check(key, argv[2]));
	int stream = !strncmp(key, "stream.", 7), dn = !strncmp(key, "daynight.", 9),
	    mo = !strncmp(key, "motion.", 7), au = !strncmp(key, "audio.", 6), os = !strncmp(key, "osd.", 4),
	    tz = !strcmp(key, "time.tz");
	if (os && !strcmp(op, "set") && argc == 3 && *osd_check(key, argv[2]))
		return fail("%s", osd_check(key, argv[2]));
	if (tz && !strcmp(op, "set") && argc == 3 && *tz_check(argv[2]))
		return fail("%s", tz_check(argv[2]));
	if (!strcmp(key, "net.plain") && !strcmp(op, "set") && argc == 3 && strcmp(argv[2], "0") && strcmp(argv[2], "1"))
		return fail("%s", "net.plain: 1 (plain HTTP ONVIF and RTSP on, the default) or 0 (off while HTTPS is up)");
	if (au && !strcmp(op, "set") && argc == 3 && *audio_check(key, argv[2]))
		return fail("%s", audio_check(key, argv[2]));
	if (mo && !strcmp(op, "set") && argc == 3 && *motion_check(key, argv[2]))
		return fail("%s", motion_check(key, argv[2]));
	if (dn && !strcmp(op, "set") && argc == 3 && *daynight_check(key, argv[2]))
		return fail("%s", daynight_check(key, argv[2]));
	if (stream && !strcmp(op, "set") && argc == 3 && *stream_check(key, argv[2]))
		return fail("%s", stream_check(key, argv[2]));
	if (lock_dir() < 0) return fail("can't lock %s", dir);
	if (load("cam.conf")) return fail("%s", "can't read cam.conf");
	int i = find(key, '=');
	int set = !strcmp(op, "set") && argc == 3;
	if (dn && (set || (!strcmp(op, "unset") && argc == 2))) {
		const char *why = dn_pair_check(key, set ? argv[2] : !strcmp(key, "daynight.night_below") ? "15" : "1500");
		if (*why) return fail("%s", why);
	}
	if (!strcmp(op, "set") && argc == 3) {
		if (strchr(argv[2], '\n') || strlen(key) + strlen(argv[2]) + 2 > MAX_LINE)
			return fail("%s", "value must be one line, under 440 characters");
		if (i < 0) {
			if (nlines == MAX_LINES) return fail("%s", "too many settings");
			i = nlines++;
		}
		snprintf(lines[i], MAX_LINE, "%s=%s", key, argv[2]);
		if (save("cam.conf")) return 1;
		if (!strcmp(key, "time.ntp")) ntp_copy(argv[2]);
		if (image || dn || mo || os || tz) {
			char msg[600];
			snprintf(msg, sizeof msg, "set %s %s\n", key, argv[2]);
			if (ctl_send(msg, 0)) fprintf(stderr, "camcfg: saved; not applied live (rtspd not running or refused)\n");
		}
		if (stream || au)
			fprintf(stderr, "camcfg: saved; streams change when rtspd restarts (camcfg ctl restart)\n");
		return 0;
	}
	if (!strcmp(op, "unset") && argc == 2) {
		if (i >= 0) drop(i);
		if (save("cam.conf")) return 1;
		if (!strcmp(key, "time.ntp")) ntp_copy(NULL);
		const char *def = ikind == 1 ? "50" : ikind == 2 ? image_other_default(key) : !strcmp(key, "daynight.mode") ? "auto" :
				  !strcmp(key, "daynight.irled") ? "96" : !strcmp(key, "daynight.invert") ? "1" :
				  !strcmp(key, "daynight.source") ? "image" : !strcmp(key, "daynight.night_below") ? "15" :
				  !strcmp(key, "daynight.day_above") ? "1500" : !strcmp(key, "motion.enabled") ? "1" :
				  !strcmp(key, "motion.sensitivity") ? "50" : !strcmp(key, "motion.mask") ?
				  "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
				  "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
				  "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
				  "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff" : os ? osd_default(key) :
				  tz ? TZ_DEFAULT : NULL;
		if (def) {                              /* back to the default, live */
			char msg[128];
			snprintf(msg, sizeof msg, "set %s %s\n", key, def);
			if (ctl_send(msg, 0)) fprintf(stderr, "camcfg: saved; not applied live (rtspd not running or refused)\n");
		}
		if (stream || au)
			fprintf(stderr, "camcfg: saved; streams change when rtspd restarts (camcfg ctl restart)\n");
		return 0;
	}
	return 2;
}

/* ---- users --------------------------------------------------------------------------- */

static int cmd_user_inner(int argc, char **argv)
{
	if (argc < 1) return 2;
	const char *op = argv[0];
	if (!strcmp(op, "list") && argc == 1) {
		if (load("users")) return fail("%s", "can't read users");
		for (int i = 0; i < nlines; i++) {
			char *a = strchr(lines[i], ':'), *b = a ? strchr(a + 1, ':') : NULL;
			if (b) printf("%.*s %.*s\n", (int)(a - lines[i]), lines[i], (int)(b - a - 1), a + 1);
		}
		return 0;
	}
	if (argc < 2 || !valid_name(argv[1])) return fail("%s", "user names: 1-32 of A-Z a-z 0-9 . _ -");
	const char *name = argv[1];
	if (lock_dir() < 0) return fail("can't lock %s", dir);
	if (load("users")) return fail("%s", "can't read users");
	int i = find(name, ':');
	char pw[80];
	if (!strcmp(op, "add") && argc == 3) {
		if (i >= 0) return fail("user %s exists", name);
		if (!valid_role(argv[2])) return fail("%s", "role: admin, operator or viewer");
		if (read_password(name, pw, sizeof pw)) return 1;
		if (nlines == MAX_LINES) return fail("%s", "too many users");
		snprintf(lines[nlines++], MAX_LINE, "%s:%s:%s", name, argv[2], pw);
		memset(pw, 0, sizeof pw);
		return save("users");
	}
	if (i < 0) return fail("no user %s", name);
	char *role = strchr(lines[i], ':') + 1, *pwd = strchr(role, ':') + 1;
	if (!strcmp(op, "passwd") && argc == 2) {
		if (read_password(name, pw, sizeof pw)) return 1;
		char r[16];
		snprintf(r, sizeof r, "%.*s", (int)(pwd - role - 1), role);
		snprintf(lines[i], MAX_LINE, "%s:%s:%s", name, r, pw);
		memset(pw, 0, sizeof pw);
		return save("users");
	}
	if (!strcmp(op, "role") && argc == 3) {
		if (!valid_role(argv[2])) return fail("%s", "role: admin, operator or viewer");
		if (is_admin(i) && strcmp(argv[2], "admin") && admins() == 1)
			return fail("%s is the last admin: make another user admin first", name);
		char p[80];
		snprintf(p, sizeof p, "%s", pwd);
		snprintf(lines[i], MAX_LINE, "%s:%s:%s", name, argv[2], p);
		return save("users");
	}
	if (!strcmp(op, "del") && argc == 2) {
		if (is_admin(i) && admins() == 1)
			return fail("%s is the last admin: make another user admin first", name);
		drop(i);
		return save("users");
	}
	return 2;
}

/* ---- SSH keys (#79): DIR/ssh/authorized_keys, which /root/.ssh links to ------------------ */

#define MAX_KEYS 16
#define KEY_LINE 2048                  /* ssh-rsa 8192 is about 1.4 KiB of base64 */
#define KEY_ROWS 64                    /* lines in the file, # comments included */

#define ROR(x, n) ((x) >> (n) | (x) << (32 - (n)))

static void sha256_block(uint32_t h[8], const uint8_t *b)
{
	static const uint32_t k[64] = {
		0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
		0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
		0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
		0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
		0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
		0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
		0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
		0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2 };
	uint32_t w[64], a[8];
	for (int i = 0; i < 16; i++)
		w[i] = (uint32_t)b[4 * i] << 24 | (uint32_t)b[4 * i + 1] << 16 | (uint32_t)b[4 * i + 2] << 8 | b[4 * i + 3];
	for (int i = 16; i < 64; i++)
		w[i] = w[i - 16] + (ROR(w[i - 15], 7) ^ ROR(w[i - 15], 18) ^ w[i - 15] >> 3) + w[i - 7] +
		       (ROR(w[i - 2], 17) ^ ROR(w[i - 2], 19) ^ w[i - 2] >> 10);
	memcpy(a, h, sizeof a);
	for (int i = 0; i < 64; i++) {
		uint32_t t1 = a[7] + (ROR(a[4], 6) ^ ROR(a[4], 11) ^ ROR(a[4], 25)) + ((a[4] & a[5]) ^ (~a[4] & a[6])) +
			      k[i] + w[i];
		uint32_t t2 = (ROR(a[0], 2) ^ ROR(a[0], 13) ^ ROR(a[0], 22)) + ((a[0] & a[1]) ^ (a[0] & a[2]) ^ (a[1] & a[2]));
		memmove(a + 1, a, 7 * sizeof a[0]);
		a[4] += t1;
		a[0] = t1 + t2;
	}
	for (int i = 0; i < 8; i++) h[i] += a[i];
}

/* SHA-256 (FIPS 180-4), for OpenSSH's key fingerprints. */
static void sha256(const uint8_t *p, size_t n, uint8_t out[32])
{
	uint32_t h[8] = { 0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
			  0x5be0cd19 };
	uint8_t b[128];
	size_t i = 0;
	for (; n - i >= 64; i += 64) sha256_block(h, p + i);
	size_t r = n - i, tot = r + 9 <= 64 ? 64 : 128;
	memset(b, 0, sizeof b);
	if (r) memcpy(b, p + i, r);
	b[r] = 0x80;
	for (int j = 0; j < 8; j++) b[tot - 1 - j] = (uint8_t)((uint64_t)n * 8 >> (8 * j));
	sha256_block(h, b);
	if (tot == 128) sha256_block(h, b + 64);
	for (int j = 0; j < 32; j++) out[j] = (uint8_t)(h[j / 4] >> (24 - 8 * (j % 4)));
}

/* ---- the recovery code's hash (#128): SHA-256 by parts, HMAC-SHA256 (RFC 2104) and
 * PBKDF2-HMAC-SHA256 (RFC 8018) -------------------------------------------------------- */

struct s256 { uint32_t h[8]; uint64_t len; uint8_t buf[64]; size_t n; };

static void s256_init(struct s256 *s)
{
	static const uint32_t iv[8] = { 0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c,
					0x1f83d9ab, 0x5be0cd19 };
	memcpy(s->h, iv, sizeof iv);
	s->len = 0;
	s->n = 0;
}

static void s256_update(struct s256 *s, const void *data, size_t n)
{
	const uint8_t *p = data;
	s->len += n;
	while (n) {
		size_t k = 64 - s->n < n ? 64 - s->n : n;
		memcpy(s->buf + s->n, p, k);
		s->n += k;
		p += k;
		n -= k;
		if (s->n == 64) {
			sha256_block(s->h, s->buf);
			s->n = 0;
		}
	}
}

static void s256_final(struct s256 *s, uint8_t out[32])
{
	uint64_t bits = s->len * 8;
	uint8_t pad = 0x80, z = 0, l[8];
	s256_update(s, &pad, 1);
	while (s->n != 56) s256_update(s, &z, 1);
	for (int j = 0; j < 8; j++) l[j] = (uint8_t)(bits >> (56 - 8 * j));
	s256_update(s, l, 8);
	for (int j = 0; j < 32; j++) out[j] = (uint8_t)(s->h[j / 4] >> (24 - 8 * (j % 4)));
}

/* HMAC-SHA256 with the key's inner and outer pads hashed once, as PBKDF2 needs them. */
struct hmac256 { struct s256 i, o; };

static void hmac256_init(struct hmac256 *m, const uint8_t *key, size_t kl)
{
	uint8_t k[64], pad[64];
	memset(k, 0, sizeof k);
	if (kl > 64) sha256(key, kl, k);
	else if (kl) memcpy(k, key, kl);
	for (int i = 0; i < 64; i++) pad[i] = k[i] ^ 0x36;
	s256_init(&m->i);
	s256_update(&m->i, pad, 64);
	for (int i = 0; i < 64; i++) pad[i] = k[i] ^ 0x5c;
	s256_init(&m->o);
	s256_update(&m->o, pad, 64);
	memset(k, 0, sizeof k);
	memset(pad, 0, sizeof pad);
}

static void hmac256(const struct hmac256 *m, const void *msg, size_t n, uint8_t out[32])
{
	struct s256 s = m->i;
	uint8_t in[32];
	s256_update(&s, msg, n);
	s256_final(&s, in);
	s = m->o;
	s256_update(&s, in, 32);
	s256_final(&s, out);
}

static void pbkdf2_sha256(const uint8_t *pw, size_t pl, const uint8_t *salt, size_t sl, unsigned long iter,
			  uint8_t *out, size_t dl)
{
	struct hmac256 m;
	hmac256_init(&m, pw, pl);
	for (uint32_t blk = 1; dl; blk++) {
		uint8_t u[32], t[32], be[4] = { (uint8_t)(blk >> 24), (uint8_t)(blk >> 16), (uint8_t)(blk >> 8),
						(uint8_t)blk };
		struct s256 s = m.i;
		s256_update(&s, salt, sl);
		s256_update(&s, be, 4);
		s256_final(&s, u);
		s = m.o;
		s256_update(&s, u, 32);
		s256_final(&s, u);
		memcpy(t, u, 32);
		for (unsigned long i = 1; i < iter; i++) {
			hmac256(&m, u, 32, u);
			for (int j = 0; j < 32; j++) t[j] ^= u[j];
		}
		size_t k = dl < 32 ? dl : 32;
		memcpy(out, t, k);
		out += k;
		dl -= k;
		memset(u, 0, sizeof u);
		memset(t, 0, sizeof t);
	}
	memset(&m, 0, sizeof m);
}

static const char b64t[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/* Strict Base64 (padding required) of in[0..n): the byte count, or -1. */
static int b64_dec(const char *in, size_t n, uint8_t *out, size_t cap)
{
	size_t o = 0;
	if (n % 4) return -1;
	for (size_t i = 0; i < n; i += 4) {
		uint32_t x = 0;
		int pad = 0;
		for (int j = 0; j < 4; j++) {
			const char *v = in[i + j] ? strchr(b64t, in[i + j]) : NULL;
			if (in[i + j] == '=' && i + 4 == n && j >= 2) { pad++; x <<= 6; continue; }
			if (!v || pad) return -1;
			x = x << 6 | (uint32_t)(v - b64t);
		}
		for (int j = 0; j < 3 - pad; j++) {
			if (o == cap) return -1;
			out[o++] = (uint8_t)(x >> (16 - 8 * j));
		}
	}
	return (int)o;
}

/* "SHA256:" and the unpadded Base64 of SHA-256(blob), as ssh-keygen -l prints it. */
static void fingerprint(const uint8_t *blob, size_t n, char out[52])
{
	uint8_t h[33] = { 0 };
	char *o = out + 7;
	sha256(blob, n, h);
	memcpy(out, "SHA256:", 7);
	for (int i = 0; i < 32; i += 3) {             /* 32 bytes: 43 characters, no padding */
		uint32_t x = (uint32_t)h[i] << 16 | (uint32_t)h[i + 1] << 8 | (i + 2 < 32 ? h[i + 2] : 0);
		for (int j = 0; j < (i + 2 < 32 ? 4 : 3); j++) *o++ = b64t[(x >> (18 - 6 * j)) & 63];
	}
	*o = 0;
}

static const char *const key_types[] = { "ssh-ed25519", "sk-ssh-ed25519@openssh.com", "ecdsa-sha2-nistp256",
					 "sk-ecdsa-sha2-nistp256@openssh.com", "ssh-rsa" };
static const int key_fields[] = { 2, 3, 3, 4, 3 };   /* SSH strings in each type's blob */
#define NKEY_TYPES (int)(sizeof key_types / sizeof key_types[0])

struct key { char type[48]; const char *comment; uint8_t blob[KEY_LINE]; size_t bl; };

/* "TYPE BASE64[ COMMENT]" split, the blob decoded. 0, or -1 if it isn't that shape. */
static int key_split(const char *line, struct key *k)
{
	size_t tl = strcspn(line, " "), bn;
	if (!tl || tl >= sizeof k->type || line[tl] != ' ') return -1;
	memcpy(k->type, line, tl);
	k->type[tl] = 0;
	const char *b = line + tl + 1;
	bn = strcspn(b, " ");
	k->comment = b[bn] ? b + bn + 1 : "";
	int n = b64_dec(b, bn, k->blob, sizeof k->blob);
	if (n <= 0) return -1;
	k->bl = (size_t)n;
	return 0;
}

/* "" if `line` is a key we take (see the top), else the reason. */
static const char *key_check(const char *line, struct key *k)
{
	size_t n = strlen(line), tl = strcspn(line, " "), off = 0;
	int t = -1, f = 0;
	if (n >= KEY_LINE) return "key line too long";
	for (size_t i = 0; i < n; i++)
		if ((unsigned char)line[i] < 0x20 || (unsigned char)line[i] > 0x7e) return "key line: printable ASCII only";
	for (int i = 0; i < NKEY_TYPES; i++)
		if (tl == strlen(key_types[i]) && !memcmp(line, key_types[i], tl)) t = i;
	if (t < 0)
		return "key type: ssh-ed25519, sk-ssh-ed25519@openssh.com, ecdsa-sha2-nistp256, "
		       "sk-ecdsa-sha2-nistp256@openssh.com or ssh-rsa, first on the line (no options)";
	if (key_split(line, k)) return "the key's base64 doesn't decode";
	while (off < k->bl) {                        /* uint32 length + bytes, exactly filling the blob */
		if (k->bl - off < 4) return "the key's data is malformed";
		uint32_t l = (uint32_t)k->blob[off] << 24 | (uint32_t)k->blob[off + 1] << 16 |
			     (uint32_t)k->blob[off + 2] << 8 | k->blob[off + 3];
		if (l > k->bl - off - 4) return "the key's data is malformed";
		if (!f && (l != tl || memcmp(k->blob + off + 4, line, tl))) return "the key's data is of another type";
		off += 4 + l;
		f++;
	}
	if (f != key_fields[t]) return "the key's data is malformed";
	if (strlen(k->comment) > 200) return "key comment: at most 200 characters";
	return "";
}

static char krows[KEY_ROWS][KEY_LINE];
static int nkrows;

static int key_row(const char *l) { return l[strspn(l, " \t")] && l[strspn(l, " \t")] != '#'; }

static int keys_load(const char *p)
{
	char buf[KEY_LINE + 2];
	nkrows = 0;
	FILE *f = fopen(p, "r");
	if (!f) return errno == ENOENT ? 0 : -1;
	while (fgets(buf, sizeof buf, f)) {
		size_t n = strcspn(buf, "\n");
		if ((buf[n] != '\n' && !feof(f)) || n >= KEY_LINE) { fclose(f); return -1; }   /* as load() */
		buf[n] = 0;
		if (!*buf) continue;
		if (nkrows == KEY_ROWS) { fclose(f); return -1; }
		memcpy(krows[nkrows++], buf, n + 1);
	}
	fclose(f);
	return 0;
}

/* One key as list shows it; a line that isn't a plain key (options, an unknown type's data)
 * gets "?" for what can't be read. Comments are cleaned to printable characters without tabs. */
static void key_print(int num, const char *l)
{
	static struct key k;
	char fp[52] = "?";
	const char *type = "?", *com = "(not a plain key line)";
	if (!key_split(l, &k)) {
		fingerprint(k.blob, k.bl, fp);
		type = k.type;
		com = k.comment;
	}
	printf("%d\t", num);
	for (const char *s = type; *s; s++) putchar((unsigned char)*s > 0x20 && (unsigned char)*s < 0x7f ? *s : '?');
	printf("\t%s\t", fp);
	for (const char *s = com; *s; s++) putchar((unsigned char)*s >= 0x20 && (unsigned char)*s < 0x7f ? *s : '?');
	putchar('\n');
}

/* Append `line` (checked: k is its key_check parse) to DIR/ssh/authorized_keys, under the lock.
 * A key already there is refused, or with dup_ok left alone (claim: an older image's claim cut
 * short could have left it).
 * 0 with *num its number in sshkey list (0 if it was there), or 1 with the reason. */
static int key_append(const char *line, const struct key *k, int dup_ok, int *num)
{
	static struct key o;
	char d[512], p[600];
	int keys = 0;
	path_of(d, sizeof d, "ssh");
	snprintf(p, sizeof p, "%s/authorized_keys", d);
	*num = 0;
	if (keys_load(p)) return fail("can't read %s", p);
	for (int i = 0; i < nkrows; i++) {
		if (!key_row(krows[i])) continue;
		keys++;
		if (!key_split(krows[i], &o) && o.bl == k->bl && !memcmp(o.blob, k->blob, k->bl))
			return dup_ok ? 0 : fail("%s", "that key is already there");
	}
	if (keys >= MAX_KEYS) return fail("%s", "at most 16 keys: delete one first");
	if (nkrows == KEY_ROWS) return fail("%s", "authorized_keys has too many lines");
	memcpy(krows[nkrows++], line, strlen(line) + 1);
	if (mkdir(d, 0700) && errno != EEXIST) return fail("can't create %s", d);
	if (save_rows(p, krows[0], KEY_LINE, nkrows)) return 1;
	*num = keys + 1;
	return 0;
}

static int cmd_sshkey(int argc, char **argv)
{
	static struct key k;
	static char line[KEY_LINE + 2];
	char d[512], p[600];
	int keys = 0, at = -1, want = 0;
	path_of(d, sizeof d, "ssh");
	snprintf(p, sizeof p, "%s/authorized_keys", d);
	if (argc == 1 && !strcmp(argv[0], "list")) {
		if (keys_load(p)) return fail("can't read %s", p);
		for (int i = 0; i < nkrows; i++)
			if (key_row(krows[i])) key_print(++keys, krows[i]);
		return 0;
	}
	if (argc == 2 && !strcmp(argv[0], "del")) {
		size_t n = strlen(argv[1]);
		want = n >= 1 && n <= 2 && strspn(argv[1], "0123456789") == n ? atoi(argv[1]) : 0;
		if (want < 1) return fail("%s", "del N: N is a key's number in sshkey list");
	} else if (argc != 1 || strcmp(argv[0], "add")) {
		return 2;
	}
	if (want == 0) {                                 /* add: one line on stdin, nothing after it */
		if (!fgets(line, sizeof line, stdin)) return fail("%s", "no key line on stdin");
		size_t n = strlen(line);
		if (n && line[n - 1] == '\n') line[--n] = 0;
		else if (!feof(stdin)) return fail("%s", "key line too long");
		while (n && (line[n - 1] == '\r' || line[n - 1] == ' ' || line[n - 1] == '\t')) line[--n] = 0;
		if (!isatty(0) && getchar() != EOF) return fail("%s", "one key line at a time");
		const char *why = key_check(line, &k);
		if (*why) return fail("%s", why);
	}
	if (lock_dir() < 0) return fail("can't lock %s", dir);
	if (!want) {
		int num;
		if (key_append(line, &k, 0, &num)) return 1;
		key_print(num, line);
		return 0;
	}
	if (keys_load(p)) return fail("can't read %s", p);
	for (int i = 0; i < nkrows; i++)
		if (key_row(krows[i]) && ++keys == want) at = i;
	if (at < 0) return fail("no key %s", argv[1]);
	memmove(krows[at], krows[at + 1], (size_t)(nkrows - at - 1) * KEY_LINE);
	nkrows--;
	return save_rows(p, krows[0], KEY_LINE, nkrows);
}

static int cmd_htdigest(const char *realm, const char *out);

/* After a user change: if the system's runtime dir exists, regenerate rtspd's Digest file and
 * have the running rtspd reload it. */
static void users_changed(void)
{
	struct stat st;
	if (!stat("/run/cam", &st) && S_ISDIR(st.st_mode)) {
		if (cmd_htdigest("camera", "/run/cam/rtspd.htdigest"))
			fprintf(stderr, "camcfg: saved; /run/cam/rtspd.htdigest not updated\n");
		else if (ctl_send("auth-reload\n", 0))
			fprintf(stderr, "camcfg: saved; rtspd not reloaded (not running?)\n");
	}
}

static int cmd_user(int argc, char **argv)
{
	int rc = cmd_user_inner(argc, argv);
	if (rc == 0 && strcmp(argv[0], "list")) users_changed();
	return rc;
}

/* ---- first-boot claim and the recovery code (#128, docs/CLAIM.md) --------------------------- */

#define RC_LEN 26                      /* base32 characters: 130 random bits */
#define RC_SALT 16
#define RC_ITER 100000UL               /* ~0.5 s on the camera's Cortex-A7 (estimate) */
#define RC_ITER_MIN 1000UL
#define RC_ITER_MAX 10000000UL
#define WRONG_CODE 3                   /* exit status of recover for a wrong (or no) code */
#define STDIN_CAP (KEY_LINE + 512)     /* claim: a password line and an SSH key line */

static const char b32[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

static int urandom(void *p, size_t n)
{
	size_t got = 0;
	int fd = open("/dev/urandom", O_RDONLY | O_CLOEXEC);
	while (fd >= 0 && got < n) {
		ssize_t k = read(fd, (char *)p + got, n - got);
		if (k < 0 && errno == EINTR) continue;
		if (k <= 0) break;
		got += (size_t)k;
	}
	if (fd >= 0) close(fd);
	return got == n ? 0 : -1;
}

static int ct_eq(const uint8_t *a, const uint8_t *b, size_t n)
{
	unsigned d = 0;
	for (size_t i = 0; i < n; i++) d |= (unsigned)(a[i] ^ b[i]);
	return d == 0;
}

static void to_hex(const uint8_t *p, size_t n, char *out)
{
	static const char h[] = "0123456789abcdef";
	for (size_t i = 0; i < n; i++) {
		out[2 * i] = h[p[i] >> 4];
		out[2 * i + 1] = h[p[i] & 15];
	}
	out[2 * n] = 0;
}

static int from_hex(const char *s, uint8_t *out, size_t n)
{
	if (strlen(s) != 2 * n) return -1;
	for (size_t i = 0; i < n; i++) {
		int v = 0;
		for (int j = 0; j < 2; j++) {
			char c = s[2 * i + j];
			int x = c >= '0' && c <= '9' ? c - '0' : c >= 'a' && c <= 'f' ? c - 'a' + 10 : -1;
			if (x < 0) return -1;
			v = v << 4 | x;
		}
		out[i] = (uint8_t)v;
	}
	return 0;
}

/* A code as typed (any case; spaces and dashes ignored) to its 26 characters. 0, or -1 if it
 * isn't one. */
static int rc_norm(const char *in, size_t n, char out[RC_LEN + 1])
{
	size_t k = 0;
	for (size_t i = 0; i < n; i++) {
		char c = in[i];
		if (c == ' ' || c == '-') continue;
		if (c >= 'a' && c <= 'z') c = (char)(c - 'a' + 'A');
		if (!c || !strchr(b32, c) || k == RC_LEN) return -1;
		out[k++] = c;
	}
	out[k] = 0;
	return k == RC_LEN ? 0 : -1;
}

/* "ABCD-EFGH-…-YZ" for showing. */
static void rc_show(const char *code, char out[40])
{
	size_t o = 0;
	for (int i = 0; i < RC_LEN; i++) {
		if (i && i % 4 == 0) out[o++] = '-';
		out[o++] = code[i];
	}
	out[o] = 0;
}

static int rc_new(char code[RC_LEN + 1])
{
	uint8_t r[RC_LEN];
	if (urandom(r, sizeof r)) return fail("%s", "can't read /dev/urandom");
	for (int i = 0; i < RC_LEN; i++) code[i] = b32[r[i] & 31];      /* 256 = 8 x 32: uniform */
	code[RC_LEN] = 0;
	memset(r, 0, sizeof r);
	return 0;
}

struct rc { unsigned long iter; uint8_t salt[RC_SALT], hash[32]; char user[40]; };

/* DIR/recovery, parsed. 0, 1 if there is none (or it is malformed: reported), -1 if unreadable.
 * Uses lines[]. */
static int rc_load(struct rc *r)
{
	char p[512];
	struct stat st;
	int seen = 0;
	memset(r, 0, sizeof *r);
	path_of(p, sizeof p, "recovery");
	if (stat(p, &st)) return errno == ENOENT ? 1 : -1;
	if (load("recovery")) return -1;
	for (int i = 0; i < nlines; i++) {
		char *v = strchr(lines[i], '=');
		if (!v) continue;
		*v++ = 0;
		if (!strcmp(lines[i], "algo") && !strcmp(v, "pbkdf2-sha256")) seen |= 1;
		else if (!strcmp(lines[i], "iterations") && strlen(v) <= 8 && strspn(v, "0123456789") == strlen(v) &&
			 *v) {
			r->iter = strtoul(v, NULL, 10);
			if (r->iter >= RC_ITER_MIN && r->iter <= RC_ITER_MAX) seen |= 2;
		} else if (!strcmp(lines[i], "salt") && !from_hex(v, r->salt, RC_SALT)) seen |= 4;
		else if (!strcmp(lines[i], "hash") && !from_hex(v, r->hash, 32)) seen |= 8;
		else if (!strcmp(lines[i], "user") && (!*v || valid_name(v))) snprintf(r->user, sizeof r->user, "%s", v);
	}
	nlines = 0;
	if (seen != 15) {
		fprintf(stderr, "camcfg: %s is malformed\n", p);
		return 1;
	}
	return 0;
}

static int rc_verify(const char *code, const struct rc *r)
{
	uint8_t dk[32];
	pbkdf2_sha256((const uint8_t *)code, RC_LEN, r->salt, RC_SALT, r->iter, dk, sizeof dk);
	int ok = ct_eq(dk, r->hash, sizeof dk);
	memset(dk, 0, sizeof dk);
	return ok;
}

/* Replace DIR/recovery with the hash of `code` (normalised) for `user`. Call under the lock. */
static int rc_store(const char *code, const char *user)
{
	static char rows[5][MAX_LINE];
	uint8_t salt[RC_SALT], dk[32];
	char sh[2 * RC_SALT + 1], dh[65], p[512];
	if (urandom(salt, sizeof salt)) return fail("%s", "can't read /dev/urandom");
	pbkdf2_sha256((const uint8_t *)code, RC_LEN, salt, sizeof salt, RC_ITER, dk, sizeof dk);
	to_hex(salt, sizeof salt, sh);
	to_hex(dk, sizeof dk, dh);
	snprintf(rows[0], MAX_LINE, "algo=pbkdf2-sha256");
	snprintf(rows[1], MAX_LINE, "iterations=%lu", RC_ITER);
	snprintf(rows[2], MAX_LINE, "salt=%s", sh);
	snprintf(rows[3], MAX_LINE, "hash=%s", dh);
	snprintf(rows[4], MAX_LINE, "user=%s", user);
	path_of(p, sizeof p, "recovery");
	int rc = save_rows(p, rows[0], MAX_LINE, 5);
	memset(dk, 0, sizeof dk);
	memset(dh, 0, sizeof dh);
	return rc;
}

/* stdin, whole (at most STDIN_CAP bytes), split into at most `max` lines (a CR before the
 * newline dropped, a last line without one taken). Each row is NUL-terminated in buf, with its
 * real length in len (a NUL inside shows as len > strlen). The number of lines, or -1 with the
 * reason. */
static int read_rows(char *buf, size_t cap, char **row, size_t *len, int max)
{
	size_t got = 0;
	ssize_t k;
	int n = 0;
	while (got < cap - 1 && (k = read(0, buf + got, cap - 1 - got)) != 0) {
		if (k < 0 && errno == EINTR) continue;
		if (k < 0) { fail("%s", "can't read stdin"); return -1; }
		got += (size_t)k;
	}
	if (got == cap - 1) {
		char c;
		if (read(0, &c, 1) > 0) { fail("%s", "input too long"); return -1; }
	}
	buf[got] = 0;
	for (size_t i = 0; i < got;) {
		char *nl = memchr(buf + i, '\n', got - i);
		size_t e = nl ? (size_t)(nl - buf) : got, l = e - i;
		if (n == max) { fail("%s", "too many lines on stdin"); return -1; }
		buf[e] = 0;
		if (l && buf[i + l - 1] == '\r') buf[i + --l] = 0;
		row[n] = buf + i;
		len[n++] = l;
		i = e + 1;
	}
	return n;
}

static int admin_index(void)                     /* in lines[] (the users file), or -1 */
{
	for (int i = 0; i < nlines; i++) {
		char *a = strchr(lines[i], ':');
		if (a && !strncmp(a + 1, "admin:", 6)) return i;
	}
	return -1;
}

/* ---- DATA lock (docs/PLAN-DATA-LOCK.md Part 2, #174) ------------------------------------- */

/* rcS's data-check writes /run/data-failed ($CAMCFG_DATA_FAILED in tests) when DATA didn't mount
 * or lost the users file of a claimed camera: the camera is locked until a signed recovery. */
static int data_failed(void)
{
	const char *p = getenv("CAMCFG_DATA_FAILED");
	return !access(p ? p : "/run/data-failed", F_OK);
}

/* DIR/claimed: written once the camera has an admin, as a file of its own (its own jffs2 inode),
 * so a DATA that later loses the users file still shows the camera was claimed. */
static int marked(void)
{
	char p[512];
	path_of(p, sizeof p, "claimed");
	return !access(p, F_OK);
}

static int mark_claimed(void)
{
	static char row[MAX_LINE] = "claimed: rcS locks the camera if the users file is lost (#174)";
	char p[512];
	path_of(p, sizeof p, "claimed");
	return save_rows(p, row, MAX_LINE, 1);
}

/* camcfg claim NAME: the first admin, with an optional SSH key and a new recovery code. */
static int cmd_claim(const char *name)
{
	static char in[STDIN_CAP], key[KEY_LINE + 2];
	static struct key k;
	char *row[3], pw[80], code[RC_LEN + 1], shown[40];
	size_t len[3];
	int num = 0;
	if (!valid_name(name)) return fail("%s", "user names: 1-32 of A-Z a-z 0-9 . _ -");
	int n = read_rows(in, sizeof in, row, len, 2);
	if (n < 0) return 1;
	if (n < 1) return fail("%s", "no password on stdin");
	int r = pw_check(name, row[0], len[0], pw, sizeof pw);
	memset(row[0], 0, len[0]);
	if (r) return 1;
	size_t l = n == 2 ? len[1] : 0;                  /* the key line, trailing blanks dropped */
	while (l && (row[1][l - 1] == ' ' || row[1][l - 1] == '\t')) l--;
	if (l) {
		const char *why = "key line: printable ASCII only, one line";
		if (l < sizeof key && !memchr(row[1], 0, l)) {
			memcpy(key, row[1], l);
			key[l] = 0;
			why = key_check(key, &k);
		}
		if (*why) { memset(pw, 0, sizeof pw); return fail("%s", why); }
	}
	if (lock_dir() < 0) return fail("can't lock %s", dir);
	if (load("users")) return fail("%s", "can't read users");
	if (admin_index() >= 0) { memset(pw, 0, sizeof pw); return fail("%s", "this camera is already claimed: it has an admin"); }
	if (data_failed() || marked()) {
		memset(pw, 0, sizeof pw);
		return fail("%s", "DATA has failed (or lost the users file of a claimed camera): the camera is locked, "
			    "a claim can't unlock it (docs/PLAN-DATA-LOCK.md)");
	}
	if (find(name, ':') >= 0) { memset(pw, 0, sizeof pw); return fail("user %s exists", name); }
	if (nlines == MAX_LINES) { memset(pw, 0, sizeof pw); return fail("%s", "too many users"); }
	char rp[512];
	path_of(rp, sizeof rp, "recovery");
	if (rc_new(code) || rc_store(code, name)) {
		memset(pw, 0, sizeof pw);
		memset(code, 0, sizeof code);
		unlink(rp);
		return 1;
	}
	snprintf(lines[nlines++], MAX_LINE, "%s:admin:%s", name, pw);
	memset(pw, 0, sizeof pw);
	r = save("users");
	memset(lines[--nlines], 0, MAX_LINE);            /* lines[] is the users file as it was */
	if (r) {
		memset(code, 0, sizeof code);
		unlink(rp);
		return 1;
	}
	/* The key only once the admin is stored, so a claim that fails leaves no root key behind for
	 * whoever claims next. If it can't be added, undo the claim: the camera stays unclaimed. */
	if (*key && key_append(key, &k, 1, &num)) {
		memset(code, 0, sizeof code);
		if (save("users"))
			return fail("can't undo the claim: %s is the admin, without the SSH key", name);
		unlink(rp);
		return fail("%s", "claim undone: the camera is still unclaimed");
	}
	users_changed();
	if (mark_claimed())                              /* the claim stands; data-check marks it at boot */
		fprintf(stderr, "camcfg: claimed, but %s/claimed wasn't written\n", dir);
	rc_show(code, shown);
	printf("recovery-code: %s\n", shown);
	memset(code, 0, sizeof code);
	return 0;
}

/* camcfg recover [NAME]: the recovery code resets an admin's password, and is replaced. */
static int cmd_recover(const char *want)
{
	static char in[1024];
	char *row[2], pw[80], code[RC_LEN + 1], fresh[RC_LEN + 1], shown[40], name[40];
	size_t len[2];
	struct rc r;
	if (want && !valid_name(want)) return fail("%s", "user names: 1-32 of A-Z a-z 0-9 . _ -");
	int n = read_rows(in, sizeof in, row, len, 2);
	if (n < 0) return 1;
	if (n < 2) return fail("%s", "stdin: the recovery code line, then the new password line");
	if (lock_dir() < 0) return fail("can't lock %s", dir);
	int lr = rc_load(&r);
	if (lr < 0) return fail("%s", "can't read the recovery file");
	int ok = !lr && !rc_norm(row[0], len[0], code) && rc_verify(code, &r);
	memset(row[0], 0, len[0]);
	memset(code, 0, sizeof code);
	if (!ok) {
		memset(row[1], 0, len[1]);
		fprintf(stderr, "camcfg: %s\n", lr ? "no recovery code is set" : "wrong recovery code");
		return WRONG_CODE;
	}
	snprintf(name, sizeof name, "%s", want ? want : r.user);
	if (load("users")) return fail("%s", "can't read users");
	int i = *name ? find(name, ':') : -1;
	if (i < 0 || strncmp(strchr(lines[i], ':') + 1, "admin:", 6)) {
		memset(row[1], 0, len[1]);
		if (!*name) return fail("%s", "give the name of an admin to reset");
		return fail(want ? "no admin %s" : "the admin the code was made for (%s) is gone: give an admin's name", name);
	}
	int bad = pw_check(name, row[1], len[1], pw, sizeof pw);
	memset(row[1], 0, len[1]);
	if (bad) return 1;
	snprintf(lines[i], MAX_LINE, "%s:admin:%s", name, pw);
	memset(pw, 0, sizeof pw);
	bad = save("users");
	memset(lines[i], 0, MAX_LINE);
	if (bad) return 1;
	users_changed();
	if (rc_new(fresh) || rc_store(fresh, name))
		return fail("%s", "password changed, but the recovery code wasn't replaced: the old one still works");
	rc_show(fresh, shown);
	printf("admin: %s\nrecovery-code: %s\n", name, shown);
	memset(fresh, 0, sizeof fresh);
	return 0;
}

/* camcfg recovery set | check */
static int cmd_recovery(const char *op)
{
	static char in[256];
	char *row[1], code[RC_LEN + 1];
	size_t len[1];
	struct rc r;
	int n;
	if (strcmp(op, "set") && strcmp(op, "check")) return 2;
	if ((n = read_rows(in, sizeof in, row, len, 1)) < 0) return 1;
	int bad = n < 1 || rc_norm(row[0], len[0], code);
	memset(in, 0, sizeof in);
	if (bad) return fail("%s", "a recovery code is 26 letters A-Z and digits 2-7 (dashes and spaces ignored)");
	if (!strcmp(op, "check")) {
		int lr = rc_load(&r), ok = !lr && rc_verify(code, &r);
		memset(code, 0, sizeof code);
		if (lr < 0) return fail("%s", "can't read the recovery file");
		if (lr) return fail("%s", "no recovery code is set");
		return ok ? 0 : fail("%s", "wrong recovery code");
	}
	if (lock_dir() < 0) return fail("can't lock %s", dir);
	if (rc_load(&r) < 0) return fail("%s", "can't read the recovery file");
	bad = rc_store(code, r.user);
	memset(code, 0, sizeof code);
	return bad;
}

/* ---- HTTPS: the camera's CA and server certificate (docs/PLAN-TLS.md §B) ------------------ */

#define TLS_HELPER_MS 10000            /* camtls gen-ca / issue / check: at most 10 s each */

static long ms_now(void)
{
	struct timespec t;
	clock_gettime(CLOCK_MONOTONIC, &t);
	return (long)t.tv_sec * 1000 + t.tv_nsec / 1000000;
}

/* Run camtls with argv (argv[0] "camtls"; no shell, PATH as its only environment, stdin
 * /dev/null) and keep what it prints (stdout and stderr, at most cap - 1 bytes, trailing blanks
 * dropped) in out. Its exit status, or -1 if it couldn't run, was killed or took longer than
 * TLS_HELPER_MS (then killed; out says so). */
static int run_camtls(char *argv[], char *out, size_t cap)
{
	const char *bin = getenv("CAMCFG_CAMTLS");
	char *envp[] = { "PATH=/usr/sbin:/usr/bin:/sbin:/bin", NULL };
	size_t got = 0;
	int p[2], st, timed_out = 0;
	if (!bin) bin = "/usr/sbin/camtls";
	*out = 0;
	if (pipe(p)) return -1;
	fflush(stdout);
	fflush(stderr);
	pid_t pid = fork();
	if (pid < 0) {
		close(p[0]);
		close(p[1]);
		snprintf(out, cap, "can't fork: %s", strerror(errno));
		return -1;
	}
	if (pid == 0) {
		int nul = open("/dev/null", O_RDONLY);
		if (nul < 0 || dup2(nul, 0) < 0 || dup2(p[1], 1) < 0 || dup2(p[1], 2) < 0) _exit(127);
		close(p[0]);
		execve(bin, argv, envp);
		dprintf(2, "can't run %s: %s\n", bin, strerror(errno));
		_exit(127);
	}
	close(p[1]);
	long end = ms_now() + TLS_HELPER_MS;
	for (;;) {                                   /* its output until EOF (more than cap: dropped) */
		long left = end - ms_now();
		struct pollfd pf = { p[0], POLLIN, 0 };
		if (left <= 0) { timed_out = 1; break; }
		int r = poll(&pf, 1, (int)left);
		if (r < 0 && errno == EINTR) continue;
		if (r <= 0) { timed_out = r == 0; break; }
		char buf[512];
		ssize_t n = read(p[0], buf, sizeof buf);
		if (n < 0 && errno == EINTR) continue;
		if (n <= 0) break;
		size_t k = (size_t)n < cap - 1 - got ? (size_t)n : cap - 1 - got;
		memcpy(out + got, buf, k);
		got += k;
	}
	close(p[0]);
	out[got] = 0;
	while (!timed_out) {                         /* then its exit, within the same 10 s */
		pid_t w = waitpid(pid, &st, WNOHANG);
		if (w == pid) break;
		if (w < 0 && errno != EINTR) { timed_out = 1; break; }
		if (ms_now() >= end) { timed_out = 1; break; }
		usleep(10000);
	}
	if (timed_out) {
		kill(pid, SIGKILL);
		while (waitpid(pid, &st, 0) < 0 && errno == EINTR) {}
		snprintf(out, cap, "camtls %s: no answer within %d s (killed)", argv[1], TLS_HELPER_MS / 1000);
		return -1;
	}
	for (char *c = out; *c; c++)                 /* a message line, not a terminal sequence */
		if ((*c < ' ' && *c != '\n') || *c == 0x7f) *c = '?';
	while (got && (out[got - 1] == '\n' || out[got - 1] == ' ')) out[--got] = 0;
	if (WIFEXITED(st)) return WEXITSTATUS(st);
	snprintf(out, cap, "camtls %s: killed by signal %d", argv[1], WIFSIGNALED(st) ? WTERMSIG(st) : 0);
	return -1;
}

/* camtls as a helper of init/renew: 0 if it exited 0, else 1 with its message */
static int tls_helper(char *argv[])
{
	char out[1024];
	int rc = run_camtls(argv, out, sizeof out);
	if (rc == 0) return 0;
	if (rc < 0) return fail("%s", *out ? out : "camtls didn't run");
	fprintf(stderr, "camcfg: camtls %s failed (exit %d)%s%s\n", argv[1], rc, *out ? ": " : "", out);
	return 1;
}

/* s is an IPv4 address in its usual form (a.b.c.d, no leading zeros) */
static int valid_ipv4(const char *s)
{
	struct in_addr a;
	char back[INET_ADDRSTRLEN];
	return strlen(s) < sizeof back && inet_pton(AF_INET, s, &a) == 1 &&
	       inet_ntop(AF_INET, &a, back, sizeof back) && !strcmp(back, s);
}

/* eth0's IPv4 address (SIOCGIFADDR) into ip; -1 if it has none (no DHCP lease yet) */
static int eth0_ipv4(char *ip, size_t cap)
{
	struct ifreq ifr;
	struct sockaddr_in sin;
	int fd = socket(AF_INET, SOCK_DGRAM, 0), r = -1;
	if (fd < 0) return -1;
	memset(&ifr, 0, sizeof ifr);
	snprintf(ifr.ifr_name, sizeof ifr.ifr_name, "%s", "eth0");
	if (!ioctl(fd, SIOCGIFADDR, &ifr) && ifr.ifr_addr.sa_family == AF_INET) {
		memcpy(&sin, &ifr.ifr_addr, sizeof sin);
		r = inet_ntop(AF_INET, &sin.sin_addr, ip, (socklen_t)cap) ? 0 : -1;
	}
	close(fd);
	return r;
}

/* Remove a helper directory and what is in it (files only: camtls writes no directories). */
static void tls_rmtmp(const char *tmp)
{
	DIR *d = opendir(tmp);
	struct dirent *e;
	char p[800];
	if (d) {
		while ((e = readdir(d)))
			if (strcmp(e->d_name, ".") && strcmp(e->d_name, "..")) {
				snprintf(p, sizeof p, "%s/%s", tmp, e->d_name);
				unlink(p);
			}
		closedir(d);
	}
	rmdir(tmp);
}

/* Under the lock: helper directories a power cut left behind (DATA is 1 MiB) */
static void tls_sweep(const char *td)
{
	DIR *d = opendir(td);
	struct dirent *e;
	char p[800];
	if (!d) return;
	while ((e = readdir(d)))
		if (!strncmp(e->d_name, ".new-", 5)) {
			snprintf(p, sizeof p, "%s/%s", td, e->d_name);
			tls_rmtmp(p);
		}
	closedir(d);
}

/* tmp/name -> td/name: a non-empty regular file, made 0600 and fsync'd, then renamed over */
static int tls_install(const char *tmp, const char *td, const char *name)
{
	char from[800], to[800];
	struct stat st;
	snprintf(from, sizeof from, "%s/%s", tmp, name);
	snprintf(to, sizeof to, "%s/%s", td, name);
	int fd = open(from, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
	if (fd < 0 || fstat(fd, &st) || !S_ISREG(st.st_mode) || st.st_size == 0 || st.st_size > MAX_FILE ||
	    fchmod(fd, 0600) || fsync(fd)) {
		if (fd >= 0) close(fd);
		return fail("camtls left no usable %s", name);
	}
	close(fd);
	if (rename(from, to)) return fail("can't replace %s", to);
	return 0;
}

/* camcfg tls init|renew|show [IP]; -1: not a tls command (usage) */
static int cmd_tls(int argc, char **argv)
{
	char ip[INET_ADDRSTRLEN] = "", td[512], tmp[600], p[700], out[1024];
	const char *op = argv[0];
	int init = !strcmp(op, "init");
	if (!init && strcmp(op, "renew") && strcmp(op, "show")) return -1;
	if (argc == 2) {
		if (!valid_ipv4(argv[1])) return fail("%s", "IP: the camera's IPv4 address (a.b.c.d)");
		snprintf(ip, sizeof ip, "%s", argv[1]);
	}
	path_of(td, sizeof td, "tls");
	if (!strcmp(op, "show")) {
		char *av[] = { "camtls", "check", td, *ip ? ip : NULL, NULL };
		int rc = run_camtls(av, out, sizeof out);
		if (rc < 0 || rc == 127) {
			fprintf(stderr, "camcfg: %s\n", *out ? out : "camtls didn't run");
			return 2;
		}
		if (*out) puts(out);
		return rc;
	}
	if (mkdir(td, 0700) && errno != EEXIST) return fail("can't create %s", td);
	if (lock_dir() < 0) return fail("can't lock %s", dir);
	tls_sweep(td);
	snprintf(p, sizeof p, "%s/ca.crt", td);
	int have = !access(p, F_OK);
	if (init && have) {
		puts("exists");
		return 0;
	}
	if (!init && !have) return fail("%s", "no CA yet: camcfg tls init makes it");
	if (!*ip && eth0_ipv4(ip, sizeof ip)) return fail("%s", "eth0 has no IPv4 address (yet): give the IP");
	snprintf(tmp, sizeof tmp, "%s/.new-XXXXXX", td);
	if (!mkdtemp(tmp)) return fail("can't make a directory in %s", td);
	int rc = 1;
	if (init) {
		char *gen[] = { "camtls", "gen-ca", tmp, NULL };
		char *iss[] = { "camtls", "issue", tmp, ip, tmp, NULL };
		/* ca.crt last: it is what says the CA exists */
		rc = tls_helper(gen) || tls_helper(iss) || tls_install(tmp, td, "ca.key") ||
		     tls_install(tmp, td, "server.key") || tls_install(tmp, td, "server.crt") ||
		     tls_install(tmp, td, "ca.crt");
	} else {
		char *iss[] = { "camtls", "issue", td, ip, tmp, NULL };
		snprintf(p, sizeof p, "%s/server.key", tmp);
		rc = tls_helper(iss) || (!access(p, F_OK) && tls_install(tmp, td, "server.key")) ||
		     tls_install(tmp, td, "server.crt");
	}
	tls_rmtmp(tmp);
	int dfd = open(td, O_RDONLY | O_CLOEXEC);    /* the renames themselves */
	if (dfd >= 0) {
		if (fsync(dfd) && !rc) rc = fail("can't sync %s", td);
		close(dfd);
	}
	if (rc) return 1;
	printf(init ? "made: CA and server certificate for %s\n" : "renewed: server certificate for %s\n", ip);
	return 0;
}

/* ---- settings backup (docs/PLAN-DATA-LOCK.md Part 1, #171) ------------------------------- */

#define BK_MAX (1024 * 1024)           /* a whole .cambak (DATA is 1 MiB) */
#define BK_HDR 512                     /* its text header, at most */
#define BK_ABYTES crypto_aead_xchacha20poly1305_ietf_ABYTES
#define BK_NONCE crypto_aead_xchacha20poly1305_ietf_NPUBBYTES
#define BK_KEY crypto_aead_xchacha20poly1305_ietf_KEYBYTES
#define BK_SALT crypto_pwhash_SALTBYTES
/* Argon2id: BK_OPS passes over BK_MEM. The camera has 64 MiB and about 11 MiB free while
 * streaming (docs/UPDATE-PATH.md), so the memory stays small and the passes make it slow; both are
 * to be measured on cam #1 (target about 2 s). Import takes a file's own values within the
 * bounds, so a file can't make camcfg take much memory or time. */
#define BK_OPS 8UL
#define BK_MEM (4UL << 20)
#define BK_OPS_MAX 32UL
#define BK_MEM_MIN (1UL << 20)
#define BK_MEM_MAX (8UL << 20)
#define PP_MIN 12
#define PP_MAX 256
#define BK_LABEL "cam-backup device 1\n"

/* What a backup holds, in DIR, in the archive's order. Import writes them in this order too:
 * ca.crt after the other TLS files (it is what says the CA exists), users last (a power cut
 * before it leaves an unclaimed camera unclaimed). text: lines of at most maxline bytes, at most
 * maxrows non-empty ones (the limits load() and keys_load() take); else any bytes, not empty. */
static const struct bk_file {
	const char *name;
	int text, maxline, maxrows;
} bk_files[] = {
	{ "cam.conf", 1, MAX_LINE - 1, MAX_LINES },
	{ "recovery", 1, MAX_LINE - 1, MAX_LINES },
	{ "ssh/authorized_keys", 1, KEY_LINE - 1, KEY_ROWS },
	{ "ssh/dropbear_ed25519_host_key", 0, 0, 0 },
	{ "tls/ca.key", 0, 0, 0 },
	{ "tls/server.key", 0, 0, 0 },
	{ "tls/server.crt", 0, 0, 0 },
	{ "tls/ca.crt", 0, 0, 0 },
	{ "users", 1, MAX_LINE - 1, MAX_LINES },
};
#define NBK (int)(sizeof bk_files / sizeof bk_files[0])
#define BK_USERS (NBK - 1)
#define BK_TLS 4                       /* tls/ca.key .. tls/ca.crt: all four or none */

static uint8_t bk_buf[BK_MAX + 1], bk_plain[BK_MAX];

/* This camera's ID for backups: the first 16 bytes of SHA-256(BK_LABEL, then eth0's MAC in lower
 * case), in hex. The MAC is U-Boot's (ethaddr in its env at mtd0 + 0x3F000, read as rcS reads it;
 * $CAMCFG_MTD0 in tests), so the ID survives a lost DATA. It doesn't print the MAC, but doesn't
 * hide it either: a maker's 2^24 MACs are quick to try. -1 without a valid ethaddr. */
static int device_id(char out[33])
{
	const char *dev = getenv("CAMCFG_MTD0");
	char env[4097], mac[18], msg[64];
	uint8_t h[32];
	int fd = open(dev ? dev : "/dev/mtd0", O_RDONLY | O_CLOEXEC);
	ssize_t n = fd < 0 ? -1 : pread(fd, env, 4096, 0x3F000);
	if (fd >= 0) close(fd);
	if (n <= 0) return -1;
	env[n] = 0;
	*mac = 0;
	for (ssize_t i = 0; i < n && !*mac; i += (ssize_t)strlen(env + i) + 1)
		if (!strncmp(env + i, "ethaddr=", 8) && strlen(env + i + 8) == 17)
			snprintf(mac, sizeof mac, "%s", env + i + 8);
	if (!*mac) return -1;
	for (int i = 0; i < 17; i++) {
		char c = mac[i];
		if (i % 3 == 2 ? c != ':' : !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')))
			return -1;
		if (c >= 'A' && c <= 'F') mac[i] = (char)(c - 'A' + 'a');
	}
	int ml = snprintf(msg, sizeof msg, "%s%s", BK_LABEL, mac);
	sha256((const uint8_t *)msg, (size_t)ml, h);
	to_hex(h, 16, out);
	return 0;
}

/* One line from fd 0, a byte at a time (nothing after it is consumed), a CR before the newline
 * dropped: its length, or -1 if it is longer than cap - 1 or stdin fails. */
static ssize_t read_line0(char *buf, size_t cap)
{
	size_t n = 0;
	for (;;) {
		char c;
		ssize_t k = read(0, &c, 1);
		if (k < 0 && errno == EINTR) continue;
		if (k < 0) return -1;
		if (k == 0 || c == '\n') break;
		if (n == cap - 1) return -1;
		buf[n++] = c;
	}
	if (n && buf[n - 1] == '\r') n--;
	buf[n] = 0;
	return (ssize_t)n;
}

/* The passphrase, stdin's first line: PP_MIN..PP_MAX bytes, no control characters (UTF-8 is
 * fine). On a terminal it is asked for with echo off, twice if `twice`. Its length, or -1 with
 * the reason. */
static int read_pp(char pp[PP_MAX + 1], int twice)
{
	struct termios t0, t1;
	char again[PP_MAX + 1];
	int tty = isatty(0) && !tcgetattr(0, &t0), same = 1;
	if (tty) {
		t1 = t0;
		t1.c_lflag &= ~(tcflag_t)ECHO;
		tcsetattr(0, TCSAFLUSH, &t1);
		fputs("backup passphrase: ", stderr);
	}
	ssize_t n = read_line0(pp, PP_MAX + 1);
	if (tty && twice && n >= 0) {
		fputs("\nagain: ", stderr);
		ssize_t m = read_line0(again, sizeof again);
		same = m == n && !memcmp(pp, again, (size_t)n);
		sodium_memzero(again, sizeof again);
	}
	if (tty) {
		tcsetattr(0, TCSAFLUSH, &t0);
		fputc('\n', stderr);
	}
	const char *why = n < 0 ? "passphrase: at most 256 bytes, on one line" :
			  !same ? "the passphrases don't match" :
			  n < PP_MIN ? "passphrase: at least 12 characters (the file holds the passwords and the CA key)" : NULL;
	for (ssize_t i = 0; !why && i < n; i++)
		if ((unsigned char)pp[i] < ' ' || pp[i] == 0x7f) why = "passphrase: no control characters";
	if (why) {
		sodium_memzero(pp, PP_MAX + 1);
		fail("%s", why);
		return -1;
	}
	return (int)n;
}

/* The installed version (/etc/cam/version, as camupdate reads it) for the header, or "unknown" */
static void fw_version(char *out, size_t cap)
{
	FILE *f = fopen("/etc/cam/version", "r");
	char v[64] = "";
	if (f) {
		if (!fgets(v, sizeof v, f)) *v = 0;
		fclose(f);
	}
	v[strcspn(v, "\n")] = 0;
	size_t n = strlen(v);
	snprintf(out, cap, "%s", n && n <= 32 && strspn(v, "0123456789.") == n ? v : "unknown");
}

static int bk_key(uint8_t key[BK_KEY], const char *pp, int pl, const uint8_t *salt, unsigned long ops,
		  unsigned long mem)
{
	if (crypto_pwhash(key, BK_KEY, pp, (unsigned long long)pl, salt, ops, mem, crypto_pwhash_ALG_ARGON2ID13))
		return fail("%s", "not enough memory for the passphrase's key (Argon2id)");
	return 0;
}

/* DIR/name, whole, into p (at most cap bytes): its size, -2 if it doesn't exist, or -1 (not a
 * regular file, larger than MAX_FILE or cap, unreadable). */
static long bk_read(const char *name, uint8_t *p, size_t cap)
{
	char path[600];
	struct stat st;
	size_t got = 0;
	path_of(path, sizeof path, name);
	int fd = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
	if (fd < 0) return errno == ENOENT ? -2 : -1;
	if (fstat(fd, &st) || !S_ISREG(st.st_mode) || st.st_size > MAX_FILE || (size_t)st.st_size > cap) {
		close(fd);
		return -1;
	}
	while (got < (size_t)st.st_size) {
		ssize_t k = read(fd, p + got, (size_t)st.st_size - got);
		if (k < 0 && errno == EINTR) continue;
		if (k <= 0) break;
		got += (size_t)k;
	}
	close(fd);
	return got == (size_t)st.st_size ? (long)got : -1;
}

struct bk_hdr {
	char device[33], firmware[40], created[24];
	unsigned long ops, mem;
	uint8_t salt[BK_SALT], nonce[BK_NONCE];
	size_t len;                        /* the header's bytes, its empty line included */
};

/* "DIGITS" (no sign, no leading zero) up to max: 0, or -1 */
static int bk_uint(const char *s, unsigned long max, unsigned long *v)
{
	size_t n = strlen(s);
	if (!n || n > 10 || strspn(s, "0123456789") != n || (s[0] == '0' && n > 1)) return -1;
	*v = strtoul(s, NULL, 10);
	return *v <= max ? 0 : -1;
}

/* The text header at the start of b[0..n): the lines in this order, nothing else. 0, or -1 with
 * the reason in *why. */
static int bk_header(const uint8_t *b, size_t n, struct bk_hdr *h, const char **why)
{
	char t[BK_HDR + 1], *line[7], *f[4], *save = NULL;
	const uint8_t *end = memmem(b, n < BK_HDR ? n : BK_HDR, "\n\n", 2);
	*why = "not a camera backup (.cambak)";
	if (n < 13 || memcmp(b, "cam-backup ", 11)) return -1;
	if (memcmp(b, "cam-backup 1\n", 13)) {
		size_t d = 11;
		while (d < n && d < 20 && b[d] >= '0' && b[d] <= '9') d++;
		if (d > 11 && d < n && b[d] == '\n')
			*why = "a backup in a newer format: restore it with the firmware that made it";
		return -1;
	}
	if (!end) return -1;
	h->len = (size_t)(end - b) + 2;
	memcpy(t, b, h->len - 1);
	t[h->len - 1] = 0;
	if (strlen(t) != h->len - 1) return -1;          /* a NUL inside */
	int k = 0;
	for (char *p = t, *nl; k < 7 && (nl = strchr(p, '\n')); p = nl + 1) {
		*nl = 0;
		line[k++] = p;
	}
	*why = "the backup's header is damaged";
	if (k != 6) return -1;
	const char *dv = !strncmp(line[1], "device ", 7) ? line[1] + 7 : "",
		   *fw = !strncmp(line[2], "firmware ", 9) ? line[2] + 9 : "",
		   *cr = !strncmp(line[3], "created ", 8) ? line[3] + 8 : "",
		   *nc = !strncmp(line[5], "nonce ", 6) ? line[5] + 6 : "";
	uint8_t dbin[16];
	if (from_hex(dv, dbin, sizeof dbin) || !*fw || strlen(fw) >= sizeof h->firmware ||
	    strspn(fw, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._+-") != strlen(fw) ||
	    strlen(cr) >= sizeof h->created || strspn(cr, "0123456789") != strlen(cr) || !*cr ||
	    from_hex(nc, h->nonce, sizeof h->nonce) || strncmp(line[4], "kdf ", 4))
		return -1;
	int nf = 0;
	for (char *p = strtok_r(line[4] + 4, " ", &save); p; p = strtok_r(NULL, " ", &save))
		if (nf < 4) f[nf++] = p; else return -1;
	if (nf != 4 || strcmp(f[0], "argon2id") || from_hex(f[3], h->salt, sizeof h->salt)) return -1;
	*why = "the backup asks for Argon2id settings outside what this camera allows";
	if (bk_uint(f[1], BK_OPS_MAX, &h->ops) || h->ops < 1 || bk_uint(f[2], BK_MEM_MAX, &h->mem) ||
	    h->mem < BK_MEM_MIN)
		return -1;
	snprintf(h->device, sizeof h->device, "%s", dv);
	snprintf(h->firmware, sizeof h->firmware, "%s", fw);
	snprintf(h->created, sizeof h->created, "%s", cr);
	return 0;
}

/* The archive a[0..n) into p_[] and n_[] (by bk_files index; NULL: not in it), checked: names
 * from bk_files only, each once, sizes as given, then "end" and nothing after. 0, or -1 with
 * *why. */
static int bk_parse(const uint8_t *a, size_t n, const uint8_t *p_[NBK], size_t n_[NBK], const char **why)
{
	size_t i = 0;
	for (int j = 0; j < NBK; j++) { p_[j] = NULL; n_[j] = 0; }
	*why = "the backup's file list is damaged";
	for (;;) {
		const uint8_t *nl = memchr(a + i, '\n', n - i);
		if (!nl) return -1;
		size_t ll = (size_t)(nl - (a + i));
		char line[96], *sp;
		if (ll >= sizeof line || memchr(a + i, 0, ll)) return -1;
		memcpy(line, a + i, ll);
		line[ll] = 0;
		i += ll + 1;
		if (!strcmp(line, "end")) return i == n ? 0 : -1;
		if (strncmp(line, "file ", 5) || !(sp = strchr(line + 5, ' '))) return -1;
		*sp = 0;
		int j = 0;
		while (j < NBK && strcmp(bk_files[j].name, line + 5)) j++;
		unsigned long sz;
		if (j == NBK) { *why = "the backup holds a file this firmware doesn't restore"; return -1; }
		if (p_[j] || bk_uint(sp + 1, MAX_FILE, &sz) || n - i < sz + 1 || a[i + sz] != '\n') return -1;
		p_[j] = a + i;
		n_[j] = sz;
		i += sz + 1;
	}
}

/* The files' contents: text files' lines within their limits, binary ones not empty; users with
 * names and roles camcfg takes and an admin; the TLS files all four or none. "" or the reason. */
static const char *bk_check(const uint8_t *p_[NBK], const size_t n_[NBK])
{
	int tls = 0;
	if (!p_[BK_USERS]) return "the backup has no users file";
	for (int j = 0; j < NBK; j++) {
		const struct bk_file *bf = &bk_files[j];
		const uint8_t *p = p_[j];
		size_t n = n_[j];
		if (!p) continue;
		if (j >= BK_USERS - BK_TLS && j < BK_USERS) tls++;
		if (!bf->text) {
			if (!n) return "the backup holds an empty key or certificate";
			continue;
		}
		if (memchr(p, 0, n)) return "the backup's text files hold a NUL byte";
		int rows = 0, admin = 0;
		for (size_t i = 0; i < n;) {
			const uint8_t *nl = memchr(p + i, '\n', n - i);
			size_t ll = nl ? (size_t)(nl - (p + i)) : n - i;
			if (ll > (size_t)bf->maxline) return "the backup holds a line that is too long";
			if (ll && ++rows > bf->maxrows) return "the backup holds a file with too many lines";
			if (ll && j == BK_USERS) {
				char u[MAX_LINE], *a, *b;
				memcpy(u, p + i, ll);
				u[ll] = 0;
				a = strchr(u, ':');
				b = a ? strchr(a + 1, ':') : NULL;
				if (!b) { sodium_memzero(u, sizeof u); return "the backup's users file is damaged"; }
				*a = *b = 0;
				int ok = valid_name(u) && valid_role(a + 1);
				admin |= ok && !strcmp(a + 1, "admin");
				sodium_memzero(u, sizeof u);
				if (!ok) return "the backup's users file is damaged";
			}
			i += ll + 1;
		}
		if (j == BK_USERS && !admin) return "the backup's users file has no admin";
	}
	if (tls && tls != BK_TLS) return "the backup holds only part of the camera's CA and certificate";
	return "";
}

/* DIR/name := p[0..n), 0600, through a temp file that is fsync'd and renamed over it */
static int bk_write(const char *name, const uint8_t *p, size_t n)
{
	char path[600], tmp[620];
	size_t put = 0;
	path_of(path, sizeof path, name);
	snprintf(tmp, sizeof tmp, "%s.tmp", path);
	unlink(tmp);
	int fd = open(tmp, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
	if (fd < 0) return fail("can't write %s", tmp);
	while (put < n) {
		ssize_t k = write(fd, p + put, n - put);
		if (k < 0 && errno == EINTR) continue;
		if (k <= 0) break;
		put += (size_t)k;
	}
	int bad = put < n || fsync(fd);
	if (close(fd) || bad || rename(tmp, path)) {
		unlink(tmp);
		return fail("can't replace %s", path);
	}
	return 0;
}

static int bk_syncdir(const char *name)
{
	char p[600];
	path_of(p, sizeof p, name);
	int fd = open(p, O_RDONLY | O_DIRECTORY | O_CLOEXEC), bad = fd < 0 || fsync(fd);
	if (fd >= 0) close(fd);
	return bad ? fail("can't sync %s", p) : 0;
}

/* A backup file (FILE, or the rest of stdin) whole into bk_buf: its size, or -1 (said why). */
static long bk_read_file(const char *file)
{
	size_t n = 0;
	struct stat st;
	int fd = file ? open(file, O_RDONLY | O_CLOEXEC) : 0;
	if (fd < 0 || fstat(fd, &st) || (file && !S_ISREG(st.st_mode))) {
		if (fd > 0) close(fd);
		fail("can't read %s", file ? file : "stdin");
		return -1;
	}
	for (;;) {
		ssize_t k = read(fd, bk_buf + n, sizeof bk_buf - n);
		if (k < 0 && errno == EINTR) continue;
		if (k <= 0) break;
		n += (size_t)k;
		if (n == sizeof bk_buf) break;
	}
	if (fd > 0) close(fd);
	if (n > BK_MAX) { fail("%s", "larger than any backup (1 MiB)"); return -1; }
	return (long)n;
}

/* bk_buf[0..n) checked whole for this camera and decrypted with the passphrase into bk_plain,
 * the files in p_[]/n_[] (bk_parse, bk_check); the passphrase is wiped. 0; 1 (said why);
 * WRONG_CODE for a wrong passphrase (or a changed file). Nothing is written. */
static int bk_open(size_t n, char *pp, int ppl, struct bk_hdr *h, const uint8_t *p_[NBK], size_t n_[NBK],
		   unsigned long long *pl)
{
	char id[33];
	uint8_t key[BK_KEY];
	const char *why;
	why = device_id(id) ? "no valid ethaddr in U-Boot's env: no device ID, no restore" :
	      bk_header(bk_buf, n, h, &why) ? why :
	      strcmp(h->device, id) ? "this backup is from another camera: a backup restores only on the camera that made it" :
	      n - h->len < BK_ABYTES ? "the backup is cut short" : NULL;
	if (why) {
		sodium_memzero(pp, PP_MAX + 1);
		return fail("%s", why);
	}
	int bad = bk_key(key, pp, ppl, h->salt, h->ops, h->mem);
	sodium_memzero(pp, PP_MAX + 1);
	if (bad) return 1;
	bad = crypto_aead_xchacha20poly1305_ietf_decrypt(bk_plain, pl, NULL, bk_buf + h->len, n - h->len, bk_buf,
							  h->len, h->nonce, key);
	sodium_memzero(key, sizeof key);
	if (bad) {
		fprintf(stderr, "camcfg: wrong passphrase, or the backup was changed\n");
		return WRONG_CODE;
	}
	why = bk_parse(bk_plain, (size_t)*pl, p_, n_, &why) ? why : bk_check(p_, n_);
	if (*why) {
		sodium_memzero(bk_plain, (size_t)*pl);
		return fail("%s; nothing was changed", why);
	}
	return 0;
}

/* The checked files into DIR (each fsync'd and renamed, users last; listed files the backup
 * doesn't hold removed), then the claimed marker; bk_plain is wiped. Call under the lock. 0, or
 * 1 (said why). Its file count in *files. */
static int bk_write_all(const uint8_t *p_[NBK], const size_t n_[NBK], unsigned long long pl, int *files)
{
	char sub[600];
	path_of(sub, sizeof sub, "ssh");
	int bad = mkdir(sub, 0700) && errno != EEXIST;
	path_of(sub, sizeof sub, "tls");
	bad |= mkdir(sub, 0700) && errno != EEXIST;
	*files = 0;
	for (int j = 0; !bad && j < NBK; j++) {
		if (p_[j]) {
			bad = bk_write(bk_files[j].name, p_[j], n_[j]);
			(*files)++;
		} else {
			char p[600];
			path_of(p, sizeof p, bk_files[j].name);
			if (unlink(p) && errno != ENOENT) bad = fail("can't remove %s", p);
		}
	}
	sodium_memzero(bk_plain, (size_t)pl);
	if (!bad) bad = mark_claimed();                  /* its users file has an admin (bk_check) */
	if (!bad) bad = bk_syncdir("ssh") | bk_syncdir("tls") | bk_syncdir(".");
	return bad ? fail("%s", "the restore stopped part way: run it again") : 0;
}

/* camcfg backup import [FILE]: stdin's first line is the passphrase; the backup is FILE, or the
 * rest of stdin. Everything is checked in memory before anything is written. Exit 3 for a wrong
 * passphrase (or a changed file: the two can't be told apart), so a caller can count it. */
static int bk_import(const char *file)
{
	char pp[PP_MAX + 1], id[33];
	const uint8_t *p_[NBK];
	size_t n_[NBK];
	struct bk_hdr h;
	unsigned long long pl;
	int files;
	if (data_failed())
		return fail("%s", "DATA has failed: /mnt/nand isn't DATA now; restore with a signed recovery, camcfg unlock (docs/PLAN-DATA-LOCK.md)");
	if (device_id(id)) return fail("%s", "no valid ethaddr in U-Boot's env: no device ID, no restore");
	int ppl = read_pp(pp, 0);
	if (ppl < 0) return 1;
	long n = bk_read_file(file);
	if (n < 0) { sodium_memzero(pp, sizeof pp); return 1; }
	int rc = bk_open((size_t)n, pp, ppl, &h, p_, n_, &pl);
	if (rc) return rc;
	if (lock_dir() < 0) { sodium_memzero(bk_plain, (size_t)pl); return fail("can't lock %s", dir); }
	if (bk_write_all(p_, n_, pl, &files)) return 1;
	users_changed();
	printf("restored: %d files from a backup made at %s (Unix time, firmware %s); reboot the camera to apply them\n",
	       files, h.created, h.firmware);
	return 0;
}

/* camcfg backup export: stdin's first line is the passphrase; the .cambak goes to stdout. */
static int bk_export(void)
{
	static uint8_t ar[BK_MAX - BK_HDR - BK_ABYTES], one[MAX_FILE];
	char pp[PP_MAX + 1], id[33], ver[40] = "unknown", hdr[BK_HDR], salt_h[2 * BK_SALT + 1],
	     nonce_h[2 * BK_NONCE + 1];
	uint8_t salt[BK_SALT], nonce[BK_NONCE], key[BK_KEY];
	size_t n = 0;
	int files = 0;
	if (isatty(1)) return fail("%s", "the backup is binary: send it to a file (camcfg backup export > FILE)");
	if (device_id(id)) return fail("%s", "no valid ethaddr in U-Boot's env: no device ID, no backup");
	int pl = read_pp(pp, 1);
	if (pl < 0) return 1;
	randombytes_buf(salt, sizeof salt);
	randombytes_buf(nonce, sizeof nonce);
	int bad = bk_key(key, pp, pl, salt, BK_OPS, BK_MEM);    /* before the lock: it takes seconds */
	sodium_memzero(pp, sizeof pp);
	if (bad) return 1;
	if (lock_dir() < 0) { sodium_memzero(key, sizeof key); return fail("can't lock %s", dir); }
	char cp[600];
	path_of(cp, sizeof cp, "tls/ca.crt");
	int tls = !access(cp, F_OK);                 /* ca.crt says the CA exists (cmd_tls) */
	for (int i = 0; i < NBK; i++) {
		if (!tls && i >= BK_USERS - BK_TLS && i < BK_USERS) continue;
		char head[80];
		long sz = bk_read(bk_files[i].name, one, sizeof one);
		if (sz == -2 && i == BK_USERS) {
			sodium_memzero(key, sizeof key);
			sodium_memzero(ar, n);
			return fail("%s", "no users file: the camera isn't claimed, nothing to back up");
		}
		if (sz == -2 || (sz == 0 && !bk_files[i].text)) continue;   /* an empty host key: sshd-run makes one */
		int hl = snprintf(head, sizeof head, "file %s %ld\n", bk_files[i].name, sz);
		if (sz < 0 || n + (size_t)hl + (size_t)sz + 1 + 4 > sizeof ar) {
			sodium_memzero(key, sizeof key);
			sodium_memzero(ar, n);
			return fail("can't read %s (not a regular file, or too large)", bk_files[i].name);
		}
		memcpy(ar + n, head, (size_t)hl);
		memcpy(ar + n + hl, one, (size_t)sz);
		sodium_memzero(one, (size_t)sz);
		n += (size_t)hl + (size_t)sz;
		ar[n++] = '\n';
		files++;
	}
	memcpy(ar + n, "end\n", 4);
	n += 4;
	const uint8_t *p_[NBK];                     /* what import would refuse isn't written */
	size_t n_[NBK];
	const char *why;
	why = bk_parse(ar, n, p_, n_, &why) ? why : bk_check(p_, n_);
	if (*why) {
		sodium_memzero(key, sizeof key);
		sodium_memzero(ar, n);
		return fail("can't back up: %s", why);
	}
	fw_version(ver, sizeof ver);
	to_hex(salt, sizeof salt, salt_h);
	to_hex(nonce, sizeof nonce, nonce_h);
	int hl = snprintf(hdr, sizeof hdr, "cam-backup 1\ndevice %s\nfirmware %s\ncreated %lld\nkdf argon2id %lu %lu %s\nnonce %s\n\n",
			  id, ver, (long long)time(NULL), BK_OPS, BK_MEM, salt_h, nonce_h);
	{
		unsigned long long cl;
		memcpy(bk_buf, hdr, (size_t)hl);
		crypto_aead_xchacha20poly1305_ietf_encrypt(bk_buf + hl, &cl, ar, n, (const uint8_t *)hdr,
							   (unsigned long long)hl, NULL, nonce, key);
		size_t total = (size_t)hl + (size_t)cl, put = 0;
		while (put < total) {
			ssize_t k = write(1, bk_buf + put, total - put);
			if (k < 0 && errno == EINTR) continue;
			if (k <= 0) break;
			put += (size_t)k;
		}
		bad = put < total ? fail("%s", "can't write the backup to stdout") : 0;
		if (!bad) fprintf(stderr, "camcfg: backup of %d files, %zu bytes\n", files, total);
	}
	sodium_memzero(key, sizeof key);
	sodium_memzero(ar, n);
	return bad;
}

/* ---- signed recovery in lock mode (docs/PLAN-DATA-LOCK.md Part 3, #176) ------------------- */

#define RECOVER_NS "cam-recover"
#define SIG_MAX 4096                   /* an armored SSHSIG of an ed25519 or sk key is under 1 KiB */

/* What an update key signs to unlock this camera (scripts/cam-recover.py builds the same bytes):
 * "cam-recover 1", then challenge HEX64 (camhttpd's monitor's, one use, 10 minutes), device ID,
 * firmware VERSION, action restore|erase, backup SHA256-HEX of the .cambak file (or "none"),
 * each line ending in "\n". Its length, or -1 if it doesn't fit. */
static int recover_msg(char *out, size_t cap, const char *challenge, const char *id, const char *fw,
		       const char *action, const char *sha)
{
	int n = snprintf(out, cap, "cam-recover 1\nchallenge %s\ndevice %s\nfirmware %s\naction %s\nbackup %s\n",
			 challenge, id, fw, action, sha);
	return n > 0 && (size_t)n < cap ? n : -1;
}

/* Erase DATA: every erase block of mtd3 (MEMERASE). $CAMCFG_MTD3 in tests: a regular file there
 * is filled with 0xFF instead. 0, or 1 (said why). */
static int erase_data(void)
{
	const char *p = getenv("CAMCFG_MTD3");
	struct stat st;
	int fd = open(p ? p : "/dev/mtd3", O_RDWR | O_CLOEXEC), bad = 0;
	if (fd < 0 || fstat(fd, &st)) {
		if (fd >= 0) close(fd);
		return fail("can't open %s", p ? p : "/dev/mtd3");
	}
	if (S_ISREG(st.st_mode)) {
		uint8_t ff[4096];
		memset(ff, 0xff, sizeof ff);
		for (off_t o = 0; !bad && o < st.st_size; o += (off_t)sizeof ff) {
			size_t k = st.st_size - o < (off_t)sizeof ff ? (size_t)(st.st_size - o) : sizeof ff;
			bad = pwrite(fd, ff, k, o) != (ssize_t)k;
		}
		bad = bad || fsync(fd);
	} else {
#ifdef __linux__
		struct mtd_info_user mi;
		bad = ioctl(fd, MEMGETINFO, &mi) || !mi.erasesize || mi.size % mi.erasesize;
		if (!bad) {                                  /* the whole partition: the driver picks its steps */
			struct erase_info_user ei = { 0, mi.size };
			bad = ioctl(fd, MEMERASE, &ei) != 0;
		}
#else
		bad = 1;
#endif
	}
	close(fd);
	return bad ? fail("%s", "erasing DATA (mtd3) failed: the camera stays locked; try again, or the CH341A") : 0;
}

/* The erased DATA, mounted (jffs2, nosuid,nodev,noexec) on /run/recover for the restore, into
 * mnt. $CAMCFG_RECOVER_DIR in tests: that directory instead, nothing mounted. 0, or 1. */
static int mount_data(char *mnt, size_t cap, int *mounted)
{
	const char *t = getenv("CAMCFG_RECOVER_DIR");
	*mounted = 0;
	if (t) {
		snprintf(mnt, cap, "%s", t);
		return 0;
	}
	snprintf(mnt, cap, "/run/recover");
	if (mkdir(mnt, 0700) && errno != EEXIST) return fail("can't make %s", mnt);
#ifdef __linux__
	if (mount("/dev/mtdblock3", mnt, "jffs2", MS_NOSUID | MS_NODEV | MS_NOEXEC, NULL))
		return fail("the erased DATA doesn't mount (%s): reboot, then claim and restore at /setup", strerror(errno));
	*mounted = 1;
	return 0;
#else
	return fail("%s", "no jffs2 here");
#endif
}

/* The armored signature from stdin, a line at a time up to and with its END line (nothing after
 * it is consumed): its length in out, or -1. */
static long read_sig(char *out, size_t cap)
{
	static const char end[] = "-----END SSH SIGNATURE-----";
	size_t n = 0;
	for (int lines = 0; lines < 64; lines++) {
		char l[128];
		ssize_t k = read_line0(l, sizeof l);
		if (k < 0 || n + (size_t)k + 2 > cap) return -1;
		memcpy(out + n, l, (size_t)k);
		n += (size_t)k;
		out[n++] = '\n';
		out[n] = 0;
		if (!strcmp(l, end)) return (long)n;
	}
	return -1;
}

/* camcfg unlock restore [-c CHALLENGE] FILE|- | unlock erase [-c CHALLENGE]: lock mode only.
 * stdin: for restore, the backup's passphrase line; with -c (camhttpd's lock page), then the
 * armored signature over recover_msg() by a key in /etc/cam/update-keys ($CAMCFG_UPDATE_KEYS in
 * tests), namespace cam-recover; for restore with FILE "-", then the backup itself (the lock
 * page's upload is exactly this stdin). Without -c it is root's own action (in lock mode SSH takes
 * the update keys only, sshd-lock). Everything is checked before DATA is erased:
 * the signature, then for restore the backup whole (bk_open). Then mtd3 is erased; restore mounts
 * it, writes the files and the marker, and unmounts. The caller reboots. Exit 3 for a bad
 * signature or a wrong passphrase, so the caller can count it. */
static int cmd_unlock(int argc, char **argv)
{
	static char armor[SIG_MAX + 1];
	char pp[PP_MAX + 1] = "", id[33], fw[40], sha[65] = "none", msg[512], signer[256], mnt[512], d[600];
	const char *challenge = NULL, *file = NULL, *why;
	const uint8_t *p_[NBK];
	size_t n_[NBK];
	struct bk_hdr h;
	unsigned long long pl = 0;
	int restore = !strcmp(argv[0], "restore"), i = 1, ppl = 0, files = 0, mounted;
	long n = 0;
	if (!strcmp(argv[0], "info") && argc == 1) {     /* for camhttpd's challenge page */
		if (device_id(id)) return fail("%s", "no valid ethaddr in U-Boot's env: no device ID");
		fw_version(fw, sizeof fw);
		printf("device %s\nfirmware %s\n", id, fw);
		return 0;
	}
	if (!restore && strcmp(argv[0], "erase")) return -1;
	if (i + 1 < argc && !strcmp(argv[i], "-c")) { challenge = argv[i + 1]; i += 2; }
	if (restore && i < argc) file = argv[i++];
	if (i != argc || (restore && !file)) return -1;
	if (challenge && (strlen(challenge) != 64 || strspn(challenge, "0123456789abcdef") != 64))
		return fail("%s", "CHALLENGE: 64 lower-case hex digits");
	if (!data_failed()) return fail("%s", "the camera isn't locked (no /run/data-failed): use camcfg backup import");
	if (device_id(id)) return fail("%s", "no valid ethaddr in U-Boot's env: no device ID, no recovery");
	fw_version(fw, sizeof fw);
	if (restore && (ppl = read_pp(pp, 0)) < 0) return 1;
	long al = challenge ? read_sig(armor, sizeof armor) : 0;
	if (restore) {
		if ((n = bk_read_file(strcmp(file, "-") ? file : NULL)) < 0) { sodium_memzero(pp, sizeof pp); return 1; }
		uint8_t hs[32];
		crypto_hash_sha256(hs, bk_buf, (unsigned long long)n);
		to_hex(hs, sizeof hs, sha);
	}
	if (challenge) {
		if (al < 0) {
			sodium_memzero(pp, sizeof pp);
			fprintf(stderr, "camcfg: recovery refused: no signature block on stdin\n");
			return WRONG_CODE;
		}
		int ml = recover_msg(msg, sizeof msg, challenge, id, fw, restore ? "restore" : "erase", sha);
		const char *keys = getenv("CAMCFG_UPDATE_KEYS");
		if (ml < 0 || sshsig_verify(armor, (size_t)al, (const uint8_t *)msg, (size_t)ml, RECOVER_NS,
					    keys ? keys : "/etc/cam/update-keys", signer, sizeof signer, &why)) {
			sodium_memzero(pp, sizeof pp);
			fprintf(stderr, "camcfg: recovery refused: %s\n", ml < 0 ? "message too long" : why);
			return WRONG_CODE;
		}
		for (char *s = signer; *s; s++)          /* a key comment, for the log line below */
			if (*s < ' ' || *s == 0x7f) *s = '?';
	}
	if (restore) {
		int rc = bk_open((size_t)n, pp, ppl, &h, p_, n_, &pl);
		if (rc) return rc;
	}
	if (erase_data()) { sodium_memzero(bk_plain, (size_t)pl); return 1; }
	if (!restore) {
		printf("erased: DATA is empty%s%s; reboot, then claim the camera afresh\n",
		       challenge ? ", signed by " : "", challenge ? signer : "");
		return 0;
	}
	if (mount_data(mnt, sizeof mnt, &mounted)) { sodium_memzero(bk_plain, (size_t)pl); return 1; }
	chmod(mnt, 0700);
	snprintf(d, sizeof d, "%s/cam", mnt);
	dir = d;
	int bad = (mkdir(dir, 0700) && errno != EEXIST) ? fail("can't make %s", dir) : 0;
	if (!bad && lock_dir() < 0) bad = fail("can't lock %s", dir);
	if (bad) sodium_memzero(bk_plain, (size_t)pl);
	else bad = bk_write_all(p_, n_, pl, &files);
	sync();
#ifdef __linux__
	if (mounted && umount(mnt)) fprintf(stderr, "camcfg: %s: can't unmount (the reboot will)\n", mnt);
#endif
	if (bad) return fail("%s", "DATA was erased but the restore didn't finish: run it again, or reboot and claim");
	printf("restored: %d files from a backup made at %s (firmware %s)%s%s; reboot now\n", files, h.created,
	       h.firmware, challenge ? ", signed by " : "", challenge ? signer : "");
	return 0;
}

/* camcfg backup export | import [FILE]; -1: not a backup command (usage) */
static int cmd_backup(int argc, char **argv)
{
	if (sodium_init() < 0) return fail("%s", "libsodium didn't start");
	if (!strcmp(argv[0], "export") && argc == 1) return bk_export();
	if (!strcmp(argv[0], "import") && argc <= 2) return bk_import(argc == 2 ? argv[1] : NULL);
	return -1;
}

/* ---- htdigest for rtspd -------------------------------------------------------------- */

static int cmd_htdigest(const char *realm, const char *out)
{
	if (!valid_name(realm)) return fail("%s", "bad realm");
	if (load("users")) return fail("%s", "can't read users");
	int n = nlines;
	static char users[MAX_LINES][MAX_LINE];
	memcpy(users, lines, sizeof users);
	nlines = 0;
	for (int i = 0; i < n; i++) {
		char *a = strchr(users[i], ':'), *b = a ? strchr(a + 1, ':') : NULL;
		if (!b) continue;
		char src[MAX_LINE + 64], ha1[33];
		int len = snprintf(src, sizeof src, "%.*s:%s:%s", (int)(a - users[i]), users[i], realm, b + 1);
		md5_hex(src, (size_t)len, ha1);
		memset(src, 0, sizeof src);                     /* held the password */
		snprintf(lines[nlines++], MAX_LINE, "%.*s:%s:%s", (int)(a - users[i]), users[i], realm, ha1);
	}
	memset(users, 0, sizeof users);
	/* rtspd may run as its own user (Gate 3): run as root, the file goes to the owner of its
	 * directory (/run/cam: rtspd, rootfs/README.md), still 0600, so rtspd can read it again on
	 * auth-reload and camctl (camhttpd) can't. Giving it to whoever owns the directory gives
	 * nobody more than they had. */
	char d[512];
	struct stat st;
	uid_t owner = (uid_t)-1;
	snprintf(d, sizeof d, "%s", out);
	char *slash = strrchr(d, '/');
	if (slash == d) d[1] = 0;                       /* "/name": the root directory */
	else if (slash) *slash = 0;
	if (geteuid() == 0 && !stat(slash ? d : ".", &st) && S_ISDIR(st.st_mode) && st.st_uid != 0)
		owner = st.st_uid;
	return save_rows_as(out, lines[0], MAX_LINE, nlines, owner);
}

/* ---- network settings (#80) -------------------------------------------------------------- */

/* NET_BASE/NET_MASK: CAM_NET, the camera CA's name constraint (camtls), from src/camnet.h */
#define NET_PENDING "net-pending"

struct net {
	char mode[8];                  /* "" = dhcp */
	char address[24];              /* A.B.C.D/PREFIX */
	char gateway[16];
	char dns[64];                  /* up to 3, comma-separated */
	char hostname[64];
};

static const char *const net_keys[] = { "net.mode", "net.address", "net.gateway", "net.dns", "net.hostname" };
#define NNET (int)(sizeof net_keys / sizeof net_keys[0])

static char *net_field(struct net *n, int k, size_t *cap)
{
	char *f[] = { n->mode, n->address, n->gateway, n->dns, n->hostname };
	size_t c[] = { sizeof n->mode, sizeof n->address, sizeof n->gateway, sizeof n->dns, sizeof n->hostname };
	*cap = c[k];
	return f[k];
}

static int net_key(const char *line, size_t len)    /* index in net_keys of the key in line[0..len), or -1 */
{
	for (int k = 0; k < NNET; k++)
		if (strlen(net_keys[k]) == len && !strncmp(line, net_keys[k], len)) return k;
	return -1;
}

/* The net.* rows among rows[0..n) (stride MAX_LINE) into *out; -1 if a value doesn't fit */
static int net_from(const char *rows, int n, struct net *out)
{
	memset(out, 0, sizeof *out);
	for (int i = 0; i < n; i++) {
		const char *l = rows + (size_t)i * MAX_LINE, *eq = strchr(l, '=');
		int k = eq ? net_key(l, (size_t)(eq - l)) : -1;
		size_t cap;
		if (k < 0) continue;
		char *f = net_field(out, k, &cap);
		if (strlen(eq + 1) >= cap) return -1;
		snprintf(f, cap, "%s", eq + 1);
	}
	return 0;
}

static int ipv4_u32(const char *s, uint32_t *v)
{
	struct in_addr a;
	if (!valid_ipv4(s) || inet_pton(AF_INET, s, &a) != 1) return -1;
	*v = ntohl(a.s_addr);
	return 0;
}

/* address A.B.C.D/PREFIX into its address and mask; "" if fine, else the reason */
static const char *net_cidr(const char *s, uint32_t *ip, uint32_t *mask)
{
	char a[24];
	const char *slash = strchr(s, '/');
	if (!slash || (size_t)(slash - s) >= sizeof a) return "address: A.B.C.D/PREFIX, inside " CAM_NET_STR;
	memcpy(a, s, (size_t)(slash - s));
	a[slash - s] = 0;
	size_t pl = strlen(slash + 1);
	if (ipv4_u32(a, ip) || pl < 1 || pl > 2 || strspn(slash + 1, "0123456789") != pl || slash[1] == '0')
		return "address: A.B.C.D/PREFIX, inside " CAM_NET_STR;
	int prefix = atoi(slash + 1);
	if (prefix < 8 || prefix > 30) return "address: the prefix is 8..30";
	*mask = 0xffffffffu << (32 - prefix);
	if ((*ip & NET_MASK) != NET_BASE)
		return "address: must be in " CAM_NET_STR ", the range the camera's HTTPS certificate can name";
	if (!(*ip & ~*mask) || (*ip & ~*mask) == ~*mask) return "address: that is the subnet's network or broadcast address";
	return "";
}

static int dns_ok(const char *s)
{
	char buf[64];
	int n = 0;
	if (strlen(s) >= sizeof buf) return 0;
	snprintf(buf, sizeof buf, "%s", s);
	for (char *p = buf, *e; ; p = e + 1) {
		uint32_t v;
		e = strchr(p, ',');
		if (e) *e = 0;
		if (++n > 3 || ipv4_u32(p, &v) || !v || v == 0xffffffffu || (v >> 24) == 127 || (v >> 28) == 0xe)
			return 0;
		if (!e) return 1;
	}
}

static int hostname_ok(const char *s)
{
	size_t n = strlen(s);
	if (n < 1 || n > 63 || s[0] == '-' || s[n - 1] == '-') return 0;
	return strspn(s, "abcdefghijklmnopqrstuvwxyz0123456789-") == n;
}

/* The settings as a whole: "" if fine, else the reason */
static const char *net_check(const struct net *n)
{
	int st = !strcmp(n->mode, "static");
	uint32_t ip = 0, mask = 0, gw;
	if (*n->mode && strcmp(n->mode, "dhcp") && !st) return "mode: dhcp or static";
	if (!st && (*n->address || *n->gateway)) return "address and gateway are for mode=static only";
	if (st) {
		if (!*n->address || !*n->gateway) return "mode=static needs an address and a gateway";
		const char *why = net_cidr(n->address, &ip, &mask);
		if (*why) return why;
		if (ipv4_u32(n->gateway, &gw)) return "gateway: an IPv4 address (A.B.C.D)";
		if ((gw & mask) != (ip & mask) || !(gw & ~mask) || (gw & ~mask) == ~mask)
			return "gateway: must be a host in the address's subnet";
		if (gw == ip) return "gateway: can't be the camera's own address";
	}
	if (*n->dns && !dns_ok(n->dns)) return "dns: 1 to 3 IPv4 servers, comma-separated (no 0.0.0.0, loopback, multicast or broadcast)";
	if (*n->hostname && !hostname_ok(n->hostname))
		return "hostname: 1-63 of a-z 0-9 -, not starting or ending with -";
	return "";
}

static int net_same(const struct net *a, const struct net *b)
{
	const char *ma = *a->mode ? a->mode : "dhcp", *mb = *b->mode ? b->mode : "dhcp";
	return !strcmp(ma, mb) && !strcmp(a->address, b->address) && !strcmp(a->gateway, b->gateway) &&
	       !strcmp(a->dns, b->dns) && !strcmp(a->hostname, b->hostname);
}

/* n's rows (only the keys it sets; the mode only when static) into rows[]; returns how many */
static int net_rows(const struct net *n, char rows[NNET][MAX_LINE])
{
	int c = 0;
	for (int k = 0; k < NNET; k++) {
		size_t cap;
		const char *f = net_field((struct net *)n, k, &cap);
		if (!*f || (k == 0 && !strcmp(f, "dhcp"))) continue;
		snprintf(rows[c++], MAX_LINE, "%s=%s", net_keys[k], f);
	}
	return c;
}

/* cam.conf (in lines[]) with its net.* rows replaced by n's, saved */
static int net_store(const struct net *n)
{
	char rows[NNET][MAX_LINE];
	int c = net_rows(n, rows);
	for (int i = nlines - 1; i >= 0; i--) {
		const char *eq = strchr(lines[i], '=');
		if (eq && net_key(lines[i], (size_t)(eq - lines[i])) >= 0) drop(i);
	}
	if (nlines + c > MAX_LINES) return fail("%s", "too many settings");
	for (int i = 0; i < c; i++) memcpy(lines[nlines++], rows[i], MAX_LINE);
	return save("cam.conf");
}

static int net_pending(void)
{
	char p[512];
	path_of(p, sizeof p, NET_PENDING);
	return !access(p, F_OK);
}

/* The confirmed settings kept in DIR/net-pending, into *n */
static int net_prev(struct net *n)
{
	if (load(NET_PENDING) || net_from(lines[0], nlines, n)) return fail("can't read %s", NET_PENDING);
	return 0;
}

static int cmd_net(int argc, char **argv)
{
	const char *op = argv[0];
	struct net cur, nw, prev;
	if (!strcmp(op, "show") && argc == 1) {
		if (load("cam.conf") || net_from(lines[0], nlines, &cur)) return fail("%s", "can't read cam.conf");
		const char *why = net_check(&cur);
		if (*why) return fail("cam.conf's network settings: %s", why);
		uint32_t ip = 0, mask = 0;
		char a[INET_ADDRSTRLEN] = "", m[INET_ADDRSTRLEN] = "", dns[64];
		if (!strcmp(cur.mode, "static")) {
			struct in_addr x;
			net_cidr(cur.address, &ip, &mask);
			x.s_addr = htonl(ip);
			inet_ntop(AF_INET, &x, a, sizeof a);
			x.s_addr = htonl(mask);
			inet_ntop(AF_INET, &x, m, sizeof m);
		}
		snprintf(dns, sizeof dns, "%s", cur.dns);
		for (char *c = dns; *c; c++)
			if (*c == ',') *c = ' ';
		printf("mode=%s\naddress=%s\nnetmask=%s\ngateway=%s\ndns=%s\nhostname=%s\npending=%d\n",
		       *cur.mode ? cur.mode : "dhcp", a, m, cur.gateway, dns, cur.hostname, net_pending());
		return 0;
	}
	if (!strcmp(op, "set") && argc >= 2) {
		int seen = 0;
		memset(&nw, 0, sizeof nw);
		for (int i = 1; i < argc; i++) {
			const char *eq = strchr(argv[i], '=');
			char key[16];
			size_t cap;
			if (!eq || (size_t)(eq - argv[i]) + 5 > sizeof key) goto badkey;
			snprintf(key, sizeof key, "net.%.*s", (int)(eq - argv[i]), argv[i]);
			int k = net_key(key, strlen(key));
			if (k < 0) goto badkey;
			if (seen & (1 << k)) return fail("%s given twice", key + 4);
			seen |= 1 << k;
			char *f = net_field(&nw, k, &cap);
			if (strlen(eq + 1) >= cap) return fail("%s: too long", key + 4);
			snprintf(f, cap, "%s", eq + 1);
		}
		if (!(seen & 1)) return fail("%s", "net set needs mode=dhcp or mode=static");
		const char *why = net_check(&nw);
		if (*why) return fail("%s", why);
		if (lock_dir() < 0) return fail("can't lock %s", dir);
		int pend = net_pending();
		if (pend && net_prev(&prev)) return 1;
		if (load("cam.conf") || net_from(lines[0], nlines, &cur)) return fail("%s", "can't read cam.conf");
		const struct net *confirmed = pend ? &prev : &cur;
		if (net_same(&nw, confirmed)) {                 /* back to the confirmed settings */
			if (net_store(&nw)) return 1;
			if (pend) {
				char p[512];
				path_of(p, sizeof p, NET_PENDING);
				if (unlink(p)) return fail("can't remove %s", p);
			}
			puts(pend ? "back to the confirmed settings: nothing waits for confirmation" : "unchanged");
			return 0;
		}
		if (!pend) {                                    /* keep the confirmed settings first */
			char rows[NNET][MAX_LINE], p[512];
			int c = net_rows(&cur, rows);
			path_of(p, sizeof p, NET_PENDING);
			if (save_rows(p, rows[0], MAX_LINE, c)) return 1;
		}
		if (net_store(&nw)) return 1;
		if (!strcmp(nw.mode, "static") && !*nw.dns)
			fprintf(stderr, "camcfg: no dns: NTP server names won't resolve (time.ntp takes addresses too)\n");
		puts("saved: applies at the next reboot; confirm within 10 minutes of it (camcfg net confirm), or the "
		     "camera goes back to the confirmed settings");
		return 0;
	}
	if ((!strcmp(op, "confirm") || !strcmp(op, "revert")) && argc == 1) {
		char p[512];
		path_of(p, sizeof p, NET_PENDING);
		if (lock_dir() < 0) return fail("can't lock %s", dir);
		if (!net_pending()) {
			if (!strcmp(op, "revert")) return fail("%s", "no change waits for confirmation");
			puts("nothing waits for confirmation");
			return 0;
		}
		if (!strcmp(op, "revert")) {
			if (net_prev(&prev)) return 1;
			if (load("cam.conf")) return fail("%s", "can't read cam.conf");
			if (net_store(&prev)) return 1;
		}
		if (unlink(p)) return fail("can't remove %s", p);
		puts(!strcmp(op, "revert") ? "reverted: the confirmed settings apply at the next reboot" : "confirmed");
		return 0;
	}
	return 2;
badkey:
	return fail("%s", "net set KEY=VALUE…: keys mode, address, gateway, dns, hostname");
}

int main(int argc, char **argv)
{
	int c;
	if (getenv("CAMCFG_DIR")) dir = getenv("CAMCFG_DIR");
	if (getenv("CAMCTL_SOCK")) ctl_sock = getenv("CAMCTL_SOCK");
	while ((c = getopt(argc, argv, "+d:")) != -1) {
		if (c == 'd') dir = optarg;
		else goto usage;
	}
	argc -= optind;
	argv += optind;
	umask(077);
	if (argc < 1) goto usage;
	if (!strcmp(argv[0], "ctl") && argc >= 2) {
		char line[512];
		size_t n = 0;
		for (int i = 1; i < argc; i++) {
			size_t k = strlen(argv[i]) + (i > 1);
			if (n + k + 2 > sizeof line) return fail("%s", "command too long");
			snprintf(line + n, sizeof line - n, "%s%s", i > 1 ? " " : "", argv[i]);
			n += k;
		}
		memcpy(line + n, "\n", 2);
		if (ctl_send(line, 1)) return fail("no ok from rtspd on %s", ctl_sock);
		return 0;
	}
	if (mkdir(dir, 0700) && errno != EEXIST) return fail("can't create %s", dir);
	int rc = 2;
	if (!strcmp(argv[0], "user")) rc = cmd_user(argc - 1, argv + 1);
	else if (!strcmp(argv[0], "sshkey") && argc >= 2) rc = cmd_sshkey(argc - 1, argv + 1);
	else if (!strcmp(argv[0], "htdigest") && argc == 3) rc = cmd_htdigest(argv[1], argv[2]);
	else if (!strcmp(argv[0], "claimed") && (argc == 1 || (argc == 2 && !strcmp(argv[1], "--mark")))) {
		rc = load("users") ? fail("%s", "can't read users") : admin_index() >= 0 ? 0 : 1;
		if (rc == 0 && argc == 2 && !marked() && (lock_dir() < 0 || mark_claimed())) rc = 1;
	}
	else if (!strcmp(argv[0], "claim") && argc == 2) rc = cmd_claim(argv[1]);
	else if (!strcmp(argv[0], "recover") && argc <= 2) rc = cmd_recover(argc == 2 ? argv[1] : NULL);
	else if (!strcmp(argv[0], "recovery") && argc == 2) rc = cmd_recovery(argv[1]);
	else if (!strcmp(argv[0], "unlock") && argc >= 2 && argc <= 5) {
		if (sodium_init() < 0) return fail("%s", "libsodium didn't start");
		rc = cmd_unlock(argc - 1, argv + 1);
		if (rc >= 0) return rc;
		rc = 2;
	}
	else if (!strcmp(argv[0], "backup") && (argc == 2 || argc == 3)) {
		rc = cmd_backup(argc - 1, argv + 1);
		if (rc >= 0) return rc;
		rc = 2;
	}
	else if (!strcmp(argv[0], "tls") && (argc == 2 || argc == 3)) {
		rc = cmd_tls(argc - 1, argv + 1);
		if (rc >= 0) return rc;               /* show: camtls check's 2 ("bad") is no usage error */
		rc = 2;
	}
	else if (!strcmp(argv[0], "net") && argc >= 2) rc = cmd_net(argc - 1, argv + 1);
	else if (!strcmp(argv[0], "get") || !strcmp(argv[0], "set") || !strcmp(argv[0], "unset") ||
		 !strcmp(argv[0], "list"))
		rc = cmd_conf(argc, argv);
	if (rc != 2) return rc;
usage:
	fprintf(stderr, "usage: camcfg [-d DIR] get KEY | set KEY VALUE | unset KEY | list\n"
			"         (time zone: set time.tz POSIX-TZ, e.g. CST6CDT,M3.2.0,M11.1.0 = US Central)\n"
			"       camcfg [-d DIR] user list | add NAME ROLE | passwd NAME | role NAME ROLE | del NAME\n"
			"       camcfg [-d DIR] sshkey list | add | del N   (add: the key line on stdin)\n"
			"       camcfg [-d DIR] htdigest REALM OUTFILE\n"
			"       camcfg [-d DIR] claimed | claim NAME | recover [NAME] | recovery set|check\n"
			"         (claim: password [and SSH key] lines on stdin; recover: code, then password)\n"
			"       camcfg [-d DIR] tls init [IP] | renew [IP] | show [IP]   (IP: eth0's by default)\n"
			"       camcfg [-d DIR] net show | confirm | revert | set mode=dhcp|static [address=A.B.C.D/N]\n"
			"                  [gateway=A.B.C.D] [dns=A.B.C.D[,…]] [hostname=NAME]\n"
			"       camcfg [-d DIR] backup export > FILE | import [FILE]   (the passphrase on stdin)\n"
			"       camcfg unlock restore [-c CHALLENGE] FILE|- | unlock erase [-c CHALLENGE] | unlock info\n"
			"       camcfg ctl get | set image.KEY 0..100 | set image.mirror|flip 0|1 |\n"
			"                  set image.nr2d|nr3d|wdr|blc 0..255 | set time.tz TZ | auth-reload\n");
	return 2;
}
