/* SPDX-License-Identifier: MIT */
/*
 * Host test for camcfg (no camera): camcfg.c is compiled in, its helpers are called directly and
 * its commands run in a forked child (as the real binary would, stdin and stdout on pipes) on a
 * directory in $TMPDIR.
 *
 *   clang -std=c11 -Wall -Wextra -g -fsanitize=address,undefined -Isrc/rtspd -Isrc/camupdate \
 *       $(pkg-config --cflags libsodium) -o $TMPDIR/test_camcfg src/camcfg/test_camcfg.c \
 *       src/rtspd/auth.c $(pkg-config --libs libsodium)
 *   $TMPDIR/test_camcfg
 *
 * Checks: SHA-256 (FIPS 180 vectors and block edges), SSH key validation (each accepted type,
 * fingerprints as ssh-keygen -l prints them, every refusal), sshkey list/add/del (numbering past
 * # lines, duplicates, the 16-key limit, atomic 0600 file), and the password policy: a 64-character
 * password with every ASCII symbol and a space survives add -> users -> htdigest -> rtspd's Digest
 * check (auth.c); 7, 65 and 300 characters, a tab, UTF-8, outer spaces, the user name, two lines
 * and no line are refused, and a refusal leaves the users file alone. Settings: image.mirror/flip
 * and the shutter limits accepted and refused value by value, and daynight.night_below <
 * daynight.day_above kept on set and unset; image.antiflicker, mains_hz and the ISP tuning keys
 * (nr2d, nr3d, wdr, blc 0..255), image.night_tuning (0|1), image.exposure_night (day|0..100) and
 * image.isp_gain_day_max/_night_max (1..4) likewise, with the defaults an unset sends to rtspd;
 * net.plain (0|1) value by value and its unset; stream.main.size / stream.sub.size (streamcfg.h's
 * sizes only) and stream.*.fps 1..30 value by value;
 * camcfg ctl's reply check (last line "ok" or "ok ...", e.g. the snapshot's "ok SIZE"), also through
 * a fake rtspd socket where bind is allowed; every osd.*
 * key's values (the title: 48 printable ASCII characters, empty allowed) and an unset; time.tz
 * (tz.h's POSIX TZ subset value by value, every web UI preset, set/get/unset) and a leftover
 * osd.tz_offset removed by unset. First-boot claim and recovery (#128): SHA-256 by parts,
 * HMAC-SHA256 (RFC 4231) and PBKDF2-HMAC-SHA256 vectors, the code's format, claimed, claim (every
 * refusal leaves nothing behind; recovery file, the admin, then the key; users or the key failing
 * undoes the claim), the last admin kept by user del/role, recovery check/set, and
 * recover (wrong code exit 3, bad password, non-admin, success and rotation, a deleted admin, the
 * file's iterations and salt, a malformed file). HTTPS (camcfg tls, with a stub camtls): show
 * passing check's line and status through, init (a bad IP, an address camtls refuses, the helper's
 * argv and PATH-only environment, the four files 0600, "exists"), renew (key kept, a new key when
 * there was none, a refused address), a power cut's leftover directory swept, a hanging camtls
 * killed after 10 s, and no camtls at all. Settings backup (#171): the device ID (a fixed vector;
 * the MAC's case and place in U-Boot's env don't matter; none without a valid ethaddr or mtd0),
 * export (refused without an ID, unclaimed, or with a passphrase of 11 or 257 bytes, a control
 * character or none; the header as documented; nothing in the clear), import (a wrong passphrase
 * exit 3 and nothing changed; every file back byte for byte, 0600; on stdin after the passphrase;
 * files added since removed; an empty host key and an unfinished CA left out), another camera's
 * backup, an edited header or box, cuts at every boundary, bad headers and Argon2id settings, and
 * forged archives encrypted right (names outside the list, duplicates, wrong sizes, no end, users
 * without an admin, part of the CA, line limits) all refused with nothing changed; the archive
 * parser fuzzed in process. Line limits: a users or authorized_keys line as long as a row holds
 * is read, one byte longer (with or without a newline) is refused. Network settings (#80): net set
 * refuses every bad address, prefix, gateway, DNS list, hostname, mode and key and writes nothing;
 * set/unset of net.* refused but net.plain kept; net-pending holds the confirmed rows through a
 * second change, revert puts them back, confirm drops them, setting them again ends the wait; net
 * show's lines, and exit 1 for hand-edited settings outside the range or too long.
 */
#define main camcfg_main
#include "camcfg.c"
#undef main

#include <dirent.h>
#include <stdarg.h>
#include <sys/wait.h>

static char tdir[512];

static void check(const char *what, int ok)
{
	if (!ok) { fprintf(stderr, "FAIL %s\n", what); exit(1); }
	printf("ok: %s\n", what);
}

/* camcfg -d tdir ARGS... in a child, `in` on its stdin (NULL: none); stdout + stderr in out. */
static int run_cc(const char *in, char *out, size_t cap, ...)
{
	char *argv[12] = { "camcfg", "-d", tdir };
	int argc = 3, pin[2], pout[2], st;
	va_list ap;
	va_start(ap, cap);
	while (argc < 11 && (argv[argc] = va_arg(ap, char *))) argc++;
	va_end(ap);
	argv[argc] = NULL;
	if (pipe(pin) || pipe(pout)) { perror("pipe"); exit(1); }
	fflush(stdout);
	pid_t pid = fork();
	if (pid == 0) {
		dup2(pin[0], 0);
		dup2(pout[1], 1);
		dup2(pout[1], 2);
		close(pin[0]); close(pin[1]); close(pout[0]); close(pout[1]);
		optind = 1;
#ifdef __APPLE__
		optreset = 1;
#endif
		int rc = camcfg_main(argc, argv);
		fflush(stdout);
		fflush(stderr);
		_exit(rc);
	}
	close(pin[0]);
	close(pout[1]);
	if (in && write(pin[1], in, strlen(in)) != (ssize_t)strlen(in)) { perror("write"); exit(1); }
	close(pin[1]);
	size_t got = 0;
	ssize_t n;
	while ((n = read(pout[0], out + got, cap - 1 - got)) > 0) got += (size_t)n;
	out[got] = 0;
	close(pout[0]);
	waitpid(pid, &st, 0);
	return WIFEXITED(st) ? WEXITSTATUS(st) : -1;
}

static void slurp(const char *path, char *out, size_t cap)
{
	FILE *f = fopen(path, "r");
	size_t n = f ? fread(out, 1, cap - 1, f) : 0;
	out[n] = 0;
	if (f) fclose(f);
}

static void spit(const char *path, const char *text)
{
	FILE *f = fopen(path, "w");
	if (!f) { perror(path); exit(1); }
	fputs(text, f);
	fclose(f);
}

static void hexs(const uint8_t *p, size_t n, char *out)
{
	for (size_t i = 0; i < n; i++) snprintf(out + 2 * i, 3, "%02x", p[i]);
}

static void test_sha256(void)
{
	static const struct { const char *in; size_t reps; const char *want; } v[] = {
		{ "", 0, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" },
		{ "abc", 0, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad" },
		{ "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", 0,
		  "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1" },
		{ "a", 55, "9f4390f8d30c2dd92ec9f095b65e2b9ae9b0a925a5258e241c9f1e910f734318" },
		{ "a", 56, "b35439a4ac6f0948b6d6f9e3c6af0f5f590ce20f1bde7090ef7970686ec6738a" },
		{ "a", 63, "7d3e74a05d7db15bce4ad9ec0658ea98e3f06eeecf16b4c6fff2da457ddc2f34" },
		{ "a", 64, "ffe054fe7ae0cb6dc65c3af9b61d5209f439851db43d0ba5997337df154668eb" },
		{ "a", 119, "31eba51c313a5c08226adf18d4a359cfdfd8d2e816b13f4af952f7ea6584dcfb" },
		{ "a", 1000000, "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0" },
	};
	uint8_t h[32];
	char hx[65];
	for (size_t i = 0; i < sizeof v / sizeof v[0]; i++) {
		size_t n = v[i].reps ? v[i].reps : strlen(v[i].in);
		uint8_t *buf = malloc(n + 1);
		if (v[i].reps) memset(buf, 'a', n);
		else memcpy(buf, v[i].in, n);
		sha256(buf, n, h);
		free(buf);
		hexs(h, 32, hx);
		check("SHA-256 vector", !strcmp(hx, v[i].want));
	}
}

/* Test keys: synthetic blobs (not real keys), base64 and fingerprints from Python's hashlib. */
#define ED "AAAAC3NzaC1lZDI1NTE5AAAAIAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8g"
#define ED_FP "SHA256:mKqU+0K8OhKmA8bBQi9Rz0Q5l7/g160hIP+rJYSTNj4"
#define SKED "AAAAGnNrLXNzaC1lZDI1NTE5QG9wZW5zc2guY29tAAAAIAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8gAAAABHNzaDo="
#define SKED_FP "SHA256:nX0hpi5mKbTIJ10yBq5/sLQhiI1Y0RBAqN0drDdgJWs"
#define EC "AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBAABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZGhscHR4fICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj8="
#define EC_FP "SHA256:zS9hnzWeppM32oaZEwFAEXagQOJYmxUFy9OmfOm9QTI"
#define SKEC "AAAAInNrLWVjZHNhLXNoYTItbmlzdHAyNTZAb3BlbnNzaC5jb20AAAAIbmlzdHAyNTYAAABBBAABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZGhscHR4fICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj8AAAAEc3NoOg=="
#define SKEC_FP "SHA256:Gkr7/6f0ZaLNSeBuBwJhmfd+tDCxEYyeeuJBopGJewU"
#define RSA "AAAAB3NzaC1yc2EAAAADAQABAAABAQDFxcXFxcXFxcXFxcXFxcXFxcXFxcXFxcXFxcXFxcXFxcXFxcXFxcXFxcXFxcXFxcXFxcXF" \
	"xcXFxcXFxcXFxcXFxcXFxcXFxcXFxcXFxcXFxcXFxcXFxcXFxcXFxcXFxcXFxcXFxcXFxcXFxcXFxcXFxcXFxcXFxcXFxcXFxcXF" \
	"xcXFxcXFxcXFxcXFxcXFxcXFxcXFxcXFxcXFxcXFxcXFxcXFxcXFxcXFxcXFxcXFxcXFxcXFxcXFxcXFxcXFxcXFxcXFxcXFxcXF" \
	"xcXFxcXFxcXFxcXFxcXFxcXFxcXFxcXFxcXFxcXFxcXFxcXFxcXFxcXFxcXFxcXFxcXFxcXF"
#define RSA_FP "SHA256:gYoTYgAx9TKX1r8WoWoTZNOaZUfQMpfiGtsuj97MDQ8"
#define ED_AS_RSA "AAAAB3NzaC1yc2EAAAAgAQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA="
#define ED_EXTRA "AAAAC3NzaC1lZDI1NTE5AAAAIAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8gAAAAAXg="
#define ED_SHORT "AAAAC3NzaC1lZDI1NTE5AAAAKAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8g"
#define DSS "AAAAB3NzaC1kc3MAAAABcAAAAAFxAAAAAWcAAAABeQ=="

/* A distinct ssh-ed25519 line: the 32 key bytes are all `b`. */
static const char *ed_line(int b, const char *comment)
{
	static char line[200];
	uint8_t blob[51] = { 0, 0, 0, 11, 's', 's', 'h', '-', 'e', 'd', '2', '5', '5', '1', '9', 0, 0, 0, 32 };
	memset(blob + 19, b, 32);
	char *o = line + snprintf(line, sizeof line, "ssh-ed25519 ");
	for (int i = 0; i < 51; i += 3) {
		uint32_t x = (uint32_t)blob[i] << 16 | (uint32_t)blob[i + 1] << 8 | blob[i + 2];
		for (int j = 0; j < 4; j++) *o++ = b64t[(x >> (18 - 6 * j)) & 63];
	}
	snprintf(o, sizeof line - (size_t)(o - line), " %s", comment);
	return line;
}

static void test_keys(void)
{
	static struct key k;
	char fp[52], line[KEY_LINE + 16];
	static const struct { const char *line, *fp; } good[] = {
		{ "ssh-ed25519 " ED " me@laptop", ED_FP },
		{ "sk-ssh-ed25519@openssh.com " SKED, SKED_FP },
		{ "ecdsa-sha2-nistp256 " EC " a comment with spaces", EC_FP },
		{ "sk-ecdsa-sha2-nistp256@openssh.com " SKEC " yubikey", SKEC_FP },
		{ "ssh-rsa " RSA " <script>alert(1)</script>", RSA_FP },
	};
	for (size_t i = 0; i < sizeof good / sizeof good[0]; i++) {
		const char *why = key_check(good[i].line, &k);
		fingerprint(k.blob, k.bl, fp);
		printf("   %s -> %s\n", k.type, fp);
		check("key accepted, fingerprint as ssh-keygen", !*why && !strcmp(fp, good[i].fp));
	}
	static const struct { const char *line, *why; } bad[] = {
		{ "ssh-ed25519 " ED_AS_RSA, "another type" },
		{ "ssh-rsa " ED_AS_RSA, "malformed" },                     /* two fields, not three */
		{ "ssh-ed25519 " ED_EXTRA, "malformed" },
		{ "ssh-ed25519 " ED_SHORT, "malformed" },
		{ "ssh-dss " DSS, "key type" },
		{ "ecdsa-sha2-nistp384 " EC, "key type" },
		{ "from=\"192.0.2.1\" ssh-ed25519 " ED, "key type" },
		{ "command=\"/bin/sh\" ssh-ed25519 " ED " x", "key type" },
		{ " ssh-ed25519 " ED, "key type" },
		{ "ssh-ed25519  " ED, "decode" },
		{ "ssh-ed25519", "decode" },
		{ "ssh-ed25519 ", "decode" },
		{ "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAEC!wQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8g", "decode" },
		{ "sk-ssh-ed25519@openssh.com AAAAGnNrLXNzaC1lZDI1NTE5QG9wZW5zc2guY29tAAAAIAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8gAAAABHNzaDo", "decode" },
		{ "ssh-ed25519 " ED " tab\there", "printable" },
		{ "ssh-ed25519 " ED " caf\xc3\xa9", "printable" },
		{ "", "key type" },
	};
	for (size_t i = 0; i < sizeof bad / sizeof bad[0]; i++) {
		const char *why = key_check(bad[i].line, &k);
		printf("   refused: %s\n", why);
		check("bad key refused for the right reason", strstr(why, bad[i].why) != NULL);
	}
	snprintf(line, sizeof line, "ssh-ed25519 " ED " %0201d", 0);
	check("a 201-character comment is refused", strstr(key_check(line, &k), "200") != NULL);
	memset(line, 'A', sizeof line - 1);
	line[sizeof line - 1] = 0;
	check("an overlong line is refused", strstr(key_check(line, &k), "too long") != NULL);
}

static void test_sshkey(void)
{
	char out[8192], path[700], file[4096];
	struct stat sb;
	snprintf(path, sizeof path, "%s/ssh/authorized_keys", tdir);
	check("list with no file: nothing", run_cc(NULL, out, sizeof out, "sshkey", "list", NULL) == 0 && !*out);
	char in[KEY_LINE + 16];
	snprintf(in, sizeof in, "ssh-ed25519 %s <script>alert(1)</script>\n", ED);
	int rc = run_cc(in, out, sizeof out, "sshkey", "add", NULL);
	printf("   %s", out);
	check("add prints the new key's list line", rc == 0 &&
	      !strcmp(out, "1\tssh-ed25519\t" ED_FP "\t<script>alert(1)</script>\n"));
	check("authorized_keys is 0600", !stat(path, &sb) && (sb.st_mode & 0777) == 0600);
	snprintf(file, sizeof file, "%s/ssh", tdir);
	check("... in a 0700 ssh dir", !stat(file, &sb) && (sb.st_mode & 0777) == 0700);
	slurp(path, file, sizeof file);
	check("... holding the line", !strcmp(file, in));
	check("the same key again is refused", run_cc(in, out, sizeof out, "sshkey", "add", NULL) == 1 &&
	      strstr(out, "already there"));
	snprintf(in, sizeof in, "ssh-ed25519 %s other comment\n", ED);
	check("... with another comment too", run_cc(in, out, sizeof out, "sshkey", "add", NULL) == 1);
	snprintf(in, sizeof in, "ssh-rsa %s rsa key \r\n", RSA);
	check("CRLF and trailing spaces are trimmed", run_cc(in, out, sizeof out, "sshkey", "add", NULL) == 0 &&
	      !strcmp(out, "2\tssh-rsa\t" RSA_FP "\trsa key\n"));
	snprintf(in, sizeof in, "%s\n%s\n", ed_line(7, "a"), ed_line(8, "b"));
	check("two lines on stdin are refused", run_cc(in, out, sizeof out, "sshkey", "add", NULL) == 1 &&
	      strstr(out, "one key line"));
	check("no line is refused", run_cc("", out, sizeof out, "sshkey", "add", NULL) == 1);
	char before[4096];
	slurp(path, before, sizeof before);
	snprintf(in, sizeof in, "ssh-dss %s\n", DSS);
	rc = run_cc(in, out, sizeof out, "sshkey", "add", NULL);
	printf("   %s", out);
	check("a bad key gets camcfg's reason", rc == 1 && strstr(out, "camcfg: key type"));
	slurp(path, file, sizeof file);
	check("... and the file is unchanged", !strcmp(before, file));

	/* a seeded file: comments and a line with options keep their place and don't count */
	snprintf(file, sizeof file, "# seeded by the image\n%s\n\ncommand=\"/bin/true\" ssh-ed25519 %s opt\n# end\n",
		 ed_line(1, "one"), ED);
	spit(path, file);
	run_cc(NULL, out, sizeof out, "sshkey", "list", NULL);
	printf("%s", out);
	check("list numbers keys past # lines and marks a line it can't read", strstr(out, "1\tssh-ed25519\tSHA256:") &&
	      strstr(out, "\tone\n2\t?\t?\t(not a plain key line)\n") && !strstr(out, "3\t"));
	for (int b = 2; b <= 15; b++) {
		snprintf(in, sizeof in, "%s\n", ed_line(b, "k"));
		if (run_cc(in, out, sizeof out, "sshkey", "add", NULL)) { printf("%s", out); check("add up to 16", 0); }
	}
	check("16 keys listed", run_cc(NULL, out, sizeof out, "sshkey", "list", NULL) == 0 && strstr(out, "\n16\t"));
	snprintf(in, sizeof in, "%s\n", ed_line(99, "k"));
	check("a 17th key is refused", run_cc(in, out, sizeof out, "sshkey", "add", NULL) == 1 && strstr(out, "at most 16"));
	check("del 2 (the line with options)", run_cc(NULL, out, sizeof out, "sshkey", "del", "2", NULL) == 0);
	slurp(path, file, sizeof file);
	check("... removed it and kept the comments", !strstr(file, "command=") && strstr(file, "# seeded by the image\n") &&
	      strstr(file, "# end\n"));
	run_cc(NULL, out, sizeof out, "sshkey", "list", NULL);
	check("... the next key is number 2 now", strstr(out, "2\tssh-ed25519\t") && !strstr(out, "\n16\t") &&
	      strstr(out, "\n15\t"));
	check("del 0 refused", run_cc(NULL, out, sizeof out, "sshkey", "del", "0", NULL) == 1);
	check("del 16 (no such key) refused", run_cc(NULL, out, sizeof out, "sshkey", "del", "16", NULL) == 1 &&
	      strstr(out, "no key 16"));
	check("del x refused", run_cc(NULL, out, sizeof out, "sshkey", "del", "x", NULL) == 1);
	check("del 123 refused", run_cc(NULL, out, sizeof out, "sshkey", "del", "123", NULL) == 1);
	check("sshkey frob is a usage error", run_cc(NULL, out, sizeof out, "sshkey", "frob", NULL) == 2);
	snprintf(file, sizeof file, "%s.tmp", path);
	check("no temp file left", stat(file, &sb) != 0);
	unlink(path);
	snprintf(file, sizeof file, "%s/ssh", tdir);
	rmdir(file);
}

/* every printable ASCII symbol, a space in the middle, 64 characters */
#define P64 "Aa0!\"#$%&'()*+,-./:;<=>?@[\\]^_ `{|}~Zz9bcdefghijklmnopqrstuvwxyz"

static void test_passwords(void)
{
	char out[1024], users[2048], path[700], hd[700], authz[512], ha1[33], ha2[33], resp[33], tmp[300], who[64];
	snprintf(path, sizeof path, "%s/users", tdir);
	snprintf(hd, sizeof hd, "%s/rtspd.htdigest", tdir);
	check("the test password is 64 characters", strlen(P64) == 64);
	check("user add with every symbol and a space", run_cc(P64 "\n", out, sizeof out, "user", "add", "alice",
	      "viewer", NULL) == 0);
	slurp(path, users, sizeof users);
	check("... stored whole, split on the first two colons", !strcmp(users, "alice:viewer:" P64 "\n"));
	check("user list shows name and role", run_cc(NULL, out, sizeof out, "user", "list", NULL) == 0 &&
	      !strcmp(out, "alice viewer\n"));
	check("role change keeps the password", run_cc(NULL, out, sizeof out, "user", "role", "alice", "admin", NULL) == 0);
	slurp(path, users, sizeof users);
	check("... (colons and all)", !strcmp(users, "alice:admin:" P64 "\n"));
	check("htdigest", run_cc(NULL, out, sizeof out, "htdigest", "camera", hd, NULL) == 0);
	check("rtspd loads it", !auth_load(hd) && auth_enabled());
	/* rtspd's Digest check (auth.c), the response computed from the raw password */
	snprintf(tmp, sizeof tmp, "alice:camera:%s", P64);
	md5_hex(tmp, strlen(tmp), ha1);
	md5_hex("DESCRIBE:rtsp://cam/", 20, ha2);
	snprintf(tmp, sizeof tmp, "%s:0123456789abcdef:00000001:c0ffee:auth:%s", ha1, ha2);
	md5_hex(tmp, strlen(tmp), resp);
	snprintf(authz, sizeof authz, "Digest username=\"alice\", realm=\"camera\", nonce=\"0123456789abcdef\", "
		 "uri=\"rtsp://cam/\", qop=auth, nc=00000001, cnonce=\"c0ffee\", response=\"%s\"", resp);
	check("rtspd accepts Digest made from the 64-character password",
	      auth_check(authz, "DESCRIBE", "0123456789abcdef", who, sizeof who) && !strcmp(who, "alice"));
	snprintf(tmp, sizeof tmp, "alice:camera:%.63s", P64);           /* the stock firmware's sin */
	md5_hex(tmp, strlen(tmp), ha1);
	snprintf(tmp, sizeof tmp, "%s:0123456789abcdef:00000001:c0ffee:auth:%s", ha1, ha2);
	md5_hex(tmp, strlen(tmp), resp);
	snprintf(authz, sizeof authz, "Digest username=\"alice\", realm=\"camera\", nonce=\"0123456789abcdef\", "
		 "uri=\"rtsp://cam/\", qop=auth, nc=00000001, cnonce=\"c0ffee\", response=\"%s\"", resp);
	check("... and refuses the password cut to 63", !auth_check(authz, "DESCRIBE", "0123456789abcdef", who, sizeof who));
	check("passwd with CRLF", run_cc(P64 "\r\n", out, sizeof out, "user", "passwd", "alice", NULL) == 0);
	slurp(path, users, sizeof users);
	check("... stored without the CR", !strcmp(users, "alice:admin:" P64 "\n"));
	check("a password with no newline at EOF", run_cc("no-newline-at-end", out, sizeof out, "user", "add", "bob",
	      "viewer", NULL) == 0);

	char p300[302];
	memset(p300, 'x', 300);
	strcpy(p300 + 300, "\n");
	char p65[67] = P64 "Q\n";
	const struct { const char *name, *pw, *why; } bad[] = {
		{ "carol", "Short7!\n", "at least 8" },
		{ "carol", p65, "at most 64" },
		{ "carol", p300, "at most 64" },
		{ "carol", "tab\tinside1\n", "ASCII" },
		{ "carol", "caf\xc3\xa9-latte\n", "ASCII" },
		{ "carol", "emoji-\xf0\x9f\x93\xb7!\n", "ASCII" },
		{ "carol", "del\x7f" "char99\n", "ASCII" },
		{ "carol", " leading-space\n", "start or end" },
		{ "carol", "trailing-space \n", "start or end" },
		{ "Carol.22", "cAROL.22\n", "user name" },
		{ "carol", "first-line\nsecond-line\n", "one line" },
		{ "carol", "", "no password" },
	};
	slurp(path, users, sizeof users);
	for (size_t i = 0; i < sizeof bad / sizeof bad[0]; i++) {
		int rc = run_cc(bad[i].pw, out, sizeof out, "user", "add", bad[i].name, "viewer", NULL);
		printf("   %s", out);
		check("bad password refused with its reason", rc == 1 && strstr(out, bad[i].why));
		if (i == 9) continue;                         /* the name rule: passwd below */
		rc = run_cc(bad[i].pw, out, sizeof out, "user", "passwd", "alice", NULL);
		check("... by passwd too", rc == 1 && strstr(out, bad[i].why));
	}
	char now[2048];
	slurp(path, now, sizeof now);
	check("refusals leave the users file alone (nothing cut to 64)", !strcmp(now, users) && !strstr(now, "xxxx"));
	check("passwd to the user name (any case) refused", run_cc("different1\n", out, sizeof out, "user", "add",
	      "alice-ABC", "viewer", NULL) == 0 && run_cc("Alice-Abc\n", out, sizeof out, "user", "passwd",
	      "alice-ABC", NULL) == 1 && strstr(out, "user name"));
	check("exactly 8 characters", run_cc("12345678\n", out, sizeof out, "user", "add", "dave", "viewer", NULL) == 0);
	unlink(path);
	unlink(hd);
}

/* image.mirror/flip, the shutter limits and the day/night threshold pair */
static void test_settings(void)
{
	char out[2048], conf[600], now[2048];
	snprintf(conf, sizeof conf, "%s/cam.conf", tdir);
	static const struct { const char *key, *val; int ok; } cs[] = {
		{ "image.mirror", "1", 1 }, { "image.mirror", "0", 1 }, { "image.mirror", "2", 0 },
		{ "image.mirror", "", 0 }, { "image.mirror", "on", 0 }, { "image.mirror", "01", 0 },
		{ "image.flip", "1", 1 }, { "image.flip", "-1", 0 },
		{ "image.shutter_day_max", "0", 1 }, { "image.shutter_day_max", "100", 1 },
		{ "image.shutter_day_max", "1000000", 1 }, { "image.shutter_day_max", "99", 0 },
		{ "image.shutter_day_max", "1000001", 0 }, { "image.shutter_day_max", "1/1000", 0 },
		{ "image.shutter_day_max", "00100", 0 }, { "image.shutter_day_max", "12345678", 0 },
		{ "image.shutter_night_max", "50000", 1 }, { "image.shutter_night_max", "20000", 1 },
		{ "image.shutter_night_max", "0", 1 }, { "image.shutter_night_max", "50001", 0 },
		{ "image.shutter_night_max", "83333", 0 }, { "image.shutter_night_max", "99", 0 },
		{ "image.brightness", "100", 1 }, { "image.brightness", "101", 0 }, { "image.rotate", "1", 0 },
		{ "daynight.night_below", "20", 1 }, { "daynight.night_below", "0", 0 },
		{ "daynight.day_above", "1000001", 0 },
	};
	for (unsigned i = 0; i < sizeof cs / sizeof cs[0]; i++) {
		int rc = run_cc(NULL, out, sizeof out, "set", cs[i].key, cs[i].val, NULL);
		char what[160];
		snprintf(what, sizeof what, "set %s '%s' %s", cs[i].key, cs[i].val, cs[i].ok ? "accepted" : "refused");
		check(what, cs[i].ok ? rc == 0 : rc == 1 && !strstr(out, "saved"));
	}
	slurp(conf, now, sizeof now);
	check("cam.conf has the accepted values", !strcmp(now, "image.mirror=0\nimage.flip=1\nimage.shutter_day_max=1000000\n"
	      "image.shutter_night_max=0\nimage.brightness=100\ndaynight.night_below=20\n"));
	run_cc(NULL, out, sizeof out, "set", "image.mirror", "x", NULL);
	check("... the reason for a bad mirror", strstr(out, "0 (off) or 1 (on)") != NULL);
	run_cc(NULL, out, sizeof out, "set", "image.shutter_night_max", "60000", NULL);
	check("... and for a night shutter over 50 ms", strstr(out, "100..50000 microseconds") != NULL);
	run_cc(NULL, out, sizeof out, "set", "image.rotate", "90", NULL);
	check("... an unknown image key names the known ones", strstr(out, "shutter_night_max") != NULL);
	/* the pair: night_below (20 now) < day_above (1500 by default) */
	check("day_above 20 (= night_below) refused", run_cc(NULL, out, sizeof out, "set", "daynight.day_above", "20",
	      NULL) == 1 && strstr(out, "must be below") && strstr(out, "night_below is 20"));
	check("night_below 1500 (= default day_above) refused", run_cc(NULL, out, sizeof out, "set",
	      "daynight.night_below", "1500", NULL) == 1 && strstr(out, "day_above is 1500"));
	check("day_above 21 accepted", run_cc(NULL, out, sizeof out, "set", "daynight.day_above", "21", NULL) == 0);
	check("unset night_below (back to 15) accepted", run_cc(NULL, out, sizeof out, "unset", "daynight.night_below",
	      NULL) == 0);
	check("night_below 30 now refused", run_cc(NULL, out, sizeof out, "set", "daynight.night_below", "30", NULL) == 1);
	check("day_above 10 refused (default night_below 15)", run_cc(NULL, out, sizeof out, "set", "daynight.day_above",
	      "10", NULL) == 1);
	check("night_below 5, then day_above 10", run_cc(NULL, out, sizeof out, "set", "daynight.night_below", "5", NULL) == 0 &&
	      run_cc(NULL, out, sizeof out, "set", "daynight.day_above", "10", NULL) == 0);
	check("unset night_below refused while day_above is 10", run_cc(NULL, out, sizeof out, "unset",
	      "daynight.night_below", NULL) == 1 && strstr(out, "day_above is 10"));
	check("unset day_above (back to 1500), then night_below", run_cc(NULL, out, sizeof out, "unset",
	      "daynight.day_above", NULL) == 0 && run_cc(NULL, out, sizeof out, "unset", "daynight.night_below", NULL) == 0);
	check("unset image.shutter_day_max", run_cc(NULL, out, sizeof out, "unset", "image.shutter_day_max", NULL) == 0);
	slurp(conf, now, sizeof now);
	check("cam.conf after the pair changes", !strcmp(now, "image.mirror=0\nimage.flip=1\nimage.shutter_night_max=0\n"
	      "image.brightness=100\n"));
	unlink(conf);
}

/* anti-flicker and the ISP tuning keys */
static void test_tuning_settings(void)
{
	char out[2048], conf[600], now[2048];
	snprintf(conf, sizeof conf, "%s/cam.conf", tdir);
	static const struct { const char *key, *val; int ok; } cs[] = {
		{ "image.antiflicker", "1", 1 }, { "image.antiflicker", "2", 0 }, { "image.antiflicker", "on", 0 },
		{ "image.mains_hz", "50", 1 }, { "image.mains_hz", "60", 1 }, { "image.mains_hz", "55", 0 },
		{ "image.mains_hz", "0", 0 }, { "image.mains_hz", "050", 0 },
		{ "image.nr2d", "0", 1 }, { "image.nr2d", "255", 1 }, { "image.nr2d", "256", 0 }, { "image.nr2d", "-1", 0 },
		{ "image.nr3d", "128", 1 }, { "image.nr3d", "0128", 0 }, { "image.nr3d", "", 0 },
		{ "image.wdr", "200", 1 }, { "image.wdr", "1000", 0 }, { "image.blc", "90", 1 }, { "image.blc", "x", 0 },
		{ "image.hlc", "1", 0 },
	};
	for (unsigned i = 0; i < sizeof cs / sizeof cs[0]; i++) {
		int rc = run_cc(NULL, out, sizeof out, "set", cs[i].key, cs[i].val, NULL);
		char what[160];
		snprintf(what, sizeof what, "set %s '%s' %s", cs[i].key, cs[i].val, cs[i].ok ? "accepted" : "refused");
		check(what, cs[i].ok ? rc == 0 : rc == 1 && !strstr(out, "saved"));
	}
	slurp(conf, now, sizeof now);
	check("cam.conf has the accepted values", !strcmp(now, "image.antiflicker=1\nimage.mains_hz=60\nimage.nr2d=255\n"
	      "image.nr3d=128\nimage.wdr=200\nimage.blc=90\n"));
	run_cc(NULL, out, sizeof out, "set", "image.nr2d", "300", NULL);
	check("... the reason for a bad NR value", strstr(out, "0..255") != NULL);
	run_cc(NULL, out, sizeof out, "set", "image.mains_hz", "55", NULL);
	check("... and for a bad mains frequency", strstr(out, "50 or 60") != NULL);
	run_cc(NULL, out, sizeof out, "set", "image.hlc", "1", NULL);
	check("... an unknown image key names the new ones", strstr(out, "antiflicker, mains_hz, nr2d, nr3d, wdr, blc") != NULL);
	check("defaults sent live on unset: 60 Hz, NR 128, the others 0",
	      !strcmp(image_other_default("image.mains_hz"), "60") && !strcmp(image_other_default("image.nr2d"), "128") &&
	      !strcmp(image_other_default("image.nr3d"), "128") && !strcmp(image_other_default("image.wdr"), "0") &&
	      !strcmp(image_other_default("image.blc"), "0") && !strcmp(image_other_default("image.antiflicker"), "0") &&
	      !strcmp(image_other_default("image.mirror"), "0") && !strcmp(image_other_default("image.shutter_day_max"), "0"));
	check("unset image.nr2d", run_cc(NULL, out, sizeof out, "unset", "image.nr2d", NULL) == 0);
	slurp(conf, now, sizeof now);
	check("... gone from cam.conf", !strstr(now, "nr2d"));
	unlink(conf);
	/* stock night tuning: 0|1, default 0 */
	static const struct { const char *val; int ok; } nt[] = {
		{ "1", 1 }, { "0", 1 }, { "2", 0 }, { "01", 0 }, { "on", 0 }, { "", 0 }, { "-1", 0 }, { "1", 1 },
	};
	for (unsigned i = 0; i < sizeof nt / sizeof nt[0]; i++) {
		int rc = run_cc(NULL, out, sizeof out, "set", "image.night_tuning", nt[i].val, NULL);
		char what[160];
		snprintf(what, sizeof what, "set image.night_tuning '%s' %s", nt[i].val, nt[i].ok ? "accepted" : "refused");
		check(what, nt[i].ok ? rc == 0 : rc == 1 && strstr(out, "image.night_tuning: 0 (off) or 1") != NULL);
	}
	slurp(conf, now, sizeof now);
	check("cam.conf has image.night_tuning=1", !strcmp(now, "image.night_tuning=1\n"));
	run_cc(NULL, out, sizeof out, "set", "image.hlc", "1", NULL);
	check("... an unknown image key names night_tuning", strstr(out, "wdr, blc, night_tuning") != NULL);
	check("... default 0 sent live on unset", !strcmp(image_other_default("image.night_tuning"), "0"));
	check("unset image.night_tuning", run_cc(NULL, out, sizeof out, "unset", "image.night_tuning", NULL) == 0);
	slurp(conf, now, sizeof now);
	check("... gone from cam.conf", !strstr(now, "night_tuning"));
	unlink(conf);
	/* stream sizes (streamcfg.h: main 2560x1440/2304x1296/1920x1080/1280x720, sub 640x360/960x540/
	 * 1280x720, exactly) and fps 1..30 */
	static const struct { const char *key, *val; int ok; } ss[] = {
		{ "stream.main.size", "2560x1440", 1 }, { "stream.main.size", "2304x1296", 1 },
		{ "stream.main.size", "1280x720", 1 }, { "stream.main.size", "1920x1080", 1 },
		{ "stream.main.size", "640x360", 0 }, { "stream.main.size", "1920X1080", 0 },
		{ "stream.main.size", "1920x1080 ", 0 }, { "stream.main.size", "1920*1080", 0 },
		{ "stream.main.size", "", 0 }, { "stream.main.size", "2560x1080", 0 },
		{ "stream.sub.size", "640x360", 1 }, { "stream.sub.size", "960x540", 1 },
		{ "stream.sub.size", "1920x1080", 0 }, { "stream.sub.size", "2560x1440", 0 },
		{ "stream.sub.size", "0640x360", 0 }, { "stream.sub.size", "1280x720", 1 },
		{ "stream.main.fps", "30", 1 }, { "stream.main.fps", "31", 0 }, { "stream.main.fps", "0", 0 },
		{ "stream.sub.fps", "1", 1 }, { "stream.sub.fps", "30", 1 }, { "stream.sub.fps", "99", 0 },
	};
	for (unsigned i = 0; i < sizeof ss / sizeof ss[0]; i++) {
		int rc = run_cc(NULL, out, sizeof out, "set", ss[i].key, ss[i].val, NULL);
		char what[160];
		snprintf(what, sizeof what, "set %s '%s' %s", ss[i].key, ss[i].val, ss[i].ok ? "accepted" : "refused");
		check(what, ss[i].ok ? rc == 0 : rc == 1 && !strstr(out, "saved"));
	}
	slurp(conf, now, sizeof now);
	check("cam.conf has the accepted sizes and fps", !strcmp(now, "stream.main.size=1920x1080\n"
	      "stream.sub.size=1280x720\nstream.main.fps=30\nstream.sub.fps=30\n"));
	run_cc(NULL, out, sizeof out, "set", "stream.sub.size", "1920x1080", NULL);
	check("... the reason for a bad sub size", strstr(out, "640x360, 960x540 or 1280x720") != NULL);
	run_cc(NULL, out, sizeof out, "set", "stream.main.size", "640x360", NULL);
	check("... and for a bad main size", strstr(out, "2560x1440, 2304x1296, 1920x1080 or 1280x720") != NULL);
	run_cc(NULL, out, sizeof out, "set", "stream.main.fps", "31", NULL);
	check("... and for a bad fps", strstr(out, "fps: 1..30") != NULL);
	run_cc(NULL, out, sizeof out, "set", "stream.main.bogus", "1", NULL);
	check("... an unknown stream key names size", strstr(out, "profile, size") != NULL);
	check("unset stream.sub.size", run_cc(NULL, out, sizeof out, "unset", "stream.sub.size", NULL) == 0);
	slurp(conf, now, sizeof now);
	check("... gone from cam.conf (the default, 640x360)", !strstr(now, "sub.size"));
	unlink(conf);
	/* net.plain (camhttpd): 0|1, default 1 */
	static const struct { const char *val; int ok; } np[] = {
		{ "0", 1 }, { "1", 1 }, { "2", 0 }, { "01", 0 }, { "off", 0 }, { "", 0 }, { "-1", 0 }, { "0", 1 },
	};
	for (unsigned i = 0; i < sizeof np / sizeof np[0]; i++) {
		int rc = run_cc(NULL, out, sizeof out, "set", "net.plain", np[i].val, NULL);
		char what[160];
		snprintf(what, sizeof what, "set net.plain '%s' %s", np[i].val, np[i].ok ? "accepted" : "refused");
		check(what, np[i].ok ? rc == 0 : rc == 1 && strstr(out, "net.plain: 1 (plain HTTP ONVIF and RTSP on") != NULL);
	}
	slurp(conf, now, sizeof now);
	check("cam.conf has net.plain=0", !strcmp(now, "net.plain=0\n"));
	check("unset net.plain", run_cc(NULL, out, sizeof out, "unset", "net.plain", NULL) == 0);
	slurp(conf, now, sizeof now);
	check("... gone from cam.conf (the default, 1)", !strstr(now, "net.plain"));
	unlink(conf);
	/* night exposure: day or 0..100; the ISP gain limits 1..4 */
	static const struct { const char *key, *val; int ok; } ex[] = {
		{ "image.exposure_night", "30", 1 }, { "image.exposure_night", "0", 1 }, { "image.exposure_night", "100", 1 },
		{ "image.exposure_night", "day", 1 }, { "image.exposure_night", "101", 0 }, { "image.exposure_night", "-1", 0 },
		{ "image.exposure_night", "Day", 0 }, { "image.exposure_night", "030", 0 }, { "image.exposure_night", "", 0 },
		{ "image.exposure_night", "night", 0 },
		{ "image.isp_gain_day_max", "1", 1 }, { "image.isp_gain_day_max", "4", 1 }, { "image.isp_gain_day_max", "0", 0 },
		{ "image.isp_gain_day_max", "5", 0 }, { "image.isp_gain_night_max", "2", 1 }, { "image.isp_gain_night_max", "02", 0 },
		{ "image.isp_gain_night_max", "1.5", 0 }, { "image.isp_gain_night_max", "", 0 },
	};
	for (unsigned i = 0; i < sizeof ex / sizeof ex[0]; i++) {
		int rc = run_cc(NULL, out, sizeof out, "set", ex[i].key, ex[i].val, NULL);
		char what[160];
		snprintf(what, sizeof what, "set %s '%s' %s", ex[i].key, ex[i].val, ex[i].ok ? "accepted" : "refused");
		check(what, ex[i].ok ? rc == 0 && strstr(out, "not applied live") :
		      rc == 1 && !strstr(out, "saved") && (strstr(out, "day (the same as image.exposure) or 0..100") ||
							   strstr(out, "isp_gain_night_max: 1..4")));
	}
	slurp(conf, now, sizeof now);
	check("cam.conf has the last accepted values", !strcmp(now, "image.exposure_night=day\nimage.isp_gain_day_max=4\n"
	      "image.isp_gain_night_max=2\n"));
	run_cc(NULL, out, sizeof out, "set", "image.hlc", "1", NULL);
	check("... an unknown image key names them", strstr(out, "night_tuning, exposure_night, isp_gain_day_max, "
	      "isp_gain_night_max") != NULL);
	check("... defaults sent live on unset: day, 4, 2", !strcmp(image_other_default("image.exposure_night"), "day") &&
	      !strcmp(image_other_default("image.isp_gain_day_max"), "4") &&
	      !strcmp(image_other_default("image.isp_gain_night_max"), "2"));
	check("unset image.exposure_night", run_cc(NULL, out, sizeof out, "unset", "image.exposure_night", NULL) == 0);
	slurp(conf, now, sizeof now);
	check("... gone from cam.conf", !strstr(now, "exposure_night"));
	unlink(conf);
}

/* camcfg ctl: rtspd's reply counts when its last line is "ok" or "ok ..." */
static void test_ctl(void)
{
	static const struct { const char *rep; int ok; } r[] = {
		{ "ok\n", 1 }, { "ok 12345\n", 1 }, { "ok 8", 1 }, { "image.brightness=50\nok\n", 1 },
		{ "motion.map=x\n--01\nok\n", 1 }, { "osd.title.text=err ok\nok\n", 1 },
		{ "err no recent snapshot\n", 0 }, { "", 0 }, { "\n", 0 }, { "ok\nerr x\n", 0 }, { "okay\n", 0 },
		{ "ok \n", 0 }, { "image.brightness=50\n", 0 }, { "no ok\n", 0 }, { "OK\n", 0 }, { " ok\n", 0 },
	};
	for (unsigned i = 0; i < sizeof r / sizeof r[0]; i++)
		if (ctl_reply_ok(r[i].rep) != r[i].ok) {
			fprintf(stderr, "FAIL ctl_reply_ok(\"%s\") != %d\n", r[i].rep, r[i].ok);
			exit(1);
		}
	check("ctl reply: last line \"ok\" or \"ok ...\" (snapshot's \"ok SIZE\") is success; err, empty, cut short not", 1);
	/* through a socket: a fake rtspd answers "ok 8" to snapshot and "err ..." to anything else */
	char sock[600], out[512];
	snprintf(sock, sizeof sock, "%s/ctl.sock", tdir);
	struct sockaddr_un a;
	memset(&a, 0, sizeof a);
	a.sun_family = AF_UNIX;
	snprintf(a.sun_path, sizeof a.sun_path, "%s", sock);
	int lfd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (strlen(sock) >= sizeof a.sun_path || lfd < 0 || bind(lfd, (struct sockaddr *)&a, sizeof a) || listen(lfd, 2)) {
		if (lfd >= 0) close(lfd);
		unlink(sock);
		check("camcfg ctl through a socket: SKIPPED (unix-socket bind not permitted here)", 1);
		return;
	}
	pid_t pid = fork();
	if (pid == 0) {
		for (int i = 0; i < 2; i++) {
			char line[128] = "";
			int fd = accept(lfd, NULL, NULL);
			if (fd < 0) _exit(1);
			ssize_t n = read(fd, line, sizeof line - 1);
			const char *rep = n > 0 && !strncmp(line, "snapshot\n", 9) ? "ok 8\n" : "err no recent snapshot\n";
			if (write(fd, rep, strlen(rep)) < 0) _exit(1);
			close(fd);
		}
		_exit(0);
	}
	setenv("CAMCTL_SOCK", sock, 1);
	int rc = run_cc(NULL, out, sizeof out, "ctl", "snapshot", NULL);
	check("camcfg ctl snapshot: \"ok 8\" exits 0 and is printed", rc == 0 && !strcmp(out, "ok 8\n"));
	rc = run_cc(NULL, out, sizeof out, "ctl", "bogus", NULL);
	check("camcfg ctl with an err reply exits 1", rc == 1 && strstr(out, "no ok from rtspd"));
	setenv("CAMCTL_SOCK", "/nonexistent/camd.sock", 1);
	waitpid(pid, NULL, 0);
	close(lfd);
	unlink(sock);
}

/* osd.* (on-screen display): each key's values, the title's characters and length, unset */
static void test_osd(void)
{
	char out[2048], conf[600], now[2048];
	snprintf(conf, sizeof conf, "%s/cam.conf", tdir);
	static const struct { const char *key, *val; int ok; } cs[] = {
		{ "osd.time.enabled", "0", 1 }, { "osd.time.enabled", "yes", 0 }, { "osd.title.enabled", "1", 1 },
		{ "osd.time.pos", "ur", 1 }, { "osd.time.pos", "UR", 0 }, { "osd.title.pos", "custom", 1 },
		{ "osd.title.x", "100", 1 }, { "osd.title.x", "101", 0 }, { "osd.title.y", "0", 1 },
		{ "osd.title.y", "007", 0 }, { "osd.time.x", "-1", 0 },
		{ "osd.time.format", "MM/dd/yyyy", 1 }, { "osd.time.format", "yyyy.MM.dd", 0 },
		{ "osd.time.12h", "1", 1 }, { "osd.time.weekday", "2", 0 }, { "osd.title.12h", "1", 0 },
		{ "osd.title.text", "Front door: 1 & 2 <\"ok\">", 1 },
		{ "osd.title.text", "123456789012345678901234567890123456789012345678", 1 },
		{ "osd.title.text", "1234567890123456789012345678901234567890123456789", 0 },
		{ "osd.title.text", "caf\xc3\xa9", 0 }, { "osd.title.text", "a\tb", 0 },
		{ "osd.size", "medium", 1 }, { "osd.size", "tiny", 0 },
		{ "osd.style", "black-on-white", 1 }, { "osd.style", "outline", 0 },
		{ "osd.tz_offset", "-300", 0 }, { "osd.tz_offset", "0", 0 }, { "osd.colour", "red", 0 },
	};
	for (unsigned i = 0; i < sizeof cs / sizeof cs[0]; i++) {
		int rc = run_cc(NULL, out, sizeof out, "set", cs[i].key, cs[i].val, NULL);
		char what[200];
		snprintf(what, sizeof what, "set %s '%s' %s", cs[i].key, cs[i].val, cs[i].ok ? "accepted" : "refused");
		check(what, cs[i].ok ? rc == 0 && strstr(out, "not applied live") : rc == 1 && !strstr(out, "saved"));
	}
	run_cc(NULL, out, sizeof out, "set", "osd.title.text", "caf\xc3\xa9", NULL);
	check("... the reason for a non-ASCII title", strstr(out, "printable ASCII only") != NULL);
	run_cc(NULL, out, sizeof out, "set", "osd.colour", "red", NULL);
	check("... an unknown osd key names the known ones", strstr(out, "osd.size, osd.style") && !strstr(out, "tz_offset"));
	run_cc(NULL, out, sizeof out, "set", "osd.tz_offset", "-300", NULL);
	check("... osd.tz_offset points to time.tz", strstr(out, "osd.tz_offset is gone") && strstr(out, "time.tz"));
	check("an empty title is accepted", run_cc(NULL, out, sizeof out, "set", "osd.title.text", "", NULL) == 0);
	check("unset osd.size", run_cc(NULL, out, sizeof out, "unset", "osd.size", NULL) == 0);
	slurp(conf, now, sizeof now);
	check("cam.conf has the accepted values", !strcmp(now, "osd.time.enabled=0\nosd.title.enabled=1\nosd.time.pos=ur\n"
	      "osd.title.pos=custom\nosd.title.x=100\nosd.title.y=0\nosd.time.format=MM/dd/yyyy\nosd.time.12h=1\n"
	      "osd.title.text=\nosd.style=black-on-white\n"));
	/* a leftover osd.tz_offset (from before time.tz) can still be removed */
	FILE *f = fopen(conf, "a");
	fputs("osd.tz_offset=-300\n", f);
	fclose(f);
	check("unset osd.tz_offset (a leftover line)", run_cc(NULL, out, sizeof out, "unset", "osd.tz_offset", NULL) == 0);
	slurp(conf, now, sizeof now);
	check("... gone from cam.conf, nothing sent to rtspd", !strstr(now, "tz_offset") && !strstr(out, "not applied"));
	unlink(conf);
}

/* time.tz: the POSIX TZ subset of tz.h, value by value, then set / unset through the command */
static void test_tz(void)
{
	/* the web UI's presets (camhttpd.c tz_presets) */
	static const char *const presets[] = { "HST10", "AKST9AKDT,M3.2.0,M11.1.0", "PST8PDT,M3.2.0,M11.1.0",
		"MST7MDT,M3.2.0,M11.1.0", "MST7", "CST6CDT,M3.2.0,M11.1.0", "EST5EDT,M3.2.0,M11.1.0",
		"AST4ADT,M3.2.0,M11.1.0", "NST3:30NDT,M3.2.0,M11.1.0", "GMT0BST,M3.5.0/1,M10.5.0",
		"CET-1CEST,M3.5.0,M10.5.0/3", "EET-2EEST,M3.5.0/3,M10.5.0/4", "MSK-3", "IST-5:30", "CST-8", "JST-9",
		"AEST-10AEDT,M10.1.0,M4.1.0/3", "NZST-12NZDT,M9.5.0,M4.1.0/3", "UTC0" };
	static const struct { const char *tz; int want; } cs[] = {
		/* signs, minutes and seconds, quoted names */
		{ "UTC0", 1 }, { "UTC+0", 1 }, { "UTC-0", 1 }, { "EST+5", 1 }, { "XXX-14", 1 }, { "XXX24", 1 },
		{ "XXX-24:00:00", 1 }, { "XXX5:45", 1 }, { "XXX5:45:30", 1 }, { "<+0545>-5:45", 1 }, { "<-03>3", 1 },
		{ "<UTC+5>-5", 1 }, { "<ABC>1<DEF>,M3.2.0,M11.1.0", 2 }, { "CST6CDT", 2 }, { "CST6CDT5", 2 },
		{ "CST6CDT5,M3.2.0,M11.1.0", 2 }, { "CST6CDT+5:00,M3.2.0/2:00,M11.1.0/2:00:00", 2 },
		/* rules: Jn, n, /time with a sign and up to 167 h */
		{ "EST5EDT,J60/2,J300/2", 2 }, { "EST5EDT,0,365", 2 }, { "EST5EDT,59/-1,300/25", 2 },
		{ "EST5EDT,M3.2.0/167,M11.1.0/-167:59:59", 2 }, { "EST5EDT,M12.5.6,M1.1.0", 2 },
		/* refused */
		{ "", 0 }, { "UTC", 0 }, { "UT0", 0 }, { "U0", 0 }, { "UTC25", 0 }, { "UTC24:00:01", 0 }, { "UTC-25", 0 },
		{ "UTC1:5", 0 }, { "UTC1:60", 0 }, { "UTC1:00:60", 0 }, { "UTC123", 0 }, { "UTC+", 0 }, { "UTC0 ", 0 },
		{ " UTC0", 0 }, { "UTC0\n", 0 }, { "UTC0\nimage.flip=1", 0 }, { "U\tC0", 0 }, { "<+05-5", 0 },
		{ "<+5>-5", 0 }, { "<+05;>-5", 0 }, { "<>0", 0 }, { "CST6CDT,", 0 }, { "CST6CDT,M3.2.0", 0 },
		{ "CST6CDT,M3.2.0,", 0 }, { "CST6CDT,M3.2.0,M11.1.0,", 0 }, { "CST6CDT,M13.2.0,M11.1.0", 0 },
		{ "CST6CDT,M0.2.0,M11.1.0", 0 }, { "CST6CDT,M3.6.0,M11.1.0", 0 }, { "CST6CDT,M3.0.0,M11.1.0", 0 },
		{ "CST6CDT,M3.2.7,M11.1.0", 0 }, { "CST6CDT,M3.2,M11.1.0", 0 }, { "CST6CDT,M3.2.0/168,M11.1.0", 0 },
		{ "CST6CDT,J0,J300", 0 }, { "CST6CDT,J366,J300", 0 }, { "CST6CDT,366,300", 0 },
		{ "CST6CDT,M3.2.0/,M11.1.0", 0 }, { "CST6CDT;reboot", 0 }, { "CST6CDT,M3.2.0,M11.1.0;reboot", 0 },
		{ "$(reboot)", 0 }, { "`reboot`", 0 }, { "UTC0|sh", 0 }, { "UTC0&", 0 }, { ":/etc/localtime", 0 },
		{ ":UTC", 0 }, { "/etc/localtime", 0 }, { "../../etc/shadow", 0 }, { "America/Chicago", 0 },
		{ "UTC0\xc3\xa9", 0 }, { "C\xc3\xa9T-1", 0 }, { "CST6CDT,M3.2.0,M11.1.0x", 0 },
		{ "<+0530>-05:30:00<+0630>-06:30:00,M3.2.0/02:00:00,M11.1.0/02:00", 2 },      /* 62 */
		{ "<+0530>-05:30:00<+0630>-06:30:00,M3.2.0/02:00:00,M11.1.0/02:00:00", 0 },   /* 65 */
	};
	char out[2048], conf[600], now[2048], what[200];
	for (unsigned i = 0; i < sizeof presets / sizeof presets[0]; i++) {
		snprintf(what, sizeof what, "preset time.tz %s accepted", presets[i]);
		check(what, tz_valid(presets[i]) == (strchr(presets[i], ',') ? 2 : 1) && !*tz_check(presets[i]));
	}
	for (int h = -12; h <= 14; h++) {                  /* the fixed offsets: <-12>12 .. <+14>-14 */
		char v[16];
		snprintf(v, sizeof v, "<%c%02d>%d", h < 0 ? '-' : '+', h < 0 ? -h : h, -h);
		if (tz_valid(v) != 1) { fprintf(stderr, "FAIL fixed offset %s\n", v); exit(1); }
	}
	check("fixed offsets <-12>12 .. <+14>-14 accepted", 1);
	for (unsigned i = 0; i < sizeof cs / sizeof cs[0]; i++) {
		int got = tz_valid(cs[i].tz);
		if (got != cs[i].want) {
			fprintf(stderr, "FAIL tz_valid(\"%s\") = %d, want %d\n", cs[i].tz, got, cs[i].want);
			exit(1);
		}
	}
	check("tz_valid: signs, minutes/seconds, quoted names, rules (Mm.w.d, Jn, n, /time) and the refusals "
	      "(shell characters, newline, paths, bad rules, over 64)", 1);
	snprintf(conf, sizeof conf, "%s/cam.conf", tdir);
	check("set time.tz (US Central)", run_cc(NULL, out, sizeof out, "set", "time.tz", "CST6CDT,M3.2.0,M11.1.0", NULL) == 0);
	check("... sent live (rtspd isn't running here)", strstr(out, "not applied live") != NULL);
	int rc = run_cc(NULL, out, sizeof out, "set", "time.tz", "CST6CDT;reboot", NULL);
	check("set time.tz with a shell character refused, with the reason", rc == 1 && strstr(out, "POSIX TZ") &&
	      !strstr(out, "saved"));
	rc = run_cc(NULL, out, sizeof out, "set", "time.tz", "UTC0\nimage.flip=1", NULL);
	check("set time.tz with a newline refused", rc == 1);
	slurp(conf, now, sizeof now);
	check("cam.conf has the good one only", !strcmp(now, "time.tz=CST6CDT,M3.2.0,M11.1.0\n"));
	check("get time.tz", run_cc(NULL, out, sizeof out, "get", "time.tz", NULL) == 0 &&
	      !strcmp(out, "CST6CDT,M3.2.0,M11.1.0\n"));
	check("unset time.tz", run_cc(NULL, out, sizeof out, "unset", "time.tz", NULL) == 0 &&
	      strstr(out, "not applied live"));                   /* "set time.tz UTC0" to rtspd */
	slurp(conf, now, sizeof now);
	check("... gone from cam.conf", !strstr(now, "time.tz"));
	unlink(conf);
}

/* Gate 3: ntpc's world-readable copy of time.ntp (made by ntpc-run, kept in step here), and the
 * htdigest's owner (only changed when run as root into someone else's directory) */
static void test_ntp_copy(void)
{
	char out[2048], conf[600], cp[600], now[512];
	struct stat st;
	snprintf(conf, sizeof conf, "%s/cam.conf", tdir);
	snprintf(cp, sizeof cp, "%s/ntp.conf", tdir);
	setenv("CAMCFG_NTP_COPY", cp, 1);
	check("set time.ntp without the copy (ntpc-run not run): saved, no copy made",
	      run_cc(NULL, out, sizeof out, "set", "time.ntp", "pool.ntp.org", NULL) == 0 && access(cp, F_OK) < 0);
	spit(cp, "");
	chmod(cp, 0600);
	check("set time.ntp with the copy there", run_cc(NULL, out, sizeof out, "set", "time.ntp", "198.51.100.36,pool.ntp.org", NULL) == 0);
	slurp(cp, now, sizeof now);
	check("... the copy holds the line, world-readable (0644)", !strcmp(now, "time.ntp=198.51.100.36,pool.ntp.org\n") &&
	      !stat(cp, &st) && (st.st_mode & 0777) == 0644);
	run_cc(NULL, out, sizeof out, "set", "image.flip", "1", NULL);
	slurp(cp, now, sizeof now);
	check("... another key leaves it alone", !strcmp(now, "time.ntp=198.51.100.36,pool.ntp.org\n"));
	check("unset time.ntp", run_cc(NULL, out, sizeof out, "unset", "time.ntp", NULL) == 0);
	slurp(cp, now, sizeof now);
	check("... the copy is empty (ntpc's default)", !strcmp(now, "") && !stat(cp, &st) && (st.st_mode & 0777) == 0644);
	check("set time.ntp empty (NTP off)", run_cc(NULL, out, sizeof out, "set", "time.ntp", "", NULL) == 0);
	slurp(cp, now, sizeof now);
	check("... the copy says so", !strcmp(now, "time.ntp=\n"));
	unsetenv("CAMCFG_NTP_COPY");
	check("without $CAMCFG_NTP_COPY and with -d DIR: no copy touched",
	      run_cc(NULL, out, sizeof out, "set", "time.ntp", "a.b", NULL) == 0);
	slurp(cp, now, sizeof now);
	check("... still the old one", !strcmp(now, "time.ntp=\n"));
	unlink(cp);
	unlink(conf);
	/* htdigest: not root here, so the file stays ours, 0600 (root into rtspd's /run/cam: rtspd's) */
	char hd[600], ul[600];
	snprintf(ul, sizeof ul, "%s/users", tdir);
	snprintf(hd, sizeof hd, "%s/ht", tdir);
	spit(ul, "admin:admin:Correct-Horse-1\n");
	chmod(ul, 0600);
	check("htdigest as a user: ours, 0600", run_cc(NULL, out, sizeof out, "htdigest", "camera", hd, NULL) == 0 &&
	      !stat(hd, &st) && st.st_uid == geteuid() && (st.st_mode & 0777) == 0600);
	unlink(hd);
	unlink(ul);
}

/* ---- #128: SHA-256 by parts, HMAC-SHA256, PBKDF2-HMAC-SHA256, claim and the recovery code ---- */

static void test_kdf(void)
{
	static uint8_t buf[300];
	uint8_t a[32], b[32], dk[64];
	char hx[129];
	struct s256 s;
	for (size_t i = 0; i < sizeof buf; i++) buf[i] = (uint8_t)(i * 7 + 3);
	for (size_t n = 0; n <= sizeof buf; n++) {         /* by parts = one shot, every split */
		sha256(buf, n, a);
		s256_init(&s);
		s256_update(&s, buf, n / 3);
		s256_update(&s, buf + n / 3, 0);
		s256_update(&s, buf + n / 3, n - n / 3);
		s256_final(&s, b);
		if (memcmp(a, b, 32)) { fprintf(stderr, "FAIL s256 by parts, %zu bytes\n", (size_t)n); exit(1); }
	}
	s256_init(&s);
	for (int i = 0; i < 1000000; i++) s256_update(&s, "a", 1);
	s256_final(&s, a);
	hexs(a, 32, hx);
	check("SHA-256 by parts: 0..300 bytes split anywhere as one shot, and a million 'a' (FIPS 180)",
	      !strcmp(hx, "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"));
	static const struct { const char *key; size_t kl; int rep; const char *msg, *want; } hm[] = {   /* RFC 4231 */
		{ "\x0b", 20, 1, "Hi There", "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7" },
		{ "Jefe", 4, 0, "what do ya want for nothing?",
		  "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843" },
		{ "\xaa", 131, 1, "Test Using Larger Than Block-Size Key - Hash Key First",
		  "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54" },
	};
	for (size_t i = 0; i < sizeof hm / sizeof hm[0]; i++) {
		uint8_t key[131];
		struct hmac256 m;
		if (hm[i].rep) memset(key, hm[i].key[0], hm[i].kl);
		else memcpy(key, hm[i].key, hm[i].kl);
		hmac256_init(&m, key, hm[i].kl);
		hmac256(&m, hm[i].msg, strlen(hm[i].msg), a);
		hexs(a, 32, hx);
		check("HMAC-SHA256 (RFC 4231 cases 1, 2, 6: short, short ASCII and a key longer than a block)",
		      !strcmp(hx, hm[i].want));
	}
	/* PBKDF2-HMAC-SHA256: the RFC 6070 inputs with SHA-256 (as widely published; checked against
	 * Python's hashlib.pbkdf2_hmac) and RFC 7914 section 11 */
	static const struct { const char *p; size_t pl; const char *s; size_t sl; unsigned long c; size_t dl;
			      const char *want; } pv[] = {
		{ "password", 8, "salt", 4, 1, 32, "120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b" },
		{ "password", 8, "salt", 4, 2, 32, "ae4d0c95af6b46d32d0adff928f06dd02a303f8ef3c251dfd6e2d85a95474c43" },
		{ "password", 8, "salt", 4, 4096, 32, "c5e478d59288c841aa530db6845c4c8d962893a001ce4e11a4963873aa98134a" },
		{ "passwordPASSWORDpassword", 24, "saltSALTsaltSALTsaltSALTsaltSALTsalt", 36, 4096, 40,
		  "348c89dbcbd32b2f32d814b8116e84cf2b17347ebc1800181c4e2a1fb8dd53e1c635518c7dac47e9" },
		{ "pass\0word", 9, "sa\0lt", 5, 4096, 16, "89b69d0516f829893c696226650a8687" },
		{ "passwd", 6, "salt", 4, 1, 64, "55ac046e56e3089fec1691c22544b605f94185216dde0465e68b9d57c20dacbc"
		  "49ca9cccf179b645991664b39d77ef317c71b845b1e30bd509112041d3a19783" },
		{ "Password", 8, "NaCl", 4, 80000, 64, "4ddcd8f60b98be21830cee5ef22701f9641a4418d04c0414aeff08876b34ab56"
		  "a1d425a1225833549adb841b51c9b3176a272bdebba1d078478f62b397f33c8d" },
	};
	for (size_t i = 0; i < sizeof pv / sizeof pv[0]; i++) {
		pbkdf2_sha256((const uint8_t *)pv[i].p, pv[i].pl, (const uint8_t *)pv[i].s, pv[i].sl, pv[i].c, dk, pv[i].dl);
		hexs(dk, pv[i].dl, hx);
		check("PBKDF2-HMAC-SHA256 vector (c = 1, 2, 4096, 80000; 16..64 bytes; NULs in password and salt)",
		      !strcmp(hx, pv[i].want));
	}
	char c[RC_LEN + 1], shown[40];
	check("a code as typed: case, spaces and dashes ignored",
	      !rc_norm("abcd efgh-ijkl-mnop-qrst-uvwx-yz", 32, c) && !strcmp(c, "ABCDEFGHIJKLMNOPQRSTUVWXYZ"));
	check("... 25 or 27 characters, 0, 1, 8, 9 or a NUL refused",
	      rc_norm("ABCDEFGHIJKLMNOPQRSTUVWXY", 25, c) && rc_norm("ABCDEFGHIJKLMNOPQRSTUVWXYZA", 27, c) &&
	      rc_norm("ABCDEFGHIJKLMNOPQRSTUVWXY0", 26, c) && rc_norm("ABCDEFGHIJKLMNOPQRSTUVWXY1", 26, c) &&
	      rc_norm("ABCDEFGHIJKLMNOPQRSTUVWXY8", 26, c) && rc_norm("ABCDEFGHIJKLMNOPQRSTUVWXY9", 26, c) &&
	      rc_norm("ABCDEFGHIJKLMNOPQRSTUVWXY\0", 26, c) && rc_norm("", 0, c));
	rc_show("ABCDEFGHIJKLMNOPQRSTUVWXYZ", shown);
	check("shown in groups of 4", !strcmp(shown, "ABCD-EFGH-IJKL-MNOP-QRST-UVWX-YZ"));
	char x[RC_LEN + 1], y[RC_LEN + 1];
	check("two new codes differ, and are base32", !rc_new(x) && !rc_new(y) && strcmp(x, y) &&
	      strspn(x, "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567") == RC_LEN);
}

/* The code from camcfg's "recovery-code: …" line, normalised; "" if none. */
static const char *code_of(const char *out)
{
	static char c[RC_LEN + 1];
	const char *p = strstr(out, "recovery-code: ");
	*c = 0;
	if (p) {
		p += 15;
		if (rc_norm(p, strcspn(p, "\n"), c)) *c = 0;
	}
	return c;
}

static void test_claim(void)
{
	char out[2048], u[2048], up[700], rp[700], kp[700], sd[700], in[512], first[RC_LEN + 1], line[600];
	struct stat st;
	snprintf(up, sizeof up, "%s/users", tdir);
	snprintf(rp, sizeof rp, "%s/recovery", tdir);
	snprintf(sd, sizeof sd, "%s/ssh", tdir);
	snprintf(kp, sizeof kp, "%s/authorized_keys", sd);
	unlink(up);
	check("claimed: no users file -> 1", run_cc(NULL, out, sizeof out, "claimed", NULL) == 1);
	spit(up, "view:viewer:Viewer-pass1\n");
	check("claimed: users but no admin -> 1 (still unclaimed)", run_cc(NULL, out, sizeof out, "claimed", NULL) == 1);
	check("claim: a bad password is refused", run_cc("short\n", out, sizeof out, "claim", "alice", NULL) == 1 &&
	      strstr(out, "at least 8"));
	check("claim: the password may not be the name", run_cc("Alice123\n", out, sizeof out, "claim", "alice123", NULL) == 1);
	check("claim: a bad key is refused", run_cc("Secret-pass1\nssh-dss AAAA\n", out, sizeof out, "claim", "alice",
	      NULL) == 1 && strstr(out, "key type"));
	check("claim: a third line is refused", run_cc("Secret-pass1\n" "ssh-ed25519 " ED "\nx\n", out, sizeof out,
	      "claim", "alice", NULL) == 1 && strstr(out, "too many lines"));
	check("claim: an existing (non-admin) name is refused", run_cc("Secret-pass1\n", out, sizeof out, "claim",
	      "view", NULL) == 1 && strstr(out, "exists"));
	check("claim: a bad name is refused", run_cc("Secret-pass1\n", out, sizeof out, "claim", "a:b", NULL) == 1);
	slurp(up, u, sizeof u);
	check("... after every refusal: users untouched, no recovery file, no key",
	      !strcmp(u, "view:viewer:Viewer-pass1\n") && stat(rp, &st) && stat(kp, &st));
	/* Gate 3: the key is written only after the admin; a claim failing on either undoes itself */
	{
		char ut[720], full[2048] = "";
		snprintf(ut, sizeof ut, "%s.tmp", up);
		mkdir(ut, 0700);                           /* users can't be replaced */
		snprintf(in, sizeof in, "Secret-pass1\nssh-ed25519 %s owner@laptop\n", ED);
		check("claim: users can't be written -> 1", run_cc(in, out, sizeof out, "claim", "alice", NULL) == 1);
		slurp(up, u, sizeof u);
		check("... no key written, no recovery file, users untouched, still unclaimed",
		      stat(kp, &st) && stat(rp, &st) && !strcmp(u, "view:viewer:Viewer-pass1\n") &&
		      run_cc(NULL, out, sizeof out, "claimed", NULL) == 1);
		rmdir(ut);
		mkdir(sd, 0700);                           /* 16 keys already: the claimer's can't be added */
		for (int i = 0; i < 16; i++) snprintf(full + strlen(full), sizeof full - strlen(full), "x%d y\n", i);
		spit(kp, full);
		check("claim: the key can't be added -> 1, claim undone", run_cc(in, out, sizeof out, "claim", "alice",
		      NULL) == 1 && strstr(out, "at most 16 keys") && strstr(out, "claim undone"));
		slurp(up, u, sizeof u);
		check("... users as before, no recovery file, still unclaimed", !strcmp(u, "view:viewer:Viewer-pass1\n") &&
		      stat(rp, &st) && run_cc(NULL, out, sizeof out, "claimed", NULL) == 1);
		slurp(kp, u, sizeof u);
		check("... authorized_keys untouched", !strcmp(u, full));
		unlink(kp);
	}
	/* a key already there (from an older image's claim cut short) is left alone */
	mkdir(sd, 0700);
	spit(kp, "ssh-ed25519 " ED " earlier\n");
	snprintf(in, sizeof in, "Secret-pass1\r\nssh-ed25519 %s owner@laptop  \n", ED);
	check("claim alice with a key", run_cc(in, out, sizeof out, "claim", "alice", NULL) == 0);
	snprintf(first, sizeof first, "%s", code_of(out));
	check("... prints the recovery code once, as recovery-code: XXXX-…", strlen(first) == RC_LEN &&
	      strstr(out, "recovery-code: ") && strlen(strstr(out, "recovery-code: ") + 15) == 33);
	slurp(up, u, sizeof u);
	check("... the admin is added, CRLF dropped", !strcmp(u, "view:viewer:Viewer-pass1\nalice:admin:Secret-pass1\n"));
	slurp(kp, u, sizeof u);
	check("... the same key isn't added twice", !strcmp(u, "ssh-ed25519 " ED " earlier\n"));
	check("claimed -> 0", run_cc(NULL, out, sizeof out, "claimed", NULL) == 0);
	slurp(rp, u, sizeof u);
	check("recovery file: pbkdf2-sha256, 100000 iterations, salt, hash, user; 0600",
	      !stat(rp, &st) && (st.st_mode & 0777) == 0600 && strstr(u, "algo=pbkdf2-sha256\n") &&
	      strstr(u, "iterations=100000\n") && strstr(u, "\nuser=alice\n") && strstr(u, "\nsalt=") &&
	      strlen(strstr(u, "\nsalt=") + 6) > 32 && strstr(u, "\nhash="));
	check("... the code itself is nowhere in DIR", !strstr(u, first));
	{
		struct rc r;
		uint8_t dk[32];
		dir = tdir;                                /* rc_load here, in the test process */
		check("... the hash is PBKDF2(code, salt, 100000)", rc_load(&r) == 0 && r.iter == 100000 &&
		      (pbkdf2_sha256((const uint8_t *)first, RC_LEN, r.salt, RC_SALT, r.iter, dk, 32), !memcmp(dk, r.hash, 32)));
	}
	check("a second claim is refused", run_cc("Other-pass1\n", out, sizeof out, "claim", "bob", NULL) == 1 &&
	      strstr(out, "already claimed"));
	slurp(up, u, sizeof u);
	check("... users untouched", !strcmp(u, "view:viewer:Viewer-pass1\nalice:admin:Secret-pass1\n"));
	/* Gate 3: camcfg itself keeps the last admin (as the web UI does) */
	check("user del: the last admin is refused", run_cc(NULL, out, sizeof out, "user", "del", "alice", NULL) == 1 &&
	      strstr(out, "alice is the last admin"));
	check("user role: the last admin can't become viewer", run_cc(NULL, out, sizeof out, "user", "role", "alice",
	      "viewer", NULL) == 1 && strstr(out, "last admin"));
	check("... nor operator", run_cc(NULL, out, sizeof out, "user", "role", "alice", "operator", NULL) == 1);
	check("... admin to admin is fine", run_cc(NULL, out, sizeof out, "user", "role", "alice", "admin", NULL) == 0);
	check("... a non-admin can still be deleted or changed", run_cc(NULL, out, sizeof out, "user", "role", "view",
	      "operator", NULL) == 0 && run_cc(NULL, out, sizeof out, "user", "role", "view", "viewer", NULL) == 0);
	slurp(up, u, sizeof u);
	check("... users untouched by the refusals", !strcmp(u, "view:viewer:Viewer-pass1\nalice:admin:Secret-pass1\n"));
	check("with a second admin, alice can be demoted", run_cc("Bob-pass-123\n", out, sizeof out, "user", "add", "bob",
	      "admin", NULL) == 0 && run_cc(NULL, out, sizeof out, "user", "role", "alice", "operator", NULL) == 0);
	check("... then bob is the last admin", run_cc(NULL, out, sizeof out, "user", "del", "bob", NULL) == 1 &&
	      strstr(out, "bob is the last admin") &&
	      run_cc(NULL, out, sizeof out, "user", "role", "bob", "viewer", NULL) == 1);
	check("... alice admin again, then bob deleted", run_cc(NULL, out, sizeof out, "user", "role", "alice", "admin",
	      NULL) == 0 && run_cc(NULL, out, sizeof out, "user", "del", "bob", NULL) == 0);
	slurp(up, u, sizeof u);
	check("... users as before", !strcmp(u, "view:viewer:Viewer-pass1\nalice:admin:Secret-pass1\n"));

	snprintf(in, sizeof in, "%c%c%c%c %s\n", first[0] | 0x20, first[1] | 0x20, first[2], first[3], first + 4);
	check("recovery check: the code (lower case, spaces) -> 0", run_cc(in, out, sizeof out, "recovery", "check", NULL) == 0);
	snprintf(in, sizeof in, "%.25s%c\n", first, first[25] == 'A' ? 'B' : 'A');
	check("recovery check: one character off -> 1", run_cc(in, out, sizeof out, "recovery", "check", NULL) == 1 &&
	      strstr(out, "wrong recovery code"));
	check("recovery check: not a code -> 1", run_cc("hello\n", out, sizeof out, "recovery", "check", NULL) == 1);

	snprintf(in, sizeof in, "%.25s%c\nNew-pass-123\n", first, first[25] == 'A' ? 'B' : 'A');
	check("recover: a wrong code -> exit 3", run_cc(in, out, sizeof out, "recover", NULL) == WRONG_CODE &&
	      strstr(out, "wrong recovery code"));
	check("recover: not a code -> exit 3", run_cc("x\nNew-pass-123\n", out, sizeof out, "recover", NULL) == WRONG_CODE);
	snprintf(in, sizeof in, "%s\nshort\n", first);
	check("recover: the right code with a bad password -> 1, the code still valid",
	      run_cc(in, out, sizeof out, "recover", NULL) == 1 && strstr(out, "at least 8"));
	snprintf(in, sizeof in, "%s\nNew-pass-123\n", first);
	check("recover: the code can't reset a non-admin", run_cc(in, out, sizeof out, "recover", "view", NULL) == 1 &&
	      strstr(out, "no admin view"));
	slurp(up, u, sizeof u);
	check("... users untouched by every refusal", !strcmp(u, "view:viewer:Viewer-pass1\nalice:admin:Secret-pass1\n"));
	check("recover: the right code resets the code's admin", run_cc(in, out, sizeof out, "recover", NULL) == 0);
	char second[RC_LEN + 1];
	snprintf(second, sizeof second, "%s", code_of(out));
	slurp(up, u, sizeof u);
	check("... password changed", !strcmp(u, "view:viewer:Viewer-pass1\nalice:admin:New-pass-123\n"));
	check("... and a new code is printed", strlen(second) == RC_LEN && strcmp(second, first));
	snprintf(in, sizeof in, "%s\nNewer-pass-123\n", first);
	check("... the old code no longer works", run_cc(in, out, sizeof out, "recover", NULL) == WRONG_CODE);
	snprintf(in, sizeof in, "%s\n", second);
	check("... the new one does", run_cc(in, out, sizeof out, "recovery", "check", NULL) == 0);

	/* the code's admin deleted: another admin by name */
	spit(up, "view:viewer:Viewer-pass1\nbob:admin:Bob-pass-123\n");
	snprintf(in, sizeof in, "%s\nNew-pass-456\n", second);
	check("recover: the code's admin is gone and no name given -> 1",
	      run_cc(in, out, sizeof out, "recover", NULL) == 1 && strstr(out, "is gone"));
	check("recover bob: any admin by name", run_cc(in, out, sizeof out, "recover", "bob", NULL) == 0);
	slurp(up, u, sizeof u);
	slurp(rp, line, sizeof line);
	check("... bob's password changed, the new code is bob's", !strcmp(u, "view:viewer:Viewer-pass1\nbob:admin:New-pass-456\n") &&
	      strstr(line, "\nuser=bob\n"));

	/* the file's own iteration count and salt are used; a malformed file is no code */
	{
		uint8_t salt[RC_SALT], dk[32];
		char sh[33], dh[65];
		memset(salt, 0x11, sizeof salt);
		pbkdf2_sha256((const uint8_t *)"ABCDEFGHIJKLMNOPQRSTUVWXYZ", RC_LEN, salt, RC_SALT, 1000, dk, 32);
		hexs(salt, RC_SALT, sh);
		hexs(dk, 32, dh);
		snprintf(line, sizeof line, "algo=pbkdf2-sha256\niterations=1000\nsalt=%s\nhash=%s\nuser=bob\n", sh, dh);
		spit(rp, line);
		check("recovery check uses the file's iterations and salt",
		      run_cc("ABCD-EFGH-IJKL-MNOP-QRST-UVWX-YZ\n", out, sizeof out, "recovery", "check", NULL) == 0);
		snprintf(line, sizeof line, "algo=pbkdf2-sha256\niterations=999\nsalt=%s\nhash=%s\nuser=bob\n", sh, dh);
		spit(rp, line);
		check("... fewer than 1000 iterations: malformed, no code",
		      run_cc("ABCD-EFGH-IJKL-MNOP-QRST-UVWX-YZ\n", out, sizeof out, "recovery", "check", NULL) == 1 &&
		      strstr(out, "malformed"));
		snprintf(line, sizeof line, "algo=pbkdf2-sha1\niterations=1000\nsalt=%s\nhash=%s\nuser=bob\n", sh, dh);
		spit(rp, line);
		check("... another algorithm: malformed", run_cc("ABCD-EFGH-IJKL-MNOP-QRST-UVWX-YZ\n", out, sizeof out,
		      "recovery", "check", NULL) == 1);
		check("... and recover counts it as a wrong code", run_cc("ABCD-EFGH-IJKL-MNOP-QRST-UVWX-YZ\nNew-pass-789\n",
		      out, sizeof out, "recover", "bob", NULL) == WRONG_CODE);
	}
	unlink(rp);
	check("recovery check with no file -> 1", run_cc("ABCD-EFGH-IJKL-MNOP-QRST-UVWX-YZ\n", out, sizeof out,
	      "recovery", "check", NULL) == 1 && strstr(out, "no recovery code"));
	check("recover with no file -> exit 3", run_cc("ABCD-EFGH-IJKL-MNOP-QRST-UVWX-YZ\nNew-pass-789\n", out,
	      sizeof out, "recover", "bob", NULL) == WRONG_CODE);
	check("recovery set refuses what isn't a code", run_cc("ABCD-EFGH\n", out, sizeof out, "recovery", "set", NULL) == 1);
	check("recovery set stores one", run_cc("ABCD-EFGH-IJKL-MNOP-QRST-UVWX-YZ\n", out, sizeof out, "recovery", "set",
	      NULL) == 0 && run_cc("abcdefghijklmnopqrstuvwxyz\n", out, sizeof out, "recovery", "check", NULL) == 0);
	slurp(rp, line, sizeof line);
	check("recovery set twice with the same code: new salt, new hash",
	      run_cc("ABCD-EFGH-IJKL-MNOP-QRST-UVWX-YZ\n", out, sizeof out, "recovery", "set", NULL) == 0 &&
	      (slurp(rp, u, sizeof u), strcmp(u, line)) && strstr(u, "iterations=100000\n"));
	check("recovery: unknown operation is a usage error", run_cc(NULL, out, sizeof out, "recovery", "new", NULL) == 2);
	unlink(up);
	unlink(rp);
	unlink(kp);
	rmdir(sd);
}

/* ---- HTTPS: camcfg tls init|renew|show with a stub camtls (docs/PLAN-TLS.md §B) ---------- */

/* The stub speaks camtls's helper interface with dummy files; it logs its argv and the variables
 * it was given, and hangs while stub.hang exists. */
static const char tls_stub[] =
	"#!/bin/sh\n"
	"T='%s'\n"
	"echo \"$*\" >> \"$T/stub.log\"\n"
	"echo \"HOME=${HOME-unset} HOOK=${CAMCFG_CAMTLS-unset} PATH=$PATH\" > \"$T/stub.env\"\n"
	"[ -e \"$T/stub.hang\" ] && exec sleep 30\n"
	"case $1 in\n"
	"gen-ca) [ $# -eq 2 ] || exit 9\n"
	"\techo ca-key > \"$2/ca.key\"; echo \"ca-crt $$\" > \"$2/ca.crt\"; chmod 644 \"$2/ca.crt\";;\n"
	"issue) [ $# -eq 4 ] || exit 9\n"
	"\tcase $3 in 192.0.2.*) ;; *) printf 'issue: \\033[31m%%s is outside 192.0.2.0/24\\n' \"$3\"; exit 2;; esac\n"
	"\t[ -s \"$2/ca.key\" ] || { echo \"issue: no CA key in $2\"; exit 1; }\n"
	"\t[ -s \"$2/server.key\" ] || echo \"server-key $$\" > \"$4/server.key\"\n"
	"\techo \"crt san=$3\" > \"$4/server.crt\";;\n"
	"check) [ -s \"$2/ca.crt\" ] || { echo 'bad no CA certificate'; exit 2; }\n"
	"\tif [ $# -eq 3 ] && ! grep -qx \"crt san=$3\" \"$2/server.crt\"; then echo 'renew SAN differs'; exit 1; fi\n"
	"\techo \"ok san=$(sed 's/crt san=//' \"$2/server.crt\") not_after=20271127T000000Z ca_fp=aa fp=bb\";;\n"
	"*) exit 9;;\n"
	"esac\n";

static int mode_is(const char *p, int mode)
{
	struct stat st;
	return !lstat(p, &st) && S_ISREG(st.st_mode) && (st.st_mode & 0777) == mode;
}

/* DATA lock (#174): the claimed marker, claimed --mark, and claim refused in lock mode. Runs after
 * test_claim, whose claims leave the marker. */
static void test_lock(void)
{
	char out[2048], up[700], mp[700], fp[700], u[2048];
	snprintf(up, sizeof up, "%s/users", tdir);
	snprintf(mp, sizeof mp, "%s/claimed", tdir);
	snprintf(fp, sizeof fp, "%s/data-failed", tdir);
	check("claim wrote the claimed marker, 0600", mode_is(mp, 0600));
	int had_users = !access(up, F_OK);
	slurp(up, u, sizeof u);
	unlink(up);
	check("marker, no users file: claimed -> 1", run_cc(NULL, out, sizeof out, "claimed", NULL) == 1);
	check("marker, no users file: a claim is refused (lock mode), nothing written",
	      run_cc("Secret-pass1\n", out, sizeof out, "claim", "mallory", NULL) == 1 && strstr(out, "locked") &&
	      access(up, F_OK));
	spit(up, "view:viewer:Viewer-pass1\n");
	check("marker, users without an admin: a claim is refused",
	      run_cc("Secret-pass1\n", out, sizeof out, "claim", "mallory", NULL) == 1 && strstr(out, "locked"));
	unlink(mp);
	check("claimed --mark on an unclaimed camera: 1, no marker",
	      run_cc(NULL, out, sizeof out, "claimed", "--mark", NULL) == 1 && access(mp, F_OK));
	spit(up, "own:admin:Secret-pass1\n");
	check("claimed without --mark writes no marker", run_cc(NULL, out, sizeof out, "claimed", NULL) == 0 && access(mp, F_OK));
	check("claimed --mark on a claimed camera: 0, marker written",
	      run_cc(NULL, out, sizeof out, "claimed", "--mark", NULL) == 0 && mode_is(mp, 0600));
	check("claimed --mark again: 0", run_cc(NULL, out, sizeof out, "claimed", "--mark", NULL) == 0);
	check("claimed --bogus is a usage error", run_cc(NULL, out, sizeof out, "claimed", "--bogus", NULL) == 2);
	/* /run/data-failed (rcS): no claim even on an empty DATA */
	unlink(mp);
	unlink(up);
	spit(fp, "mount: DATA (mtd3) didn't mount as jffs2\n");
	setenv("CAMCFG_DATA_FAILED", fp, 1);
	check("data-failed: a claim on the empty tmpfs is refused, nothing written",
	      run_cc("Secret-pass1\n", out, sizeof out, "claim", "mallory", NULL) == 1 && strstr(out, "locked") &&
	      access(up, F_OK) && access(mp, F_OK));
	unsetenv("CAMCFG_DATA_FAILED");
	unlink(fp);
	if (had_users) spit(up, u);
	else unlink(up);
}

static int no_leftovers(const char *td)        /* no .new-* helper directory in DIR/tls */
{
	DIR *d = opendir(td);
	struct dirent *e;
	int n = 0;
	if (!d) return 1;
	while ((e = readdir(d))) n += !strncmp(e->d_name, ".new-", 5);
	closedir(d);
	return n == 0;
}

static void test_tls(void)
{
	char out[2048], stub[600], td[600], f[700], a[800], b[256], log[2048], env[512];
	const char *names[] = { "ca.key", "ca.crt", "server.key", "server.crt" };
	snprintf(stub, sizeof stub, "%s/camtls-stub", tdir);
	snprintf(td, sizeof td, "%s/tls", tdir);
	FILE *sf = fopen(stub, "w");
	if (!sf) { perror(stub); exit(1); }
	fprintf(sf, tls_stub, tdir);
	fclose(sf);
	chmod(stub, 0700);
	setenv("CAMCFG_CAMTLS", stub, 1);
	check("tls show before init: camtls check's bad line and exit 2 (not a usage error)",
	      run_cc(NULL, out, sizeof out, "tls", "show", NULL) == 2 && !strcmp(out, "bad no CA certificate\n"));
	check("tls renew before init: refused", run_cc(NULL, out, sizeof out, "tls", "renew", "192.0.2.159", NULL) == 1 &&
	      strstr(out, "no CA yet"));
	check("tls init with a bad IP: refused before camtls runs",
	      run_cc(NULL, out, sizeof out, "tls", "init", "192.0.2.300", NULL) == 1 &&
	      run_cc(NULL, out, sizeof out, "tls", "init", "192.0.2.01", NULL) == 1 &&
	      run_cc(NULL, out, sizeof out, "tls", "init", "192.0.2.1 ", NULL) == 1 && strstr(out, "IPv4"));
	check("tls with an unknown operation or too many arguments: usage",
	      run_cc(NULL, out, sizeof out, "tls", "new", NULL) == 2 && strstr(out, "usage") &&
	      run_cc(NULL, out, sizeof out, "tls", "init", "192.0.2.1", "x", NULL) == 2 &&
	      run_cc(NULL, out, sizeof out, "tls", NULL) == 2);
	check("tls init for an address outside 192.0.2.0/24: camtls's message (escape made harmless), exit 1",
	      run_cc(NULL, out, sizeof out, "tls", "init", "192.168.1.5", NULL) == 1 &&
	      strstr(out, "camtls issue failed (exit 2): issue: ?[31m192.168.1.5 is outside 192.0.2.0/24") &&
	      !strchr(out, 033));
	snprintf(f, sizeof f, "%s/ca.crt", td);
	check("... nothing installed, no helper directory left", access(f, F_OK) && no_leftovers(td));
	snprintf(f, sizeof f, "%s/stub.log", tdir);
	unlink(f);
	check("tls init 192.0.2.159", run_cc(NULL, out, sizeof out, "tls", "init", "192.0.2.159", NULL) == 0 &&
	      !strcmp(out, "made: CA and server certificate for 192.0.2.159\n"));
	slurp(f, log, sizeof log);
	{
		char dir1[600] = "", dir2[600] = "", dir3[600] = "", ip[32] = "";
		int n = sscanf(log, "gen-ca %599s\nissue %599s %31s %599s\n", dir1, dir2, ip, dir3);
		check("... camtls gen-ca TMP, then issue TMP IP TMP, TMP a .new- directory in DIR/tls", n == 4 &&
		      !strcmp(dir1, dir2) && !strcmp(dir1, dir3) && !strcmp(ip, "192.0.2.159") &&
		      !strncmp(dir1, td, strlen(td)) && !strncmp(dir1 + strlen(td), "/.new-", 6));
	}
	snprintf(f, sizeof f, "%s/stub.env", tdir);
	slurp(f, env, sizeof env);
	check("... camtls's environment: PATH only", !strcmp(env, "HOME=unset HOOK=unset PATH=/usr/sbin:/usr/bin:/sbin:/bin\n"));
	int all = 1;
	for (size_t i = 0; i < 4; i++) {
		snprintf(f, sizeof f, "%s/%s", td, names[i]);
		all = all && mode_is(f, 0600);
	}
	check("... ca.key, ca.crt (0644 from camtls), server.key, server.crt: all 0600 in DIR/tls", all && no_leftovers(td));
	snprintf(f, sizeof f, "%s/ca.crt", td);
	slurp(f, a, sizeof a);
	check("tls init again: exists, nothing touched", run_cc(NULL, out, sizeof out, "tls", "init", NULL) == 0 &&
	      !strcmp(out, "exists\n") && (slurp(f, b, sizeof b), !strcmp(a, b)));
	check("tls show 192.0.2.159: ok line, exit 0", run_cc(NULL, out, sizeof out, "tls", "show", "192.0.2.159", NULL) == 0 &&
	      !strncmp(out, "ok san=192.0.2.159 not_after=", 29));
	check("tls show for another address: renew, exit 1",
	      run_cc(NULL, out, sizeof out, "tls", "show", "192.0.2.160", NULL) == 1 && !strcmp(out, "renew SAN differs\n"));
	snprintf(f, sizeof f, "%s/server.key", td);
	slurp(f, a, sizeof a);
	check("tls renew 192.0.2.160", run_cc(NULL, out, sizeof out, "tls", "renew", "192.0.2.160", NULL) == 0 &&
	      !strcmp(out, "renewed: server certificate for 192.0.2.160\n"));
	slurp(f, b, sizeof b);
	snprintf(f, sizeof f, "%s/server.crt", td);
	slurp(f, log, sizeof log);
	check("... the key kept, the certificate for the new address, 0600, CADIR = DIR/tls",
	      !strcmp(a, b) && !strcmp(log, "crt san=192.0.2.160\n") && mode_is(f, 0600) && no_leftovers(td) &&
	      run_cc(NULL, out, sizeof out, "tls", "show", "192.0.2.160", NULL) == 0);
	snprintf(f, sizeof f, "%s/server.key", td);
	unlink(f);
	check("tls renew without server.key: camtls's new key is installed too",
	      run_cc(NULL, out, sizeof out, "tls", "renew", "192.0.2.161", NULL) == 0 && mode_is(f, 0600) &&
	      (slurp(f, b, sizeof b), strncmp(b, "server-key ", 11) == 0 && strcmp(a, b)));
	check("tls renew outside 192.0.2.0/24: refused, the certificate stays",
	      run_cc(NULL, out, sizeof out, "tls", "renew", "198.51.100.5", NULL) == 1 &&
	      run_cc(NULL, out, sizeof out, "tls", "show", "192.0.2.161", NULL) == 0);
	{
		char ifip[INET_ADDRSTRLEN];
		if (eth0_ipv4(ifip, sizeof ifip))
			check("tls renew without an IP and no eth0 address: refused",
			      run_cc(NULL, out, sizeof out, "tls", "renew", NULL) == 1 && strstr(out, "eth0 has no IPv4"));
		else
			printf("skip: this host has an eth0 address (%s)\n", ifip);
	}
	/* a power cut during init/renew leaves a helper directory: the next one under the lock sweeps it */
	snprintf(f, sizeof f, "%s/.new-cut123", td);
	mkdir(f, 0700);
	snprintf(a, sizeof a, "%s/server.crt", f);
	spit(a, "half\n");
	check("a helper directory left by a power cut is removed by the next renew",
	      run_cc(NULL, out, sizeof out, "tls", "renew", "192.0.2.162", NULL) == 0 && no_leftovers(td));
	/* camtls hanging: killed after 10 s, nothing installed */
	snprintf(a, sizeof a, "%s/stub.hang", tdir);
	spit(a, "");
	snprintf(f, sizeof f, "%s/server.crt", td);
	slurp(f, log, sizeof log);
	long t0 = ms_now();
	int rc = run_cc(NULL, out, sizeof out, "tls", "renew", "192.0.2.163", NULL);
	long took = ms_now() - t0;
	check("a camtls that hangs is killed after 10 s: renew fails, the certificate stays",
	      rc == 1 && strstr(out, "no answer within 10 s") && took >= 9500 && took < 15000 &&
	      (slurp(f, b, sizeof b), !strcmp(log, b)) && no_leftovers(td));
	unlink(a);
	setenv("CAMCFG_CAMTLS", "/nonexistent/camtls", 1);
	check("no camtls binary: show exits 2, init/renew 1, with the reason",
	      run_cc(NULL, out, sizeof out, "tls", "show", NULL) == 2 && strstr(out, "can't run /nonexistent/camtls") &&
	      run_cc(NULL, out, sizeof out, "tls", "renew", "192.0.2.164", NULL) == 1 && strstr(out, "can't run"));
	unsetenv("CAMCFG_CAMTLS");
	for (size_t i = 0; i < 4; i++) {
		snprintf(f, sizeof f, "%s/%s", td, names[i]);
		unlink(f);
	}
	check("tls dir cleaned up", rmdir(td) == 0);
	const char *extra[] = { "stub.log", "stub.env", "camtls-stub" };
	for (size_t i = 0; i < 3; i++) {
		snprintf(f, sizeof f, "%s/%s", tdir, extra[i]);
		unlink(f);
	}
}

/* A line as long as a row holds (MAX_LINE - 1 / KEY_LINE - 1) is read; one byte more, with or
 * without a newline after it, is refused, not copied past the row. */
static void test_line_limits(void)
{
	static char big[KEY_LINE + 64], out[KEY_LINE * 2], p[600];
	snprintf(p, sizeof p, "%s/users", tdir);
	for (int extra = 0; extra < 3; extra++) {
		size_t len = MAX_LINE - 1 + (size_t)extra;
		int n = snprintf(big, sizeof big, "own:admin:");
		memset(big + n, 'p', len - (size_t)n);
		big[len] = 0;
		if (extra < 2) strcat(big, "\n");                     /* extra 2: the last line, no newline */
		spit(p, big);
		int rc = run_cc(NULL, out, sizeof out, "user", "list", NULL);
		snprintf(big, sizeof big, "users line of %zu bytes%s: %s", len, extra == 2 ? " (no newline)" : "",
			 extra ? "refused" : "read");
		check(big, extra ? rc == 1 && strstr(out, "can't read users") : rc == 0 && strstr(out, "own"));
	}
	unlink(p);
	snprintf(p, sizeof p, "%s/ssh", tdir);
	mkdir(p, 0700);
	snprintf(p, sizeof p, "%s/ssh/authorized_keys", tdir);
	for (int extra = 0; extra < 3; extra++) {
		size_t len = KEY_LINE - 1 + (size_t)extra;
		memset(big, 'k', len);
		big[len] = 0;
		if (extra < 2) strcat(big, "\n");
		spit(p, big);
		int rc = run_cc(NULL, out, sizeof out, "sshkey", "list", NULL);
		snprintf(big, sizeof big, "authorized_keys line of %zu bytes%s: %s", len, extra == 2 ? " (no newline)" : "",
			 extra ? "refused" : "read");
		check(big, extra ? rc == 1 && strstr(out, "can't read") : rc == 0);
	}
	unlink(p);
	snprintf(p, sizeof p, "%s/ssh", tdir);
	rmdir(p);
}


/* ---- settings backup (#171) ---------------------------------------------------------------- */

/* camcfg -d tdir ARGS... in a child: in[0..inlen) on stdin (inlen 0: strlen), stdout into the
 * file outp (NULL: with stderr into err), stderr into err. */
static int run_io(const char *in, size_t inlen, const char *outp, char *err, size_t cap, ...)
{
	char *argv[12] = { "camcfg", "-d", tdir };
	int argc = 3, pin[2], perr[2], st;
	va_list ap;
	va_start(ap, cap);
	while (argc < 11 && (argv[argc] = va_arg(ap, char *))) argc++;
	va_end(ap);
	argv[argc] = NULL;
	if (pipe(pin) || pipe(perr)) { perror("pipe"); exit(1); }
	fflush(stdout);
	pid_t pid = fork();
	if (pid == 0) {
		int o = outp ? open(outp, O_WRONLY | O_CREAT | O_TRUNC, 0600) : perr[1];
		dup2(pin[0], 0);
		dup2(o, 1);
		dup2(perr[1], 2);
		close(pin[0]); close(pin[1]); close(perr[0]); close(perr[1]);
		optind = 1;
#ifdef __APPLE__
		optreset = 1;
#endif
		int rc = camcfg_main(argc, argv);
		fflush(stdout);
		fflush(stderr);
		_exit(rc);
	}
	close(pin[0]);
	close(perr[1]);
	if (in && !inlen) inlen = strlen(in);
	if (in && write(pin[1], in, inlen) != (ssize_t)inlen) { perror("write"); exit(1); }
	close(pin[1]);
	size_t got = 0;
	ssize_t n;
	while ((n = read(perr[0], err + got, cap - 1 - got)) > 0) got += (size_t)n;
	err[got] = 0;
	close(perr[0]);
	waitpid(pid, &st, 0);
	return WIFEXITED(st) ? WEXITSTATUS(st) : -1;
}

/* A fake mtd0 at p: U-Boot's env at 0x3F000 holding env[0..n) */
static void fake_mtd0(const char *p, const char *env, size_t n)
{
	static uint8_t img[0x40000];
	memset(img, 0xff, sizeof img);
	memcpy(img + 0x3F000, env, n);
	FILE *f = fopen(p, "wb");
	if (!f || fwrite(img, 1, sizeof img, f) != sizeof img) { perror(p); exit(1); }
	fclose(f);
}

static size_t bin_read(const char *p, uint8_t *b, size_t cap)
{
	FILE *f = fopen(p, "rb");
	size_t n = f ? fread(b, 1, cap, f) : 0;
	if (f) fclose(f);
	return n;
}

static void bin_write(const char *p, const uint8_t *b, size_t n)
{
	FILE *f = fopen(p, "wb");
	if (!f || fwrite(b, 1, n, f) != n) { perror(p); exit(1); }
	fclose(f);
}

/* A .cambak for device `id` over archive a[0..n), made here (Argon2id at the smallest settings
 * import takes, so the forged cases run fast); `kdf` overrides the kdf line's numbers. */
static size_t forge(uint8_t *out, const char *id, const char *kdf, const uint8_t *a, size_t n, const char *pp)
{
	uint8_t salt[BK_SALT], nonce[BK_NONCE], key[BK_KEY];
	char sh[2 * BK_SALT + 1], nh[2 * BK_NONCE + 1];
	unsigned long long cl;
	randombytes_buf(salt, sizeof salt);
	randombytes_buf(nonce, sizeof nonce);
	hexs(salt, sizeof salt, sh);
	hexs(nonce, sizeof nonce, nh);
	int hl = snprintf((char *)out, BK_HDR, "cam-backup 1\ndevice %s\nfirmware 20261026.1\ncreated 1793000000\n"
			 "kdf argon2id %s %s\nnonce %s\n\n", id, kdf ? kdf : "1 1048576", sh, nh);
	if (crypto_pwhash(key, sizeof key, pp, strlen(pp), salt, 1, 1048576, crypto_pwhash_ALG_ARGON2ID13)) exit(1);
	crypto_aead_xchacha20poly1305_ietf_encrypt(out + hl, &cl, a, n, out, (unsigned long long)hl, NULL, nonce, key);
	return (size_t)hl + (size_t)cl;
}

static void rm_tree(const char *p)
{
	DIR *d = opendir(p);
	struct dirent *e;
	char q[900];
	struct stat st;
	if (!d) { unlink(p); return; }
	while ((e = readdir(d)))
		if (strcmp(e->d_name, ".") && strcmp(e->d_name, "..")) {
			snprintf(q, sizeof q, "%s/%s", p, e->d_name);
			if (!lstat(q, &st) && S_ISDIR(st.st_mode)) rm_tree(q);
			else unlink(q);
		}
	closedir(d);
	rmdir(p);
}

static int same_file(const char *p, const char *text)
{
	static char b[MAX_FILE + 1];
	slurp(p, b, sizeof b);
	return !strcmp(b, text);
}

static void test_backup(void)
{
	static uint8_t f[BK_MAX + 64], g[BK_MAX + 64], ar[8192];
	static char err[4096];
	char top[512], mtd[600], mtd2[600], bk[600], p[700], id[33], env[200];
	const char *pp = "correct horse battery\n";
	snprintf(top, sizeof top, "%s", tdir);
	snprintf(mtd, sizeof mtd, "%s/mtd0", top);
	snprintf(mtd2, sizeof mtd2, "%s/mtd0-other", top);
	snprintf(bk, sizeof bk, "%s/x.cambak", top);
	snprintf(tdir, sizeof tdir, "%s/bk", top);
	mkdir(tdir, 0700);
	check("libsodium starts", sodium_init() >= 0);

	/* the device ID: U-Boot's ethaddr as rcS reads it */
	static const char e1[] = "\x12\x34\x56\x78" "bootdelay=1\0ethaddr=00:11:22:AA:bb:cc\0baudrate=115200\0";
	fake_mtd0(mtd, e1, sizeof e1);
	setenv("CAMCFG_MTD0", mtd, 1);
	check("device ID: SHA-256 of the label and the MAC in lower case, first 16 bytes",
	      !device_id(id) && !strcmp(id, "2afc57ce8604f5b6fbd6c026517444da"));
	static const char e2[] = "\x12\x34\x56\x78" "a=b\0baudrate=1\0ethaddr=00:11:22:AA:BB:CC\0";
	fake_mtd0(mtd2, e2, sizeof e2);
	setenv("CAMCFG_MTD0", mtd2, 1);
	check("device ID: the same MAC in another case and place gives the same ID",
	      !device_id(id) && !strcmp(id, "2afc57ce8604f5b6fbd6c026517444da"));
	const struct { const char *env; size_t n; const char *what; } noid[] = {
		{ "\x12\x34\x56\x78" "bootdelay=1\0", 16, "no ethaddr" },
		{ "\x12\x34\x56\x78" "xethaddr=00:11:22:aa:bb:cc\0", 31, "ethaddr not at the start of an entry" },
		{ "\x12\x34\x56\x78" "ethaddr=00:11:22:aa:bb:c\0", 29, "a short MAC" },
		{ "\x12\x34\x56\x78" "ethaddr=00-11-22-aa-bb-cc\0", 30, "dashes" },
		{ "\x12\x34\x56\x78" "ethaddr=00:11:22:aa:bb:cg\0", 30, "a non-hex digit" },
	};
	for (size_t i = 0; i < sizeof noid / sizeof noid[0]; i++) {
		fake_mtd0(mtd2, noid[i].env, noid[i].n);
		snprintf(env, sizeof env, "device ID: none for %s", noid[i].what);
		check(env, device_id(id) == -1);
	}
	setenv("CAMCFG_MTD0", "/nonexistent/mtd0", 1);
	check("device ID: none without mtd0", device_id(id) == -1);
	check("export: refused without a device ID",
	      run_io(pp, 0, bk, err, sizeof err, "backup", "export", NULL) == 1 && strstr(err, "no valid ethaddr"));

	/* a camera's DATA */
	setenv("CAMCFG_MTD0", mtd, 1);
	check("export: refused on an unclaimed camera",
	      run_io(pp, 0, bk, err, sizeof err, "backup", "export", NULL) == 1 && strstr(err, "isn't claimed"));
	mkdir(strcat(strcpy(p, tdir), "/ssh"), 0700);
	mkdir(strcat(strcpy(p, tdir), "/tls"), 0700);
	const char *names[] = { "users", "cam.conf", "recovery", "ssh/authorized_keys", "ssh/dropbear_ed25519_host_key",
				"tls/ca.key", "tls/server.key", "tls/server.crt", "tls/ca.crt" };
	const char *texts[] = { "own:admin:pass:with:colons\nview:viewer:abcdefgh9\n", "image.flip=1\ntime.tz=UTC0\n",
				"algo=pbkdf2-sha256\niterations=1000\n", "ssh-ed25519 AAAAC3Nza test\n",
				"\x01\x02host key bytes\n\0\xff", "-----ca key-----\n", "-----server key-----\n",
				"-----server cert-----\n", "-----ca cert-----\n" };
	const size_t lens[] = { 0, 0, 0, 0, 20, 0, 0, 0, 0 };
	for (int i = 0; i < 9; i++) {
		snprintf(p, sizeof p, "%s/%s", tdir, names[i]);
		bin_write(p, (const uint8_t *)texts[i], lens[i] ? lens[i] : strlen(texts[i]));
	}
	check("export: a passphrase of 11 characters is refused",
	      run_io("elevenchars\n", 0, bk, err, sizeof err, "backup", "export", NULL) == 1 && strstr(err, "at least 12"));
	check("export: a control character in the passphrase is refused",
	      run_io("twelve\tchars!\n", 0, bk, err, sizeof err, "backup", "export", NULL) == 1 && strstr(err, "control"));
	static char longpp[400];
	memset(longpp, 'a', 257);
	longpp[257] = '\n';
	check("export: a passphrase of 257 bytes is refused",
	      run_io(longpp, 0, bk, err, sizeof err, "backup", "export", NULL) == 1 && strstr(err, "at most 256"));
	check("export: no passphrase is refused",
	      run_io("", 0, bk, err, sizeof err, "backup", "export", NULL) == 1);
	check("export: 9 files", run_io("correct horse battery\r\n", 0, bk, err, sizeof err, "backup", "export", NULL) == 0 &&
	      strstr(err, "backup of 9 files"));
	size_t n = bin_read(bk, f, sizeof f);
	const char *hdr0 = "cam-backup 1\ndevice 2afc57ce8604f5b6fbd6c026517444da\nfirmware unknown\ncreated ";
	check("export: the header as documented, Argon2id 8 passes over 4 MiB",
	      n > 200 && !memcmp(f, hdr0, strlen(hdr0)) &&
	      memmem(f, 300, "\nkdf argon2id 8 4194304 ", 24) && memmem(f, 300, "\nnonce ", 7));
	check("export: no file's bytes in the clear", !memmem(f, n, "pass:with", 9) && !memmem(f, n, "ca key", 6));

	/* restore over a changed camera: every file back, byte for byte, 0600 */
	snprintf(p, sizeof p, "%s/users", tdir);
	spit(p, "intruder:admin:xxxxxxxx1\n");
	snprintf(p, sizeof p, "%s/cam.conf", tdir);
	unlink(p);
	snprintf(p, sizeof p, "%s/tls/ca.key", tdir);
	spit(p, "other");
	check("import: a wrong passphrase gives exit 3", run_io("correct horse battery!\n", 0, NULL, err, sizeof err,
							     "backup", "import", bk, NULL) == 3 && strstr(err, "wrong passphrase"));
	snprintf(p, sizeof p, "%s/users", tdir);
	check("import: ... and changes nothing", same_file(p, "intruder:admin:xxxxxxxx1\n"));
	check("import: the right passphrase restores",
	      run_io(pp, 0, NULL, err, sizeof err, "backup", "import", bk, NULL) == 0 && strstr(err, "restored: 9 files"));
	int all = 1;
	for (int i = 0; i < 9; i++) {
		uint8_t b[64];
		size_t l = lens[i] ? lens[i] : strlen(texts[i]);
		snprintf(p, sizeof p, "%s/%s", tdir, names[i]);
		all &= bin_read(p, b, sizeof b) == l && !memcmp(b, texts[i], l) && mode_is(p, 0600);
	}
	check("import: every file as it was, 0600", all);
	snprintf(p, sizeof p, "%s/claimed", tdir);
	check("import: the claimed marker written (#174)", mode_is(p, 0600));
	snprintf(p, sizeof p, "%s/users.tmp", tdir);
	check("import: no temp file left", access(p, F_OK) && no_leftovers(strcat(strcpy(p, tdir), "/tls")));
	/* stdin: the passphrase line, then the backup */
	memcpy(g, pp, strlen(pp));
	memcpy(g + strlen(pp), f, n);
	snprintf(p, sizeof p, "%s/users", tdir);
	spit(p, "intruder:admin:xxxxxxxx1\n");
	check("import: the backup on stdin after the passphrase line",
	      run_io((const char *)g, strlen(pp) + n, NULL, err, sizeof err, "backup", "import", NULL) == 0 &&
	      same_file(p, texts[0]));

	snprintf(p, sizeof p, "%s/data-failed", top);
	spit(p, "users: lost\n");
	setenv("CAMCFG_DATA_FAILED", p, 1);
	check("import: refused in lock mode (DATA failed; /mnt/nand is a tmpfs)",
	      run_io(pp, 0, NULL, err, sizeof err, "backup", "import", bk, NULL) == 1 && strstr(err, "signed recovery"));
	unsetenv("CAMCFG_DATA_FAILED");
	unlink(p);

	/* a backup holds what it held: files added since are removed */
	snprintf(p, sizeof p, "%s/ssh/authorized_keys", tdir);
	unlink(p);
	snprintf(p, sizeof p, "%s/ssh/dropbear_ed25519_host_key", tdir);
	bin_write(p, (const uint8_t *)"", 0);
	check("export: an empty host key isn't backed up", run_io(pp, 0, bk, err, sizeof err, "backup", "export", NULL) == 0 &&
	      strstr(err, "backup of 7 files"));
	snprintf(p, sizeof p, "%s/ssh/authorized_keys", tdir);
	spit(p, "ssh-ed25519 AAAAlater added\n");
	check("import: restores", run_io(pp, 0, NULL, err, sizeof err, "backup", "import", bk, NULL) == 0);
	check("import: a key added after the backup is gone", access(p, F_OK) && errno == ENOENT);
	snprintf(p, sizeof p, "%s/tls/ca.crt", tdir);
	unlink(p);
	check("export: without ca.crt (an unfinished tls init) the TLS files are left out",
	      run_io(pp, 0, bk, err, sizeof err, "backup", "export", NULL) == 0 && strstr(err, "backup of 3 files"));
	snprintf(p, sizeof p, "%s/tls/ca.key", tdir);
	check("import: ... and restoring it removes them", run_io(pp, 0, NULL, err, sizeof err, "backup", "import", bk, NULL) == 0 &&
	      access(p, F_OK));
	n = bin_read(bk, f, sizeof f);

	/* the header: another camera, edits, cuts */
	setenv("CAMCFG_MTD0", mtd2, 1);
	static const char e3[] = "\x12\x34\x56\x78" "a=b\0ethaddr=00:11:22:aa:bb:cd\0";
	fake_mtd0(mtd2, e3, sizeof e3);
	char other[33];
	device_id(other);
	snprintf(p, sizeof p, "%s/users", tdir);
	spit(p, "keep:admin:keepkeep1\n");
	check("import: another camera's backup is refused before the passphrase is tried",
	      run_io(pp, 0, NULL, err, sizeof err, "backup", "import", bk, NULL) == 1 && strstr(err, "another camera"));
	memcpy(g, f, n);
	memcpy(memmem(g, 100, "device ", 7) + 7, other, 32);
	bin_write(bk, g, n);
	check("import: its device line edited to this camera fails the box (exit 3)",
	      run_io(pp, 0, NULL, err, sizeof err, "backup", "import", bk, NULL) == 3);
	setenv("CAMCFG_MTD0", mtd, 1);
	const char *edits[][2] = { { "firmware unknown", "firmware unknowm" }, { "created 1", "created 2" },
				   { "kdf argon2id 8 ", "kdf argon2id 9 " } };
	for (int i = 0; i < 3; i++) {
		memcpy(g, f, n);
		memcpy(memmem(g, 300, edits[i][0], strlen(edits[i][0])), edits[i][1], strlen(edits[i][1]));
		bin_write(bk, g, n);
		snprintf(env, sizeof env, "import: header edited (%s) fails the box (exit 3)", edits[i][1]);
		check(env, run_io(pp, 0, NULL, err, sizeof err, "backup", "import", bk, NULL) == 3);
	}
	memcpy(g, f, n);
	g[n - 1] ^= 1;
	bin_write(bk, g, n);
	check("import: a flipped bit in the box: exit 3", run_io(pp, 0, NULL, err, sizeof err, "backup", "import", bk, NULL) == 3);
	size_t hl = (size_t)((uint8_t *)memmem(f, 300, "\n\n", 2) - f) + 2;
	const size_t cuts[] = { n - 1, hl + 15, hl, hl - 1, 40, 12, 0 };
	for (size_t i = 0; i < sizeof cuts / sizeof cuts[0]; i++) {
		bin_write(bk, f, cuts[i]);
		snprintf(env, sizeof env, "import: cut to %zu bytes: refused", cuts[i]);
		int rc = run_io(pp, 0, NULL, err, sizeof err, "backup", "import", bk, NULL);
		check(env, rc == 1 || rc == 3);
	}
	const char *bad_hdr[][2] = {
		{ "cam-backup 2\n", "newer format" }, { "cam-backup 1\ndevice x\n\n", "damaged" },
		{ "cam-backup 1\r\n", "not a camera backup" }, { "GIF89a", "not a camera backup" },
	};
	for (size_t i = 0; i < sizeof bad_hdr / sizeof bad_hdr[0]; i++) {
		bin_write(bk, (const uint8_t *)bad_hdr[i][0], strlen(bad_hdr[i][0]));
		snprintf(env, sizeof env, "import: header \"%.12s\": %s", bad_hdr[i][0], bad_hdr[i][1]);
		check(env, run_io(pp, 0, NULL, err, sizeof err, "backup", "import", bk, NULL) == 1 && strstr(err, bad_hdr[i][1]));
	}
	memset(g, 'x', BK_MAX + 1);
	bin_write(bk, g, BK_MAX + 1);
	check("import: more than 1 MiB refused", run_io(pp, 0, NULL, err, sizeof err, "backup", "import", bk, NULL) == 1 &&
	      strstr(err, "larger than"));
	snprintf(p, sizeof p, "%s/users", tdir);
	check("import: none of the refusals changed anything", same_file(p, "keep:admin:keepkeep1\n"));

	/* forged archives, encrypted right: the archive and contents checks */
	char me[33];
	device_id(me);
	const char *users = "file users 15\nown:admin:pw123\n";
	const char *kdfs[][2] = { { "0 1048576", "outside" }, { "33 1048576", "outside" }, { "1 1048575", "outside" },
				  { "1 8388609", "outside" }, { "1 01048576", "outside" }, { "1 -1", "outside" } };
	for (size_t i = 0; i < sizeof kdfs / sizeof kdfs[0]; i++) {
		size_t al = (size_t)snprintf((char *)ar, sizeof ar, "%send\n", users);
		size_t m = forge(g, me, kdfs[i][0], ar, al, "correct horse battery");
		bin_write(bk, g, m);
		snprintf(env, sizeof env, "import: kdf %s refused before the key is made", kdfs[i][0]);
		check(env, run_io(pp, 0, NULL, err, sizeof err, "backup", "import", bk, NULL) == 1 && strstr(err, kdfs[i][1]));
	}
	const struct { const char *ar; size_t len; const char *why; } forged[] = {
		{ "file users 15\nown:admin:pw123\nend\n", 0, NULL },
		{ "file cam.conf 3\na=1\nfile users 15\nown:admin:pw123\nend\n", 0, NULL },
		{ "end\n", 0, "no users file" },
		{ "file ../users 15\nown:admin:pw123\nend\n", 0, "doesn't restore" },
		{ "file /etc/passwd 15\nown:admin:pw123\nend\n", 0, "doesn't restore" },
		{ "file ssh 2\nx\nfile users 15\nown:admin:pw123\nend\n", 0, "doesn't restore" },
		{ "file .lock 2\nx\nfile users 15\nown:admin:pw123\nend\n", 0, "doesn't restore" },
		{ "file users 15\nown:admin:pw123\nfile users 15\nown:admin:pw123\nend\n", 0, "damaged" },
		{ "file users 16\nown:admin:pw123\nend\n", 0, "damaged" },
		{ "file users 14\nown:admin:pw123\nend\n", 0, "damaged" },
		{ "file users 015\nown:admin:pw123\nend\n", 0, "damaged" },
		{ "file users 15\nown:admin:pw123\nend\nx", 0, "damaged" },
		{ "file users 15\nown:admin:pw123\n", 0, "damaged" },
		{ "file users 99999999\nown:admin:pw123\nend\n", 0, "damaged" },
		{ "file users 15\nown:admin:pw123\nend", 0, "damaged" },
		{ "file  users 15\nown:admin:pw123\nend\n", 0, "doesn't restore" },
		{ "file users 15\nown:viewr:pw123\nend\n", 0, "users file is damaged" },
		{ "file users 15\nown:viewer:pw12\nend\n", 0, "no admin" },
		{ "file users 15\no/n:admin:pw123\nend\n", 0, "users file is damaged" },
		{ "file users 15\nownadminpw12345\nend\n", 0, "users file is damaged" },
		{ "file users 15\nown:admin:pw\0" "34\nend\n", 34, "NUL" },
		{ "file tls/ca.key 1\nk\nfile users 15\nown:admin:pw123\nend\n", 0, "only part" },
		{ "file ssh/dropbear_ed25519_host_key 0\n\nfile users 15\nown:admin:pw123\nend\n", 0, "empty key" },
	};
	for (size_t i = 0; i < sizeof forged / sizeof forged[0]; i++) {
		size_t al = forged[i].len ? forged[i].len : strlen(forged[i].ar);
		size_t m = forge(g, me, NULL, (const uint8_t *)forged[i].ar, al, "correct horse battery");
		bin_write(bk, g, m);
		int rc = run_io(pp, 0, NULL, err, sizeof err, "backup", "import", bk, NULL);
		snprintf(env, sizeof env, "import: forged archive %zu %s", i, forged[i].why ? forged[i].why : "restores");
		check(env, forged[i].why ? rc == 1 && strstr(err, forged[i].why) && strstr(err, "nothing was changed") : rc == 0);
		if (!forged[i].why) { snprintf(p, sizeof p, "%s/users", tdir); spit(p, "keep:admin:keepkeep1\n"); }
	}
	snprintf(p, sizeof p, "%s/users", tdir);
	check("import: no refused archive changed anything", same_file(p, "keep:admin:keepkeep1\n"));
	/* long lines: one byte within the readers' limits, and one over */
	size_t al = (size_t)snprintf((char *)ar, sizeof ar, "file users %d\nown:admin:", MAX_LINE - 1);
	memset(ar + al, 'p', MAX_LINE - 11);
	al += MAX_LINE - 11;
	al += (size_t)snprintf((char *)ar + al, sizeof ar - al, "\nend\n");
	bin_write(bk, g, forge(g, me, NULL, ar, al, "correct horse battery"));
	check("import: a users line of 511 bytes restores", run_io(pp, 0, NULL, err, sizeof err, "backup", "import", bk, NULL) == 0);
	al = (size_t)snprintf((char *)ar, sizeof ar, "file users %d\nown:admin:", MAX_LINE);
	memset(ar + al, 'p', MAX_LINE - 10);
	al += MAX_LINE - 10;
	al += (size_t)snprintf((char *)ar + al, sizeof ar - al, "\nend\n");
	bin_write(bk, g, forge(g, me, NULL, ar, al, "correct horse battery"));
	check("import: a users line of 512 bytes is refused", run_io(pp, 0, NULL, err, sizeof err, "backup", "import", bk, NULL) == 1 &&
	      strstr(err, "too long"));

	/* the archive parser and checks, fuzzed in this process (ASan/UBSan watch) */
	static const char seed[] = "file cam.conf 4\na=1\n\nfile tls/ca.key 1\nk\nfile tls/server.key 1\ns\n"
				   "file tls/server.crt 1\nc\nfile tls/ca.crt 1\nC\nfile users 15\nown:admin:pw123\nend\n";
	const uint8_t *p_[NBK];
	size_t n_[NBK];
	const char *why;
	check("parser: the seed archive passes", !bk_parse((const uint8_t *)seed, sizeof seed - 1, p_, n_, &why) &&
	      !*bk_check(p_, n_));
	uint32_t r = 12345;
	int passes = 0;
	for (int it = 0; it < 20000; it++) {
		size_t sl = sizeof seed - 1;
		uint8_t *m = malloc(sl + 8);                /* exact size: ASan sees any overread */
		memcpy(m, seed, sl);
		for (int k = 0; k < 1 + it % 4 && sl; k++) {
			r = r * 1103515245 + 12345;
			size_t at = (r >> 8) % sl;
			r = r * 1103515245 + 12345;
			switch ((r >> 16) % 4) {
			case 0: m[at] = (uint8_t)(r >> 24); break;
			case 1: m[at] ^= (uint8_t)(1u << ((r >> 24) % 8)); break;
			case 2: sl = at; break;
			default: m[at] = "0123456789\n "[(r >> 24) % 12];
			}
		}
		uint8_t *e = malloc(sl ? sl : 1);
		memcpy(e, m, sl);
		if (!bk_parse(e, sl, p_, n_, &why) && !*bk_check(p_, n_)) passes++;
		free(e);
		free(m);
	}
	printf("ok: parser fuzzed, 20000 mutations (%d still valid)\n", passes);

	unsetenv("CAMCFG_MTD0");
	rm_tree(tdir);
	unlink(mtd);
	unlink(mtd2);
	unlink(bk);
	snprintf(tdir, sizeof tdir, "%s", top);
}

/* ---- signed recovery (#176): camcfg unlock, with ssh-keygen's signatures -------------------- */

static void sign_msg(const char *key, const char *ns, const char *msg, char *sig, size_t cap)
{
	char mp[700], cmd[2400];
	snprintf(mp, sizeof mp, "%s/msg", tdir);
	spit(mp, msg);
	snprintf(cmd, sizeof cmd, "rm -f '%s.sig' && ssh-keygen -q -Y sign -f '%s' -n %s '%s' </dev/null >/dev/null 2>&1",
		 mp, key, ns, mp);
	if (system(cmd)) { fprintf(stderr, "FAIL ssh-keygen -Y sign\n"); exit(1); }
	snprintf(mp, sizeof mp, "%s/msg.sig", tdir);
	slurp(mp, sig, cap);
}

static int all_ff(const char *p)
{
	static uint8_t b[65536];
	size_t n = bin_read(p, b, sizeof b);
	for (size_t i = 0; i < n; i++)
		if (b[i] != 0xff) return 0;
	return n == sizeof b;
}

static void fill_mtd3(const char *p)
{
	static uint8_t b[65536];
	randombytes_buf(b, sizeof b);
	b[0] = 0;
	bin_write(p, b, sizeof b);
}

static void test_unlock(void)
{
	static char sig[8192], in[16384], err[4096];
	static uint8_t f[BK_MAX];
	char top[512], mtd0[600], mtd3[600], newd[600], failed[600], k[600], o[600], cmd[2000], bk[600], bk2[600],
	     id[33], fw[40], sha[65], sha2[65], msg[512], p[700];
	const char *pp = "correct horse battery\n", *ch = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
		   *ch2 = "ffeeddccbbaa99887766554433221100ffeeddccbbaa99887766554433221100";
	snprintf(top, sizeof top, "%s", tdir);
	snprintf(tdir, sizeof tdir, "%s/ul", top);
	mkdir(tdir, 0700);
	snprintf(mtd0, sizeof mtd0, "%s/mtd0", tdir);
	snprintf(mtd3, sizeof mtd3, "%s/mtd3", tdir);
	snprintf(newd, sizeof newd, "%s/newdata", tdir);
	snprintf(failed, sizeof failed, "%s/data-failed", tdir);
	snprintf(k, sizeof k, "%s/k", tdir);
	snprintf(o, sizeof o, "%s/o", tdir);
	snprintf(bk, sizeof bk, "%s/a.cambak", tdir);
	snprintf(bk2, sizeof bk2, "%s/b.cambak", tdir);
	static const char e1[] = "\x12\x34\x56\x78" "a=b\0ethaddr=00:11:22:aa:bb:cc\0";
	fake_mtd0(mtd0, e1, sizeof e1);
	setenv("CAMCFG_MTD0", mtd0, 1);
	setenv("CAMCFG_MTD3", mtd3, 1);
	setenv("CAMCFG_RECOVER_DIR", newd, 1);
	snprintf(cmd, sizeof cmd, "ssh-keygen -q -t ed25519 -N '' -C 'owner key' -f '%s' </dev/null && "
		 "ssh-keygen -q -t ed25519 -N '' -C stranger -f '%s' </dev/null", k, o);
	check("ssh-keygen makes the test keys", system(cmd) == 0);
	snprintf(p, sizeof p, "%s.pub", k);
	setenv("CAMCFG_UPDATE_KEYS", p, 1);
	check("libsodium starts", sodium_init() >= 0);

	/* two backups of this camera (the second with other settings), made before the lock */
	snprintf(p, sizeof p, "%s/users", tdir);
	spit(p, "own:admin:Secret-pass1\n");
	snprintf(p, sizeof p, "%s/cam.conf", tdir);
	spit(p, "image.flip=1\n");
	check("unlock: a backup to restore", run_io(pp, 0, bk, err, sizeof err, "backup", "export", NULL) == 0);
	spit(p, "image.flip=0\n");
	check("unlock: a second backup", run_io(pp, 0, bk2, err, sizeof err, "backup", "export", NULL) == 0);
	size_t n = bin_read(bk, f, sizeof f);
	uint8_t hs[32];
	crypto_hash_sha256(hs, f, n);
	to_hex(hs, 32, sha);
	n = bin_read(bk2, f, sizeof f);
	crypto_hash_sha256(hs, f, n);
	to_hex(hs, 32, sha2);
	check("device ID and firmware for the message", !device_id(id) && (fw_version(fw, sizeof fw), 1));
	recover_msg(msg, sizeof msg, ch, "2afc57ce8604f5b6fbd6c026517444da", "20261026.1", "restore",
		    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
	check("the signed message's fixed vector (scripts/test_cam_recover.py has the same bytes)",
	      !strcmp(msg, "cam-recover 1\nchallenge 00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff\n"
			   "device 2afc57ce8604f5b6fbd6c026517444da\nfirmware 20261026.1\naction restore\n"
			   "backup e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\n"));

	fill_mtd3(mtd3);
	check("unlock: refused when the camera isn't locked",
	      run_io(NULL, 0, NULL, err, sizeof err, "unlock", "erase", NULL) == 1 && strstr(err, "isn't locked") && !all_ff(mtd3));
	spit(failed, "mount: test\n");
	setenv("CAMCFG_DATA_FAILED", failed, 1);
	check("unlock info: device and firmware, in or out of lock mode",
	      run_io(NULL, 0, NULL, err, sizeof err, "unlock", "info", NULL) == 0 && strstr(err, "device ") &&
	      strstr(err, id) && strstr(err, "\nfirmware "));
	check("unlock: usage errors", run_io(NULL, 0, NULL, err, sizeof err, "unlock", "restore", NULL) == 2 &&
	      run_io(NULL, 0, NULL, err, sizeof err, "unlock", "wipe", NULL) == 2 &&
	      run_io(NULL, 0, NULL, err, sizeof err, "unlock", "erase", "-c", NULL) == 2);
	check("unlock: a malformed challenge is refused",
	      run_io(NULL, 0, NULL, err, sizeof err, "unlock", "erase", "-c", "XYZ", NULL) == 1 && !all_ff(mtd3));

	/* erase */
	recover_msg(msg, sizeof msg, ch, id, fw, "erase", "none");
	sign_msg(o, RECOVER_NS, msg, sig, sizeof sig);
	check("erase signed by a key that isn't an update key: exit 3, nothing erased",
	      run_io(sig, 0, NULL, err, sizeof err, "unlock", "erase", "-c", ch, NULL) == 3 && strstr(err, "untrusted") &&
	      !all_ff(mtd3));
	sign_msg(k, "cam-firmware", msg, sig, sizeof sig);
	check("erase signed in another namespace: exit 3",
	      run_io(sig, 0, NULL, err, sizeof err, "unlock", "erase", "-c", ch, NULL) == 3 && strstr(err, "namespace") &&
	      !all_ff(mtd3));
	sign_msg(k, RECOVER_NS, msg, sig, sizeof sig);
	check("erase: a signature for another challenge: exit 3",
	      run_io(sig, 0, NULL, err, sizeof err, "unlock", "erase", "-c", ch2, NULL) == 3 && !all_ff(mtd3));
	check("erase: no signature on stdin: exit 3",
	      run_io("", 0, NULL, err, sizeof err, "unlock", "erase", "-c", ch, NULL) == 3 && !all_ff(mtd3));
	check("erase: the update key's signature erases mtd3",
	      run_io(sig, 0, NULL, err, sizeof err, "unlock", "erase", "-c", ch, NULL) == 0 && all_ff(mtd3) &&
	      strstr(err, "erased") && strstr(err, "owner key"));
	fill_mtd3(mtd3);
	recover_msg(msg, sizeof msg, ch, "00000000000000000000000000000000", fw, "erase", "none");
	sign_msg(k, RECOVER_NS, msg, sig, sizeof sig);
	check("erase: a signature for another device: exit 3",
	      run_io(sig, 0, NULL, err, sizeof err, "unlock", "erase", "-c", ch, NULL) == 3 && !all_ff(mtd3));
	check("erase without -c (root over lock-mode SSH)",
	      run_io(NULL, 0, NULL, err, sizeof err, "unlock", "erase", NULL) == 0 && all_ff(mtd3));

	/* restore */
	fill_mtd3(mtd3);
	recover_msg(msg, sizeof msg, ch, id, fw, "erase", "none");
	sign_msg(k, RECOVER_NS, msg, sig, sizeof sig);
	snprintf(in, sizeof in, "%s%s", pp, sig);
	check("restore with an erase signature: exit 3, nothing erased",
	      run_io(in, 0, NULL, err, sizeof err, "unlock", "restore", "-c", ch, bk, NULL) == 3 && !all_ff(mtd3));
	recover_msg(msg, sizeof msg, ch, id, fw, "restore", sha);
	sign_msg(k, RECOVER_NS, msg, sig, sizeof sig);
	snprintf(in, sizeof in, "%s%s", pp, sig);
	check("restore: another backup than the one signed for: exit 3, nothing erased",
	      run_io(in, 0, NULL, err, sizeof err, "unlock", "restore", "-c", ch, bk2, NULL) == 3 && !all_ff(mtd3));
	snprintf(in, sizeof in, "the wrong passphrase\n%s", sig);
	check("restore: a wrong passphrase: exit 3, nothing erased",
	      run_io(in, 0, NULL, err, sizeof err, "unlock", "restore", "-c", ch, bk, NULL) == 3 &&
	      strstr(err, "wrong passphrase") && !all_ff(mtd3));
	snprintf(in, sizeof in, "%s%s", pp, sig);
	mkdir(newd, 0700);
	check("restore: the signed backup erases mtd3 and is written to the new DATA",
	      run_io(in, 0, NULL, err, sizeof err, "unlock", "restore", "-c", ch, bk, NULL) == 0 && all_ff(mtd3) &&
	      strstr(err, "restored: 2 files"));
	snprintf(p, sizeof p, "%s/cam/cam.conf", newd);
	check("... cam.conf as backed up", same_file(p, "image.flip=1\n") && mode_is(p, 0600));
	snprintf(p, sizeof p, "%s/cam/users", newd);
	check("... users", same_file(p, "own:admin:Secret-pass1\n"));
	snprintf(p, sizeof p, "%s/cam/claimed", newd);
	check("... and the claimed marker", mode_is(p, 0600));
	/* another camera's backup, even signed for */
	static const char e2[] = "\x12\x34\x56\x78" "a=b\0ethaddr=00:11:22:aa:bb:cd\0";
	fake_mtd0(mtd0, e2, sizeof e2);
	char id2[33];
	device_id(id2);
	fill_mtd3(mtd3);
	recover_msg(msg, sizeof msg, ch, id2, fw, "restore", sha);
	sign_msg(k, RECOVER_NS, msg, sig, sizeof sig);
	snprintf(in, sizeof in, "%s%s", pp, sig);
	check("restore: another camera's backup, signed: refused, nothing erased",
	      run_io(in, 0, NULL, err, sizeof err, "unlock", "restore", "-c", ch, bk, NULL) == 1 &&
	      strstr(err, "another camera") && !all_ff(mtd3));
	fake_mtd0(mtd0, e1, sizeof e1);
	snprintf(in, sizeof in, "%s", pp);
	check("restore without -c (root over lock-mode SSH)",
	      run_io(in, 0, NULL, err, sizeof err, "unlock", "restore", bk2, NULL) == 0 && all_ff(mtd3));
	snprintf(p, sizeof p, "%s/cam/cam.conf", newd);
	check("... the second backup's cam.conf", same_file(p, "image.flip=0\n"));
	/* the lock page's upload: passphrase, signature, then the backup, all on stdin (FILE "-") */
	fill_mtd3(mtd3);
	recover_msg(msg, sizeof msg, ch, id, fw, "restore", sha);
	sign_msg(k, RECOVER_NS, msg, sig, sizeof sig);
	n = bin_read(bk, f, sizeof f);
	static char body[BK_MAX + 16384];
	size_t bl = (size_t)snprintf(body, sizeof body, "%s%s", pp, sig);
	memcpy(body + bl, f, n);
	check("restore -c with everything on stdin (the lock page's body)",
	      run_io(body, bl + n, NULL, err, sizeof err, "unlock", "restore", "-c", ch, "-", NULL) == 0 && all_ff(mtd3));
	snprintf(p, sizeof p, "%s/cam/cam.conf", newd);
	check("... the first backup's cam.conf again", same_file(p, "image.flip=1\n"));
	fill_mtd3(mtd3);
	body[bl + 100] ^= 1;
	check("... one byte of it changed: exit 3 (its hash isn't the signed one), nothing erased",
	      run_io(body, bl + n, NULL, err, sizeof err, "unlock", "restore", "-c", ch, "-", NULL) == 3 && !all_ff(mtd3));

	unsetenv("CAMCFG_MTD0");
	unsetenv("CAMCFG_MTD3");
	unsetenv("CAMCFG_RECOVER_DIR");
	unsetenv("CAMCFG_UPDATE_KEYS");
	unsetenv("CAMCFG_DATA_FAILED");
	rm_tree(tdir);
	snprintf(tdir, sizeof tdir, "%s", top);
}

/* ---- #80: network settings -------------------------------------------------------------- */

static void test_net(void)
{
	char out[2048], conf[600], pend[600], now[1024];
	snprintf(conf, sizeof conf, "%s/cam.conf", tdir);
	snprintf(pend, sizeof pend, "%s/net-pending", tdir);
	check("net show with nothing set: DHCP, nothing waiting",
	      run_cc(NULL, out, sizeof out, "net", "show", NULL) == 0 &&
	      !strcmp(out, "mode=dhcp\naddress=\nnetmask=\ngateway=\ndns=\nhostname=\npending=0\n"));
	static const char *bad[][6] = {
		{ "mode=static", "address=198.51.100.5/24", "gateway=198.51.100.1" },      /* outside the CA's range */
		{ "mode=static", "address=192.0.2.0/24", "gateway=192.0.2.1" },      /* network address */
		{ "mode=static", "address=192.0.2.255/24", "gateway=192.0.2.1" },    /* broadcast */
		{ "mode=static", "address=192.0.2.5/31", "gateway=192.0.2.4" },
		{ "mode=static", "address=192.0.2.5/7", "gateway=192.0.2.4" },
		{ "mode=static", "address=192.0.2.5/024", "gateway=192.0.2.1" },
		{ "mode=static", "address=192.0.2.5", "gateway=192.0.2.1" },
		{ "mode=static", "address=0192.0.2.5/24", "gateway=192.0.2.1" },
		{ "mode=static", "address=192.0.2.5/24" },                           /* no gateway */
		{ "mode=static", "gateway=192.0.2.1" },
		{ "mode=static", "address=192.0.2.5/24", "gateway=198.51.100.1" },      /* other subnet */
		{ "mode=static", "address=192.0.2.5/24", "gateway=192.0.2.5" },      /* itself */
		{ "mode=static", "address=192.0.2.5/24", "gateway=192.0.2.0" },
		{ "mode=dhcp", "address=192.0.2.5/24" },
		{ "mode=dhcp", "gateway=192.0.2.1" },
		{ "mode=dhcp", "dns=127.0.0.1" }, { "mode=dhcp", "dns=0.0.0.0" }, { "mode=dhcp", "dns=224.0.0.1" },
		{ "mode=dhcp", "dns=255.255.255.255" }, { "mode=dhcp", "dns=1.1.1.1,2.2.2.2,3.3.3.3,4.4.4.4" },
		{ "mode=dhcp", "dns=1.1.1.1," }, { "mode=dhcp", "dns=1.1.1.1 2.2.2.2" }, { "mode=dhcp", "dns=x" },
		{ "mode=dhcp", "hostname=-cam" }, { "mode=dhcp", "hostname=cam-" }, { "mode=dhcp", "hostname=Cam" },
		{ "mode=dhcp", "hostname=cam.lan" }, { "mode=dhcp", "hostname=cam;reboot" },
		{ "mode=dhcp", "hostname=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" }, /* 64 */
		{ "mode=manual" }, { "hostname=cam" }, { "mode=dhcp", "mode=dhcp" }, { "mode=dhcp", "foo=1" },
		{ "mode" }, { "mode=dhcp", "=x" },
	};
	for (size_t i = 0; i < sizeof bad / sizeof bad[0]; i++) {
		char what[300];
		snprintf(what, sizeof what, "net set refuses %s %s %s, and writes nothing", bad[i][0],
			 bad[i][1] ? bad[i][1] : "", bad[i][2] ? bad[i][2] : "");
		int rc = run_cc(NULL, out, sizeof out, "net", "set", bad[i][0], bad[i][1], bad[i][2], NULL);
		check(what, rc == 1 && access(conf, F_OK) < 0 && access(pend, F_OK) < 0);
	}
	check("set net.mode is refused (only net set writes them)",
	      run_cc(NULL, out, sizeof out, "set", "net.mode", "static", NULL) == 1 && access(conf, F_OK) < 0);
	check("unset net.address is refused", run_cc(NULL, out, sizeof out, "unset", "net.address", NULL) == 1);
	check("net.plain is still an ordinary setting", run_cc(NULL, out, sizeof out, "set", "net.plain", "0", NULL) == 0);
	check("net set static", run_cc(NULL, out, sizeof out, "net", "set", "mode=static", "address=192.0.2.159/24",
					"gateway=192.0.2.1", "dns=192.0.2.1,1.1.1.1", "hostname=cam1", NULL) == 0);
	slurp(conf, now, sizeof now);
	check("... cam.conf keeps net.plain and gains the five rows",
	      !strcmp(now, "net.plain=0\nnet.mode=static\nnet.address=192.0.2.159/24\nnet.gateway=192.0.2.1\n"
			   "net.dns=192.0.2.1,1.1.1.1\nnet.hostname=cam1\n"));
	slurp(pend, now, sizeof now);
	check("... the confirmed settings (DHCP: no rows) wait in net-pending", access(pend, F_OK) == 0 && !*now);
	check("net show", run_cc(NULL, out, sizeof out, "net", "show", NULL) == 0 &&
	      !strcmp(out, "mode=static\naddress=192.0.2.159\nnetmask=255.255.255.0\ngateway=192.0.2.1\n"
			   "dns=192.0.2.1 1.1.1.1\nhostname=cam1\npending=1\n"));
	check("get net.address still works", run_cc(NULL, out, sizeof out, "get", "net.address", NULL) == 0 &&
	      !strcmp(out, "192.0.2.159/24\n"));
	check("a second change while one waits", run_cc(NULL, out, sizeof out, "net", "set", "mode=static",
							 "address=192.0.2.60/25", "gateway=192.0.2.1", NULL) == 0);
	slurp(pend, now, sizeof now);
	check("... net-pending still holds the confirmed (DHCP) settings", !*now);
	check("net revert", run_cc(NULL, out, sizeof out, "net", "revert", NULL) == 0);
	slurp(conf, now, sizeof now);
	check("... DHCP again, net.plain kept, net-pending gone", !strcmp(now, "net.plain=0\n") && access(pend, F_OK) < 0);
	check("net revert with nothing waiting: exit 1", run_cc(NULL, out, sizeof out, "net", "revert", NULL) == 1);
	check("net confirm with nothing waiting: exit 0", run_cc(NULL, out, sizeof out, "net", "confirm", NULL) == 0);
	check("net set to the confirmed settings: unchanged, nothing waits",
	      run_cc(NULL, out, sizeof out, "net", "set", "mode=dhcp", NULL) == 0 && strstr(out, "unchanged") &&
	      access(pend, F_OK) < 0);
	check("net set static without dns: saved, with a warning",
	      run_cc(NULL, out, sizeof out, "net", "set", "mode=static", "address=192.0.2.159/24", "gateway=192.0.2.1",
		     NULL) == 0 && strstr(out, "no dns"));
	check("net confirm", run_cc(NULL, out, sizeof out, "net", "confirm", NULL) == 0 && access(pend, F_OK) < 0);
	check("net set dhcp with dns and hostname", run_cc(NULL, out, sizeof out, "net", "set", "mode=dhcp",
							 "dns=9.9.9.9", "hostname=porch-1", NULL) == 0);
	slurp(pend, now, sizeof now);
	check("... net-pending holds the confirmed static rows",
	      !strcmp(now, "net.mode=static\nnet.address=192.0.2.159/24\nnet.gateway=192.0.2.1\n"));
	check("net set back to the confirmed static settings: nothing waits any more",
	      run_cc(NULL, out, sizeof out, "net", "set", "mode=static", "address=192.0.2.159/24", "gateway=192.0.2.1",
		     NULL) == 0 && access(pend, F_OK) < 0);
	slurp(conf, now, sizeof now);
	check("... and cam.conf holds them", !strcmp(now, "net.plain=0\nnet.mode=static\nnet.address=192.0.2.159/24\n"
						  "net.gateway=192.0.2.1\n"));
	spit(conf, "net.mode=static\nnet.address=192.168.1.5/24\nnet.gateway=192.168.1.1\n");
	check("net show of hand-edited settings outside the range: exit 1",
	      run_cc(NULL, out, sizeof out, "net", "show", NULL) == 1 && strstr(out, "192.0.2.0/24"));
	spit(conf, "net.mode=static\nnet.address=192.0.2.5/24\nnet.gateway=192.0.2.1\nnet.dns="
		   "1.1.1.1,1.1.1.1,1.1.1.1,1.1.1.1,1.1.1.1,1.1.1.1,1.1.1.1,1.1.1.1,1.1.1.1,1.1.1.1\n");
	check("net show of an overlong value: exit 1", run_cc(NULL, out, sizeof out, "net", "show", NULL) == 1);
	unlink(conf);
	unlink(pend);
}

int main(void)
{
	const char *tmp = getenv("TMPDIR");
	char lock[600];
	snprintf(tdir, sizeof tdir, "%s/camcfg-test-%d", tmp && *tmp ? tmp : ".", (int)getpid());
	if (mkdir(tdir, 0700)) { perror(tdir); return 1; }
	setvbuf(stdout, NULL, _IOLBF, 0);
	setenv("CAMCTL_SOCK", "/nonexistent/camd.sock", 1);
	test_sha256();
	test_keys();
	test_sshkey();
	test_passwords();
	test_settings();
	test_tuning_settings();
	test_ctl();
	test_osd();
	test_tz();
	test_ntp_copy();
	test_kdf();
	test_claim();
	test_tls();
	test_lock();
	test_line_limits();
	test_backup();
	test_unlock();
	test_net();
	snprintf(lock, sizeof lock, "%s/.lock", tdir);
	unlink(lock);
	check("test dir cleaned up", rmdir(tdir) == 0);
	printf("all camcfg tests passed\n");
	return 0;
}
