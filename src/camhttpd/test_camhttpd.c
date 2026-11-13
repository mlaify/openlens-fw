/* SPDX-License-Identifier: MIT */
/*
 * Host test for camhttpd (no camera, no network port): camhttpd.c is compiled in and its request
 * handler (http_feed) and WS-Discovery matcher (disco_probe) run on canned input.
 *
 *   clang -std=c11 -Wall -Wextra -g -fsanitize=address,undefined -Isrc/rtspd \
 *       -o $TMPDIR/test_camhttpd src/camhttpd/test_camhttpd.c src/rtspd/auth.c
 *   $TMPDIR/test_camhttpd
 *
 * Checks: SHA-1 (FIPS 180 vectors), Base64 (RFC 4648), the UsernameToken digest (ONVIF
 * Programmer's Guide example), HTTP Digest (RFC 2617 example and the full 401 flow: nc replay,
 * stale and forged nonces, wrong URI), PRE_AUTH vs protected operations, roles (GetUsers,
 * SetSystemDateAndTime), UsernameToken replay/clock window/PasswordText, the per-address lockout,
 * media answers from cam.conf, faults, the snapshot path (503 without rtspd; a fake rtspd where
 * unix sockets are allowed), malformed/oversized requests and a mutation fuzz, Probe matching,
 * the operations Surveillance Station needs (SetVideoEncoderConfiguration via a fake camcfg, incl.
 * the stream sizes it may pick from ResolutionsAvailable, 1..30 fps, the sub at most the main's fps,
 * the video source staying 2560x1440, the OSD's FontSize following the main size; NTP;$TEST_CAMCFG=a host-built camcfg also runs the real fork/exec), and Imaging and Events
 * against a fake rtspd (get/set/motion) with a movable monotonic clock (held PullMessages), and
 * Analytics (CellMotionEngine/CellMotionDetector: PackBits ActiveCells <-> motion.mask), and audio
 * (the microphone's configurations in both profiles, or none with audio.enabled=0), and the
 * speaker (output/decoder configurations in the profiles' Extension, DeviceIO), and the web UI
 * (#79): every page and form per role, CSRF, escaping, form parsing, users and SSH keys through a
 * fake camcfg (the real one with $TEST_CAMCFG, password policy included), reboot,
 * and /preview.mjpg over a socketpair; and the OSD (Media GetOSDs/GetOSD/GetOSDOptions/SetOSD/
 * CreateOSD/DeleteOSD as SSS sends them, positions both ways, faults, roles; the OSD page); and the
 * time zone (time.tz: Get/SetSystemDateAndTime TZ and LocalDateTime, InvalidTimeZone; the Time
 * page's zone form, the Status page's local time); and the first-boot claim and admin recovery
 * (#128): unclaimed in and after the window, /setup's Host, CSRF and rate checks, the claim and
 * its log line, /recover's window, lockout and rotation (end to end with $TEST_CAMCFG); and the
 * firmware update (#104): the raw upload's checks before any body byte, streaming to the staged
 * file, one upload at a time, cancel and write failure, camupdate --check through a stub script
 * (OK, REFUSED, garbage, missing, hung), the Install form bound to its upload, and camupdate
 * started detached after the reply, with a clean environment; and HTTPS (docs/PLAN-TLS.md B):
 * the PROXY-line parser (table and fuzz), -t's refusals, camtls connections on a socketpair (uid,
 * PROXY line, its time limit, the per-address limits after it, SO_SNDBUF), the https Origin, Host
 * and link rules, and port 80's redirects while camtls's ready file exists (and not without it); and
 * the System page's HTTPS status and the CA download (#183: admin only, the file's checks, no other
 * path serves it); and the settings backup (#172, #173): the multipart parser (cases and a fuzz), the
 * System page's download and restore and /setup/restore through a camcfg stub script (roles,
 * HTTPS only, CSRF, sizes, wrong passwords and passphrases counted, the monitor's checks, the
 * reboot after the reply), the claim's backup offer, and with $TEST_CAMCFG the real camcfg end to
 * end on a fake mtd0.
 * Temp files go to $TMPDIR.
 */
#define _GNU_SOURCE                    /* as camhttpd.c, before any system header */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include "tz.h"                        /* the fake rtspd checks time.tz as the real one */

static struct timeval set_tv;
static int set_calls;
static int fake_settime(const struct timeval *tv) { set_tv = *tv; set_calls++; return 0; }
#define SET_TIME(tv) fake_settime(tv)
static long long mono_adj;              /* ms added to the monotonic clock */
#define MONO_ADJ_MS mono_adj
static int ctl_cmd(const char *line, char *out, size_t cap, int ms);
static const char *fake_ctl;           /* canned snapshot reply, or NULL for the real socket */
static int ctl_calls, restarts;
/* A fake rtspd for get/set/motion: its image settings, day/night mode and motion detector. */
static int fake_img[5] = { 50, 50, 50, 50, 50 }, fake_down, fake_mstate, motion_calls;
static char fake_mode[8] = "auto", set_log[1024];
static unsigned long fake_mseq;
static long fake_msince;
static int fake_msens = 50;
static int fake_mirror, fake_flip, fake_set_err;     /* fake_set_err: "set" refusals (rtspd's err) */
static long fake_sh[2], fake_nb = 15, fake_da = 1500;
static const char *const tune_keys[6] = { "image.nr2d", "image.nr3d", "image.wdr", "image.blc", "image.mains_hz",
					  "image.antiflicker" };
static int fake_tune[6] = { 128, 128, 0, 0, 60, 0 }, fake_nt;
static char fake_en[8] = "day";        /* image.exposure_night */
static char fake_osd[1024];             /* "osd.KEY=VALUE\n" lines rtspd's get adds */
static void fake_osd_set(const char *k, const char *v)
{
	char out[1024] = "", *l = fake_osd;
	size_t kl = strlen(k);
	for (char *e; *l; l = e) {                       /* every other key's line kept */
		e = l + strcspn(l, "\n") + 1;
		if (strncmp(l, k, kl) || l[kl] != '=') snprintf(out + strlen(out), sizeof out - strlen(out), "%.*s", (int)(e - l), l);
	}
	snprintf(out + strlen(out), sizeof out - strlen(out), "%s=%s\n", k, v);
	snprintf(fake_osd, sizeof fake_osd, "%s", out);
}
static char fake_mask[257] = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
	"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
	"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
	"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
static int test_ctl(const char *line, char *out, size_t cap, int ms)
{
	static const char *const keys[5] = { "image.brightness", "image.contrast", "image.saturation",
					     "image.sharpness", "image.exposure" };
	ctl_calls++;
	if (fake_down) return -1;
	if (!strcmp(line, "get\n")) {
		snprintf(out, cap, "image.brightness=%d\nimage.contrast=%d\nimage.saturation=%d\n"
			 "image.sharpness=%d\nimage.exposure=%d\nimage.exposure_night=%s\nimage.mirror=%d\nimage.flip=%d\n"
			 "image.shutter_day_max=%ld\nimage.shutter_night_max=%ld\ndaynight.mode=%s\ndaynight.irled=96\n"
			 "daynight.invert=1\ndaynight.night_below=%ld\ndaynight.day_above=%ld\ndaynight.state=day\n"
			 "daynight.score=4321\nmotion.enabled=1\nmotion.sensitivity=%d\n"
			 "motion.grid=32x32\nmotion.mask=%s\nimage.nr2d=%d\nimage.nr3d=%d\nimage.wdr=%d\nimage.blc=%d\n"
			 "image.mains_hz=%d\nimage.antiflicker=%d\nimage.night_tuning=%d\n%sok\n", fake_img[0], fake_img[1],
			 fake_img[2], fake_img[3], fake_img[4], fake_en, fake_mirror, fake_flip, fake_sh[0], fake_sh[1], fake_mode,
			 fake_nb, fake_da, fake_msens, fake_mask, fake_tune[0], fake_tune[1], fake_tune[2], fake_tune[3],
			 fake_tune[4], fake_tune[5], fake_nt, fake_osd);
		return 0;
	}
	if (!strcmp(line, "motion\n")) {
		motion_calls++;
		snprintf(out, cap, "motion.state=%d\nmotion.seq=%lu\nmotion.since=%ld\nok\n", fake_mstate,
			 fake_mseq, fake_msince);
		return 0;
	}
	if (!strncmp(line, "set ", 4)) {
		char k[40], v[16];
		size_t ll = strlen(set_log);
		snprintf(set_log + ll, sizeof set_log - ll, "%.*s;", (int)strcspn(line, "\n"), line);
		if (!strncmp(line, "set osd.", 8)) {            /* rtspd takes the rest of the line */
			char k[40], v[80] = "";
			const char *sp = strchr(line + 4, ' ');
			size_t kl = sp ? (size_t)(sp - line - 4) : strcspn(line + 4, "\n");
			snprintf(k, sizeof k, "%.*s", (int)kl, line + 4);
			if (sp) snprintf(v, sizeof v, "%.*s", (int)strcspn(sp + 1, "\n"), sp + 1);
			fake_osd_set(k, v);
			snprintf(out, cap, "ok\n");
			return 0;
		}
		if (!strncmp(line, "set time.tz ", 12)) {         /* rtspd checks it as camcfg does */
			char v[80];
			snprintf(v, sizeof v, "%.*s", (int)strcspn(line + 12, "\n"), line + 12);
			snprintf(out, cap, tz_valid(v) ? "ok\n" : "err time.tz\n");
			return 0;
		}
		if (!strncmp(line, "set motion.mask ", 16)) {
			size_t hl = strcspn(line + 16, "\n");
			if (hl == 256 && strspn(line + 16, "0123456789abcdefABCDEF") == 256) {
				memcpy(fake_mask, line + 16, 256);
				snprintf(out, cap, "ok\n");
			} else snprintf(out, cap, "err motion.mask: 256 hex digits\n");
			return 0;
		}
		snprintf(out, cap, "err unknown key\n");
		if (sscanf(line, "set %39s %15s", k, v) != 2) return 0;
		for (int i = 0; i < 5; i++)
			if (!strcmp(k, keys[i])) { fake_img[i] = atoi(v); snprintf(out, cap, "ok\n"); }
		if (!strcmp(k, "daynight.mode")) { snprintf(fake_mode, sizeof fake_mode, "%s", v); snprintf(out, cap, "ok\n"); }
		if (!strcmp(k, "motion.sensitivity")) { fake_msens = atoi(v); snprintf(out, cap, "ok\n"); }
		if (!strcmp(k, "image.mirror")) { fake_mirror = atoi(v); snprintf(out, cap, "ok\n"); }
		if (!strcmp(k, "image.flip")) { fake_flip = atoi(v); snprintf(out, cap, "ok\n"); }
		if (!strcmp(k, "image.night_tuning")) { fake_nt = atoi(v); snprintf(out, cap, "ok\n"); }
		if (!strcmp(k, "image.exposure_night")) { snprintf(fake_en, sizeof fake_en, "%s", v); snprintf(out, cap, "ok\n"); }
		for (int i = 0; i < 6; i++)
			if (!strcmp(k, tune_keys[i])) { fake_tune[i] = atoi(v); snprintf(out, cap, "ok\n"); }
		if (!strcmp(k, "image.shutter_day_max")) { fake_sh[0] = atol(v); snprintf(out, cap, "ok\n"); }
		if (!strcmp(k, "image.shutter_night_max")) { fake_sh[1] = atol(v); snprintf(out, cap, "ok\n"); }
		if (!strcmp(k, "daynight.night_below") || !strcmp(k, "daynight.day_above")) {   /* rtspd keeps nb < da */
			int nb = !strcmp(k, "daynight.night_below");
			if (nb ? atol(v) < fake_da : fake_nb < atol(v)) {
				*(nb ? &fake_nb : &fake_da) = atol(v);
				snprintf(out, cap, "ok\n");
			} else {
				fake_set_err++;
				snprintf(out, cap, "err night_below < day_above\n");
			}
		}
		return 0;
	}
	if (!strcmp(line, "motion map\n")) {
		snprintf(out, cap, "motion.map=change/10%% 4x2 mean=40.0 bg=40.0 jump=0 learn=0 share=0%%\n"
			 "--01\n#9+-\nok\n");
		return 0;
	}
	if (!strcmp(line, "restart\n")) {                 /* rtspd acknowledges, then exits */
		restarts++;
		snprintf(out, cap, "ok\n");
		return 0;
	}
	if (!fake_ctl) return ctl_cmd(line, out, cap, ms);
	snprintf(out, cap, "%s", fake_ctl);
	return strcmp(line, "snapshot\n") ? -1 : 0;
}
#define CTL_CMD test_ctl
static unsigned long long scan_bytes, hash_bytes;
#define SCAN_COUNT(n) (scan_bytes += (unsigned long long)(n))
#define HASH_COUNT(n) (hash_bytes += (unsigned long long)(n))
static int fake_camcfg(const char *key, const char *val);
#define RUN_CAMCFG fake_camcfg
static const char *camcfg_bin = "/nonexistent/camcfg";   /* $TEST_CAMCFG: a host-built camcfg */
#define CAMCFG camcfg_bin
static int fake_exec(const char *dir, const char *const *args, const char *in, char *out, size_t cap);
#define CAMCFG_EXEC fake_exec          /* camcfg user/sshkey for the web UI */
static int reboots;
#define DO_REBOOT() (reboots++, 0)
static const char *camupdate_bin = "/nonexistent/camupdate";   /* test_firmware: a stub script */
#define CAMUPDATE camupdate_bin
#define CAMCFG_MS 1500                 /* test_gate3: a hung camcfg is killed sooner than on the camera */
static char *bk_env[] = { "PATH=/usr/sbin:/usr/bin:/sbin:/bin", NULL, NULL };   /* [1]: test_backup's fake mtd0 */
#define CAMCFG_ENV bk_env
static void reply_seen(const char *p, size_t n);
#define MON_REPLY_SEEN(p, n) reply_seen(p, n)   /* test_monitor: no password or HA1 in any reply */
#define main camhttpd_main
#include "camhttpd.c"
#undef main

#include <sys/wait.h>

/* Stands in for "camcfg set KEY VALUE": logs the call and replaces or adds the cam.conf line. */
static char camcfg_log[2048];
static int camcfg_calls, camcfg_fail;
static int fake_camcfg(const char *key, const char *val)
{
	static char buf[8192];
	char line[300];
	size_t n = 0, kl = strlen(key), ll = strlen(camcfg_log);
	camcfg_calls++;
	snprintf(camcfg_log + ll, sizeof camcfg_log - ll, "%s=%s;", key, val);
	if (camcfg_fail) return 1;
	FILE *f = fopen(conf_path, "r");
	if (f) {
		while (fgets(line, sizeof line, f) && n < sizeof buf - sizeof line)
			if (strncmp(line, key, kl) || line[kl] != '=') n += (size_t)snprintf(buf + n, sizeof buf - n, "%s", line);
		fclose(f);
	}
	snprintf(buf + n, sizeof buf - n, "%s=%s\n", key, val);
	if (!(f = fopen(conf_path, "w"))) return 1;
	fputs(buf, f);
	fclose(f);
	return 0;
}

/* Stands in for "camcfg user ..." (on the users file) and "camcfg sshkey ..." (on fake_keys),
 * logging argv and stdin apart; no validation, that is camcfg's (real_exec runs the real one). */
static char exec_log[4096], exec_in[UI_BODY_MAX + 2];
static int exec_fail, real_exec;
static char fake_keys[UI_KEYS + 2][700];          /* "type\tfingerprint\tcomment" */
static int nfake_keys;

/* Stands in for "camcfg claim NAME" and "camcfg recover [NAME]" (#128): the users file, one
 * recovery code (rotated by one character on each use) and the admin it was made for. */
static char fake_code[27] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ", fake_code_user[40];
static void fake_code_show(char *out, size_t cap)
{
	size_t o = 0;
	for (int i = 0; i < 26 && o + 2 < cap; i++) {
		if (i && i % 4 == 0) out[o++] = '-';
		out[o++] = fake_code[i];
	}
	out[o] = 0;
}
static int fake_claim(const char *const *args, const char *in, char *out, size_t cap)
{
	static char rows[40][300];
	char a[300], b[700], code[300], shown[40];
	int n = 0, admin = 0, at = -1;
	const char *nl = strchr(in, '\n');
	snprintf(a, sizeof a, "%.*s", nl ? (int)(nl - in) : (int)strlen(in), in);
	snprintf(b, sizeof b, "%.*s", nl ? (int)strcspn(nl + 1, "\n") : 0, nl ? nl + 1 : "");
	FILE *f = fopen(users_path, "r");
	while (f && n < 40 && fgets(rows[n], sizeof rows[0], f)) rows[n][strcspn(rows[n], "\n")] = 0, n++;
	if (f) fclose(f);
	for (int i = 0; i < n; i++) admin |= strstr(rows[i], ":admin:") != NULL;
	if (!strcmp(args[0], "claim")) {
		if (admin) { snprintf(out, cap, "camcfg: this camera is already claimed: it has an admin\n"); return 1; }
		snprintf(rows[n++], sizeof rows[0], "%s:admin:%s", args[1], a);
		if (*b) {
			char type[64] = "?";
			sscanf(b, "%63s", type);
			snprintf(fake_keys[nfake_keys++], sizeof fake_keys[0], "%s\tSHA256:claimed\tfrom setup", type);
		}
		snprintf(fake_code_user, sizeof fake_code_user, "%s", args[1]);
		fake_code_show(shown, sizeof shown);
		snprintf(out, cap, "camcfg: saved; rtspd not reloaded (not running?)\nrecovery-code: %s\n", shown);
	} else {
		size_t k = 0;
		for (const char *p = a; *p && k < sizeof code - 1; p++)
			if (*p != ' ' && *p != '-') code[k++] = (char)toupper((unsigned char)*p);
		code[k] = 0;
		if (strcmp(code, fake_code)) { snprintf(out, cap, "camcfg: wrong recovery code\n"); return 3; }
		const char *name = args[1] ? args[1] : fake_code_user;
		size_t nl2 = strlen(name);
		for (int i = 0; i < n; i++)
			if (!strncmp(rows[i], name, nl2) && !strncmp(rows[i] + nl2, ":admin:", 7)) at = i;
		if (at < 0) { snprintf(out, cap, "camcfg: no admin %s\n", name); return 1; }
		snprintf(rows[at], sizeof rows[0], "%s:admin:%s", name, b);
		memmove(fake_code, fake_code + 1, 25);              /* a new code: the old one rotated */
		fake_code[25] = code[0];
		snprintf(fake_code_user, sizeof fake_code_user, "%s", name);
		fake_code_show(shown, sizeof shown);
		snprintf(out, cap, "admin: %s\nrecovery-code: %s\n", name, shown);
	}
	if (!(f = fopen(users_path, "w"))) return 1;
	for (int i = 0; i < n; i++) fprintf(f, "%s\n", rows[i]);
	fclose(f);
	return 0;
}

static int fake_exec(const char *dir, const char *const *args, const char *in, char *out, size_t cap)
{
	static char rows[40][300];
	char line[300];
	int n = 0;
	if (real_exec) return camcfg_exec(dir, args, in, out, cap);
	for (int i = 0; args[i]; i++)
		snprintf(exec_log + strlen(exec_log), sizeof exec_log - strlen(exec_log), "%s%s", i ? " " : "", args[i]);
	snprintf(exec_log + strlen(exec_log), sizeof exec_log - strlen(exec_log), ";");
	if (in) snprintf(exec_in, sizeof exec_in, "%s", in);
	*out = 0;
	if (exec_fail) { snprintf(out, cap, "camcfg: <b>refused</b> & logged\n"); return 1; }
	if (!strcmp(args[0], "claim") || !strcmp(args[0], "recover")) return fake_claim(args, in, out, cap);
	if (!strcmp(args[0], "sshkey")) {
		if (!strcmp(args[1], "list"))
			for (int i = 0; i < nfake_keys; i++)
				snprintf(out + strlen(out), cap - strlen(out), "%d\t%s\n", i + 1, fake_keys[i]);
		else if (!strcmp(args[1], "add")) {
			char type[64] = "?", b64[600] = "", *com;
			sscanf(in, "%63s %599s", type, b64);
			com = strchr(in, ' ') ? strchr(strchr(in, ' ') + 1, ' ') : NULL;
			snprintf(fake_keys[nfake_keys], sizeof fake_keys[0], "%s\tSHA256:fake%d\t%.*s", type, nfake_keys,
				 com ? (int)strcspn(com + 1, "\n") : 0, com ? com + 1 : "");
			snprintf(out, cap, "%d\t%s\n", nfake_keys + 1, fake_keys[nfake_keys]);
			nfake_keys++;
		} else if (!strcmp(args[1], "del")) {
			int k = atoi(args[2]) - 1;
			memmove(fake_keys[k], fake_keys[k + 1], (size_t)(nfake_keys - k - 1) * sizeof fake_keys[0]);
			nfake_keys--;
		}
		return 0;
	}
	FILE *f = fopen(users_path, "r");
	while (f && n < 40 && fgets(rows[n], sizeof rows[0], f)) rows[n][strcspn(rows[n], "\n")] = 0, n++;
	if (f) fclose(f);
	const char *op = args[1], *name = args[2];
	size_t nl = strlen(name);
	int at = -1;
	for (int i = 0; i < n; i++)
		if (!strncmp(rows[i], name, nl) && rows[i][nl] == ':') at = i;
	if (!strcmp(op, "add")) snprintf(rows[n++], sizeof rows[0], "%s:%s:%.*s", name, args[3], (int)strcspn(in, "\n"), in);
	else if (at < 0) { snprintf(out, cap, "camcfg: no user %s\n", name); return 1; }
	else if (!strcmp(op, "passwd")) {
		char *r = strchr(rows[at], ':') + 1, *p = strchr(r, ':') + 1;
		snprintf(line, sizeof line, "%.*s%.*s", (int)(p - rows[at]), rows[at], (int)strcspn(in, "\n"), in);
		snprintf(rows[at], sizeof rows[0], "%s", line);
	} else if (!strcmp(op, "role")) {
		char *r = strchr(rows[at], ':') + 1, *p = strchr(r, ':') + 1;
		snprintf(line, sizeof line, "%s:%s:%s", name, args[3], p);
		snprintf(rows[at], sizeof rows[0], "%s", line);
	} else if (!strcmp(op, "del")) {
		memmove(rows[at], rows[at + 1], (size_t)(n - at - 1) * sizeof rows[0]);
		n--;
	}
	if (!(f = fopen(users_path, "w"))) return 1;
	for (int i = 0; i < n; i++) fprintf(f, "%s\n", rows[i]);
	fclose(f);
	return 0;
}

static struct client cl;
static char resp[2 * OUT_CAP + SNAP_MAX / 64];
static const char *peer_ip = "192.0.2.50";
static int as_tls;                                     /* run/run_on: as a connection from camtls (PROXY taken) */

static void auth_reset(void)
{
	memset(fails, 0, sizeof fails);
	memset(&gfail, 0, sizeof gfail);
	memset(good, 0, sizeof good);
}

static void check(const char *what, int ok)
{
	if (!ok) { fprintf(stderr, "FAIL %s\n", what); exit(1); }
	printf("ok: %s\n", what);
}

static void expect(const char *what, const char *r, const char *want)
{
	if (!strstr(r, want)) {
		fprintf(stderr, "FAIL %s: want \"%s\" in:\n%s\n", what, want, r);
		exit(1);
	}
	printf("ok: %s\n", what);
}

static void absent(const char *what, const char *r, const char *bad)
{
	if (strstr(r, bad)) {
		fprintf(stderr, "FAIL %s: unexpected \"%s\" in:\n%s\n", what, bad, r);
		exit(1);
	}
}

/* Feed a raw request to the handler `chunk` bytes at a time, as client_read would. */
static const char *run_n(const char *req, size_t n, size_t chunk)
{
	size_t off = 0;
	client_reset(&cl, -1);
	inet_pton(AF_INET, peer_ip, &cl.peer);
	strcpy(cl.local, "192.0.2.10");
	cl.tls = as_tls;
	while (!cl.state && off < n && cl.in_len < REQ_CAP) {
		size_t k = n - off < chunk ? n - off : chunk;
		if (k > REQ_CAP - cl.in_len) k = REQ_CAP - cl.in_len;
		memcpy(cl.in + cl.in_len, req + off, k);
		cl.in_len += k;
		off += k;
		http_feed(&cl);
	}
	size_t rn = cl.out_len;
	memcpy(resp, cl.out, rn);
	if (cl.file_fd >= 0) {
		ssize_t k;
		while (cl.file_left > 0 && (k = read(cl.file_fd, resp + rn, sizeof resp - 1 - rn)) > 0) {
			rn += (size_t)k;
			cl.file_left -= k;
		}
		close(cl.file_fd);
		cl.file_fd = -1;
	}
	resp[rn] = 0;
	return resp;
}

static const char *run(const char *req) { return run_n(req, strlen(req), 1 << 20); }

/* The reply queued on a client (after a held PullMessages was answered). */
static const char *reply_of(struct client *c)
{
	memcpy(resp, c->out, c->out_len);
	resp[c->out_len] = 0;
	return resp;
}

/* A whole request on one of the loop's clients (fd: something to close, /dev/null). */
static const char *run_on(struct client *c, const char *req)
{
	client_reset(c, open("/dev/null", O_RDONLY));
	inet_pton(AF_INET, peer_ip, &c->peer);
	strcpy(c->local, "192.0.2.10");
	c->tls = as_tls;
	memcpy(c->in, req, strlen(req));
	c->in_len = strlen(req);
	http_feed(c);
	return reply_of(c);
}

static const char *soap_req(const char *path, const char *header, const char *body, const char *authz)
{
	static char buf[REQ_CAP];
	char env[8192];
	int bl = snprintf(env, sizeof env, "<?xml version=\"1.0\" encoding=\"UTF-8\"?><s:Envelope "
			  "xmlns:s=\"http://www.w3.org/2003/05/soap-envelope\" "
			  "xmlns:tds=\"http://www.onvif.org/ver10/device/wsdl\" "
			  "xmlns:trt=\"http://www.onvif.org/ver10/media/wsdl\" "
			  "xmlns:tt=\"http://www.onvif.org/ver10/schema\">%s<s:Body>%s</s:Body></s:Envelope>",
			  header ? header : "", body);
	snprintf(buf, sizeof buf, "POST %s HTTP/1.1\r\nHost: 192.0.2.10\r\nContent-Type: "
		 "application/soap+xml; charset=utf-8\r\n%s%s%sContent-Length: %d\r\n\r\n%s", path,
		 authz ? "Authorization: " : "", authz ? authz : "", authz ? "\r\n" : "", bl, env);
	return buf;
}

/* A WS-Security header with a fresh nonce (or `reuse` the last one). */
static const char *wsse(const char *user, const char *pw, long long created, int text, int reuse)
{
	static char h[2048];
	static uint8_t nonce[16];
	static unsigned counter;
	char cr[32], n64[32], d64[32];
	uint8_t d[20];
	time_t t = (time_t)created;
	struct tm g;
	if (!reuse) { counter++; memset(nonce, 0x5a, 16); memcpy(nonce, &counter, sizeof counter); }
	gmtime_r(&t, &g);
	strftime(cr, sizeof cr, "%Y-%m-%dT%H:%M:%SZ", &g);
	struct sha1 s;
	sha1_init(&s);
	sha1_update(&s, nonce, 16);
	sha1_update(&s, cr, strlen(cr));
	sha1_update(&s, pw, strlen(pw));
	sha1_final(&s, d);
	b64_enc(nonce, 16, n64);
	b64_enc(d, 20, d64);
	snprintf(h, sizeof h, "<s:Header><wsse:Security xmlns:wsse=\"http://docs.oasis-open.org/wss/"
		 "2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd\" xmlns:wsu=\"http://docs.oasis-open.org/"
		 "wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd\"><wsse:UsernameToken>"
		 "<wsse:Username>%s</wsse:Username><wsse:Password Type=\"http://docs.oasis-open.org/wss/"
		 "2004/01/oasis-200401-wss-username-token-profile-1.0#%s\">%s</wsse:Password><wsse:Nonce "
		 "EncodingType=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-"
		 "security-1.0#Base64Binary\">%s</wsse:Nonce><wsu:Created>%s</wsu:Created>"
		 "</wsse:UsernameToken></wsse:Security></s:Header>", user,
		 text ? "PasswordText" : "PasswordDigest", text ? pw : d64, n64, cr);
	return h;
}

static const char *digest(const char *user, const char *pw, const char *method, const char *uri,
			  const char *nonce, unsigned nc)
{
	static char h[512];
	char ha1[33], ha2[33], r[33], ncs[9];
	snprintf(ncs, sizeof ncs, "%08x", nc);
	md5_str(ha1, "%s:%s:%s", user, REALM, pw);
	md5_str(ha2, "%s:%s", method, uri);
	md5_str(r, "%s:%s:%s:0a4f113b:auth:%s", ha1, nonce, ncs, ha2);
	snprintf(h, sizeof h, "Digest username=\"%s\", realm=\"camera\", nonce=\"%s\", uri=\"%s\", "
		 "algorithm=MD5, qop=auth, nc=%s, cnonce=\"0a4f113b\", response=\"%s\"", user, nonce,
		 uri, ncs, r);
	return h;
}

static void nonce_of(const char *r, char out[NONCE_LEN + 1])
{
	const char *p = strstr(r, "nonce=\"");
	if (!p) { fprintf(stderr, "FAIL: no challenge in\n%s\n", r); exit(1); }
	memcpy(out, p + 7, NONCE_LEN);
	out[NONCE_LEN] = 0;
}

static void write_file(const char *path, const char *text)
{
	FILE *f = fopen(path, "w");
	if (!f) { perror(path); exit(1); }
	fputs(text, f);
	fclose(f);
}

static void test_crypto(void)
{
	static const char *const sv[][2] = {
		{ "", "da39a3ee5e6b4b0d3255bfef95601890afd80709" },
		{ "abc", "a9993e364706816aba3e25717850c26c9cd0d89d" },
		{ "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
		  "84983e441c3bd26ebaae4aa1f95129e5e54670f1" },
	};
	uint8_t h[20], buf[64];
	char hx[41];
	for (int i = 0; i < 3; i++) {
		sha1(sv[i][0], strlen(sv[i][0]), h);
		hex(h, 20, hx);
		expect("SHA-1 vector", hx, sv[i][1]);
	}
	struct sha1 s;
	sha1_init(&s);
	memset(buf, 'a', 64);
	for (int i = 0; i < 1000000 / 64; i++) sha1_update(&s, buf, 64);
	sha1_final(&s, h);
	hex(h, 20, hx);
	expect("SHA-1 of a million 'a'", hx, "34aa973cd4c4daa4f61eeb2bdbad27316534016f");

	static const char *const bv[][2] = { { "", "" }, { "f", "Zg==" }, { "fo", "Zm8=" },
		{ "foo", "Zm9v" }, { "foob", "Zm9vYg==" }, { "fooba", "Zm9vYmE=" }, { "foobar", "Zm9vYmFy" } };
	for (int i = 0; i < 7; i++) {
		char e[16];
		b64_enc((const uint8_t *)bv[i][0], strlen(bv[i][0]), e);
		int n = b64_dec(bv[i][1], buf, sizeof buf);
		if (strcmp(e, bv[i][1]) || n != (int)strlen(bv[i][0]) || memcmp(buf, bv[i][0], (size_t)n)) {
			fprintf(stderr, "FAIL base64 %s\n", bv[i][1]);
			exit(1);
		}
	}
	static const char *const badb64[] = { "Zm9", "Zm9=v", "Z===", "Zm 9", "Zm9v=", "=Zm9", "Zg=a" };
	for (int i = 0; i < 7; i++)
		if (b64_dec(badb64[i], buf, sizeof buf) >= 0) { fprintf(stderr, "FAIL base64 accepted %s\n", badb64[i]); exit(1); }
	if (b64_dec("Zm9vYmFy", buf, 5) >= 0) { fprintf(stderr, "FAIL base64 overflow\n"); exit(1); }
	printf("ok: Base64 (RFC 4648 vectors, bad input refused)\n");

	/* ONVIF Application Programmer's Guide: PasswordDigest example */
	char d64[32];
	int nn = b64_dec("LKqI6G/AikKCQrN0zqZFlg==", buf, sizeof buf);
	sha1_init(&s);
	sha1_update(&s, buf, (size_t)nn);
	sha1_update(&s, "2010-09-16T07:50:45Z", 20);
	sha1_update(&s, "userpassword", 12);
	sha1_final(&s, h);
	b64_enc(h, 20, d64);
	expect("UsernameToken digest (ONVIF example)", d64, "tuOSpGlFlIXsozq4HFNeeGeFLEI=");

	/* RFC 2617 3.5 */
	char ha1[33], ha2[33], r[33];
	md5_str(ha1, "Mufasa:testrealm@host.com:Circle Of Life");
	md5_str(ha2, "GET:/dir/index.html");
	md5_str(r, "%s:dcd98b7102dd2f0e8b11d0f600bfb0c093:00000001:0a4f113b:auth:%s", ha1, ha2);
	expect("HTTP Digest response (RFC 2617)", r, "6629fae49393a05397450978507c4ef1");

	long long t;
	if (parse_created("2010-09-16T07:50:45Z", &t) || t != 1284623445 ||
	    parse_created("2010-09-16T09:50:45.123+02:00", &t) || t != 1284623445 ||
	    !parse_created("2010-02-30T07:50:45Z", &t) || !parse_created("2010-09-16T07:50:45", &t) ||
	    !parse_created("2010-09-16T07:50:45Zjunk", &t)) {
		fprintf(stderr, "FAIL parse_created\n");
		exit(1);
	}
	printf("ok: xs:dateTime parsing\n");
}

#define DEV "/onvif/device_service"
#define MED "/onvif/media_service"
#define B_INFO "<tds:GetDeviceInformation/>"
#define B_PROFILES "<trt:GetProfiles/>"
#define B_USERS "<tds:GetUsers/>"

/* The number in <tt:FIELD> inside <tt:WHICH> of a GetSystemDateAndTime answer */
static int dt_field(const char *r, const char *which, const char *field)
{
	char a[64], b[64];
	snprintf(a, sizeof a, "<tt:%s>", which);
	snprintf(b, sizeof b, "<tt:%s>", field);
	const char *p = strstr(r, a), *q = p ? strstr(p, b) : NULL;
	if (!q) { fprintf(stderr, "FAIL no %s/%s in:\n%s\n", which, field, r); exit(1); }
	return atoi(q + strlen(b));
}

/* LocalDateTime minus UTCDateTime in minutes (both from the same instant) */
static int dt_offset(const char *r)
{
	long long s[2];
	for (int i = 0; i < 2; i++) {
		const char *w = i ? "LocalDateTime" : "UTCDateTime";
		s[i] = days_from_civil(dt_field(r, w, "Year"), dt_field(r, w, "Month"), dt_field(r, w, "Day")) * 86400 +
		       dt_field(r, w, "Hour") * 3600 + dt_field(r, w, "Minute") * 60 + dt_field(r, w, "Second");
	}
	return (int)((s[1] - s[0]) / 60);
}

/* time.tz over ONVIF: Get shows it with LocalDateTime in it, Set checks, saves and applies it */
static void test_onvif_tz(void)
{
	const char *r;
	long long now = time(NULL);
	char body[1024];
	const char *set_tz = "<tds:SetSystemDateAndTime><tds:DateTimeType>%s</tds:DateTimeType>"
		"<tds:DaylightSavings>true</tds:DaylightSavings><tds:TimeZone><tt:TZ>%s</tt:TZ></tds:TimeZone>"
		"%s</tds:SetSystemDateAndTime>";
	const char *utc = "<tds:UTCDateTime><tt:Date><tt:Year>2026</tt:Year><tt:Month>10</tt:Month><tt:Day>23</tt:Day>"
		"</tt:Date><tt:Time><tt:Hour>12</tt:Hour><tt:Minute>34</tt:Minute><tt:Second>56</tt:Second>"
		"</tt:Time></tds:UTCDateTime>";
	/* the admin SetSystemDateAndTime above carried TZ CST-8 (UTC+8) */
	check("SetSystemDateAndTime saved its TZ as time.tz", strstr(camcfg_log, "time.tz=CST-8;") != NULL);
	r = run(soap_req(DEV, NULL, "<tds:GetSystemDateAndTime/>", NULL));
	expect("GetSystemDateAndTime: TZ is time.tz", r, "<tt:TimeZone><tt:TZ>CST-8</tt:TZ></tt:TimeZone>");
	check("... LocalDateTime is UTC+8", dt_offset(r) == 8 * 60);
	expect("... DaylightSavings stays false", r, "<tt:DaylightSavings>false</tt:DaylightSavings>");
	/* US Central with NTP: saved, applied live, LocalDateTime UTC-5 (CDT) or UTC-6 (CST) */
	*camcfg_log = *set_log = 0;
	snprintf(body, sizeof body, set_tz, "NTP", "CST6CDT,M3.2.0,M11.1.0", "");
	r = run(soap_req(DEV, wsse("admin", "Adm1nPass!", now, 0, 0), body, NULL));
	expect("SetSystemDateAndTime NTP + TZ US Central", r, "<tds:SetSystemDateAndTimeResponse/>");
	check("... saved", !strcmp(camcfg_log, "time.tz=CST6CDT,M3.2.0,M11.1.0;"));
	check("... and applied live", strstr(set_log, "set time.tz CST6CDT,M3.2.0,M11.1.0;") != NULL);
	r = run(soap_req(DEV, NULL, "<tds:GetSystemDateAndTime/>", NULL));
	expect("... read back", r, "<tt:TZ>CST6CDT,M3.2.0,M11.1.0</tt:TZ>");
	struct tm l;
	time_t t = (time_t)now;
	localtime_r(&t, &l);                               /* camhttpd set our TZ to it */
	check("... LocalDateTime is CDT (UTC-5) or CST (UTC-6) as the date says",
	      dt_offset(r) == (l.tm_isdst > 0 ? -300 : -360));
	r = run(soap_req(DEV, wsse("admin", "Adm1nPass!", now, 0, 0), body, NULL));
	check("the same TZ again: nothing saved", !strcmp(camcfg_log, "time.tz=CST6CDT,M3.2.0,M11.1.0;"));
	/* quoted names come escaped both ways */
	snprintf(body, sizeof body, set_tz, "NTP", "&lt;+0530&gt;-5:30", "");
	r = run(soap_req(DEV, wsse("admin", "Adm1nPass!", now, 0, 0), body, NULL));
	expect("SetSystemDateAndTime TZ <+0530>-5:30", r, "<tds:SetSystemDateAndTimeResponse/>");
	check("... saved unescaped", strstr(camcfg_log, "time.tz=<+0530>-5:30;") != NULL);
	r = run(soap_req(DEV, NULL, "<tds:GetSystemDateAndTime/>", NULL));
	expect("... read back escaped", r, "<tt:TZ>&lt;+0530&gt;-5:30</tt:TZ>");
	check("... LocalDateTime is UTC+5:30", dt_offset(r) == 330);
	/* refusals: nothing saved, the clock untouched */
	static const char *const bad[] = { "CST6CDT;reboot", "$(reboot)", ":/etc/localtime", "UTC25", "CST6CDT,M3.2.0",
		"&lt;+0530&gt;-05:30:00&lt;+0630&gt;-06:30:00,M3.2.0/02:00:00,M11.1.0/02:00:00",     /* 65 */
		"UTC0&amp;", "A2345678901234567890123456789012345678901234567890123456789012345678901234567890" };
	int calls = camcfg_calls, sc = set_calls;
	for (unsigned i = 0; i < sizeof bad / sizeof bad[0]; i++) {
		snprintf(body, sizeof body, set_tz, "Manual", bad[i], utc);
		r = run(soap_req(DEV, wsse("admin", "Adm1nPass!", now, 0, 0), body, NULL));
		expect(bad[i], r, "ter:InvalidTimeZone");
	}
	check("... nothing saved and the clock not set", camcfg_calls == calls && set_calls == sc);
	snprintf(body, sizeof body, set_tz, "NTP", "", "");
	r = run(soap_req(DEV, wsse("admin", "Adm1nPass!", now, 0, 0), body, NULL));
	expect("an empty TZ is accepted", r, "<tds:SetSystemDateAndTimeResponse/>");
	check("... and changes nothing", camcfg_calls == calls);
	snprintf(body, sizeof body, set_tz, "NTP", "EST5EDT,M3.2.0,M11.1.0", "");
	r = run(soap_req(DEV, wsse("op", "0perPass", now, 0, 0), body, NULL));
	expect("operator may not set the time zone", r, "ter:NotAuthorized");
	check("... nothing saved", camcfg_calls == calls);
	camcfg_fail = 1;
	r = run(soap_req(DEV, wsse("admin", "Adm1nPass!", now, 0, 0), body, NULL));
	expect("camcfg failing -> the settings could not be saved", r, "The settings could not be saved");
	camcfg_fail = 0;
	write_file(conf_path, "time.tz=EST5EDT;reboot\n");          /* cam.conf edited by hand: refused */
	r = run(soap_req(DEV, NULL, "<tds:GetSystemDateAndTime/>", NULL));
	expect("a bad time.tz in cam.conf reads as UTC0", r, "<tt:TZ>UTC0</tt:TZ>");
	check("... LocalDateTime = UTCDateTime", dt_offset(r) == 0);
	write_file(conf_path, "image.brightness=55\nstream.main.kbps=6000\nstream.main.profile=main\n"
		   "stream.main.fps=99\nstream.sub.enabled=1\n");
	r = run(soap_req(DEV, NULL, "<tds:GetSystemDateAndTime/>", NULL));
	expect("no time.tz: UTC0", r, "<tt:TZ>UTC0</tt:TZ>");
}

static void test_onvif(void)
{
	const char *r;
	long long now = time(NULL);
	char nonce[NONCE_LEN + 1], bad[NONCE_LEN + 1];

	r = run(soap_req(DEV, NULL, "<tds:GetSystemDateAndTime/>", NULL));
	expect("GetSystemDateAndTime is PRE_AUTH", r, "HTTP/1.1 200 OK");
	expect("GetSystemDateAndTime answer", r, "<tt:UTCDateTime><tt:Time><tt:Hour>");
	r = run(soap_req(DEV, wsse("admin", "wrong", now - 3600, 0, 0), "<tds:GetSystemDateAndTime/>", NULL));
	expect("PRE_AUTH ignores bad credentials (client clock off)", r, "200 OK");
	r = run(soap_req(DEV, NULL, "<tds:GetCapabilities><tds:Category>All</tds:Category></tds:GetCapabilities>", NULL));
	expect("GetCapabilities XAddr on the request's address", r, "<tt:XAddr>http://192.0.2.10/onvif/media_service</tt:XAddr>");
	r = run(soap_req(DEV, NULL, "<tds:GetCapabilities><tds:Category>PTZ</tds:Category></tds:GetCapabilities>", NULL));
	expect("GetCapabilities PTZ -> NoSuchService", r, "ter:NoSuchService");
	r = run(soap_req(DEV, NULL, "<tds:GetServices><tds:IncludeCapability>true</tds:IncludeCapability></tds:GetServices>", NULL));
	expect("GetServices with capabilities", r, "<trt:Capabilities SnapshotUri=\"true\"");
	r = run(soap_req("/onvif/Media", NULL, "<trt:GetServiceCapabilities/>", NULL));
	expect("GetServiceCapabilities on /onvif/Media is the media one", r, "trt:GetServiceCapabilitiesResponse");
	r = run(soap_req(DEV, NULL, "<tds:GetEndpointReference/>", NULL));
	expect("GetEndpointReference", r, "<tds:GUID>urn:uuid:");

	r = run(soap_req(DEV, NULL, B_INFO, NULL));
	expect("protected op without credentials -> 401", r, "HTTP/1.1 401 Unauthorized");
	expect("401 carries a Digest challenge", r, "WWW-Authenticate: Digest realm=\"camera\", qop=\"auth\"");
	expect("401 carries ter:NotAuthorized", r, "ter:NotAuthorized");

	/* WS-UsernameToken */
	r = run(soap_req(DEV, wsse("view", "V1ew:Pass&", now, 0, 0), B_INFO, NULL));
	expect("UsernameToken viewer: GetDeviceInformation", r, "<tds:Model>IPC-D240W-S</tds:Model>");
	expect("serial is 0", r, "<tds:SerialNumber>0</tds:SerialNumber>");
	expect("firmware version from the build", r, "<tds:FirmwareVersion>" FW_VERSION "<");
	r = run(soap_req(DEV, wsse("view", "V1ew:Pass&", now, 0, 1), B_INFO, NULL));
	expect("replayed UsernameToken -> 401 (Digest may still work)", r, "HTTP/1.1 401 Unauthorized");
	expect("replay fault", r, "ter:NotAuthorized");
	r = run(soap_req(DEV, wsse("view", "V1ew:Pass&", now - skew - 30, 0, 0), B_INFO, NULL));
	expect("Created outside the window -> 401", r, "401 Unauthorized");
	r = run(soap_req(DEV, wsse("view", "V1ew:Pass&", now + FUTURE_MAX - 2, 0, 0), B_INFO, NULL));
	expect("Created a little ahead -> 200", r, "200 OK");
	r = run(soap_req(DEV, wsse("view", "V1ew:Pass&", now + FUTURE_MAX + 5, 0, 0), B_INFO, NULL));
	expect("Created further ahead than FUTURE_MAX -> 401", r, "401 Unauthorized");
	r = run(soap_req(DEV, wsse("view", "V1ew:Pass&", now, 1, 0), B_INFO, NULL));
	expect("PasswordText refused", r, "401 Unauthorized");
	check("refusals before a password check count no failure", gfail.n == 0);
	r = run(soap_req(DEV, wsse("nobody", "x", now, 0, 0), B_INFO, NULL));
	expect("unknown user refused", r, "400 Bad Request");
	check("a wrong password counts", gfail.n == 1);
	auth_reset();

	r = run(soap_req(DEV, wsse("view", "V1ew:Pass&", now, 0, 0), B_USERS, NULL));
	expect("viewer may not GetUsers", r, "ter:NotAuthorized");
	r = run(soap_req(DEV, wsse("op", "0perPass", now, 0, 0), B_USERS, NULL));
	expect("operator may not GetUsers", r, "400 Bad Request");
	r = run(soap_req(DEV, wsse("admin", "Adm1nPass!", now, 0, 0), B_USERS, NULL));
	expect("admin GetUsers", r, "<tt:Username>admin</tt:Username><tt:UserLevel>Administrator</tt:UserLevel>");
	expect("GetUsers viewer level", r, "<tt:Username>view</tt:Username><tt:UserLevel>User</tt:UserLevel>");
	absent("GetUsers has no passwords", r, "Adm1nPass");
	absent("GetUsers has no passwords", r, "V1ew");
	absent("bad role line skipped", r, "rooty");

	const char *set = "<tds:SetSystemDateAndTime><tds:DateTimeType>Manual</tds:DateTimeType>"
		"<tds:DaylightSavings>false</tds:DaylightSavings><tds:TimeZone><tt:TZ>CST-8</tt:TZ></tds:TimeZone>"
		"<tds:UTCDateTime><tt:Date><tt:Year>2026</tt:Year><tt:Month>10</tt:Month><tt:Day>23</tt:Day>"
		"</tt:Date><tt:Time><tt:Hour>12</tt:Hour><tt:Minute>34</tt:Minute><tt:Second>56</tt:Second>"
		"</tt:Time></tds:UTCDateTime></tds:SetSystemDateAndTime>";
	r = run(soap_req(DEV, wsse("op", "0perPass", now, 0, 0), set, NULL));
	expect("operator may not SetSystemDateAndTime", r, "ter:NotAuthorized");
	if (set_calls) { fprintf(stderr, "FAIL: time set by operator\n"); exit(1); }
	r = run(soap_req(DEV, wsse("admin", "Adm1nPass!", now, 0, 0), set, NULL));
	expect("admin SetSystemDateAndTime", r, "<tds:SetSystemDateAndTimeResponse/>");
	if (set_calls != 1 || set_tv.tv_sec != 1792758896) { fprintf(stderr, "FAIL: settime %ld\n", (long)set_tv.tv_sec); exit(1); }
	printf("ok: settimeofday got 2026-10-23T12:34:56Z\n");
	check("SetSystemDateAndTime raises the UsernameToken floor", seen_floor >= 1792758896);
	r = run(soap_req(DEV, wsse("admin", "Adm1nPass!", now, 0, 0), B_INFO, NULL));
	expect("a token made before the clock change is refused", r, "401 Unauthorized");
	seen_floor = -1;                                   /* the fake didn't move our clock */
	char feb[2048];
	snprintf(feb, sizeof feb, "%s", set);
	memcpy(strstr(feb, "<tt:Month>10") + 10, "02", 2);
	memcpy(strstr(feb, "<tt:Day>23") + 8, "30", 2);
	r = run(soap_req(DEV, wsse("admin", "Adm1nPass!", now, 0, 0), feb, NULL));
	expect("Feb 30 -> InvalidDateTime", r, "ter:InvalidDateTime");
	int sc = set_calls;
	r = run(soap_req(DEV, wsse("admin", "Adm1nPass!", now, 0, 0),
			 "<tds:SetSystemDateAndTime><tds:DateTimeType>NTP</tds:DateTimeType></tds:SetSystemDateAndTime>", NULL));
	expect("DateTimeType NTP (default servers) is acknowledged", r, "<tds:SetSystemDateAndTimeResponse/>");
	check("... without setting the clock", set_calls == sc);
	test_onvif_tz();

	/* HTTP Digest */
	r = run(soap_req(MED, NULL, B_PROFILES, NULL));
	nonce_of(r, nonce);
	r = run(soap_req(MED, NULL, B_PROFILES, digest("view", "V1ew:Pass&", "POST", MED, nonce, 1)));
	expect("HTTP Digest viewer: GetProfiles", r, "<trt:Profiles token=\"Profile_2\"");
	expect("main bitrate from cam.conf", r, "<tt:BitrateLimit>6000</tt:BitrateLimit>");
	expect("sub defaults", r, "<tt:Width>640</tt:Width><tt:Height>360</tt:Height>");
	expect("main profile from cam.conf", r, "<tt:H264Profile>Main</tt:H264Profile>");
	r = run(soap_req(MED, NULL, B_PROFILES, digest("view", "V1ew:Pass&", "POST", MED, nonce, 1)));
	expect("Digest nc replay -> 401 stale", r, "stale=true");
	r = run(soap_req(MED, NULL, B_PROFILES, digest("view", "V1ew:Pass&", "POST", MED, nonce, 2)));
	expect("Digest next nc -> 200", r, "200 OK");
	r = run(soap_req(MED, NULL, B_PROFILES, digest("view", "wrong", "POST", MED, nonce, 3)));
	expect("Digest wrong password -> 401", r, "401 Unauthorized");
	absent("wrong password is not stale", r, "stale=true");
	r = run(soap_req(MED, NULL, B_PROFILES, digest("view", "V1ew:Pass&", "POST", DEV, nonce, 4)));
	expect("Digest for another URI -> 401", r, "401 Unauthorized");
	memcpy(bad, nonce, sizeof bad);
	bad[30] = bad[30] == 'a' ? 'b' : 'a';
	r = run(soap_req(MED, NULL, B_PROFILES, digest("view", "V1ew:Pass&", "POST", MED, bad, 1)));
	expect("forged nonce -> 401", r, "401 Unauthorized");
	absent("forged nonce is not stale", r, "stale=true");
	nonce_make((unsigned long)mono() - NONCE_LIFE - 5, 1, bad);
	r = run(soap_req(MED, NULL, B_PROFILES, digest("view", "V1ew:Pass&", "POST", MED, bad, 1)));
	expect("expired nonce -> 401 stale", r, "stale=true");
	r = run(soap_req(MED, NULL, B_USERS, digest("view", "V1ew:Pass&", "POST", MED, nonce, 5)));
	expect("Digest viewer GetUsers -> 400 NotAuthorized", r, "ter:NotAuthorized");
	auth_reset();

	/* lockout: five bad, then the right password is refused too */
	for (int i = 0; i < FAIL_MAX; i++) run(soap_req(DEV, wsse("admin", "guess", now, 0, 0), B_INFO, NULL));
	r = run(soap_req(DEV, wsse("admin", "Adm1nPass!", now, 0, 0), B_INFO, NULL));
	expect("locked out after 5 failures", r, "400 Bad Request");
	for (int i = 0; i < FAIL_SLOTS; i++) fails[i].t -= FAIL_WINDOW + 1;
	r = run(soap_req(DEV, wsse("admin", "Adm1nPass!", now, 0, 0), B_INFO, NULL));
	expect("lockout ends after the window", r, "200 OK");
	auth_reset();

	/* every other operation, as a viewer: { path, body, wanted, unwanted } */
#define PT(op, tok) "<trt:" op "><trt:ProfileToken>" tok "</trt:ProfileToken></trt:" op ">"
#define CT(op, tok) "<trt:" op "><trt:ConfigurationToken>" tok "</trt:ConfigurationToken></trt:" op ">"
	static const char *const cases[][4] = {
		{ MED, "<trt:GetStreamUri><trt:StreamSetup><tt:Stream>RTP-Unicast</tt:Stream><tt:Transport>"
		  "<tt:Protocol>RTSP</tt:Protocol></tt:Transport></trt:StreamSetup><trt:ProfileToken>Profile_2"
		  "</trt:ProfileToken></trt:GetStreamUri>", "<tt:Uri>rtsp://192.0.2.10:554/sub</tt:Uri>", NULL },
		{ MED, PT("GetStreamUri", "Profile_1"), "<tt:Uri>rtsp://192.0.2.10:554/</tt:Uri>", NULL },
		{ MED, "<trt:GetStreamUri><trt:StreamSetup><tt:Stream>RTP-Multicast</tt:Stream></trt:StreamSetup>"
		  "<trt:ProfileToken>Profile_1</trt:ProfileToken></trt:GetStreamUri>", "ter:InvalidStreamSetup", NULL },
		{ MED, PT("GetStreamUri", "Profile_9"), "ter:NoProfile", NULL },
		{ MED, PT("GetStreamUri", "Profile_1x"), "ter:NoProfile", NULL },
		{ MED, PT("GetSnapshotUri", "Profile_1"), "<tt:Uri>http://192.0.2.10/snapshot.jpg</tt:Uri>", NULL },
		{ MED, PT("GetProfile", "Profile_1"), "<trt:Profile token=\"Profile_1\" fixed=\"true\">", "Profile_2" },
		{ MED, PT("GetVideoEncoderConfigurationOptions", "Profile_2"),
		  "<tt:ResolutionsAvailable><tt:Width>640</tt:Width><tt:Height>360</tt:Height></tt:ResolutionsAvailable>"
		  "<tt:ResolutionsAvailable><tt:Width>960</tt:Width><tt:Height>540</tt:Height></tt:ResolutionsAvailable>"
		  "<tt:ResolutionsAvailable><tt:Width>1280</tt:Width><tt:Height>720</tt:Height></tt:ResolutionsAvailable>"
		  "<tt:GovLength", "<tt:Width>2560</tt:Width>" },
		{ MED, PT("GetVideoEncoderConfigurationOptions", "Profile_1"),
		  "<tt:H264><tt:ResolutionsAvailable><tt:Width>2560</tt:Width><tt:Height>1440</tt:Height></tt:ResolutionsAvailable>"
		  "<tt:ResolutionsAvailable><tt:Width>2304</tt:Width><tt:Height>1296</tt:Height></tt:ResolutionsAvailable>"
		  "<tt:ResolutionsAvailable><tt:Width>1920</tt:Width><tt:Height>1080</tt:Height></tt:ResolutionsAvailable>"
		  "<tt:ResolutionsAvailable><tt:Width>1280</tt:Width><tt:Height>720</tt:Height></tt:ResolutionsAvailable>"
		  "<tt:GovLength", "<tt:Width>640</tt:Width>" },
		{ MED, "<trt:GetVideoEncoderConfigurationOptions/>",
		  "<tt:Width>1280</tt:Width><tt:Height>720</tt:Height></tt:ResolutionsAvailable><tt:ResolutionsAvailable>"
		  "<tt:Width>640</tt:Width><tt:Height>360</tt:Height></tt:ResolutionsAvailable><tt:ResolutionsAvailable>"
		  "<tt:Width>960</tt:Width><tt:Height>540</tt:Height></tt:ResolutionsAvailable><tt:GovLength", NULL },
		{ MED, PT("GetVideoEncoderConfigurationOptions", "Profile_1"),
		  "<tt:FrameRateRange><tt:Min>1</tt:Min><tt:Max>30</tt:Max></tt:FrameRateRange>", NULL },
		{ MED, "<trt:GetVideoEncoderConfigurationOptions/>", "<tt:BitrateRange><tt:Min>64</tt:Min>", NULL },
		{ MED, CT("GetVideoEncoderConfigurationOptions", "VideoEncoder_7"), "ter:NoConfig", NULL },
		{ MED, CT("GetVideoEncoderConfiguration", "VideoEncoder_1"),
		  "<trt:Configuration token=\"VideoEncoder_1\">", NULL },
		{ MED, PT("GetCompatibleVideoEncoderConfigurations", "Profile_2"), "VideoEncoder_2", "VideoEncoder_1" },
		{ MED, "<trt:GetVideoEncoderConfigurations/>", "VideoEncoder_1", NULL },
		{ MED, "<trt:GetVideoSources/>", "<trt:VideoSources token=\"VideoSource_1\"><tt:Framerate>30<", NULL },
		{ MED, "<trt:GetVideoSourceConfigurations/>", "<tt:SourceToken>VideoSource_1</tt:SourceToken>", NULL },
		{ MED, PT("GetCompatibleVideoSourceConfigurations", "Profile_1"), "VideoSourceConfig_1", NULL },
		{ MED, CT("GetVideoSourceConfiguration", "VideoSourceConfig_1"), "<tt:UseCount>2</tt:UseCount>", NULL },
		{ MED, "<trt:GetAudioOutputs/>", "<trt:AudioOutputs token=\"AudioOutput_1\"/>", NULL },
		{ DEV, "<tds:GetNetworkInterfaces/>", "<tt:HwAddress>02:00:00:00:00:01</tt:HwAddress>", NULL },
		{ DEV, "<tds:GetNetworkInterfaces/>", "<tt:PrefixLength>24</tt:PrefixLength>", NULL },
		{ DEV, "<tds:GetScopes/>", "onvif://www.onvif.org/Profile/Streaming", NULL },
		{ DEV, "<tds:GetHostname/>", "<tt:Name>", NULL },
		{ DEV, "<tds:GetNetworkProtocols/>", "<tt:Name>RTSP</tt:Name><tt:Enabled>true</tt:Enabled><tt:Port>554", NULL },
		{ DEV, "<tds:GetDiscoveryMode/>", "Discoverable", NULL },
		{ DEV, "<tds:GetWsdlUrl/>", "<tds:WsdlUrl>", NULL },
		{ DEV, "<tds:GetServiceCapabilities/>", "<tds:Security", NULL },
		{ DEV, "<tptz:GetNodes xmlns:tptz=\"x\"/>", "HTTP/1.1 500", NULL },
		{ DEV, "<GetNodes/>", "<env:Value>env:Receiver</env:Value><env:Subcode><env:Value>"
		  "ter:ActionNotSupported", NULL },
		{ DEV, "<tds:Get\x01Users/>", "ter:WellFormed", NULL },
	};
	for (size_t i = 0; i < sizeof cases / sizeof cases[0]; i++) {
		r = run(soap_req(cases[i][0], wsse("view", "V1ew:Pass&", now, 0, 0), cases[i][1], NULL));
		expect(cases[i][1], r, cases[i][2]);
		if (cases[i][3]) absent(cases[i][1], r, cases[i][3]);
	}
	/* #80: a static address (net-up's /run/net-status) is reported as Manual, DHCP false */
	char ns[600];
	const char *tmp = getenv("TMPDIR");
	snprintf(ns, sizeof ns, "%s/net-status-%d", tmp && *tmp ? tmp : ".", (int)getpid());
	net_status_path = ns;
	r = run(soap_req(DEV, wsse("view", "V1ew:Pass&", now, 0, 0), "<tds:GetNetworkInterfaces/>", NULL));
	expect("GetNetworkInterfaces without net-status: DHCP", r,
	       "<tt:FromDHCP><tt:Address>192.0.2.10</tt:Address><tt:PrefixLength>24</tt:PrefixLength></tt:FromDHCP>"
	       "<tt:DHCP>true</tt:DHCP>");
	write_file(ns, "configured=static\nmode=dhcp\nstate=fallback\nreason=x\npending=0\n");
	r = run(soap_req(DEV, wsse("view", "V1ew:Pass&", now, 0, 0), "<tds:GetNetworkInterfaces/>", NULL));
	expect("GetNetworkInterfaces after a fallback to DHCP: DHCP", r, "<tt:DHCP>true</tt:DHCP>");
	write_file(ns, "configured=static\nmode=static\nstate=ok\nreason=\npending=0\n");
	r = run(soap_req(DEV, wsse("view", "V1ew:Pass&", now, 0, 0), "<tds:GetNetworkInterfaces/>", NULL));
	expect("GetNetworkInterfaces with a static address: Manual", r,
	       "<tt:Manual><tt:Address>192.0.2.10</tt:Address><tt:PrefixLength>24</tt:PrefixLength></tt:Manual>"
	       "<tt:DHCP>false</tt:DHCP>");
	absent("... and no FromDHCP", r, "FromDHCP");
	unlink(ns);
	net_status_path = "/run/net-status";
}

static void test_http(const char *dir)
{
	const char *r;
	char req[1024], nonce[NONCE_LEN + 1], path[600], *big;
	r = run("GET /snapshot.jpg HTTP/1.1\r\nHost: 192.0.2.10\r\n\r\n");
	expect("snapshot without credentials -> 401", r, "401 Unauthorized");
	nonce_of(r, nonce);
	snprintf(req, sizeof req, "GET /snapshot.jpg HTTP/1.1\r\nHost: 192.0.2.10\r\nAuthorization: %s\r\n\r\n",
		 digest("view", "V1ew:Pass&", "GET", "/snapshot.jpg", nonce, 1));
	r = run(req);
	expect("snapshot without rtspd -> 503", r, "503 Service Unavailable");
	write_file(snap_path, "\xff\xd8JPEGDATA\xff\xd9");
	static const char *const replies[][2] = { { "ok 12\n", "200 OK" }, { "ok\n", "200 OK" },
		{ "ok 99\n", "503" }, { "err no frame\n", "503" }, { "ok 12", "503" }, { "okay\n", "503" } };
	for (int i = 0; i < 6; i++) {
		fake_ctl = replies[i][0];
		snap_asked = mono_ms() - SNAP_REUSE_MS;
		snprintf(req, sizeof req, "GET /snapshot.jpg HTTP/1.1\r\nHost: 192.0.2.10\r\nAuthorization: %s\r\n\r\n",
			 digest("view", "V1ew:Pass&", "GET", "/snapshot.jpg", nonce, 10 + (unsigned)i));
		r = run(req);
		expect("snapshot with a canned rtspd reply", r, replies[i][1]);
		if (i == 0)
			expect("snapshot body", r, "Content-Type: image/jpeg\r\nContent-Length: 12\r\n\r\n"
			       "\xff\xd8JPEGDATA\xff\xd9");
	}
	/* #8: rtspd is asked at most once a second; requests in between share its answer */
	unsigned nc = 30;
	const char *const outcome[2][2] = { { "ok 12\n", "200 OK" }, { "err busy\n", "503" } };
	for (int k = 0; k < 2; k++) {
		fake_ctl = outcome[k][0];
		snap_asked = mono_ms() - SNAP_REUSE_MS;
		int before = ctl_calls;
		for (int i = 0; i < 5; i++) {
			snprintf(req, sizeof req, "GET /snapshot.jpg HTTP/1.1\r\nHost: 192.0.2.10\r\nAuthorization: %s\r\n\r\n",
				 digest("view", "V1ew:Pass&", "GET", "/snapshot.jpg", nonce, nc++));
			r = run(req);
			expect("rapid snapshots share one rtspd answer", r, outcome[k][1]);
		}
		check("five rapid snapshots ask rtspd once", ctl_calls - before == 1);
	}
	fake_ctl = NULL;
	unlink(snap_path);

	/* a fake rtspd answering "snapshot" (needs unix-socket bind; not in every sandbox) */
	struct sockaddr_un a;
	int lfd = socket(AF_UNIX, SOCK_STREAM, 0);
	snprintf(path, sizeof path, "%s/camd.sock", dir);
	memset(&a, 0, sizeof a);
	a.sun_family = AF_UNIX;
	snprintf(a.sun_path, sizeof a.sun_path, "%s", path);
	if (strlen(path) < sizeof a.sun_path && !bind(lfd, (struct sockaddr *)&a, sizeof a) && !listen(lfd, 1)) {
		ctl_path = path;
		snap_asked = mono_ms() - SNAP_REUSE_MS;
		pid_t pid = fork();
		if (pid == 0) {
			char line[64];
			alarm(10); /* if camhttpd never connects, fail the check below instead of hanging waitpid */
			int fd = accept(lfd, NULL, NULL);
			ssize_t n = read(fd, line, sizeof line - 1);
			if (n == 9 && !memcmp(line, "snapshot\n", 9)) {
				write_file(snap_path, "\xff\xd8JPEGDATA\xff\xd9");
				n = write(fd, "ok 12\n", 6);
			}
			_exit(n == 6 ? 0 : 1);
		}
		/* nc must exceed every count this nonce has used (30..39 above), or camhttpd refuses it as a replay */
		snprintf(req, sizeof req, "GET /snapshot.jpg HTTP/1.1\r\nHost: 192.0.2.10\r\nAuthorization: %s\r\n\r\n",
			 digest("view", "V1ew:Pass&", "GET", "/snapshot.jpg", nonce, nc++));
		r = run(req);
		int status;
		waitpid(pid, &status, 0);
		expect("snapshot via rtspd", r, "Content-Type: image/jpeg\r\nContent-Length: 12\r\n\r\n\xff\xd8JPEGDATA\xff\xd9");
		expect("snapshot not cached", r, "Cache-Control: no-store");
		ctl_path = "/nonexistent/camd.sock";
	} else {
		printf("skip: fake rtspd (unix socket bind: %s)\n", strerror(errno));
	}
	close(lfd);
	unlink(path);

	expect("GET elsewhere -> 404", run("GET /index.html HTTP/1.1\r\n\r\n"), "404 Not Found");
	expect("GET on ONVIF -> 405", run("GET /onvif/device_service HTTP/1.1\r\n\r\n"), "405 Method Not Allowed");
	expect("DELETE -> 405", run("DELETE /snapshot.jpg HTTP/1.1\r\nHost: 192.0.2.10\r\n\r\n"), "405");
	expect("HTTP/2.0 -> 400", run("GET /snapshot.jpg HTTP/2.0\r\n\r\n"), "400 Bad Request");
	expect("no target -> 400", run("GET  HTTP/1.1\r\n\r\n"), "400 Bad Request");
	expect("chunked -> 501", run("POST /onvif/device_service HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n"), "501");
	expect("two Content-Lengths -> 400", run("POST /onvif/device_service HTTP/1.1\r\nContent-Length: 1\r\n"
						 "Content-Length: 2\r\n\r\nab"), "400 Bad Request");
	expect("negative Content-Length -> 400", run("POST /onvif/device_service HTTP/1.1\r\nContent-Length: -1\r\n\r\n"), "400");
	expect("huge Content-Length -> 413", run("POST /onvif/device_service HTTP/1.1\r\nContent-Length: 9999999\r\n\r\n"), "413");
	static const char nul[] = "GET /snapshot.jpg HTTP/1.1\r\nX: a\0b\r\n\r\n";
	expect("NUL in headers -> 400", run_n(nul, sizeof nul - 1, 64), "400");
	expect("empty body -> WellFormed fault", run("POST /onvif/device_service HTTP/1.1\r\n"
	       "Content-Type: application/soap+xml\r\n\r\n"), "ter:WellFormed");
	expect("not SOAP -> WellFormed fault", run("POST /onvif/device_service HTTP/1.1\r\nContent-Type: text/xml\r\n"
	       "Content-Length: 5\r\n\r\nhello"), "ter:WellFormed");
	big = malloc(REQ_CAP + 100);
	memset(big, 'A', REQ_CAP + 100);
	memcpy(big, "GET /x HTTP/1.1\r\nX: ", 20);
	expect("headers over 8 KiB -> 431", run_n(big, REQ_CAP + 100, 4000), "431");
	scan_bytes = 0;
	r = run_n(big, REQ_CAP + 100, 1);                  /* #7: one byte per recv */
	expect("headers fed a byte at a time -> 431 at 8 KiB", r, "431");
	check("header-end search is linear (resumes where it stopped)", cl.in_len == HDR_CAP &&
	      scan_bytes < 5ULL * HDR_CAP);
	free(big);
	const char *full = soap_req(DEV, NULL, "<tds:GetSystemDateAndTime/>", NULL);
	r = run_n(full, strlen(full), 7);
	expect("request fed 7 bytes at a time", r, "GetSystemDateAndTimeResponse");
	char ex[REQ_CAP];
	snprintf(ex, sizeof ex, "%s", full);
	char *cl_at = strstr(ex, "Content-Length:");
	memmove(cl_at + 22, cl_at, strlen(cl_at) + 1);
	memcpy(cl_at, "Expect: 100-continue\r\n", 22);
	size_t hl = (size_t)(strstr(ex, "\r\n\r\n") + 4 - ex);
	client_reset(&cl, -1);
	strcpy(cl.local, "192.0.2.10");
	memcpy(cl.in, ex, hl);
	cl.in_len = hl;
	http_feed(&cl);
	cl.out[cl.out_len] = 0;
	expect("Expect: 100-continue", cl.out, "HTTP/1.1 100 Continue\r\n\r\n");
}

/* SetVideoEncoderConfiguration as SSS sends it (every field of the configuration it read back). */
static const char *setvec(int i, const char *enc, int w, int h, int fps, int ei, int kbps, int gop,
			  const char *prof)
{
	static char b[2048];
	snprintf(b, sizeof b, "<trt:SetVideoEncoderConfiguration><trt:Configuration token=\"VideoEncoder_%d\">"
		 "<tt:Name>VideoEncoder_%d</tt:Name><tt:UseCount>1</tt:UseCount><tt:Encoding>%s</tt:Encoding>"
		 "<tt:Resolution><tt:Width>%d</tt:Width><tt:Height>%d</tt:Height></tt:Resolution>"
		 "<tt:Quality>5</tt:Quality><tt:RateControl><tt:FrameRateLimit>%d</tt:FrameRateLimit>"
		 "<tt:EncodingInterval>%d</tt:EncodingInterval><tt:BitrateLimit>%d</tt:BitrateLimit>"
		 "</tt:RateControl><tt:H264><tt:GovLength>%d</tt:GovLength><tt:H264Profile>%s</tt:H264Profile>"
		 "</tt:H264><tt:Multicast><tt:Address><tt:Type>IPv4</tt:Type><tt:IPv4Address>0.0.0.0"
		 "</tt:IPv4Address></tt:Address><tt:Port>0</tt:Port><tt:TTL>1</tt:TTL><tt:AutoStart>false"
		 "</tt:AutoStart></tt:Multicast><tt:SessionTimeout>PT60S</tt:SessionTimeout>"
		 "</trt:Configuration><trt:ForcePersistence>true</trt:ForcePersistence>"
		 "</trt:SetVideoEncoderConfiguration>", i + 1, i + 1, enc, w, h, fps, ei, kbps, gop, prof);
	return b;
}

static const char *ntp_body(const char *dhcp, const char *manual)
{
	static char b[2048];
	snprintf(b, sizeof b, "<tds:SetNTP><tds:FromDHCP>%s</tds:FromDHCP>%s</tds:SetNTP>", dhcp, manual);
	return b;
}

#define NTPM(type, el, v) "<tds:NTPManual><tt:Type>" type "</tt:Type><tt:" el ">" v "</tt:" el "></tds:NTPManual>"

/* What Surveillance Station does when it adds the camera and loads its capacity (live log of
 * 2026-10-23, cam #2): the operations it called that we lacked, shaped like its requests. */
static void test_sss(const char *dir)
{
	long long now = time(NULL);
	const char *r;
	char a[64], b[64];
	write_file(conf_path, "stream.main.kbps=6000\nstream.main.profile=main\nstream.sub.enabled=1\n");
	camcfg_calls = restarts = 0;
	*camcfg_log = 0;
#define OP wsse("op", "0perPass", now, 0, 0)
#define ADMIN wsse("admin", "Adm1nPass!", now, 0, 0)
#define VIEW wsse("view", "V1ew:Pass&", now, 0, 0)

	r = run(soap_req(MED, VIEW, setvec(0, "H264", 2560, 1440, 30, 1, 6000, 100, "Main"), NULL));
	expect("SetVideoEncoderConfiguration needs operator (ACTUATE)", r, "ter:NotAuthorized");
	r = run(soap_req(MED, OP, setvec(0, "H264", 2560, 1440, 30, 1, 6000, 100, "Main"), NULL));
	expect("SetVideoEncoderConfiguration with the current values", r, "<trt:SetVideoEncoderConfigurationResponse/>");
	check("... changes nothing and doesn't restart rtspd", camcfg_calls == 0 && restarts == 0);
	r = run(soap_req(MED, OP, setvec(0, "H264", 2560, 1440, 20, 1, 6144, 40, "High"), NULL));
	expect("SetVideoEncoderConfiguration with new values", r, "<trt:SetVideoEncoderConfigurationResponse/>");
	printf("   camcfg calls: %s\n", camcfg_log);
	check("... saves each changed key with camcfg (the sub's fps down to the main's)", !strcmp(camcfg_log,
	      "stream.main.kbps=6144;stream.main.fps=20;stream.main.gop=40;stream.main.profile=high;stream.sub.fps=20;"));
	check("... and restarts rtspd once", restarts == 1);
	r = run(soap_req(MED, VIEW, "<trt:GetVideoEncoderConfiguration><trt:ConfigurationToken>VideoEncoder_1"
			 "</trt:ConfigurationToken></trt:GetVideoEncoderConfiguration>", NULL));
	expect("GetVideoEncoderConfiguration reads the new cam.conf", r, "<tt:FrameRateLimit>20</tt:FrameRateLimit>"
	       "<tt:EncodingInterval>1</tt:EncodingInterval><tt:BitrateLimit>6144</tt:BitrateLimit>");
	expect("... GOP and profile", r, "<tt:GovLength>40</tt:GovLength><tt:H264Profile>High</tt:H264Profile>");
	r = run(soap_req(MED, VIEW, B_PROFILES, NULL));
	expect("GetProfiles too", r, "<tt:BitrateLimit>6144</tt:BitrateLimit>");

	static const struct { int i; const char *enc; int w, h, fps, ei, kbps, gop; const char *prof, *why; } bad[] = {
		{ 0, "H264", 1600, 900, 25, 1, 4000, 100, "High", "a resolution we don't offer" },
		{ 0, "H264", 640, 360, 25, 1, 4000, 100, "High", "a sub-stream resolution on the main" },
		{ 1, "H264", 2560, 1440, 25, 1, 500, 100, "High", "the main resolution on the sub-stream" },
		{ 1, "H264", 1920, 1080, 25, 1, 500, 100, "High", "1920x1080 on the sub-stream" },
		{ 0, "H264", 2560, 1440, 31, 1, 4000, 100, "High", "31 fps" },
		{ 0, "H264", 2560, 1440, 0, 1, 4000, 100, "High", "0 fps" },
		{ 0, "H264", 2560, 1440, 25, 2, 4000, 100, "High", "EncodingInterval 2" },
		{ 0, "H264", 2560, 1440, 25, 1, 99999, 100, "High", "99999 kbps" },
		{ 0, "H264", 2560, 1440, 25, 1, 32, 100, "High", "32 kbps" },
		{ 0, "H264", 2560, 1440, 25, 1, 4000, 0, "High", "GOP 0" },
		{ 0, "H264", 2560, 1440, 25, 1, 4000, 1001, "High", "GOP 1001" },
		{ 0, "H264", 2560, 1440, 25, 1, 4000, 100, "Extended", "profile Extended" },
		{ 0, "JPEG", 2560, 1440, 25, 1, 4000, 100, "High", "JPEG" },
	};
	int calls = camcfg_calls;
	for (size_t k = 0; k < sizeof bad / sizeof bad[0]; k++) {
		r = run(soap_req(MED, OP, setvec(bad[k].i, bad[k].enc, bad[k].w, bad[k].h, bad[k].fps, bad[k].ei,
					   bad[k].kbps, bad[k].gop, bad[k].prof), NULL));
		expect(bad[k].why, r, "ter:ConfigModify");
	}
	check("... nothing saved, no restart", camcfg_calls == calls && restarts == 1);
	char tok[2048];
	snprintf(tok, sizeof tok, "%s", setvec(0, "H264", 2560, 1440, 25, 1, 4000, 100, "High"));
	memcpy(strstr(tok, "VideoEncoder_1\">"), "VideoEncoder_3\">", 16);
	r = run(soap_req(MED, OP, tok, NULL));
	expect("unknown encoder configuration -> NoConfig", r, "ter:NoConfig");

	r = run(soap_req(MED, VIEW, "<trt:GetGuaranteedNumberOfVideoEncoderInstances><trt:ConfigurationToken>"
			 "VideoSourceConfig_1</trt:ConfigurationToken></trt:GetGuaranteedNumberOfVideoEncoderInstances>", NULL));
	expect("GetGuaranteedNumberOfVideoEncoderInstances", r, "<trt:TotalNumber>2</trt:TotalNumber>"
	       "<trt:JPEG>0</trt:JPEG><trt:H264>2</trt:H264>");
	*camcfg_log = 0;
	r = run(soap_req(MED, OP, setvec(1, "H265", 640, 360, 25, 1, 500, 100, "High"), NULL));
	expect("sub-stream to H.265", r, "<trt:SetVideoEncoderConfigurationResponse/>");
	/* Gate 3 #11: SSS sets both encoders back to back; rtspd restarts once per RESTART_GAP_MS */
	check("... one key saved; within 10 s of the last restart, rtspd's restart is put off",
	      !strcmp(camcfg_log, "stream.sub.codec=h265;") && restarts == 1 && restart_wanted);
	restart_tick(mono_ms() + RESTART_GAP_MS - 1000);
	check("... not before its time", restarts == 1);
	restart_tick(mono_ms() + RESTART_GAP_MS);
	check("... then one restart applies it", restarts == 2 && !restart_wanted);
	restart_last = -RESTART_GAP_MS;                    /* as if long ago, for the tests below */
	r = run(soap_req(MED, VIEW, "<trt:GetVideoEncoderConfiguration><trt:ConfigurationToken>VideoEncoder_2"
			 "</trt:ConfigurationToken></trt:GetVideoEncoderConfiguration>", NULL));
	expect("... and read back", r, "<tt:Encoding>H265</tt:Encoding>");
	r = run(soap_req(MED, VIEW, "<trt:GetGuaranteedNumberOfVideoEncoderInstances/>", NULL));
	expect("... guaranteed H.264 instances follow", r, "<trt:TotalNumber>2</trt:TotalNumber><trt:JPEG>0</trt:JPEG><trt:H264>1</trt:H264>");
	camcfg_fail = 1;
	r = run(soap_req(MED, OP, setvec(1, "H264", 640, 360, 25, 1, 500, 100, "High"), NULL));
	expect("camcfg failing -> a Receiver fault", r, "The settings could not be saved");
	check("... and no restart", restarts == 2);
	camcfg_fail = 0;

	/* stream sizes (owner 2026-10-25): SSS picks one of ResolutionsAvailable; saved as
	 * stream.<main|sub>.size, one restart; the sub's fps follows the main's, at most */
	*camcfg_log = 0;
	r = run(soap_req(MED, OP, setvec(0, "H264", 1920, 1080, 30, 1, 6144, 40, "High"), NULL));
	expect("SSS: main to 1920x1080 at 30 fps", r, "<trt:SetVideoEncoderConfigurationResponse/>");
	check("... fps and size saved, rtspd restarted", !strcmp(camcfg_log, "stream.main.fps=30;stream.main.size=1920x1080;") &&
	      restarts == 3);
	restart_last = -RESTART_GAP_MS;
	r = run(soap_req(MED, VIEW, B_PROFILES, NULL));
	expect("Profile_1 reports 1920x1080", r, "<trt:Profiles token=\"Profile_1\" fixed=\"true\"><tt:Name>MainStream</tt:Name>");
	expect("... in its encoder configuration", r, "<tt:Encoding>H264</tt:Encoding><tt:Resolution><tt:Width>1920</tt:Width>"
	       "<tt:Height>1080</tt:Height></tt:Resolution><tt:Quality>5</tt:Quality><tt:RateControl><tt:FrameRateLimit>30"
	       "</tt:FrameRateLimit><tt:EncodingInterval>1</tt:EncodingInterval><tt:BitrateLimit>6144</tt:BitrateLimit>");
	expect("... the video source still the sensor's 2560x1440", r, "<tt:Bounds x=\"0\" y=\"0\" width=\"2560\" height=\"1440\"/>");
	absent("... nowhere 1920 in the bounds", r, "width=\"1920\"");
	streams_load();
	check("OSD FontSize in 1920x1080 main-stream pixels (osd.c's x3): 48 / 80 / 96",
	      osd_px(0) == 48 && osd_px(1) == 80 && osd_px(2) == 96);
	expect("... Profile_2 still 640x360 at 20 fps (saved before)", r, "<tt:Width>640</tt:Width><tt:Height>360</tt:Height>"
	       "</tt:Resolution><tt:Quality>5</tt:Quality><tt:RateControl><tt:FrameRateLimit>20</tt:FrameRateLimit>"
	       "<tt:EncodingInterval>1</tt:EncodingInterval><tt:BitrateLimit>500</tt:BitrateLimit>");
	*camcfg_log = 0;
	r = run(soap_req(MED, OP, setvec(1, "H265", 1280, 720, 30, 1, 500, 100, "High"), NULL));
	expect("sub to 1280x720 at 30 fps", r, "<trt:SetVideoEncoderConfigurationResponse/>");
	check("... fps and size saved; kbps left at the 640x360 default stays unset", !strcmp(camcfg_log,
	      "stream.sub.fps=30;stream.sub.size=1280x720;") && restarts == 4);
	restart_last = -RESTART_GAP_MS;
	r = run(soap_req(MED, VIEW, "<trt:GetVideoEncoderConfiguration><trt:ConfigurationToken>VideoEncoder_2"
			 "</trt:ConfigurationToken></trt:GetVideoEncoderConfiguration>", NULL));
	expect("... read back: 1280x720, 30 fps, the 720p default 1500 kbit/s", r, "<tt:Width>1280</tt:Width><tt:Height>720"
	       "</tt:Height></tt:Resolution><tt:Quality>5</tt:Quality><tt:RateControl><tt:FrameRateLimit>30</tt:FrameRateLimit>"
	       "<tt:EncodingInterval>1</tt:EncodingInterval><tt:BitrateLimit>1500</tt:BitrateLimit>");
	*camcfg_log = 0;
	r = run(soap_req(MED, OP, setvec(0, "H264", 1920, 1080, 15, 1, 6144, 40, "High"), NULL));
	expect("main down to 15 fps", r, "<trt:SetVideoEncoderConfigurationResponse/>");
	check("... takes the sub down with it", !strcmp(camcfg_log, "stream.main.fps=15;stream.sub.fps=15;"));
	restart_last = -RESTART_GAP_MS;
	*camcfg_log = 0;
	r = run(soap_req(MED, OP, setvec(1, "H265", 1280, 720, 30, 1, 1500, 100, "High"), NULL));
	expect("sub at 30 fps above the main's 15: accepted as 15", r, "<trt:SetVideoEncoderConfigurationResponse/>");
	check("... nothing to save", !*camcfg_log);
	*camcfg_log = 0;
	r = run(soap_req(MED, OP, setvec(0, "H264", 2560, 1440, 30, 1, 6144, 40, "High"), NULL));
	check("main back to 2560x1440 at 30 fps (the sub stays 15 until set)",
	      !strcmp(camcfg_log, "stream.main.fps=30;stream.main.size=2560x1440;"));
	restart_last = -RESTART_GAP_MS;
	write_file(conf_path, "stream.main.kbps=6144\nstream.main.fps=20\nstream.main.gop=40\nstream.main.profile=high\n"
		   "stream.sub.enabled=1\nstream.sub.fps=20\nstream.sub.codec=h265\n");     /* as before this block */

	r = run(soap_req(MED, VIEW, "<trt:GetVideoSourceConfigurationOptions><trt:ConfigurationToken>"
			 "VideoSourceConfig_1</trt:ConfigurationToken></trt:GetVideoSourceConfigurationOptions>", NULL));
	expect("GetVideoSourceConfigurationOptions", r, "<tt:WidthRange><tt:Min>2560</tt:Min><tt:Max>2560</tt:Max>");
	expect("... with the source token", r, "<tt:VideoSourceTokensAvailable>VideoSource_1</tt:VideoSourceTokensAvailable>");
	r = run(soap_req(MED, VIEW, "<trt:GetVideoSourceConfigurationOptions><trt:ConfigurationToken>x"
			 "</trt:ConfigurationToken></trt:GetVideoSourceConfigurationOptions>", NULL));
	expect("... unknown token -> NoConfig", r, "ter:NoConfig");
	r = run(soap_req(MED, VIEW, "<trt:GetAudioEncoderConfigurationOptions><trt:ProfileToken>Profile_1"
			 "</trt:ProfileToken></trt:GetAudioEncoderConfigurationOptions>", NULL));
	expect("GetAudioEncoderConfigurationOptions: G.711", r, "<tt:Encoding>G711</tt:Encoding>");
	r = run(soap_req(DEV, VIEW, "<tds:GetRelayOutputs/>", NULL));
	expect("GetRelayOutputs: none", r, "<tds:GetRelayOutputsResponse/>");
	r = run(soap_req(MED, VIEW, "<trt:CreateProfile><trt:Name>SSS</trt:Name></trt:CreateProfile>", NULL));
	expect("CreateProfile stays unsupported (SSS goes on with ours)", r, "ter:ActionNotSupported");

	/* NTP */
	r = run(soap_req(DEV, VIEW, "<tds:GetNTP/>", NULL));
	expect("GetNTP default", r, "<tt:FromDHCP>false</tt:FromDHCP><tt:NTPManual><tt:Type>DNS</tt:Type>"
	       "<tt:DNSname>time.cloudflare.com</tt:DNSname></tt:NTPManual>");
	r = run(soap_req(DEV, NULL, "<tds:GetSystemDateAndTime/>", NULL));
	expect("GetSystemDateAndTime says NTP", r, "<tt:DateTimeType>NTP</tt:DateTimeType>");
	r = run(soap_req(DEV, NULL, "<tds:GetServiceCapabilities/>", NULL));
	expect("device capabilities: 3 NTP servers", r, "NTP=\"3\"");
	*camcfg_log = 0;
	const char *two = NTPM("DNS", "DNSname", "pool.ntp.org") NTPM("IPv4", "IPv4Address", "192.0.2.123");
	r = run(soap_req(DEV, OP, ntp_body("false", two), NULL));
	expect("SetNTP needs admin", r, "ter:NotAuthorized");
	r = run(soap_req(DEV, ADMIN, ntp_body("false", two), NULL));
	expect("SetNTP", r, "<tds:SetNTPResponse/>");
	check("... saved as time.ntp", !strcmp(camcfg_log, "time.ntp=pool.ntp.org,192.0.2.123;"));
	r = run(soap_req(DEV, VIEW, "<tds:GetNTP/>", NULL));
	expect("GetNTP reads it back", r, "<tt:DNSname>pool.ntp.org</tt:DNSname></tt:NTPManual><tt:NTPManual>"
	       "<tt:Type>IPv4</tt:Type><tt:IPv4Address>192.0.2.123</tt:IPv4Address>");
	static const char *const ntp_bad[][3] = {
		{ "false", NTPM("IPv6", "IPv6Address", "2001:db8::1"), "ter:InvalidArgs" },
		{ "false", NTPM("DNS", "DNSname", "bad_name"), "ter:InvalidDnsName" },
		{ "false", NTPM("DNS", "DNSname", "a;reboot"), "ter:InvalidDnsName" },
		{ "false", NTPM("DNS", "DNSname", "a,b"), "ter:InvalidDnsName" },
		{ "false", NTPM("DNS", "DNSname", "-x.example"), "ter:InvalidDnsName" },
		{ "false", NTPM("IPv4", "IPv4Address", "300.1.1.1"), "ter:InvalidIPv4Address" },
		{ "false", NTPM("DNS", "DNSname", "a") NTPM("DNS", "DNSname", "b") NTPM("DNS", "DNSname", "c")
			   NTPM("DNS", "DNSname", "d"), "ter:InvalidArgs" },
		{ "true", "", "ter:InvalidArgs" },
	};
	calls = camcfg_calls;
	for (size_t k = 0; k < sizeof ntp_bad / sizeof ntp_bad[0]; k++) {
		r = run(soap_req(DEV, ADMIN, ntp_body(ntp_bad[k][0], ntp_bad[k][1]), NULL));
		expect("SetNTP refuses a bad server list", r, ntp_bad[k][2]);
	}
	check("... nothing saved", camcfg_calls == calls);
	int sc = set_calls;
	r = run(soap_req(DEV, ADMIN, "<tds:SetSystemDateAndTime><tds:DateTimeType>NTP</tds:DateTimeType>"
			 "<tds:DaylightSavings>false</tds:DaylightSavings></tds:SetSystemDateAndTime>", NULL));
	expect("SetSystemDateAndTime NTP is acknowledged", r, "<tds:SetSystemDateAndTimeResponse/>");
	check("... and leaves the clock alone", set_calls == sc);
	r = run(soap_req(DEV, ADMIN, ntp_body("false", ""), NULL));
	expect("SetNTP with no servers", r, "<tds:SetNTPResponse/>");
	r = run(soap_req(DEV, NULL, "<tds:GetSystemDateAndTime/>", NULL));
	expect("... GetSystemDateAndTime says Manual", r, "<tt:DateTimeType>Manual</tt:DateTimeType>");
	r = run(soap_req(DEV, ADMIN, "<tds:SetSystemDateAndTime><tds:DateTimeType>NTP</tds:DateTimeType>"
			 "</tds:SetSystemDateAndTime>", NULL));
	expect("... and SetSystemDateAndTime NTP -> NtpServerUndefined", r, "ter:NtpServerUndefined");
	r = run(soap_req(DEV, VIEW, "<tds:GetNTP/>", NULL));
	absent("... GetNTP lists none", r, "NTPManual");

	/* the real fork/exec path: a missing camcfg fails cleanly; a host-built one ($TEST_CAMCFG)
	 * really writes cam.conf */
	camcfg_bin = "/nonexistent/camcfg";
	check("run_camcfg: a missing camcfg is a failure", run_camcfg("stream.main.fps", "20") != 0);
	if (getenv("TEST_CAMCFG")) {
		camcfg_bin = getenv("TEST_CAMCFG");
		write_file(conf_path, "stream.main.fps=25\n");
		check("run_camcfg runs camcfg -d <dir> set", !run_camcfg("stream.main.fps", "12") &&
		      !run_camcfg("time.ntp", "pool.ntp.org,192.0.2.1"));
		check("... which wrote cam.conf", conf_get("stream.main.fps", a, sizeof a) && !strcmp(a, "12") &&
		      conf_get("time.ntp", b, sizeof b) && !strcmp(b, "pool.ntp.org,192.0.2.1"));
		check("run_camcfg: camcfg refusing a value is a failure", run_camcfg("stream.main.fps", "99") != 0);
		char mh[2 * MASK_BYTES + 1], got[300];
		for (int i = 0; i < MASK_BYTES; i++) snprintf(mh + 2 * i, 3, "%02x", i);
		check("real camcfg takes motion.mask; conf_get reads the 268-character line back",
		      !run_camcfg("motion.mask", mh) && conf_get("motion.mask", got, sizeof got) && !strcmp(got, mh));
		check("... and refuses a short one", run_camcfg("motion.mask", "ff") != 0);
		check("real camcfg takes an OSD title with spaces and symbols, read back whole",
		      !run_camcfg("osd.title.text", " Gate 2 & <yard> ") && conf_get("osd.title.text", got, sizeof got) &&
		      !strcmp(got, " Gate 2 & <yard> "));
		check("... and an empty one", !run_camcfg("osd.title.text", "") && conf_get("osd.title.text", got, sizeof got) &&
		      !*got);
		check("... refuses UTF-8 and a bad position", run_camcfg("osd.title.text", "caf\xc3\xa9") != 0 &&
		      run_camcfg("osd.time.pos", "middle") != 0);
		check("real camcfg takes time.tz <+0530>-5:30, read back whole", !run_camcfg("time.tz", "<+0530>-5:30") &&
		      conf_get("time.tz", got, sizeof got) && !strcmp(got, "<+0530>-5:30"));
		check("... and refuses CST6CDT;reboot and the old osd.tz_offset", run_camcfg("time.tz", "CST6CDT;reboot") != 0 &&
		      run_camcfg("osd.tz_offset", "-300") != 0);
		char lock[700];
		snprintf(lock, sizeof lock, "%s/.lock", dir);
		unlink(lock);
	} else {
		printf("skip: real camcfg (set TEST_CAMCFG to a host build of src/camcfg/camcfg.c)\n");
	}
	write_file(conf_path, "image.brightness=55\nstream.main.kbps=6000\nstream.main.profile=main\n"
		   "stream.main.fps=99\nstream.sub.enabled=1\n");
#undef OP
#undef ADMIN
#undef VIEW
}

#define IMG "/onvif/imaging_service"
#define EV "/onvif/event_service"
#define SUBSCRIBE(filter, ttl) "<tev:CreatePullPointSubscription><tev:Filter><wsnt:TopicExpression " \
	"Dialect=\"http://www.onvif.org/ver10/tev/topicExpression/ConcreteSet\" " \
	"xmlns:tns1=\"http://www.onvif.org/ver10/topics\">" filter "</wsnt:TopicExpression></tev:Filter>" \
	"<tev:InitialTerminationTime>" ttl "</tev:InitialTerminationTime></tev:CreatePullPointSubscription>"

static const char *imaging_body(const char *token, const char *settings)
{
	static char b[4096];
	snprintf(b, sizeof b, "<timg:SetImagingSettings><timg:VideoSourceToken>%s</timg:VideoSourceToken>"
		 "<timg:ImagingSettings>%s</timg:ImagingSettings><timg:ForcePersistence>true"
		 "</timg:ForcePersistence></timg:SetImagingSettings>", token, settings);
	return b;
}

static const char *pull_body(const char *timeout, int limit)
{
	static char b[256];
	snprintf(b, sizeof b, "<tev:PullMessages><tev:Timeout>%s</tev:Timeout><tev:MessageLimit>%d"
		 "</tev:MessageLimit></tev:PullMessages>", timeout, limit);
	return b;
}

/* The path of the subscription address in a CreatePullPointSubscriptionResponse. */
static void sub_path(const char *r, char *out, size_t cap)
{
	const char *a = strstr(r, "<wsa:Address>http://192.0.2.10");
	if (!a) { fprintf(stderr, "FAIL: no subscription address in\n%s\n", r); exit(1); }
	a += strlen("<wsa:Address>http://192.0.2.10");
	snprintf(out, cap, "%.*s", (int)strcspn(a, "<"), a);
}

static int count(const char *r, const char *what)
{
	int n = 0;
	for (const char *p = r; (p = strstr(p, what)); p++) n++;
	return n;
}

/* Imaging (#103), as SSS's image sliders use it: rtspd's get/set faked, camcfg faked. */
static void test_imaging(void)
{
	long long now = time(NULL);
	const char *r;
#define VIEW wsse("view", "V1ew:Pass&", now, 0, 0)
#define OP wsse("op", "0perPass", now, 0, 0)
#define GETIMG "<timg:GetImagingSettings><timg:VideoSourceToken>VideoSource_1</timg:VideoSourceToken>" \
	"</timg:GetImagingSettings>"
	write_file(conf_path, "image.brightness=55\nstream.sub.enabled=1\n");
	camcfg_calls = 0;
	*camcfg_log = *set_log = 0;
	r = run(soap_req(IMG, NULL, GETIMG, NULL));
	expect("GetImagingSettings needs credentials", r, "401 Unauthorized");
	r = run(soap_req(IMG, VIEW, GETIMG, NULL));
	expect("GetImagingSettings from rtspd", r, "<timg:ImagingSettings><tt:Brightness>50</tt:Brightness>"
	       "<tt:ColorSaturation>50</tt:ColorSaturation><tt:Contrast>50</tt:Contrast><tt:IrCutFilter>AUTO"
	       "</tt:IrCutFilter><tt:Sharpness>50</tt:Sharpness></timg:ImagingSettings>");
	strcpy(fake_mode, "day");
	expect("daynight day -> IrCutFilter ON (filter in)", run(soap_req(IMG, VIEW, GETIMG, NULL)),
	       "<tt:IrCutFilter>ON</tt:IrCutFilter>");
	strcpy(fake_mode, "night");
	expect("daynight night -> IrCutFilter OFF", run(soap_req(IMG, VIEW, GETIMG, NULL)),
	       "<tt:IrCutFilter>OFF</tt:IrCutFilter>");
	strcpy(fake_mode, "auto");
	fake_down = 1;
	expect("rtspd not answering: cam.conf values", run(soap_req("/onvif/Imaging", VIEW, GETIMG, NULL)),
	       "<tt:Brightness>55</tt:Brightness>");
	fake_down = 0;
	r = run(soap_req(IMG, VIEW, "<timg:GetImagingSettings><timg:VideoSourceToken>VideoSource_9"
			 "</timg:VideoSourceToken></timg:GetImagingSettings>", NULL));
	expect("unknown video source -> NoSource", r, "ter:NoSource");
	r = run(soap_req(IMG, VIEW, "<timg:GetOptions><timg:VideoSourceToken>VideoSource_1</timg:VideoSourceToken>"
			 "</timg:GetOptions>", NULL));
	expect("GetOptions ranges", r, "<tt:Brightness><tt:Min>0</tt:Min><tt:Max>100</tt:Max></tt:Brightness>");
	expect("GetOptions IrCutFilterModes", r, "<tt:IrCutFilterModes>ON</tt:IrCutFilterModes><tt:IrCutFilterModes>"
	       "OFF</tt:IrCutFilterModes><tt:IrCutFilterModes>AUTO</tt:IrCutFilterModes>");

	/* SetImagingSettings as a client sends it: everything it read, a few values changed */
	const char *sss = "<tt:BacklightCompensation><tt:Mode>OFF</tt:Mode></tt:BacklightCompensation>"
		"<tt:Brightness>60</tt:Brightness><tt:ColorSaturation>40.5</tt:ColorSaturation>"
		"<tt:Contrast>50</tt:Contrast><tt:Exposure><tt:Mode>AUTO</tt:Mode><tt:MinExposureTime>10"
		"</tt:MinExposureTime><tt:MaxExposureTime>40000</tt:MaxExposureTime><tt:MinGain>0</tt:MinGain>"
		"<tt:MaxGain>100</tt:MaxGain></tt:Exposure><tt:IrCutFilter>OFF</tt:IrCutFilter>"
		"<tt:Sharpness>50</tt:Sharpness><tt:WideDynamicRange><tt:Mode>OFF</tt:Mode>"
		"</tt:WideDynamicRange><tt:WhiteBalance><tt:Mode>AUTO</tt:Mode></tt:WhiteBalance>";
	r = run(soap_req(IMG, VIEW, imaging_body("VideoSource_1", sss), NULL));
	expect("SetImagingSettings needs operator (ACTUATE)", r, "ter:NotAuthorized");
	r = run(soap_req(IMG, OP, imaging_body("VideoSource_1", sss), NULL));
	expect("SetImagingSettings", r, "<timg:SetImagingSettingsResponse/>");
	printf("   camcfg: %s  rtspd: %s\n", camcfg_log, set_log);
	check("... saves each changed value with camcfg",
	      !strcmp(camcfg_log, "image.brightness=60;image.saturation=41;daynight.mode=night;"));
	check("... and applies it live", !strcmp(set_log, "set image.brightness 60;set image.saturation 41;"
	      "set daynight.mode night;"));
	expect("... read back", run(soap_req(IMG, VIEW, GETIMG, NULL)), "<tt:Brightness>60</tt:Brightness>"
	       "<tt:ColorSaturation>41</tt:ColorSaturation><tt:Contrast>50</tt:Contrast><tt:IrCutFilter>OFF");
	/* video orientation (SSS's "Video Orientation" panel): Rotate 180 = mirror + flip */
	{
		const char *vsc_get = "<trt:GetVideoSourceConfiguration><trt:ConfigurationToken>VideoSourceConfig_1"
				      "</trt:ConfigurationToken></trt:GetVideoSourceConfiguration>";
		char body[900];
		const char *fmt = "<trt:SetVideoSourceConfiguration><trt:Configuration token=\"VideoSourceConfig_1\">"
			"<tt:Name>VideoSourceConfig_1</tt:Name><tt:UseCount>2</tt:UseCount><tt:SourceToken>VideoSource_1"
			"</tt:SourceToken><tt:Bounds x=\"0\" y=\"0\" width=\"%d\" height=\"1440\"/><tt:Extension>"
			"<tt:Rotate><tt:Mode>%s</tt:Mode><tt:Degree>%s</tt:Degree></tt:Rotate></tt:Extension>"
			"</trt:Configuration><trt:ForcePersistence>true</trt:ForcePersistence>"
			"</trt:SetVideoSourceConfiguration>";
		expect("capabilities: Rotation", run(soap_req(MED, VIEW, "<trt:GetServiceCapabilities/>", NULL)),
		       "Rotation=\"true\"");
		expect("GetVideoSourceConfiguration: Rotate OFF", run(soap_req(MED, VIEW, vsc_get, NULL)),
		       "height=\"1440\"/><tt:Extension><tt:Rotate><tt:Mode>OFF</tt:Mode><tt:Degree>0</tt:Degree>"
		       "</tt:Rotate></tt:Extension></trt:Configuration>");
		expect("options: Rotate OFF/ON, 180", run(soap_req(MED, VIEW, "<trt:GetVideoSourceConfigurationOptions/>",
		       NULL)), "<tt:Extension><tt:Rotate><tt:Mode>OFF</tt:Mode><tt:Mode>ON</tt:Mode><tt:DegreeList>"
		       "<tt:Items>180</tt:Items></tt:DegreeList></tt:Rotate></tt:Extension></trt:Options>");
		snprintf(body, sizeof body, fmt, 2560, "ON", "180");
		expect("SetVideoSourceConfiguration needs operator", run(soap_req(MED, VIEW, body, NULL)), "ter:NotAuthorized");
		*camcfg_log = 0;
		*set_log = 0;
		expect("Rotate ON 180", run(soap_req(MED, OP, body, NULL)), "<trt:SetVideoSourceConfigurationResponse/>");
		check("... mirror and flip saved and applied", !strcmp(camcfg_log, "image.mirror=1;image.flip=1;") &&
		      !strcmp(set_log, "set image.mirror 1;set image.flip 1;"));
		expect("... read back", run(soap_req(MED, VIEW, vsc_get, NULL)), "<tt:Mode>ON</tt:Mode><tt:Degree>180</tt:Degree>");
		expect("... in the profiles too", run(soap_req(MED, VIEW, "<trt:GetProfiles/>", NULL)),
		       "<tt:Rotate><tt:Mode>ON</tt:Mode><tt:Degree>180</tt:Degree></tt:Rotate>");
		*camcfg_log = 0;
		expect("the same again", run(soap_req(MED, OP, body, NULL)), "<trt:SetVideoSourceConfigurationResponse/>");
		check("... saves nothing", !*camcfg_log);
		snprintf(body, sizeof body, fmt, 2560, "ON", "90");
		expect("Rotate 90 refused (no real rotation yet, #123)", run(soap_req(MED, OP, body, NULL)), "ter:ConfigModify");
		snprintf(body, sizeof body, fmt, 2560, "AUTO", "0");
		expect("Rotate AUTO refused", run(soap_req(MED, OP, body, NULL)), "ter:ConfigModify");
		snprintf(body, sizeof body, fmt, 1280, "OFF", "0");
		expect("other Bounds refused", run(soap_req(MED, OP, body, NULL)), "ter:ConfigModify");
		snprintf(body, sizeof body, fmt, 2560, "OFF", "0");
		*camcfg_log = 0;
		expect("Rotate OFF", run(soap_req(MED, OP, body, NULL)), "<trt:SetVideoSourceConfigurationResponse/>");
		check("... back to no mirror/flip", !strcmp(camcfg_log, "image.mirror=0;image.flip=0;"));
		expect("unknown configuration token", run(soap_req(MED, OP, "<trt:SetVideoSourceConfiguration>"
		       "<trt:Configuration token=\"x\"/></trt:SetVideoSourceConfiguration>", NULL)), "ter:NoConfig");
	}
	int calls = camcfg_calls;
	*set_log = 0;
	r = run(soap_req(IMG, OP, imaging_body("VideoSource_1", sss), NULL));
	expect("the same settings again", r, "<timg:SetImagingSettingsResponse/>");
	check("... save and apply nothing", camcfg_calls == calls && !*set_log);
	static const char *const bad[] = {
		"<tt:Brightness>101</tt:Brightness>", "<tt:Brightness>-1</tt:Brightness>",
		"<tt:Contrast>1e2</tt:Contrast>", "<tt:Sharpness>5.5.5</tt:Sharpness>",
		"<tt:ColorSaturation></tt:ColorSaturation>", "<tt:IrCutFilter>MAYBE</tt:IrCutFilter>",
		"<tt:Brightness>1000</tt:Brightness>",
	};
	for (size_t k = 0; k < sizeof bad / sizeof bad[0]; k++)
		expect("bad imaging value -> SettingsInvalid", run(soap_req(IMG, OP, imaging_body("VideoSource_1", bad[k]),
		       NULL)), "ter:SettingsInvalid");
	expect("unknown source -> NoSource", run(soap_req(IMG, OP, imaging_body("VideoSource_2",
	       "<tt:Brightness>10</tt:Brightness>"), NULL)), "ter:NoSource");
	check("... nothing saved or applied", camcfg_calls == calls && !*set_log);
	fake_down = 1;
	r = run(soap_req(IMG, OP, imaging_body("VideoSource_1", "<tt:Brightness>70</tt:Brightness>"), NULL));
	expect("rtspd not answering: saved for its next start", r, "<timg:SetImagingSettingsResponse/>");
	check("... with camcfg", camcfg_calls == calls + 1 && strstr(camcfg_log, "image.brightness=70;"));
	fake_down = 0;
	camcfg_fail = 1;
	r = run(soap_req(IMG, OP, imaging_body("VideoSource_1", "<tt:Brightness>20</tt:Brightness>"), NULL));
	expect("camcfg failing -> a Receiver fault, nothing applied", r, "The settings could not be saved");
	check("... nothing applied live", !strstr(set_log, "20"));
	camcfg_fail = 0;
	expect("GetStatus (no focus motor)", run(soap_req(IMG, VIEW, "<timg:GetStatus><timg:VideoSourceToken>"
	       "VideoSource_1</timg:VideoSourceToken></timg:GetStatus>", NULL)), "<timg:Status/>");
	expect("GetMoveOptions", run(soap_req(IMG, VIEW, "<timg:GetMoveOptions><timg:VideoSourceToken>"
	       "VideoSource_1</timg:VideoSourceToken></timg:GetMoveOptions>", NULL)), "<timg:MoveOptions/>");
	expect("Move -> ActionNotSupported", run(soap_req(IMG, OP, "<timg:Move><timg:VideoSourceToken>"
	       "VideoSource_1</timg:VideoSourceToken><timg:Focus><tt:Continuous><tt:Speed>1</tt:Speed>"
	       "</tt:Continuous></timg:Focus></timg:Move>", NULL)), "ter:ActionNotSupported");
	expect("Imaging GetServiceCapabilities", run(soap_req("/onvif/Imaging", NULL,
	       "<timg:GetServiceCapabilities/>", NULL)), "<timg:GetServiceCapabilitiesResponse><timg:Capabilities");
	memcpy(fake_img, (int[5]){ 50, 50, 50, 50, 50 }, sizeof fake_img);
	strcpy(fake_mode, "auto");
#undef GETIMG
#undef VIEW
#undef OP
}

/* OSD over ONVIF Media ver10, as SSS uses it: rtspd's get/set and camcfg faked. */
static const char *osd_body(const char *op, const char *token, const char *pos, const char *text)
{
	static char b[4096];
	snprintf(b, sizeof b, "<trt:%s><trt:OSD token=\"%s\"><tt:VideoSourceConfigurationToken>VideoSourceConfig_1"
		 "</tt:VideoSourceConfigurationToken><tt:Type>Text</tt:Type><tt:Position>%s</tt:Position>"
		 "<tt:TextString>%s</tt:TextString></trt:OSD></trt:%s>", op, token, pos, text, op);
	return b;
}

static void test_osd(void)
{
	long long now = time(NULL);
	const char *r;
#define VIEW wsse("view", "V1ew:Pass&", now, 0, 0)
#define OP wsse("op", "0perPass", now, 0, 0)
#define GETOSDS "<trt:GetOSDs><trt:ConfigurationToken>VideoSourceConfig_1</trt:ConfigurationToken></trt:GetOSDs>"
	write_file(conf_path, "stream.sub.enabled=1\n");
	*fake_osd = *camcfg_log = *set_log = 0;
	fake_down = 0;
	expect("Media capabilities: OSD", run(soap_req(MED, NULL, "<trt:GetServiceCapabilities/>", NULL)), "OSD=\"true\"");
	expect("GetOSDs needs credentials", run(soap_req(MED, NULL, GETOSDS, NULL)), "401 Unauthorized");
	r = run(soap_req(MED, VIEW, GETOSDS, NULL));
	expect("GetOSDs: the clock, top left, by default", r, "<trt:GetOSDsResponse><trt:OSDs token=\"osd_time\">"
	       "<tt:VideoSourceConfigurationToken>VideoSourceConfig_1</tt:VideoSourceConfigurationToken><tt:Type>Text"
	       "</tt:Type><tt:Position><tt:Type>UpperLeft</tt:Type></tt:Position><tt:TextString><tt:Type>DateAndTime"
	       "</tt:Type><tt:DateFormat>yyyy-MM-dd</tt:DateFormat><tt:TimeFormat>HH:mm:ss</tt:TimeFormat><tt:FontSize>64"
	       "</tt:FontSize></tt:TextString></trt:OSDs></trt:GetOSDsResponse>");
	absent("... the title is off", r, "osd_title");
	expect("GetOSDs without a token", run(soap_req(MED, VIEW, "<trt:GetOSDs/>", NULL)), "token=\"osd_time\"");
	expect("GetOSDs, another configuration -> NoConfig", run(soap_req(MED, VIEW, "<trt:GetOSDs><trt:ConfigurationToken>"
	       "VideoSourceConfig_2</trt:ConfigurationToken></trt:GetOSDs>", NULL)), "ter:NoConfig");
	r = run(soap_req(MED, VIEW, "<trt:GetOSDOptions><trt:ConfigurationToken>VideoSourceConfig_1</trt:ConfigurationToken>"
			 "</trt:GetOSDOptions>", NULL));
	expect("GetOSDOptions: two, one of each", r, "<trt:OSDOptions><tt:MaximumNumberOfOSDs Total=\"2\" Image=\"0\" "
	       "PlainText=\"1\" Date=\"0\" Time=\"0\" DateAndTime=\"1\"/><tt:Type>Text</tt:Type><tt:PositionOption>"
	       "UpperLeft</tt:PositionOption><tt:PositionOption>UpperRight</tt:PositionOption><tt:PositionOption>LowerLeft"
	       "</tt:PositionOption><tt:PositionOption>LowerRight</tt:PositionOption><tt:PositionOption>Custom"
	       "</tt:PositionOption><tt:TextOption><tt:Type>Plain</tt:Type><tt:Type>DateAndTime</tt:Type>");
	expect("... font sizes (main-stream pixels)", r, "<tt:FontSizeRange><tt:Min>64</tt:Min><tt:Max>128</tt:Max>");
	expect("... date formats", r, "<tt:DateFormat>yyyy-MM-dd</tt:DateFormat><tt:DateFormat>yyyy/MM/dd</tt:DateFormat>"
	       "<tt:DateFormat>dd/MM/yyyy</tt:DateFormat><tt:DateFormat>MM/dd/yyyy</tt:DateFormat><tt:DateFormat>dd-MM-yyyy"
	       "</tt:DateFormat><tt:DateFormat>MM-dd-yyyy</tt:DateFormat><tt:TimeFormat>HH:mm:ss</tt:TimeFormat>"
	       "<tt:TimeFormat>hh:mm:ss tt</tt:TimeFormat></tt:TextOption></trt:OSDOptions>");
	expect("GetOSDOptions without a token -> NoConfig", run(soap_req(MED, VIEW, "<trt:GetOSDOptions/>", NULL)),
	       "ter:NoConfig");
	expect("GetOSD osd_time", run(soap_req(MED, VIEW, "<trt:GetOSD><trt:OSDToken>osd_time</trt:OSDToken></trt:GetOSD>",
	       NULL)), "<trt:GetOSDResponse><trt:OSD token=\"osd_time\">");
	expect("GetOSD of the title while off -> NoConfig", run(soap_req(MED, VIEW, "<trt:GetOSD><trt:OSDToken>osd_title"
	       "</trt:OSDToken></trt:GetOSD>", NULL)), "ter:NoConfig");
	expect("GetOSD unknown -> NoConfig", run(soap_req(MED, VIEW, "<trt:GetOSD><trt:OSDToken>OSD_1</trt:OSDToken>"
	       "</trt:GetOSD>", NULL)), "ter:NoConfig");

	/* SetOSD as SSS sends it: a custom place, the US date, 12 h, a font size */
	const char *pos = "<tt:Type>Custom</tt:Type><tt:Pos x=\"0.5\" y=\"-0.5\"/>";
	const char *txt = "<tt:Type>DateAndTime</tt:Type><tt:DateFormat>MM/dd/yyyy</tt:DateFormat><tt:TimeFormat>hh:mm:ss tt"
		"</tt:TimeFormat><tt:FontSize>100</tt:FontSize>";
	expect("SetOSD needs operator", run(soap_req(MED, VIEW, osd_body("SetOSD", "osd_time", pos, txt), NULL)),
	       "ter:NotAuthorized");
	r = run(soap_req(MED, OP, osd_body("SetOSD", "osd_time", pos, txt), NULL));
	expect("SetOSD", r, "<trt:SetOSDResponse/>");
	printf("   camcfg: %s  rtspd: %s\n", camcfg_log, set_log);
	check("... saves what changed: x 0.5 -> 75 %, y -0.5 (up) -> 75 % down, 100 px -> medium (96)",
	      !strcmp(camcfg_log, "osd.time.pos=custom;osd.time.x=75;osd.time.y=75;osd.time.format=MM/dd/yyyy;"
		      "osd.time.12h=1;osd.size=medium;"));
	check("... and applies it live", strstr(set_log, "set osd.time.x 75;") && strstr(set_log, "set osd.size medium;"));
	r = run(soap_req(MED, VIEW, GETOSDS, NULL));
	expect("... read back", r, "<tt:Position><tt:Type>Custom</tt:Type><tt:Pos x=\"0.5\" y=\"-0.5\"/></tt:Position>"
	       "<tt:TextString><tt:Type>DateAndTime</tt:Type><tt:DateFormat>MM/dd/yyyy</tt:DateFormat><tt:TimeFormat>"
	       "hh:mm:ss tt</tt:TimeFormat><tt:FontSize>96</tt:FontSize>");
	int calls = camcfg_calls;
	run(soap_req(MED, OP, osd_body("SetOSD", "osd_time", pos, txt), NULL));
	check("the same SetOSD again saves nothing", camcfg_calls == calls);
	/* positions both ways */
	static const struct { const char *x, *y; int px, py; const char *back; } pv[] = {
		{ "-1", "1", 0, 0, "x=\"-1\" y=\"1\"" }, { "1", "-1", 100, 100, "x=\"1\" y=\"-1\"" },
		{ "0", "0", 50, 50, "x=\"0\" y=\"0\"" }, { "-0.98", "0.02", 1, 49, "x=\"-0.98\" y=\"0.02\"" },
		{ "1.0E0", "-1.0", 100, 100, "x=\"1\" y=\"-1\"" },
	};
	for (size_t i = 0; i < sizeof pv / sizeof pv[0]; i++) {
		char p[160], wx[32], wy[32], what[96];
		snprintf(p, sizeof p, "<tt:Type>Custom</tt:Type><tt:Pos x=\"%s\" y=\"%s\"/>", pv[i].x, pv[i].y);
		expect("SetOSD custom", run(soap_req(MED, OP, osd_body("SetOSD", "osd_time", p, "<tt:Type>DateAndTime</tt:Type>"),
		       NULL)), "<trt:SetOSDResponse/>");
		snprintf(wx, sizeof wx, "osd.time.x=%d\n", pv[i].px);
		snprintf(wy, sizeof wy, "osd.time.y=%d\n", pv[i].py);
		snprintf(what, sizeof what, "Pos %s,%s -> %d %%, %d %%", pv[i].x, pv[i].y, pv[i].px, pv[i].py);
		check(what, strstr(fake_osd, wx) && strstr(fake_osd, wy));
		expect("... read back", run(soap_req(MED, VIEW, GETOSDS, NULL)), pv[i].back);
	}
	expect("corners", run(soap_req(MED, OP, osd_body("SetOSD", "osd_time", "<tt:Type>LowerRight</tt:Type>",
	       "<tt:Type>DateAndTime</tt:Type>"), NULL)), "<trt:SetOSDResponse/>");
	check("... LowerRight -> lr", strstr(fake_osd, "osd.time.pos=lr\n") != NULL);

	/* CreateOSD of a plain text: the title, switched on last; its text escaped on the way back */
	*camcfg_log = 0;
	r = run(soap_req(MED, OP, osd_body("CreateOSD", "", "<tt:Type>UpperRight</tt:Type>",
			 "<tt:Type>Plain</tt:Type><tt:PlainText>Front door &amp; &lt;gate&gt;</tt:PlainText>"), NULL));
	expect("CreateOSD Plain -> osd_title", r, "<trt:CreateOSDResponse><trt:OSDToken>osd_title</trt:OSDToken>");
	check("... saved, on last", !strcmp(camcfg_log, "osd.title.pos=ur;osd.title.text=Front door & <gate>;"
	      "osd.title.enabled=1;"));
	r = run(soap_req(MED, VIEW, GETOSDS, NULL));
	expect("GetOSDs lists both", r, "<trt:OSDs token=\"osd_title\"><tt:VideoSourceConfigurationToken>VideoSourceConfig_1"
	       "</tt:VideoSourceConfigurationToken><tt:Type>Text</tt:Type><tt:Position><tt:Type>UpperRight</tt:Type>"
	       "</tt:Position><tt:TextString><tt:Type>Plain</tt:Type><tt:FontSize>96</tt:FontSize><tt:PlainText>"
	       "Front door &amp; &lt;gate&gt;</tt:PlainText></tt:TextString></trt:OSDs>");
	expect("... time first", r, "<trt:GetOSDsResponse><trt:OSDs token=\"osd_time\">");
	expect("CreateOSD DateAndTime -> osd_time", run(soap_req(MED, OP, osd_body("CreateOSD", "x", "<tt:Type>UpperLeft"
	       "</tt:Type>", "<tt:Type>DateAndTime</tt:Type>"), NULL)), "<trt:OSDToken>osd_time</trt:OSDToken>");

	/* refusals: nothing saved */
	calls = camcfg_calls;
	static const struct { const char *tok, *pos, *text, *want; } bad[] = {
		{ "osd_time", "<tt:Type>UpperLeft</tt:Type>", "<tt:Type>Plain</tt:Type><tt:PlainText>x</tt:PlainText>", "ter:ConfigModify" },
		{ "osd_title", "<tt:Type>UpperLeft</tt:Type>", "<tt:Type>Plain</tt:Type><tt:PlainText>"
		  "1234567890123456789012345678901234567890123456789</tt:PlainText>", "ter:ConfigModify" },
		{ "osd_title", "<tt:Type>UpperLeft</tt:Type>", "<tt:Type>Plain</tt:Type><tt:PlainText>caf\xc3\xa9</tt:PlainText>",
		  "ter:ConfigModify" },
		{ "osd_title", "<tt:Type>UpperLeft</tt:Type>", "<tt:Type>Plain</tt:Type><tt:PlainText>a&#9;b</tt:PlainText>",
		  "ter:ConfigModify" },
		{ "osd_time", "<tt:Type>Custom</tt:Type><tt:Pos x=\"1.5\" y=\"0\"/>", "<tt:Type>DateAndTime</tt:Type>", "ter:ConfigModify" },
		{ "osd_time", "<tt:Type>Custom</tt:Type>", "<tt:Type>DateAndTime</tt:Type>", "ter:ConfigModify" },
		{ "osd_time", "<tt:Type>Custom</tt:Type><tt:Pos x=\"nan\" y=\"0\"/>", "<tt:Type>DateAndTime</tt:Type>", "ter:ConfigModify" },
		{ "osd_time", "<tt:Type>Middle</tt:Type>", "<tt:Type>DateAndTime</tt:Type>", "ter:ConfigModify" },
		{ "osd_time", "<tt:Type>UpperLeft</tt:Type>", "<tt:Type>DateAndTime</tt:Type><tt:DateFormat>yy/MM/dd</tt:DateFormat>",
		  "ter:ConfigModify" },
		{ "osd_time", "<tt:Type>UpperLeft</tt:Type>", "<tt:Type>DateAndTime</tt:Type><tt:TimeFormat>HH:mm</tt:TimeFormat>",
		  "ter:ConfigModify" },
		{ "osd_time", "<tt:Type>UpperLeft</tt:Type>", "<tt:Type>DateAndTime</tt:Type><tt:FontSize>big</tt:FontSize>",
		  "ter:ConfigModify" },
		{ "osd_time", "<tt:Type>UpperLeft</tt:Type>", "<tt:Type>Date</tt:Type>", "ter:ConfigModify" },
		{ "OSD_3", "<tt:Type>UpperLeft</tt:Type>", "<tt:Type>DateAndTime</tt:Type>", "ter:NoConfig" },
	};
	for (size_t i = 0; i < sizeof bad / sizeof bad[0]; i++)
		expect(bad[i].want, run(soap_req(MED, OP, osd_body("SetOSD", bad[i].tok, bad[i].pos, bad[i].text), NULL)),
		       bad[i].want);
	expect("SetOSD of an image -> ConfigModify", run(soap_req(MED, OP, "<trt:SetOSD><trt:OSD token=\"osd_title\">"
	       "<tt:VideoSourceConfigurationToken>VideoSourceConfig_1</tt:VideoSourceConfigurationToken><tt:Type>Image"
	       "</tt:Type><tt:Position><tt:Type>UpperLeft</tt:Type></tt:Position><tt:Image><tt:ImgPath>http://x/y.png"
	       "</tt:ImgPath></tt:Image></trt:OSD></trt:SetOSD>", NULL)), "ter:ConfigModify");
	expect("CreateOSD of an image -> ConfigModify", run(soap_req(MED, OP, "<trt:CreateOSD><trt:OSD token=\"\">"
	       "<tt:VideoSourceConfigurationToken>VideoSourceConfig_1</tt:VideoSourceConfigurationToken><tt:Type>Image"
	       "</tt:Type><tt:Position><tt:Type>UpperLeft</tt:Type></tt:Position></trt:OSD></trt:CreateOSD>", NULL)),
	       "ter:ConfigModify");
	expect("SetOSD on another source -> NoConfig", run(soap_req(MED, OP, "<trt:SetOSD><trt:OSD token=\"osd_time\">"
	       "<tt:VideoSourceConfigurationToken>VideoSourceConfig_9</tt:VideoSourceConfigurationToken><tt:Type>Text"
	       "</tt:Type></trt:OSD></trt:SetOSD>", NULL)), "ter:NoConfig");
	expect("SetOSD without an OSD -> InvalidArgs", run(soap_req(MED, OP, "<trt:SetOSD/>", NULL)), "ter:InvalidArgs");
	check("... nothing saved", camcfg_calls == calls);

	/* DeleteOSD: off, then not listed */
	expect("DeleteOSD needs operator", run(soap_req(MED, VIEW, "<trt:DeleteOSD><trt:OSDToken>osd_title</trt:OSDToken>"
	       "</trt:DeleteOSD>", NULL)), "ter:NotAuthorized");
	*camcfg_log = 0;
	expect("DeleteOSD", run(soap_req(MED, OP, "<trt:DeleteOSD><trt:OSDToken>osd_title</trt:OSDToken></trt:DeleteOSD>",
	       NULL)), "<trt:DeleteOSDResponse/>");
	check("... osd.title.enabled=0", !strcmp(camcfg_log, "osd.title.enabled=0;"));
	absent("... gone from GetOSDs", run(soap_req(MED, VIEW, GETOSDS, NULL)), "osd_title");
	expect("DeleteOSD unknown -> NoConfig", run(soap_req(MED, OP, "<trt:DeleteOSD><trt:OSDToken>x</trt:OSDToken>"
	       "</trt:DeleteOSD>", NULL)), "ter:NoConfig");
	camcfg_fail = 1;
	expect("camcfg failing -> Receiver fault", run(soap_req(MED, OP, "<trt:DeleteOSD><trt:OSDToken>osd_time"
	       "</trt:OSDToken></trt:DeleteOSD>", NULL)), "The settings could not be saved");
	camcfg_fail = 0;
	/* rtspd down: cam.conf (what fake camcfg wrote) */
	fake_down = 1;
	r = run(soap_req(MED, VIEW, GETOSDS, NULL));
	expect("rtspd down: from cam.conf", r, "<tt:Position><tt:Type>UpperLeft</tt:Type></tt:Position>");
	fake_down = 0;
	*fake_osd = 0;
	write_file(conf_path, "stream.sub.enabled=1\n");
#undef GETOSDS
#undef VIEW
#undef OP
}

/* Events (#77): PullPoint subscriptions on rtspd's motion detector (faked), held PullMessages
 * answered by events_tick on a change or at the timeout (the clock moved by mono_adj). */
static void test_events(void)
{
	long long now = time(NULL);
	const char *r;
	char path[128], hdr2[2600];
	int mc;
	struct client *h = &clients[0];
#define VIEW wsse("view", "V1ew:Pass&", now, 0, 0)
	memset(subs, 0, sizeof subs);
	fake_mstate = 0;
	fake_mseq = 0;
	fake_msince = 7;

	r = run(soap_req(DEV, NULL, "<tds:GetCapabilities><tds:Category>All</tds:Category></tds:GetCapabilities>", NULL));
	expect("GetCapabilities: Events", r, "<tt:Events><tt:XAddr>http://192.0.2.10/onvif/event_service</tt:XAddr>"
	       "<tt:WSSubscriptionPolicySupport>false</tt:WSSubscriptionPolicySupport><tt:WSPullPointSupport>true");
	expect("GetCapabilities: Imaging", r, "<tt:Imaging><tt:XAddr>http://192.0.2.10/onvif/imaging_service</tt:XAddr>");
	r = run(soap_req(DEV, NULL, "<tds:GetCapabilities><tds:Category>Events</tds:Category></tds:GetCapabilities>", NULL));
	expect("GetCapabilities Category Events", r, "<tt:Events>");
	absent("... only Events", r, "<tt:Media>");
	r = run(soap_req(DEV, NULL, "<tds:GetServices><tds:IncludeCapability>true</tds:IncludeCapability></tds:GetServices>", NULL));
	expect("GetServices: Imaging ver20", r, "<tds:Namespace>http://www.onvif.org/ver20/imaging/wsdl</tds:Namespace>"
	       "<tds:XAddr>http://192.0.2.10/onvif/imaging_service</tds:XAddr>");
	expect("GetServices: Events", r, "<tds:Namespace>http://www.onvif.org/ver10/events/wsdl</tds:Namespace>"
	       "<tds:XAddr>http://192.0.2.10/onvif/event_service</tds:XAddr><tds:Capabilities><tev:Capabilities");
	expect("Events GetServiceCapabilities", run(soap_req("/onvif/Events", NULL, "<tev:GetServiceCapabilities/>",
	       NULL)), "WSPullPointSupport=\"true\"");

	r = run(soap_req(EV, NULL, "<tev:GetEventProperties/>", NULL));
	expect("GetEventProperties needs credentials", r, "401 Unauthorized");
	r = run(soap_req(EV, VIEW, "<tev:GetEventProperties/>", NULL));
	expect("GetEventProperties: cell motion", r, "<tns1:RuleEngine wstop:topic=\"false\"><CellMotionDetector "
	       "wstop:topic=\"false\"><Motion wstop:topic=\"true\">");
	expect("... IsMotion", r, "<tt:SimpleItemDescription Name=\"IsMotion\" Type=\"xs:boolean\"/>");
	expect("... motion alarm", r, "<tns1:VideoSource wstop:topic=\"false\"><MotionAlarm wstop:topic=\"true\">");
	expect("... ConcreteSet", r, "http://www.onvif.org/ver10/tev/topicExpression/ConcreteSet");
	expect("... wsa:Action", r, "<env:Header><wsa:Action>http://www.onvif.org/ver10/events/wsdl/EventPortType/"
	       "GetEventPropertiesResponse</wsa:Action></env:Header><env:Body>");

	r = run(soap_req(EV, VIEW, SUBSCRIBE("tns1:RuleEngine/CellMotionDetector/Motion", "PT60S"), NULL));
	expect("CreatePullPointSubscription", r, "<tev:SubscriptionReference><wsa:Address>http://192.0.2.10/onvif/"
	       "event_service?sub=");
	expect("... TerminationTime", r, "<wsnt:TerminationTime>");
	sub_path(r, path, sizeof path);
	check("... id: 16 hex digits", strlen(path) == strlen(EV "?sub=") + 16);
	r = run(soap_req(path, VIEW, pull_body("PT5S", 10), NULL));
	expect("first pull, motion off: answered", r, "<tev:PullMessagesResponse>");
	absent("... with no message (stock never sends Initialized)", r, "NotificationMessage");
	expect("... wsa:Action", r, "PullPointSubscription/PullMessagesResponse</wsa:Action>");

	run_on(h, soap_req(path, VIEW, pull_body("PT5S", 10), NULL));
	check("no news: the pull is held, nothing sent", h->state == 2 && h->out_len == 0);
	mc = motion_calls;
	events_tick(mono_ms());
	check("... rtspd isn't asked again within POLL_MS", motion_calls == mc && h->state == 2);
	fake_mstate = 1;
	fake_mseq = 1;
	fake_msince = 0;
	mono_adj += POLL_MS + 100;
	events_tick(mono_ms());
	check("motion: the next poll answers the held pull", motion_calls == mc + 1 && h->state == 1);
	r = reply_of(h);
	expect("... Changed, IsMotion true", r, "PropertyOperation=\"Changed\"><tt:Source><tt:SimpleItem "
	       "Name=\"VideoSourceConfigurationToken\" Value=\"VideoSourceConfig_1\"/>");
	expect("... true", r, "<tt:SimpleItem Name=\"IsMotion\" Value=\"true\"/>");
	check("... only the filtered topic", count(r, "<wsnt:NotificationMessage>") == 1 && !strstr(r, "MotionAlarm"));
	client_close(h);

	run_on(h, soap_req(path, VIEW, pull_body("PT2S", 10), NULL));
	check("held again", h->state == 2);
	mono_adj += 2100;
	events_tick(mono_ms());
	r = reply_of(h);
	check("timeout: answered", h->state == 1);
	expect("... an empty PullMessagesResponse", r, "<tev:PullMessagesResponse><tev:CurrentTime>");
	absent("... without messages", r, "NotificationMessage");
	client_close(h);
	run_on(h, soap_req(path, VIEW, pull_body("PT60S", 10), NULL));
	check("Timeout is held at most PULL_MAX_MS", h->state == 2 && h->park_until - mono_ms() <= PULL_MAX_MS);
	mono_adj += PULL_MAX_MS + 100;
	events_tick(mono_ms());
	check("... then answered", h->state == 1 && !strstr(reply_of(h), "NotificationMessage"));
	client_close(h);

	fake_mstate = 0;
	fake_mseq = 3;
	{
		static const char *const want[3] = { "false", "true", "false" };
		int ok = 1;
		for (int k = 0; k < 3; k++) {
			char v[40];
			r = run(soap_req(path, VIEW, pull_body("PT5S", 10), NULL));
			snprintf(v, sizeof v, "IsMotion\" Value=\"%s\"", want[k]);
			ok &= count(r, "<wsnt:NotificationMessage>") == 1 && strstr(r, v) && strstr(r, "\"Changed\"");
		}
		check("missed edges: false, true, false, one per pull, each answered at once", ok);
	}
	r = run(soap_req(path, VIEW, pull_body("PT0S", 10), NULL));
	absent("... then nothing", r, "NotificationMessage");
	fake_mseq = 5;
	r = run(soap_req(path, VIEW, pull_body("PT0S", 1), NULL));
	check("two more edges: true", count(r, "<wsnt:NotificationMessage>") == 1 && strstr(r, "IsMotion\" Value=\"true\""));
	r = run(soap_req(path, VIEW, pull_body("PT0S", 1), NULL));
	check("... then false", count(r, "<wsnt:NotificationMessage>") == 1 && strstr(r, "IsMotion\" Value=\"false\""));
	fake_mseq = 0;
	fake_mstate = 1;
	r = run(soap_req(path, VIEW, pull_body("PT0S", 10), NULL));
	check("rtspd restarted (seq went back): the state change", count(r, "<wsnt:NotificationMessage>") == 1 &&
	      strstr(r, "IsMotion\" Value=\"true\""));
	r = run(soap_req(path, VIEW, "<tev:SetSynchronizationPoint/>", NULL));
	expect("SetSynchronizationPoint", r, "<tev:SetSynchronizationPointResponse/>");
	r = run(soap_req(path, VIEW, pull_body("PT0S", 10), NULL));
	expect("... next pull: motion on is reported again", r, "PropertyOperation=\"Changed\"");
	expect("... true", r, "IsMotion\" Value=\"true\"");
	absent("... never Initialized", r, "Initialized");
	fake_down = 1;
	fake_mstate = 0;
	r = run(soap_req(path, VIEW, pull_body("PT0S", 10), NULL));
	check("rtspd not answering: nothing reported", strstr(r, "PullMessagesResponse") && !strstr(r, "Notification"));
	fake_down = 0;

	r = run(soap_req(path, VIEW, "<wsnt:Renew><wsnt:TerminationTime>PT120S</wsnt:TerminationTime></wsnt:Renew>", NULL));
	expect("Renew", r, "<wsnt:RenewResponse><wsnt:TerminationTime>");
	expect("... wsa:Action", r, "http://docs.oasis-open.org/wsn/bw-2/SubscriptionManager/RenewResponse");
	snprintf(hdr2, sizeof hdr2, "%s", VIEW);
	snprintf(strstr(hdr2, "</s:Header>"), 200, "<wsa:To xmlns:wsa=\"http://www.w3.org/2005/08/addressing\">"
		 "http://192.0.2.10%s</wsa:To></s:Header>", path);
	r = run(soap_req(EV, hdr2, pull_body("PT0S", 10), NULL));
	expect("addressed by wsa:To instead of the query", r, "<tev:PullMessagesResponse>");
	expect("... (the change it missed)", r, "IsMotion\" Value=\"false\"");
	r = run(soap_req(path, NULL, pull_body("PT0S", 10), NULL));
	expect("the subscription id is no credential", r, "401 Unauthorized");
	r = run(soap_req(EV "?sub=0123456789abcdef", VIEW, pull_body("PT0S", 10), NULL));
	expect("unknown subscription -> fault", r, "<wsrf-r:ResourceUnknownFault><wsrf-bf:Timestamp>");
	expect("... 400", r, "HTTP/1.1 400");
	expect("no subscription -> fault", run(soap_req(EV, VIEW, pull_body("PT0S", 10), NULL)), "ResourceUnknownFault");
	expect("bad Timeout -> InvalidArgs", run(soap_req(path, VIEW, pull_body("5", 10), NULL)), "ter:InvalidArgs");
	run_on(h, soap_req(path, VIEW, pull_body("PT5S", 10), NULL));
	check("held", h->state == 2);
	r = run(soap_req(path, VIEW, "<wsnt:Unsubscribe/>", NULL));
	expect("Unsubscribe", r, "<wsnt:UnsubscribeResponse/>");
	events_tick(mono_ms());
	expect("... the held pull gets the fault", reply_of(h), "ResourceUnknownFault");
	client_close(h);
	expect("... and so does the next", run(soap_req(path, VIEW, pull_body("PT0S", 10), NULL)), "ResourceUnknownFault");

	/* both topics, filters */
	fake_mstate = 1;
	r = run(soap_req(EV, VIEW, "<tev:CreatePullPointSubscription/>", NULL));
	sub_path(r, path, sizeof path);
	r = run(soap_req(path, VIEW, pull_body("PT1S", 10), NULL));
	check("no filter, motion on: cell motion first", count(r, "<wsnt:NotificationMessage>") == 1 &&
	      strstr(r, "tns1:RuleEngine/CellMotionDetector/Motion</wsnt:Topic>"));
	r = run(soap_req(path, VIEW, pull_body("PT1S", 10), NULL));
	check("... then the motion alarm", count(r, "<wsnt:NotificationMessage>") == 1 &&
	      strstr(r, "tns1:VideoSource/MotionAlarm</wsnt:Topic>") &&
	      strstr(r, "<tt:SimpleItem Name=\"Source\" Value=\"VideoSource_1\"/>") &&
	      strstr(r, "<tt:SimpleItem Name=\"State\" Value=\"true\"/>"));
	check("topic filters", topic_mask("tns1:VideoSource//.") == T_ALARM &&
	      topic_mask("tns1:RuleEngine/*/Motion") == T_MOTION &&
	      topic_mask(" tns1:RuleEngine//. | tns1:VideoSource/MotionAlarm ") == (T_MOTION | T_ALARM) &&
	      topic_mask("tns1:Foo/Bar") == 0 && topic_mask("tns1:RuleEngine") == 0 &&
	      topic_mask("//.") == 0 && topic_mask("a/b/c/d/e/f") == 0);
	r = run(soap_req(EV, VIEW, SUBSCRIBE("tns1:VideoSource//.", "PT10S"), NULL));
	sub_path(r, path, sizeof path);
	r = run(soap_req(path, VIEW, pull_body("PT1S", 10), NULL));
	check("filter VideoSource//.: only MotionAlarm", count(r, "<wsnt:NotificationMessage>") == 1 &&
	      strstr(r, "MotionAlarm"));
	fake_mstate = 0;
	for (int k = 0; k < 3; k++) {                              /* 24 s on a 10 s subscription */
		mono_adj += 8000;
		r = run(soap_req(path, VIEW, pull_body("PT0S", 10), NULL));
	}
	expect("each pull extends the subscription (SSS never renews)", r, "<tev:PullMessagesResponse>");
	mono_adj += 11000;
	expect("expired subscription -> fault", run(soap_req(path, VIEW, pull_body("PT0S", 10), NULL)),
	       "ResourceUnknownFault");
	expect("unknown topic filter: all topics", run(soap_req(EV, VIEW, SUBSCRIBE("tns1:Foo/Bar", "PT10S"), NULL)),
	       "event_service?sub=");
	expect("InitialTerminationTime garbage -> InvalidArgs", run(soap_req(EV, VIEW,
	       SUBSCRIBE("tns1:VideoSource//.", "soon"), NULL)), "ter:InvalidArgs");
	char at[24], body[512];
	iso(time(NULL) + 120, at);
	snprintf(body, sizeof body, "<tev:CreatePullPointSubscription><tev:InitialTerminationTime>%s"
		 "</tev:InitialTerminationTime></tev:CreatePullPointSubscription>", at);
	expect("absolute InitialTerminationTime", run(soap_req(EV, VIEW, body, NULL)), "event_service?sub=");
	check("when(): durations and times", when("PT60S") == 60 && when("PT1M30S") == 90 && when("P1DT1H") == 90000 &&
	      when("PT0.5S") == 0 && when("PT") < 0 && when("P1M") < 0 && when("60") < 0 && when(at) >= 119);

	/* at most MAX_SUBS: the least recently pulled goes, unless every one has a pull held */
	memset(subs, 0, sizeof subs);
	char paths[MAX_SUBS][128];
	for (int k = 0; k < MAX_SUBS; k++) {
		sub_path(run(soap_req(EV, VIEW, "<tev:CreatePullPointSubscription/>", NULL)), paths[k], sizeof paths[k]);
		mono_adj += 10;
	}
	run(soap_req(paths[0], VIEW, pull_body("PT0S", 10), NULL));    /* 0 used last, 1 least */
	sub_path(run(soap_req(EV, VIEW, "<tev:CreatePullPointSubscription/>", NULL)), path, sizeof path);
	expect("one more subscription evicts the least recently pulled", run(soap_req(paths[1], VIEW,
	       pull_body("PT0S", 10), NULL)), "ResourceUnknownFault");
	expect("... the others stay", run(soap_req(paths[0], VIEW, pull_body("PT0S", 10), NULL)), "PullMessagesResponse");
	fake_mstate = 1;
	/* the live subscriptions after the eviction: every one but paths[1] */
	const char *held[MAX_SUBS];
	int nh = 0;
	for (int k = 0; k < MAX_SUBS; k++) if (k != 1) held[nh++] = paths[k];
	held[nh++] = path;
	for (int k = 0; k < MAX_SUBS; k++)                         /* drain: one message per pull */
		for (int d = 0; d < 4 && strstr(run(soap_req(held[k], VIEW, pull_body("PT0S", 10), NULL)),
						 "NotificationMessage"); d++) {}
	for (int k = 0; k < MAX_SUBS; k++) run_on(&clients[k], soap_req(held[k], VIEW, pull_body("PT5S", 10), NULL));
	int all_held = 1;
	for (int k = 0; k < MAX_SUBS; k++) all_held &= clients[k].state == 2;
	check("a pull held on every subscription", all_held);
	expect("every subscription held: another is refused", run(soap_req(EV, VIEW,
	       "<tev:CreatePullPointSubscription/>", NULL)), "Every subscription is in use");
	run_on(&clients[MAX_SUBS], soap_req(held[0], VIEW, pull_body("PT5S", 10), NULL));
	check("a second pull on a held subscription is answered at once (one held per subscription)",
	      clients[MAX_SUBS].state == 1 && strstr(reply_of(&clients[MAX_SUBS]), "<tev:PullMessagesResponse>"));
	fake_mstate = 0;
	fake_mseq++;
	mono_adj += POLL_MS + 100;
	mc = motion_calls;
	events_tick(mono_ms());
	int all_answered = 1;
	for (int k = 0; k < MAX_SUBS; k++) all_answered &= clients[k].state == 1;
	check("one poll answers every held pull", motion_calls == mc + 1 && all_answered);
	for (int k = 0; k < MAX_CLIENTS; k++) client_close(&clients[k]);
	memset(subs, 0, sizeof subs);
	mono_adj = 0;
	fake_mstate = 0;
	fake_mseq = 0;
#undef VIEW
}

#define AN "/onvif/analytics_service"

/* ActiveCells for a mask: base64 of its PackBits, as a client would write it. */
static const char *cells_of(const uint8_t mask[MASK_BYTES])
{
	static char b64[300];
	uint8_t pb[MASK_BYTES + 2];
	b64_enc(pb, packbits_enc(mask, MASK_BYTES, pb), b64);
	return b64;
}

static const char *rules_body(const char *op, const char *name, const char *type, const char *cells,
			      const char *mincount)
{
	static char b[2048];
	snprintf(b, sizeof b, "<tan:%s><tan:ConfigurationToken>VideoAnalyticsConfig_1</tan:ConfigurationToken>"
		 "<tan:Rule Name=\"%s\" Type=\"%s\"><tt:Parameters><tt:SimpleItem Name=\"MinCount\" Value=\"%s\"/>"
		 "<tt:SimpleItem Name=\"AlarmOnDelay\" Value=\"1000\"/><tt:SimpleItem Name=\"AlarmOffDelay\" "
		 "Value=\"1000\"/><tt:SimpleItem Name=\"ActiveCells\" Value=\"%s\"/></tt:Parameters></tan:Rule>"
		 "</tan:%s>", op, name, type, mincount, cells, op);
	return b;
}

static const char *modules_body(const char *name, const char *sens, int cols, int rows)
{
	static char b[2048];
	snprintf(b, sizeof b, "<tan:ModifyAnalyticsModules><tan:ConfigurationToken>VideoAnalyticsConfig_1"
		 "</tan:ConfigurationToken><tan:AnalyticsModule Name=\"%s\" Type=\"tt:CellMotionEngine\">"
		 "<tt:Parameters><tt:SimpleItem Name=\"Sensitivity\" Value=\"%s\"/><tt:ElementItem Name=\"Layout\">"
		 "<tt:CellLayout Columns=\"%d\" Rows=\"%d\"><tt:Transformation><tt:Translate x=\"-1.0\" y=\"-1.0\"/>"
		 "<tt:Scale x=\"0.0625\" y=\"0.0625\"/></tt:Transformation></tt:CellLayout></tt:ElementItem>"
		 "</tt:Parameters></tan:AnalyticsModule></tan:ModifyAnalyticsModules>", name, sens, cols, rows);
	return b;
}

/* Analytics (#77): the motion detector as SSS edits its area. rtspd's get/set and camcfg faked. */
static void test_analytics(void)
{
	long long now = time(NULL);
	const char *r;
	uint8_t mk[MASK_BYTES], back[MASK_BYTES], pb[MASK_BYTES + 2], raw[600];
	char hexs[2 * MASK_BYTES + 1], want[300];
	size_t n;
#define VIEW wsse("view", "V1ew:Pass&", now, 0, 0)
#define OP wsse("op", "0perPass", now, 0, 0)

	/* PackBits */
	memset(mk, 0xff, sizeof mk);
	n = packbits_enc(mk, MASK_BYTES, pb);
	check("PackBits all ones: one run packet", n == 2 && pb[0] == 0x81 && pb[1] == 0xff && !strcmp(cells_of(mk), "gf8="));
	memset(mk, 0, sizeof mk);
	n = packbits_enc(mk, MASK_BYTES, pb);
	check("PackBits all zeros", n == 2 && pb[0] == 0x81 && pb[1] == 0 && !packbits_dec(pb, n, back, MASK_BYTES) &&
	      !memcmp(mk, back, MASK_BYTES));
	for (int i = 0; i < MASK_BYTES; i++) mk[i] = (i / 4) % 2 ? 0x55 : 0xaa;     /* checkerboard */
	n = packbits_enc(mk, MASK_BYTES, pb);
	check("PackBits checkerboard round trip", !packbits_dec(pb, n, back, MASK_BYTES) && !memcmp(mk, back, MASK_BYTES));
	for (int i = 0; i < MASK_BYTES; i++) mk[i] = (uint8_t)i;                     /* no repeats at all */
	n = packbits_enc(mk, MASK_BYTES, pb);
	check("PackBits all literal: 129 bytes", n == 129 && !packbits_dec(pb, n, back, MASK_BYTES) &&
	      !memcmp(mk, back, MASK_BYTES));
	srand(7);
	int ok = 1;
	for (int t = 0; t < 2000 && ok; t++) {
		for (int i = 0; i < MASK_BYTES; i++) mk[i] = (uint8_t)(rand() % 4 ? (t & 1 ? 0xff : 0) : rand());
		n = packbits_enc(mk, MASK_BYTES, pb);
		ok = n <= MASK_BYTES + MASK_BYTES / 128 + 1 && !packbits_dec(pb, n, back, MASK_BYTES) &&
		     !memcmp(mk, back, MASK_BYTES);
	}
	check("PackBits 2000 random masks round trip, never longer than n + n/128 + 1", ok);
	for (int i = 0; i < MASK_BYTES; i++) mk[i] = i % 3 ? (uint8_t)(i / 3 * 2 + 1) : (uint8_t)(i * 7 + 200);
	n = packbits_enc(mk, MASK_BYTES, pb);                /* x yy z ww ...: pairs don't expand it */
	check("PackBits single/pair pattern stays within bounds", n <= MASK_BYTES + 1 &&
	      !packbits_dec(pb, n, back, MASK_BYTES) && !memcmp(mk, back, MASK_BYTES));
	static const struct { uint8_t b[8]; size_t n; } badpb[] = {
		{ { 0x05, 1, 2, 3 }, 4 },                 /* literal runs past the end */
		{ { 0x81 }, 1 },                          /* run without its byte */
		{ { 0xfe, 0xff }, 2 },                    /* 3 bytes, not 128 */
		{ { 0x81, 0xff, 0x81, 0xff }, 4 },        /* 256 bytes */
		{ { 0x81, 0xff, 0x00, 0x01 }, 4 },        /* 129 */
		{ { 0 }, 0 },
	};
	for (size_t k = 0; k < sizeof badpb / sizeof badpb[0]; k++)
		if (!packbits_dec(badpb[k].b, badpb[k].n, back, MASK_BYTES)) { fprintf(stderr, "FAIL packbits %zu\n", k); exit(1); }
	static const uint8_t noop[] = { 0x80, 0x81, 0xff, 0x80 };
	check("PackBits refuses overruns and wrong lengths; -128 is a no-op",
	      !packbits_dec(noop, sizeof noop, back, MASK_BYTES));
	check("ActiveCells base64: padding optional (the spec's example has too much)",
	      b64_dec_loose("gf8", raw, sizeof raw) == 2 && b64_dec_loose("gf8=", raw, sizeof raw) == 2 &&
	      b64_dec_loose("/v/+8A===", raw, sizeof raw) == 4 && raw[0] == 0xfe && raw[3] == 0xf0 &&
	      b64_dec_loose("g", raw, sizeof raw) < 0 && b64_dec_loose("g!8=", raw, sizeof raw) < 0 &&
	      b64_dec_loose("", raw, sizeof raw) < 0);

	/* the services */
	memset(fake_mask, 'f', 256);
	fake_msens = 50;
	camcfg_calls = 0;
	*camcfg_log = *set_log = 0;
	r = run(soap_req(DEV, NULL, "<tds:GetCapabilities><tds:Category>All</tds:Category></tds:GetCapabilities>", NULL));
	expect("GetCapabilities: Analytics", r, "<tt:Analytics><tt:XAddr>http://192.0.2.10/onvif/analytics_service"
	       "</tt:XAddr><tt:RuleSupport>true</tt:RuleSupport><tt:AnalyticsModuleSupport>true");
	r = run(soap_req(DEV, NULL, "<tds:GetServices><tds:IncludeCapability>true</tds:IncludeCapability></tds:GetServices>", NULL));
	expect("GetServices: Analytics ver20", r, "<tds:Namespace>http://www.onvif.org/ver20/analytics/wsdl</tds:Namespace>"
	       "<tds:XAddr>http://192.0.2.10/onvif/analytics_service</tds:XAddr><tds:Capabilities><tan:Capabilities "
	       "RuleSupport=\"true\" AnalyticsModuleSupport=\"true\"");
	expect("Analytics GetServiceCapabilities on /onvif/Analytics", run(soap_req("/onvif/Analytics", NULL,
	       "<tan:GetServiceCapabilities/>", NULL)), "<tan:GetServiceCapabilitiesResponse><tan:Capabilities");
	r = run(soap_req(MED, VIEW, "<trt:GetProfiles/>", NULL));
	check("both profiles carry the analytics configuration",
	      count(r, "<tt:VideoAnalyticsConfiguration token=\"VideoAnalyticsConfig_1\">") == 2);
	expect("... after the encoders (video, audio)", r, "</tt:AudioEncoderConfiguration><tt:VideoAnalyticsConfiguration");
	expect("... with the module", r, "<tt:AnalyticsEngineConfiguration><tt:AnalyticsModule Name=\"MyCellMotionModule\" "
	       "Type=\"tt:CellMotionEngine\"><tt:Parameters><tt:SimpleItem Name=\"Sensitivity\" Value=\"50\"/>");
	expect("... and the rule", r, "<tt:RuleEngineConfiguration><tt:Rule Name=\"MyMotionDetectorRule\" "
	       "Type=\"tt:CellMotionDetector\">");
	expect("... all cells active", r, "<tt:SimpleItem Name=\"ActiveCells\" Value=\"gf8=\"/>");
	expect("GetVideoAnalyticsConfigurations", run(soap_req(MED, VIEW, "<trt:GetVideoAnalyticsConfigurations/>", NULL)),
	       "<trt:Configurations token=\"VideoAnalyticsConfig_1\"><tt:Name>VideoAnalyticsConfig_1</tt:Name><tt:UseCount>2");
	expect("GetVideoAnalyticsConfiguration", run(soap_req(MED, VIEW, "<trt:GetVideoAnalyticsConfiguration>"
	       "<trt:ConfigurationToken>VideoAnalyticsConfig_1</trt:ConfigurationToken></trt:GetVideoAnalyticsConfiguration>",
	       NULL)), "<trt:Configuration token=\"VideoAnalyticsConfig_1\">");
	expect("GetCompatibleVideoAnalyticsConfigurations", run(soap_req(MED, VIEW, "<trt:GetCompatibleVideoAnalyticsConfigurations>"
	       "<trt:ProfileToken>Profile_1</trt:ProfileToken></trt:GetCompatibleVideoAnalyticsConfigurations>", NULL)),
	       "<trt:Configurations token=\"VideoAnalyticsConfig_1\">");
	expect("AddVideoAnalyticsConfiguration (already there)", run(soap_req(MED, OP, "<trt:AddVideoAnalyticsConfiguration>"
	       "<trt:ProfileToken>Profile_1</trt:ProfileToken><trt:ConfigurationToken>VideoAnalyticsConfig_1"
	       "</trt:ConfigurationToken></trt:AddVideoAnalyticsConfiguration>", NULL)),
	       "<trt:AddVideoAnalyticsConfigurationResponse/>");
	expect("... another token -> NoConfig", run(soap_req(MED, OP, "<trt:AddVideoAnalyticsConfiguration>"
	       "<trt:ProfileToken>Profile_1</trt:ProfileToken><trt:ConfigurationToken>X</trt:ConfigurationToken>"
	       "</trt:AddVideoAnalyticsConfiguration>", NULL)), "ter:NoConfig");

#define TOK "<tan:ConfigurationToken>VideoAnalyticsConfig_1</tan:ConfigurationToken>"
	r = run(soap_req(AN, VIEW, "<tan:GetSupportedAnalyticsModules>" TOK "</tan:GetSupportedAnalyticsModules>", NULL));
	expect("GetSupportedAnalyticsModules", r, "<tt:AnalyticsModuleDescription Name=\"tt:CellMotionEngine\"><tt:Parameters>"
	       "<tt:SimpleItemDescription Name=\"Sensitivity\" Type=\"xs:integer\"/><tt:ElementItemDescription "
	       "Name=\"Layout\" Type=\"tt:CellLayout\"/>");
	r = run(soap_req(AN, VIEW, "<tan:GetAnalyticsModules>" TOK "</tan:GetAnalyticsModules>", NULL));
	expect("GetAnalyticsModules: the 32x32 layout", r, "<tt:CellLayout Columns=\"32\" Rows=\"32\"><tt:Transformation>"
	       "<tt:Translate x=\"-1.000000\" y=\"-1.000000\"/><tt:Scale x=\"0.062500\" y=\"0.062500\"/>");
	r = run(soap_req(AN, VIEW, "<tan:GetSupportedRules>" TOK "</tan:GetSupportedRules>", NULL));
	expect("GetSupportedRules", r, "<tt:RuleDescription Name=\"tt:CellMotionDetector\">");
	expect("... ActiveCells", r, "<tt:SimpleItemDescription Name=\"ActiveCells\" Type=\"xs:base64Binary\"/>");
	expect("... its event", r, "<tt:ParentTopic>tns1:RuleEngine/CellMotionDetector/Motion</tt:ParentTopic>");
	r = run(soap_req(AN, VIEW, "<tan:GetRules>" TOK "</tan:GetRules>", NULL));
	expect("GetRules", r, "<tan:Rule Name=\"MyMotionDetectorRule\" Type=\"tt:CellMotionDetector\"><tt:Parameters>"
	       "<tt:SimpleItem Name=\"MinCount\" Value=\"1\"/>");
	expect("... ActiveCells", r, "<tt:SimpleItem Name=\"ActiveCells\" Value=\"gf8=\"/>");
	expect("GetRules: another configuration -> NoConfig", run(soap_req(AN, VIEW, "<tan:GetRules><tan:ConfigurationToken>"
	       "X</tan:ConfigurationToken></tan:GetRules>", NULL)), "ter:NoConfig");

	/* ModifyRules: the area SSS draws (here the left half and the bottom row) */
	memset(mk, 0, sizeof mk);
	for (int row = 0; row < GRID; row++)
		for (int col = 0; col < GRID; col++)
			if (col < GRID / 2 || row == GRID - 1) mk[(row * GRID + col) / 8] |= (uint8_t)(0x80 >> (col % 8));
	snprintf(want, sizeof want, "%s", cells_of(mk));
	hex(mk, MASK_BYTES, hexs);
	r = run(soap_req(AN, VIEW, rules_body("ModifyRules", RULE_NAME, "tt:CellMotionDetector", want, "5"), NULL));
	expect("ModifyRules needs operator", r, "ter:NotAuthorized");
	r = run(soap_req(AN, OP, rules_body("ModifyRules", RULE_NAME, "tt:CellMotionDetector", want, "5"), NULL));
	expect("ModifyRules", r, "<tan:ModifyRulesResponse/>");
	char logwant[600];
	snprintf(logwant, sizeof logwant, "motion.mask=%s;", hexs);
	check("... saves motion.mask with camcfg", !strcmp(camcfg_log, logwant));
	snprintf(logwant, sizeof logwant, "set motion.mask %s;", hexs);
	check("... and applies it live", !strcmp(set_log, logwant) && !strcmp(fake_mask, hexs));
	r = run(soap_req(AN, VIEW, "<tan:GetRules>" TOK "</tan:GetRules>", NULL));
	snprintf(logwant, sizeof logwant, "Name=\"ActiveCells\" Value=\"%s\"", want);
	expect("GetRules reads the new cells back", r, logwant);
	int calls = camcfg_calls;
	*set_log = 0;
	r = run(soap_req(AN, OP, rules_body("ModifyRules", RULE_NAME, "tt:CellMotionDetector", want, "1"), NULL));
	expect("the same cells again", r, "<tan:ModifyRulesResponse/>");
	check("... save and apply nothing", camcfg_calls == calls && !*set_log);
	static const char *const badcells[] = {
		"BQECAw==",                               /* PackBits literal past the end */
		"gQ==",                                   /* run without its byte */
		"/v8=",                                   /* 3 bytes */
		"gf+B/w==",                               /* 256 bytes */
		"!!!!",                                   /* not base64 */
		"g",                                      /* not base64 either */
	};
	for (size_t k = 0; k < sizeof badcells / sizeof badcells[0]; k++)
		expect("bad ActiveCells -> InvalidRule", run(soap_req(AN, OP, rules_body("ModifyRules", RULE_NAME,
		       "tt:CellMotionDetector", badcells[k], "1"), NULL)), "ter:InvalidRule");
	static char longcells[1200];
	memset(longcells, 'A', 1100);
	longcells[1100] = 0;
	expect("overlong ActiveCells -> InvalidRule", run(soap_req(AN, OP, rules_body("ModifyRules", RULE_NAME,
	       "tt:CellMotionDetector", longcells, "1"), NULL)), "ter:InvalidRule");
	expect("MinCount not a number -> InvalidRule", run(soap_req(AN, OP, rules_body("ModifyRules", RULE_NAME,
	       "tt:CellMotionDetector", want, "lots"), NULL)), "ter:InvalidRule");
	expect("another rule type -> InvalidRule", run(soap_req(AN, OP, rules_body("ModifyRules", RULE_NAME,
	       "tt:LineDetector", want, "1"), NULL)), "ter:InvalidRule");
	expect("another rule name -> RuleNotExistent", run(soap_req(AN, OP, rules_body("ModifyRules", "Other",
	       "tt:CellMotionDetector", want, "1"), NULL)), "ter:RuleNotExistent");
	check("... nothing saved or applied", camcfg_calls == calls && !*set_log);
	memset(mk, 0xff, sizeof mk);
	r = run(soap_req(AN, OP, rules_body("CreateRules", RULE_NAME, "tt:CellMotionDetector", cells_of(mk), "1"), NULL));
	expect("CreateRules for our rule modifies it", r, "<tan:CreateRulesResponse/>");
	check("... all cells again", camcfg_calls == calls + 1 && !strncmp(fake_mask, "ffff", 4));
	r = run(soap_req(AN, OP, rules_body("CreateRules", "Another", "tt:CellMotionDetector", "gf8=", "1"), NULL));
	expect("CreateRules for another -> TooManyRules", r, "ter:TooManyRules");
	expect("DeleteRules -> ActionNotSupported", run(soap_req(AN, OP, "<tan:DeleteRules>" TOK "<tan:RuleName>"
	       "MyMotionDetectorRule</tan:RuleName></tan:DeleteRules>", NULL)), "ter:ActionNotSupported");

	/* ModifyAnalyticsModules: Sensitivity */
	*camcfg_log = *set_log = 0;
	r = run(soap_req(AN, OP, modules_body(MODULE_NAME, "70", 32, 32), NULL));
	expect("ModifyAnalyticsModules", r, "<tan:ModifyAnalyticsModulesResponse/>");
	check("... motion.sensitivity saved and applied", !strcmp(camcfg_log, "motion.sensitivity=70;") &&
	      !strcmp(set_log, "set motion.sensitivity 70;") && fake_msens == 70);
	expect("... read back", run(soap_req(AN, VIEW, "<tan:GetAnalyticsModules>" TOK "</tan:GetAnalyticsModules>", NULL)),
	       "<tt:SimpleItem Name=\"Sensitivity\" Value=\"70\"/>");
	calls = camcfg_calls;
	expect("another layout -> InvalidModule", run(soap_req(AN, OP, modules_body(MODULE_NAME, "60", 22, 18), NULL)),
	       "ter:InvalidModule");
	expect("Sensitivity 150 -> InvalidModule", run(soap_req(AN, OP, modules_body(MODULE_NAME, "150", 32, 32), NULL)),
	       "ter:InvalidModule");
	expect("another module -> ModuleNotExistent", run(soap_req(AN, OP, modules_body("Other", "60", 32, 32), NULL)),
	       "ter:ModuleNotExistent");
	expect("ModifyAnalyticsModules needs operator", run(soap_req(AN, VIEW, modules_body(MODULE_NAME, "60", 32, 32),
	       NULL)), "ter:NotAuthorized");
	check("... nothing saved", camcfg_calls == calls);

	/* Media's SetVideoAnalyticsConfiguration: both at once */
	char body[4096];
	memset(mk, 0, sizeof mk);
	mk[0] = 0x80;                                      /* only the top-left cell */
	*camcfg_log = 0;
	snprintf(body, sizeof body, "<trt:SetVideoAnalyticsConfiguration><trt:Configuration token=\"VideoAnalyticsConfig_1\">"
		 "<tt:Name>VideoAnalyticsConfig_1</tt:Name><tt:UseCount>2</tt:UseCount><tt:AnalyticsEngineConfiguration>"
		 "<tt:AnalyticsModule Name=\"MyCellMotionModule\" Type=\"tt:CellMotionEngine\"><tt:Parameters>"
		 "<tt:SimpleItem Name=\"Sensitivity\" Value=\"40\"/></tt:Parameters></tt:AnalyticsModule>"
		 "</tt:AnalyticsEngineConfiguration><tt:RuleEngineConfiguration><tt:Rule Name=\"MyMotionDetectorRule\" "
		 "Type=\"tt:CellMotionDetector\"><tt:Parameters><tt:SimpleItem Name=\"ActiveCells\" Value=\"%s\"/>"
		 "</tt:Parameters></tt:Rule></tt:RuleEngineConfiguration></trt:Configuration><trt:ForcePersistence>true"
		 "</trt:ForcePersistence></trt:SetVideoAnalyticsConfiguration>", cells_of(mk));
	r = run(soap_req(MED, OP, body, NULL));
	expect("SetVideoAnalyticsConfiguration", r, "<trt:SetVideoAnalyticsConfigurationResponse/>");
	check("... sensitivity and cells saved", !strncmp(camcfg_log, "motion.sensitivity=40;motion.mask=8000", 38) &&
	      !strncmp(fake_mask, "8000", 4));
	fake_down = 1;
	char conf[400] = "motion.sensitivity=33\nmotion.mask=";
	for (int i = 0; i < MASK_BYTES; i++) strcat(conf, i % 2 ? "ff" : "00");
	strcat(conf, "\nstream.sub.enabled=1\n");
	write_file(conf_path, conf);
	struct mset ms;
	check("rtspd not answering: cam.conf's motion settings (a 268-character line)", !motion_settings(&ms) &&
	      ms.sens == 33 && ms.mask[0] == 0 && ms.mask[1] == 0xff && ms.mask[127] == 0xff);
	fake_down = 0;
	sbn = 0;
	sbover = 0;
	notification(0, 1, "Changed", 0);
	sb[sbn] = 0;
	check("Events name the same analytics configuration and rule", strstr(sb, "Value=\"" VA_TOKEN "\"") &&
	      strstr(sb, "Name=\"Rule\" Value=\"" RULE_NAME "\""));
	memset(fake_mask, 'f', 256);
	fake_msens = 50;
	write_file(conf_path, "image.brightness=55\nstream.main.kbps=6000\nstream.main.profile=main\n"
		   "stream.main.fps=99\nstream.sub.enabled=1\n");
#undef TOK
#undef VIEW
#undef OP
}

static const char *setaec_body(const char *tok, const char *enc, const char *bitrate, const char *rate)
{
	static char b[2048];
	snprintf(b, sizeof b, "<trt:SetAudioEncoderConfiguration><trt:Configuration token=\"%s\"><tt:Name>%s"
		 "</tt:Name><tt:UseCount>2</tt:UseCount><tt:Encoding>%s</tt:Encoding><tt:Bitrate>%s</tt:Bitrate>"
		 "<tt:SampleRate>%s</tt:SampleRate><tt:Multicast><tt:Address><tt:Type>IPv4</tt:Type><tt:IPv4Address>"
		 "0.0.0.0</tt:IPv4Address></tt:Address><tt:Port>0</tt:Port><tt:TTL>1</tt:TTL><tt:AutoStart>false"
		 "</tt:AutoStart></tt:Multicast><tt:SessionTimeout>PT60S</tt:SessionTimeout></trt:Configuration>"
		 "<trt:ForcePersistence>true</trt:ForcePersistence></trt:SetAudioEncoderConfiguration>",
		 tok, tok, enc, bitrate, rate);
	return b;
}

/* Audio (#110): the microphone in both profiles unless audio.enabled=0; G.711 only, read-only. */
static void test_audio(void)
{
	long long now = time(NULL);
	const char *r;
#define VIEW wsse("view", "V1ew:Pass&", now, 0, 0)
#define OP wsse("op", "0perPass", now, 0, 0)
#define PROF(op, extra) "<trt:" op "><trt:ProfileToken>Profile_2</trt:ProfileToken>" extra "</trt:" op ">"
	write_file(conf_path, "stream.sub.enabled=1\n");
	camcfg_calls = 0;
	r = run(soap_req(MED, VIEW, "<trt:GetProfiles/>", NULL));
	check("both profiles carry the audio configurations", count(r, "<tt:AudioSourceConfiguration token="
	      "\"AudioSourceConfig_1\">") == 2 && count(r, "<tt:AudioEncoderConfiguration token=\"AudioEncoderConfig_1\">") == 2);
	expect("... in tt:Profile's order: video source, audio source", r, "</tt:VideoSourceConfiguration>"
	       "<tt:AudioSourceConfiguration token=\"AudioSourceConfig_1\"><tt:Name>AudioSourceConfig_1</tt:Name>"
	       "<tt:UseCount>2</tt:UseCount><tt:SourceToken>AudioSource_1</tt:SourceToken></tt:AudioSourceConfiguration>"
	       "<tt:VideoEncoderConfiguration");
	expect("... video encoder, audio encoder, analytics", r, "</tt:VideoEncoderConfiguration><tt:AudioEncoderConfiguration "
	       "token=\"AudioEncoderConfig_1\"><tt:Name>AudioEncoderConfig_1</tt:Name><tt:UseCount>2</tt:UseCount>"
	       "<tt:Encoding>G711</tt:Encoding><tt:Bitrate>64</tt:Bitrate><tt:SampleRate>8</tt:SampleRate><tt:Multicast>");
	expect("... then analytics", r, "</tt:AudioEncoderConfiguration><tt:VideoAnalyticsConfiguration");
	expect("GetProfile too", run(soap_req(MED, VIEW, PROF("GetProfile", ""), NULL)), "<tt:AudioEncoderConfiguration ");
	expect("GetAudioSources", run(soap_req(MED, VIEW, "<trt:GetAudioSources/>", NULL)),
	       "<trt:AudioSources token=\"AudioSource_1\"><tt:Channels>1</tt:Channels></trt:AudioSources>");
	expect("GetAudioSourceConfigurations", run(soap_req(MED, VIEW, "<trt:GetAudioSourceConfigurations/>", NULL)),
	       "<trt:Configurations token=\"AudioSourceConfig_1\">");
	expect("GetCompatibleAudioSourceConfigurations", run(soap_req(MED, VIEW,
	       PROF("GetCompatibleAudioSourceConfigurations", ""), NULL)), "<tt:SourceToken>AudioSource_1</tt:SourceToken>");
	expect("GetAudioSourceConfiguration", run(soap_req(MED, VIEW, "<trt:GetAudioSourceConfiguration>"
	       "<trt:ConfigurationToken>AudioSourceConfig_1</trt:ConfigurationToken></trt:GetAudioSourceConfiguration>",
	       NULL)), "<trt:Configuration token=\"AudioSourceConfig_1\">");
	expect("... another token -> NoConfig", run(soap_req(MED, VIEW, "<trt:GetAudioSourceConfiguration>"
	       "<trt:ConfigurationToken>X</trt:ConfigurationToken></trt:GetAudioSourceConfiguration>", NULL)), "ter:NoConfig");
	expect("GetAudioSourceConfigurationOptions", run(soap_req(MED, VIEW, PROF("GetAudioSourceConfigurationOptions",
	       "<trt:ConfigurationToken>AudioSourceConfig_1</trt:ConfigurationToken>"), NULL)),
	       "<trt:Options><tt:InputTokensAvailable>AudioSource_1</tt:InputTokensAvailable></trt:Options>");
	expect("GetAudioEncoderConfigurations", run(soap_req(MED, VIEW, "<trt:GetAudioEncoderConfigurations/>", NULL)),
	       "<trt:Configurations token=\"AudioEncoderConfig_1\">");
	expect("GetCompatibleAudioEncoderConfigurations", run(soap_req(MED, VIEW,
	       PROF("GetCompatibleAudioEncoderConfigurations", ""), NULL)), "<tt:Encoding>G711</tt:Encoding>");
	expect("GetAudioEncoderConfiguration", run(soap_req(MED, VIEW, "<trt:GetAudioEncoderConfiguration>"
	       "<trt:ConfigurationToken>AudioEncoderConfig_1</trt:ConfigurationToken></trt:GetAudioEncoderConfiguration>",
	       NULL)), "<trt:Configuration token=\"AudioEncoderConfig_1\">");
	r = run(soap_req(MED, VIEW, PROF("GetAudioEncoderConfigurationOptions", ""), NULL));
	expect("GetAudioEncoderConfigurationOptions: G.711 64 kbit/s 8 kHz", r, "<trt:Options><tt:Options><tt:Encoding>G711"
	       "</tt:Encoding><tt:BitrateList><tt:Items>64</tt:Items></tt:BitrateList><tt:SampleRateList><tt:Items>8"
	       "</tt:Items></tt:SampleRateList></tt:Options></trt:Options>");
	expect("... another configuration -> NoConfig", run(soap_req(MED, VIEW, "<trt:GetAudioEncoderConfigurationOptions>"
	       "<trt:ConfigurationToken>X</trt:ConfigurationToken></trt:GetAudioEncoderConfigurationOptions>", NULL)),
	       "ter:NoConfig");
	expect("... a bad profile -> NoProfile", run(soap_req(MED, VIEW, "<trt:GetAudioEncoderConfigurationOptions>"
	       "<trt:ProfileToken>Profile_7</trt:ProfileToken></trt:GetAudioEncoderConfigurationOptions>", NULL)),
	       "ter:NoProfile");
	expect("GetStreamUri unchanged (the same RTSP URL carries the audio)", run(soap_req(MED, VIEW,
	       PROF("GetStreamUri", ""), NULL)), "<tt:Uri>rtsp://192.0.2.10:554/sub</tt:Uri>");

	/* Add, Remove, Set */
	expect("AddAudioSourceConfiguration needs operator", run(soap_req(MED, VIEW, PROF("AddAudioSourceConfiguration",
	       "<trt:ConfigurationToken>AudioSourceConfig_1</trt:ConfigurationToken>"), NULL)), "ter:NotAuthorized");
	expect("AddAudioSourceConfiguration (already there)", run(soap_req(MED, OP, PROF("AddAudioSourceConfiguration",
	       "<trt:ConfigurationToken>AudioSourceConfig_1</trt:ConfigurationToken>"), NULL)),
	       "<trt:AddAudioSourceConfigurationResponse/>");
	expect("AddAudioEncoderConfiguration (already there)", run(soap_req(MED, OP, PROF("AddAudioEncoderConfiguration",
	       "<trt:ConfigurationToken>AudioEncoderConfig_1</trt:ConfigurationToken>"), NULL)),
	       "<trt:AddAudioEncoderConfigurationResponse/>");
	expect("... the source token for the encoder -> NoConfig", run(soap_req(MED, OP, PROF("AddAudioEncoderConfiguration",
	       "<trt:ConfigurationToken>AudioSourceConfig_1</trt:ConfigurationToken>"), NULL)), "ter:NoConfig");
	expect("... a bad profile -> NoProfile", run(soap_req(MED, OP, "<trt:AddAudioEncoderConfiguration><trt:ProfileToken>"
	       "Profile_3</trt:ProfileToken><trt:ConfigurationToken>AudioEncoderConfig_1</trt:ConfigurationToken>"
	       "</trt:AddAudioEncoderConfiguration>", NULL)), "ter:NoProfile");
	expect("RemoveAudioEncoderConfiguration: acknowledged", run(soap_req(MED, OP,
	       PROF("RemoveAudioEncoderConfiguration", ""), NULL)), "<trt:RemoveAudioEncoderConfigurationResponse/>");
	expect("RemoveAudioSourceConfiguration: acknowledged", run(soap_req(MED, OP,
	       PROF("RemoveAudioSourceConfiguration", ""), NULL)), "<trt:RemoveAudioSourceConfigurationResponse/>");
	expect("... and ignored: the microphone stays", run(soap_req(MED, VIEW, PROF("GetProfile", ""), NULL)),
	       "<tt:AudioSourceConfiguration token=");
	expect("SetAudioEncoderConfiguration needs operator", run(soap_req(MED, VIEW,
	       setaec_body(AEC_TOKEN, "G711", "64", "8"), NULL)), "ter:NotAuthorized");
	expect("SetAudioEncoderConfiguration with what we have", run(soap_req(MED, OP,
	       setaec_body(AEC_TOKEN, "G711", "64", "8"), NULL)), "<trt:SetAudioEncoderConfigurationResponse/>");
	static const char *const bad[][3] = { { "AAC", "64", "8" }, { "G726", "64", "8" }, { "G711", "32", "8" },
					      { "G711", "64", "16" }, { "G711", "", "8" } };
	for (size_t k = 0; k < sizeof bad / sizeof bad[0]; k++)
		expect("anything else -> ConfigModify", run(soap_req(MED, OP, setaec_body(AEC_TOKEN, bad[k][0], bad[k][1],
		       bad[k][2]), NULL)), "ter:ConfigModify");
	expect("... another token -> NoConfig", run(soap_req(MED, OP, setaec_body("X", "G711", "64", "8"), NULL)),
	       "ter:NoConfig");
	expect("SetAudioSourceConfiguration", run(soap_req(MED, OP, "<trt:SetAudioSourceConfiguration><trt:Configuration "
	       "token=\"AudioSourceConfig_1\"><tt:Name>AudioSourceConfig_1</tt:Name><tt:UseCount>2</tt:UseCount>"
	       "<tt:SourceToken>AudioSource_1</tt:SourceToken></trt:Configuration><trt:ForcePersistence>true"
	       "</trt:ForcePersistence></trt:SetAudioSourceConfiguration>", NULL)), "<trt:SetAudioSourceConfigurationResponse/>");
	expect("... another source -> ConfigModify", run(soap_req(MED, OP, "<trt:SetAudioSourceConfiguration>"
	       "<trt:Configuration token=\"AudioSourceConfig_1\"><tt:SourceToken>AudioSource_2</tt:SourceToken>"
	       "</trt:Configuration></trt:SetAudioSourceConfiguration>", NULL)), "ter:ConfigModify");
	check("... none of it saved anything", camcfg_calls == 0);
	expect("another audio operation -> ActionNotSupported", run(soap_req(MED, VIEW,
	       "<trt:GetAudioSourceConfigurationOptionsX/>", NULL)), "<env:Value>ter:ActionNotSupported</env:Value></env:Subcode>");

	/* audio.enabled=0: no audio anywhere */
	write_file(conf_path, "stream.sub.enabled=1\naudio.enabled=0\n");
	r = run(soap_req(MED, VIEW, "<trt:GetProfiles/>", NULL));
	check("audio.enabled=0: the profiles have no audio", strstr(r, "Profile_2") && !strstr(r, "Audio"));
	expect("... GetAudioSources -> AudioNotSupported", run(soap_req(MED, VIEW, "<trt:GetAudioSources/>", NULL)),
	       "ter:AudioNotSupported");
	expect("... empty encoder options (as before audio)", run(soap_req(MED, VIEW,
	       PROF("GetAudioEncoderConfigurationOptions", ""), NULL)), "<trt:Options/>");
	expect("... Add -> AudioNotSupported", run(soap_req(MED, OP, PROF("AddAudioSourceConfiguration",
	       "<trt:ConfigurationToken>AudioSourceConfig_1</trt:ConfigurationToken>"), NULL)), "ter:AudioNotSupported");
	expect("... an unknown audio operation -> AudioNotSupported", run(soap_req(MED, VIEW,
	       "<trt:GetAudioSourceConfigurationOptionsX/>", NULL)), "ter:AudioNotSupported");
	write_file(conf_path, "stream.sub.enabled=1\naudio.enabled=maybe\n");
	expect("a bad audio.enabled counts as on (as rtspd ignores it)", run(soap_req(MED, VIEW,
	       "<trt:GetAudioSources/>", NULL)), "<trt:AudioSources token=");
	write_file(conf_path, "image.brightness=55\nstream.main.kbps=6000\nstream.main.profile=main\n"
		   "stream.main.fps=99\nstream.sub.enabled=1\n");
#undef PROF
#undef VIEW
#undef OP
}

#define DIO "/onvif/deviceio_service"

static const char *setaoc_body(const char *tok, const char *out, const char *primacy, const char *level)
{
	static char b[2048];
	snprintf(b, sizeof b, "<trt:SetAudioOutputConfiguration><trt:Configuration token=\"%s\"><tt:Name>%s</tt:Name>"
		 "<tt:UseCount>2</tt:UseCount><tt:OutputToken>%s</tt:OutputToken><tt:SendPrimacy>%s</tt:SendPrimacy>"
		 "<tt:OutputLevel>%s</tt:OutputLevel></trt:Configuration><trt:ForcePersistence>true"
		 "</trt:ForcePersistence></trt:SetAudioOutputConfiguration>", tok, tok, out, primacy, level);
	return b;
}

/* Two-way audio (#117): the speaker as AudioOutput + output/decoder configurations in the
 * profiles' Extension, and DeviceIO's counts; hidden with audio.enabled=0. */
static void test_talk(void)
{
	long long now = time(NULL);
	const char *r;
#define VIEW wsse("view", "V1ew:Pass&", now, 0, 0)
#define OP wsse("op", "0perPass", now, 0, 0)
#define PROF(op, extra) "<trt:" op "><trt:ProfileToken>Profile_2</trt:ProfileToken>" extra "</trt:" op ">"
#define AUTO "www.onvif.org/ver20/HalfDuplex/Auto"
	write_file(conf_path, "stream.sub.enabled=1\n");
	camcfg_calls = 0;
	r = run(soap_req(MED, VIEW, "<trt:GetProfiles/>", NULL));
	check("both profiles carry the speaker in their Extension", count(r, "<tt:Extension><tt:AudioOutputConfiguration") == 2);
	expect("... after the analytics configuration, output then decoder, then the profile ends", r,
	       "</tt:VideoAnalyticsConfiguration><tt:Extension><tt:AudioOutputConfiguration token=\"AudioOutputConfig_1\">"
	       "<tt:Name>AudioOutputConfig_1</tt:Name><tt:UseCount>2</tt:UseCount><tt:OutputToken>AudioOutput_1"
	       "</tt:OutputToken><tt:SendPrimacy>" AUTO "</tt:SendPrimacy><tt:OutputLevel>100</tt:OutputLevel>"
	       "</tt:AudioOutputConfiguration><tt:AudioDecoderConfiguration token=\"AudioDecoderConfig_1\"><tt:Name>"
	       "AudioDecoderConfig_1</tt:Name><tt:UseCount>2</tt:UseCount></tt:AudioDecoderConfiguration></tt:Extension>"
	       "</trt:Profiles>");
	expect("GetAudioOutputs", run(soap_req(MED, VIEW, "<trt:GetAudioOutputs/>", NULL)),
	       "<trt:GetAudioOutputsResponse><trt:AudioOutputs token=\"AudioOutput_1\"/></trt:GetAudioOutputsResponse>");
	expect("GetAudioOutputConfigurations", run(soap_req(MED, VIEW, "<trt:GetAudioOutputConfigurations/>", NULL)),
	       "<trt:GetAudioOutputConfigurationsResponse><trt:Configurations token=\"AudioOutputConfig_1\">");
	expect("GetCompatibleAudioOutputConfigurations", run(soap_req(MED, VIEW,
	       PROF("GetCompatibleAudioOutputConfigurations", ""), NULL)), "<tt:OutputToken>AudioOutput_1</tt:OutputToken>");
	expect("GetAudioOutputConfiguration", run(soap_req(MED, VIEW, "<trt:GetAudioOutputConfiguration>"
	       "<trt:ConfigurationToken>AudioOutputConfig_1</trt:ConfigurationToken></trt:GetAudioOutputConfiguration>",
	       NULL)), "<trt:GetAudioOutputConfigurationResponse><trt:Configuration token=\"AudioOutputConfig_1\">");
	expect("... the decoder's token -> NoConfig", run(soap_req(MED, VIEW, "<trt:GetAudioOutputConfiguration>"
	       "<trt:ConfigurationToken>AudioDecoderConfig_1</trt:ConfigurationToken></trt:GetAudioOutputConfiguration>",
	       NULL)), "ter:NoConfig");
	expect("GetAudioDecoderConfigurations", run(soap_req(MED, VIEW, "<trt:GetAudioDecoderConfigurations/>", NULL)),
	       "<trt:GetAudioDecoderConfigurationsResponse><trt:Configurations token=\"AudioDecoderConfig_1\">");
	expect("GetCompatibleAudioDecoderConfigurations", run(soap_req(MED, VIEW,
	       PROF("GetCompatibleAudioDecoderConfigurations", ""), NULL)), "<trt:Configurations token=\"AudioDecoderConfig_1\">");
	expect("GetAudioDecoderConfiguration", run(soap_req(MED, VIEW, "<trt:GetAudioDecoderConfiguration>"
	       "<trt:ConfigurationToken>AudioDecoderConfig_1</trt:ConfigurationToken></trt:GetAudioDecoderConfiguration>",
	       NULL)), "<trt:Configuration token=\"AudioDecoderConfig_1\">");
	expect("... a bad profile -> NoProfile", run(soap_req(MED, VIEW, "<trt:GetCompatibleAudioDecoderConfigurations>"
	       "<trt:ProfileToken>P</trt:ProfileToken></trt:GetCompatibleAudioDecoderConfigurations>", NULL)), "ter:NoProfile");
	r = run(soap_req(MED, VIEW, PROF("GetAudioOutputConfigurationOptions",
		"<trt:ConfigurationToken>AudioOutputConfig_1</trt:ConfigurationToken>"), NULL));
	expect("GetAudioOutputConfigurationOptions", r, "<trt:Options><tt:OutputTokensAvailable>AudioOutput_1"
	       "</tt:OutputTokensAvailable><tt:SendPrimacyOptions>www.onvif.org/ver20/HalfDuplex/Server</tt:SendPrimacyOptions>");
	expect("... Auto, and the level range", r, "<tt:SendPrimacyOptions>" AUTO "</tt:SendPrimacyOptions>"
	       "<tt:OutputLevelRange><tt:Min>0</tt:Min><tt:Max>100</tt:Max></tt:OutputLevelRange>");
	expect("GetAudioDecoderConfigurationOptions: G.711", run(soap_req(MED, VIEW,
	       PROF("GetAudioDecoderConfigurationOptions", ""), NULL)), "<trt:Options><tt:G711DecOptions><tt:Bitrate>"
	       "<tt:Items>64</tt:Items></tt:Bitrate><tt:SampleRateRange><tt:Items>8</tt:Items></tt:SampleRateRange>");
	expect("... another configuration -> NoConfig", run(soap_req(MED, VIEW, "<trt:GetAudioDecoderConfigurationOptions>"
	       "<trt:ConfigurationToken>AudioOutputConfig_1</trt:ConfigurationToken></trt:GetAudioDecoderConfigurationOptions>",
	       NULL)), "ter:NoConfig");

	/* DeviceIO and the capabilities */
	r = run(soap_req(DEV, NULL, "<tds:GetCapabilities><tds:Category>All</tds:Category></tds:GetCapabilities>", NULL));
	expect("GetCapabilities: DeviceIO in the Extension", r, "</tt:Media><tt:Extension><tt:DeviceIO><tt:XAddr>"
	       "http://192.0.2.10/onvif/deviceio_service</tt:XAddr><tt:VideoSources>1</tt:VideoSources><tt:VideoOutputs>0"
	       "</tt:VideoOutputs><tt:AudioSources>1</tt:AudioSources><tt:AudioOutputs>1</tt:AudioOutputs>");
	absent("... not for one category", run(soap_req(DEV, NULL, "<tds:GetCapabilities><tds:Category>Media"
	       "</tds:Category></tds:GetCapabilities>", NULL)), "DeviceIO");
	expect("GetServices: DeviceIO", run(soap_req(DEV, NULL, "<tds:GetServices><tds:IncludeCapability>true"
	       "</tds:IncludeCapability></tds:GetServices>", NULL)), "<tds:Namespace>http://www.onvif.org/ver10/deviceIO/wsdl"
	       "</tds:Namespace><tds:XAddr>http://192.0.2.10/onvif/deviceio_service</tds:XAddr><tds:Capabilities>"
	       "<tmd:Capabilities VideoSources=\"1\" VideoOutputs=\"0\" AudioSources=\"1\" AudioOutputs=\"1\"");
	expect("DeviceIO GetServiceCapabilities", run(soap_req(DIO, NULL, "<tmd:GetServiceCapabilities/>", NULL)),
	       "<tmd:GetServiceCapabilitiesResponse><tmd:Capabilities");
	expect("DeviceIO GetAudioOutputs: tokens", run(soap_req(DIO, VIEW, "<tmd:GetAudioOutputs/>", NULL)),
	       "<tmd:GetAudioOutputsResponse><tmd:Token>AudioOutput_1</tmd:Token></tmd:GetAudioOutputsResponse>");
	expect("DeviceIO GetAudioSources: tokens", run(soap_req(DIO, VIEW, "<tmd:GetAudioSources/>", NULL)),
	       "<tmd:Token>AudioSource_1</tmd:Token>");
	expect("DeviceIO GetVideoSources: tokens", run(soap_req(DIO, VIEW, "<tmd:GetVideoSources/>", NULL)),
	       "<tmd:Token>VideoSource_1</tmd:Token>");
	expect("DeviceIO GetRelayOutputs: none", run(soap_req(DIO, VIEW, "<tmd:GetRelayOutputs/>", NULL)),
	       "<tmd:GetRelayOutputsResponse/>");

	/* Add, Remove, Set */
	expect("AddAudioOutputConfiguration needs operator", run(soap_req(MED, VIEW, PROF("AddAudioOutputConfiguration",
	       "<trt:ConfigurationToken>AudioOutputConfig_1</trt:ConfigurationToken>"), NULL)), "ter:NotAuthorized");
	expect("AddAudioOutputConfiguration (already there)", run(soap_req(MED, OP, PROF("AddAudioOutputConfiguration",
	       "<trt:ConfigurationToken>AudioOutputConfig_1</trt:ConfigurationToken>"), NULL)),
	       "<trt:AddAudioOutputConfigurationResponse/>");
	expect("AddAudioDecoderConfiguration (already there)", run(soap_req(MED, OP, PROF("AddAudioDecoderConfiguration",
	       "<trt:ConfigurationToken>AudioDecoderConfig_1</trt:ConfigurationToken>"), NULL)),
	       "<trt:AddAudioDecoderConfigurationResponse/>");
	expect("... the output's token for the decoder -> NoConfig", run(soap_req(MED, OP,
	       PROF("AddAudioDecoderConfiguration", "<trt:ConfigurationToken>AudioOutputConfig_1</trt:ConfigurationToken>"),
	       NULL)), "ter:NoConfig");
	expect("RemoveAudioOutputConfiguration: acknowledged", run(soap_req(MED, OP,
	       PROF("RemoveAudioOutputConfiguration", ""), NULL)), "<trt:RemoveAudioOutputConfigurationResponse/>");
	expect("RemoveAudioDecoderConfiguration: acknowledged", run(soap_req(MED, OP,
	       PROF("RemoveAudioDecoderConfiguration", ""), NULL)), "<trt:RemoveAudioDecoderConfigurationResponse/>");
	expect("... and ignored: the speaker stays", run(soap_req(MED, VIEW, PROF("GetProfile", ""), NULL)),
	       "<tt:Extension><tt:AudioOutputConfiguration");
	expect("SetAudioOutputConfiguration needs operator", run(soap_req(MED, VIEW,
	       setaoc_body(AOC_TOKEN, AO_TOKEN, AUTO, "100"), NULL)), "ter:NotAuthorized");
	expect("SetAudioOutputConfiguration as read", run(soap_req(MED, OP, setaoc_body(AOC_TOKEN, AO_TOKEN, AUTO, "100"),
	       NULL)), "<trt:SetAudioOutputConfigurationResponse/>");
	expect("... Client primacy, level 50", run(soap_req(MED, OP, setaoc_body(AOC_TOKEN, AO_TOKEN,
	       "www.onvif.org/ver20/HalfDuplex/Client", "50"), NULL)), "<trt:SetAudioOutputConfigurationResponse/>");
	static const char *const bad[][3] = { { AO_TOKEN, AUTO, "101" }, { AO_TOKEN, AUTO, "-1" }, { AO_TOKEN, AUTO, "loud" },
					      { AO_TOKEN, "www.onvif.org/ver20/FullDuplex", "100" }, { "AudioOutput_2", AUTO, "100" } };
	for (size_t k = 0; k < sizeof bad / sizeof bad[0]; k++)
		expect("bad output configuration -> ConfigModify", run(soap_req(MED, OP, setaoc_body(AOC_TOKEN, bad[k][0],
		       bad[k][1], bad[k][2]), NULL)), "ter:ConfigModify");
	expect("... another token -> NoConfig", run(soap_req(MED, OP, setaoc_body("X", AO_TOKEN, AUTO, "100"), NULL)),
	       "ter:NoConfig");
	expect("SetAudioDecoderConfiguration", run(soap_req(MED, OP, "<trt:SetAudioDecoderConfiguration><trt:Configuration "
	       "token=\"AudioDecoderConfig_1\"><tt:Name>AudioDecoderConfig_1</tt:Name><tt:UseCount>2</tt:UseCount>"
	       "</trt:Configuration><trt:ForcePersistence>true</trt:ForcePersistence></trt:SetAudioDecoderConfiguration>",
	       NULL)), "<trt:SetAudioDecoderConfigurationResponse/>");
	check("... nothing saved", camcfg_calls == 0);
	expect("an unknown audio output operation -> ActionNotSupported", run(soap_req(MED, VIEW,
	       "<trt:GetAudioOutputConfigurationOptionsX/>", NULL)), "<env:Value>ter:ActionNotSupported</env:Value></env:Subcode>");

	/* audio.enabled=0 hides it */
	write_file(conf_path, "stream.sub.enabled=1\naudio.enabled=0\n");
	r = run(soap_req(MED, VIEW, "<trt:GetProfiles/>", NULL));
	check("audio.enabled=0: no audio output in the profiles", strstr(r, "Profile_2") &&
	      !strstr(r, "AudioOutputConfiguration") && !strstr(r, "AudioDecoderConfiguration"));
	expect("... GetAudioOutputs -> AudioOutputNotSupported", run(soap_req(MED, VIEW, "<trt:GetAudioOutputs/>", NULL)),
	       "ter:AudioOutputNotSupported");
	expect("... decoder configurations too", run(soap_req(MED, VIEW, "<trt:GetAudioDecoderConfigurations/>", NULL)),
	       "ter:AudioOutputNotSupported");
	expect("... Add too", run(soap_req(MED, OP, PROF("AddAudioOutputConfiguration",
	       "<trt:ConfigurationToken>AudioOutputConfig_1</trt:ConfigurationToken>"), NULL)), "ter:AudioOutputNotSupported");
	expect("... an unknown output operation too", run(soap_req(MED, VIEW, "<trt:GetAudioOutputConfigurationOptionsX/>",
	       NULL)), "ter:AudioOutputNotSupported");
	expect("... DeviceIO counts none", run(soap_req(DIO, NULL, "<tmd:GetServiceCapabilities/>", NULL)),
	       "AudioSources=\"0\" AudioOutputs=\"0\"");
	expect("... nor does GetCapabilities", run(soap_req(DEV, NULL, "<tds:GetCapabilities><tds:Category>All"
	       "</tds:Category></tds:GetCapabilities>", NULL)), "<tt:AudioSources>0</tt:AudioSources><tt:AudioOutputs>0");
	write_file(conf_path, "image.brightness=55\nstream.main.kbps=6000\nstream.main.profile=main\n"
		   "stream.main.fps=99\nstream.sub.enabled=1\n");
#undef AUTO
#undef PROF
#undef VIEW
#undef OP
}

/* ---- web UI (#79) ---------------------------------------------------------------------- */

/* every printable ASCII symbol, a space in the middle, 64 characters */
#define P64 "Aa0!\"#$%&'()*+,-./:;<=>?@[\\]^_ `{|}~Zz9bcdefghijklmnopqrstuvwxyz"
#define FORM_CT "Content-Type: application/x-www-form-urlencoded\r\n"
#define SAME "Origin: http://192.0.2.10\r\n" FORM_CT

static unsigned long ui_ctr = 2000000;                /* above every other test's nonce counter */

/* A browser's request: Digest as user (NULL: none) for a fresh nonce, extra headers, a body. */
static const char *ui_req(const char *method, const char *target, const char *user, const char *pw,
			  const char *extra, const char *body)
{
	static char buf[REQ_CAP];
	char nonce[NONCE_LEN + 1];
	nonce_make((unsigned long)mono(), ++ui_ctr, nonce);
	snprintf(buf, sizeof buf, "%s %s HTTP/1.1\r\nHost: 192.0.2.10\r\n%s%s%s%sContent-Length: %zu\r\n\r\n%s",
		 method, target, user ? "Authorization: " : "", user ? digest(user, pw, method, target, nonce, 1) : "",
		 user ? "\r\n" : "", extra ? extra : "", body ? strlen(body) : 0, body ? body : "");
	return buf;
}

static const char *ui_get(const char *path, const char *user, const char *pw)
{
	return run(ui_req("GET", path, user, pw, NULL, NULL));
}

static const char *token(const char *user, long long ago)
{
	static char t[41];
	csrf_token(user, (long long)mono() / CSRF_BUCKET - ago, t);
	return t;
}

/* A form POST from our own page: csrf=<user's token>& and the rest. */
static const char *ui_post(const char *path, const char *user, const char *pw, const char *fmt, ...)
{
	static char body[3 * UI_BODY_MAX];
	va_list ap;
	int n = snprintf(body, sizeof body, "csrf=%s&", token(user, 0));
	va_start(ap, fmt);
	vsnprintf(body + n, sizeof body - (size_t)n, fmt, ap);
	va_end(ap);
	return run(ui_req("POST", path, user, pw, SAME, body));
}

/* As a browser encodes a form value (rotating buffers: several per call). */
static const char *urlenc(const char *s)
{
	static char o[4][3 * 1024];
	static int k;
	char *p = o[k = (k + 1) % 4];
	for (; *s && p < o[k] + sizeof o[0] - 4; s++) {
		unsigned char ch = (unsigned char)*s;
		if (isalnum(ch) || strchr("*-._", ch)) *p++ = (char)ch;
		else if (ch == ' ') *p++ = '+';
		else p += snprintf(p, 4, "%%%02X", ch);
	}
	*p = 0;
	return o[k];
}

#define A_PW "Adm1nPass!"
#define O_PW "0perPass"
#define V_PW "V1ew:Pass&"
static const char users_txt[] = "admin:admin:Adm1nPass!\nop:operator:0perPass\nview:viewer:V1ew:Pass&\n"
	"x:rooty:whatever\n:viewer:nameless\n";

static void test_form(void)
{
	static const struct { const char *in; int ok; const char *k, *v; } c[] = {
		{ "", 1, NULL, NULL },
		{ "a=1&b=x+y%21%3a", 1, "b", "x y!:" },
		{ "key=ssh-ed25519+AAAA%2B%2F%3D+me%40host", 1, "key", "ssh-ed25519 AAAA+/= me@host" },
		{ "a=b=c", 1, "a", "b=c" },
		{ "a=", 1, "a", "" },
		{ "pw=%09tab", 1, "pw", "\ttab" },                 /* for camcfg to refuse, with its reason */
		{ "pw=caf%C3%A9", 1, "pw", "caf\xc3\xa9" },
		{ "a=%zz", 0, NULL, NULL }, { "a=%4", 0, NULL, NULL }, { "a=%", 0, NULL, NULL },
		{ "a=%00", 0, NULL, NULL }, { "a=1&a=2", 0, NULL, NULL }, { "a", 0, NULL, NULL },
		{ "=1", 0, NULL, NULL }, { "a=1&", 0, NULL, NULL }, { "&a=1", 0, NULL, NULL },
		{ "a=1&&b=2", 0, NULL, NULL }, { "A=1", 0, NULL, NULL }, { "a-b=1", 0, NULL, NULL },
		{ "a=x y", 0, NULL, NULL }, { "a=\xc3\xa9", 0, NULL, NULL }, { "a=1\r\n", 0, NULL, NULL },
		{ "abcdefghijklmnopqrstuvwxy=1", 0, NULL, NULL },
	};
	for (size_t i = 0; i < sizeof c / sizeof c[0]; i++) {
		int r = form_parse(c[i].in, strlen(c[i].in));
		if ((r == 0) != c[i].ok || (c[i].k && (!form_get(c[i].k) || strcmp(form_get(c[i].k), c[i].v)))) {
			fprintf(stderr, "FAIL form_parse(\"%s\")\n", c[i].in);
			exit(1);
		}
	}
	char many[FORM_MAX * 8 + 16] = "";                  /* FORM_MAX pairs parse, one more doesn't */
	for (int i = 0; i < FORM_MAX; i++) snprintf(many + strlen(many), sizeof many - strlen(many), "%sf%d=1", i ? "&" : "", i);
	check("FORM_MAX pairs parse", form_parse(many, strlen(many)) == 0 && form.n == FORM_MAX);
	strcat(many, "&x=1");
	check("... one more is refused", form_parse(many, strlen(many)) == -1);
	printf("ok: form parsing: +, %%xx, bad %%, NUL, duplicates, empty pairs, names, raw bytes, %d pairs max\n", FORM_MAX);
	static char big[UI_BODY_MAX + 10];
	memset(big, 'x', sizeof big - 1);
	memcpy(big, "a=", 2);
	check("a form over 8 KiB is refused", form_parse(big, UI_BODY_MAX + 1) != 0 && form_parse(big, UI_BODY_MAX) == 0);
	memset(&form, 0, sizeof form);
}

static void test_ui(const char *dir)
{
	const char *r;
	char b[4096], path[700];
	int calls;
	write_file(users_path, users_txt);
	write_file(conf_path, "stream.main.kbps=6000\nstream.sub.enabled=1\n");
	fake_down = 0;
	auth_reset();

	r = run("GET / HTTP/1.1\r\nHost: 192.0.2.10\r\n\r\n");
	expect("/ redirects to /ui/", r, "HTTP/1.1 302 Found\r\n");
	expect("... Location", r, "Location: /ui/\r\n");
	r = run("GET /ui.css HTTP/1.1\r\nHost: 192.0.2.10\r\n\r\n");
	expect("/ui.css without a login", r, "200 OK");
	expect("... as CSS", r, "Content-Type: text/css; charset=utf-8");
	r = ui_get("/ui/", NULL, NULL);
	expect("/ui/ without credentials -> 401", r, "401 Unauthorized");
	expect("... with a Digest challenge", r, "WWW-Authenticate: Digest realm=\"camera\"");
	r = run("GET /ui.js HTTP/1.1\r\nHost: 192.0.2.10\r\n\r\n");
	expect("/ui.js without a login", r, "200 OK");
	expect("... as JavaScript", r, "Content-Type: text/javascript; charset=utf-8");
	expect("... keeps slider and number in step", r, "r.addEventListener('input', () => { n.value = r.value; });");
	expect("... applies a live form on release", r, "fetch(f.action, { method: 'POST'");
	expect("... and when a select or a checkbox in it changes", r,
	       "querySelectorAll('form[data-live] select, form[data-live] input[type=checkbox]')");
	expect("... reloads a data-refresh image", r, "next.src = base + '?t=' + Date.now();");
	r = ui_get("/ui/", NULL, NULL);
	static const char *const hdrs[] = { ("Content-Security-Policy: default-src 'none'; img-src 'self'; style-src "
		"'self'; script-src 'self'; connect-src 'self'; form-action 'self'; frame-ancestors 'none'; "
		"base-uri 'none'\r\n"), "X-Frame-Options: DENY\r\n",
		"X-Content-Type-Options: nosniff\r\n", "Referrer-Policy: same-origin\r\n", "Cache-Control: no-store\r\n" };
	for (int i = 0; i < 5; i++) expect("security headers on the 401", r, hdrs[i]);

	r = ui_get("/ui/", "view", V_PW);
	expect("viewer: status page", r, "200 OK");
	for (int i = 0; i < 5; i++) expect("security headers on a page", r, hdrs[i]);
	expect("firmware version from /etc/cam/version", r, "<th>Firmware</th><td>1.2.3-test</td>");
	expect("uptime", r, "<th>Uptime</th><td>1 d 01:01</td>");
	expect("memory", r, "<th>Memory</th><td>32 MiB free of 64 MiB</td>");
	expect("address", r, "<td>192.0.2.10/24 (netmask 255.255.255.0) on eth0</td>");
	expect("gateway from the route table", r, "<th>Gateway</th><td>192.0.2.1</td>");
	expect("DNS", r, "<th>DNS</th><td>192.0.2.53, 192.0.2.54</td>");
	expect("MAC (documentation value)", r, "<th>MAC</th><td>02:00:00:00:00:01</td>");
	expect("day/night from rtspd", r, "<td>day (mode auto)</td>");
	expect("motion state", r, "<th>Motion</th><td>no motion</td>");
	expect("streams", r, "<th>Main stream</th><td>H.264 2560x1440, 30 fps, 6000 kbit/s</td>");
	expect("NTP", r, "<th>NTP</th><td>time.cloudflare.com</td>");
	expect("the snapshot", r, "<img src=\"/snapshot.jpg\"");
	absent("status takes no preview slot", r, "preview.mjpg");
	expect("viewer's nav", r, "<a href=\"/ui/\" class=\"on\">Status</a></nav>");
	absent("no Image link for a viewer", r, "/ui/image");
	absent("no form for a viewer", r, "<form");
	absent("no inline JavaScript (only /ui.js)", r, "<script>");

	/* every page for every role */
	static const char *const paths[] = { "/ui/", "/ui/image", "/ui/osd", "/ui/streams", "/ui/motion", "/ui/time",
					     "/ui/users", "/ui/ssh", "/ui/system" };
	static const struct { const char *u, *pw; int pages; } who[] = { { "view", V_PW, 1 }, { "op", O_PW, 5 },
									  { "admin", A_PW, 9 } };
	for (int w = 0; w < 3; w++)
		for (int p = 0; p < 9; p++) {
			r = ui_get(paths[p], who[w].u, who[w].pw);
			snprintf(b, sizeof b, "%s GET %s", who[w].u, paths[p]);
			expect(b, r, p < who[w].pages ? "200 OK" : "403 Forbidden");
			if (p < who[w].pages) absent(b, r, "<script>");
		}
	r = ui_get("/ui/", "admin", A_PW);
	expect("admin sees every link", r, "<a href=\"/ui/system\">System</a>");
	r = ui_get("/ui/", "op", O_PW);
	expect("operator sees Motion", r, "/ui/motion");
	absent("... not Users", r, "/ui/users");
	expect("unknown UI page -> 404", ui_get("/ui/nope", "admin", A_PW), "404");
	expect("POST to status -> 405", run(ui_req("POST", "/ui/", "admin", A_PW, SAME, "a=1")), "405");
	expect("PUT -> 405", run(ui_req("PUT", "/ui/image", "admin", A_PW, NULL, NULL)), "405");
	auth_reset();

	/* Image */
	fake_img[0] = 50; fake_img[1] = 50; strcpy(fake_mode, "auto");
	r = ui_get("/ui/image", "op", O_PW);
	expect("image page: preview refreshed by /ui.js", r, "<img src=\"/snapshot.jpg\" data-refresh");
	expect("... the stream as a link without scripts", r, "<noscript>");
	absent("... no stream held open by the page", r, "<img src=\"/preview.mjpg\"");
	r = ui_get("/snapshot.jpg?t=1761234567890", "op", O_PW);
	absent("... /snapshot.jpg?t=... passes Digest (the uri carries the query)", r, "401");
	r = ui_get("/ui/image", "op", O_PW);
	expect("image page: slider and number", r, "name=\"brightness\" min=\"0\" max=\"100\" value=\"50\"> <input "
	       "type=\"number\" name=\"brightness_n\"");
	expect("image page: exposure", r, "name=\"exposure\"");
	expect("image page: a live form (applied on release by /ui.js)", r, "<form method=\"post\" action=\"/ui/image\" data-live>");
	expect("... with a place for its result", r, "<span class=\"live\"></span>");
	expect("image page: IR LED from rtspd", r, "name=\"irled\" min=\"0\" max=\"100\" value=\"96\"");
	expect("image page: the form's token", r, token("op", 0));
	*camcfg_log = 0;
	*set_log = 0;
	r = ui_post("/ui/image", "op", O_PW, "brightness=60&brightness_n=50&contrast=50&contrast_n=70&mode=night");
	expect("image POST", r, "Saved and applied.");
	check("... slider, number field and mode saved", !strcmp(camcfg_log, "image.brightness=60;image.contrast=70;"
	      "daynight.mode=night;"));
	check("... and applied live", strstr(set_log, "set image.brightness 60;") && strstr(set_log, "set daynight.mode night;"));
	expect("... page shows the new values", r, "name=\"contrast\" min=\"0\" max=\"100\" value=\"70\"");
	r = ui_post("/ui/image", "op", O_PW, "brightness=60&brightness_n=60");
	expect("same values: nothing changed", r, "Nothing changed.");
	calls = camcfg_calls;
	static const char *const img_bad[] = { "brightness=101", "brightness_n=-1", "contrast=abc", "mode=dusk",
					       "irled=1000", "exposure=" };
	for (int i = 0; i < 6; i++) {
		r = ui_post("/ui/image", "op", O_PW, "%s", img_bad[i]);
		expect(img_bad[i], r, "400 Bad Request");
		expect("... with the reason", r, "class=\"msg err\"");
	}
	check("... nothing saved", camcfg_calls == calls);
	r = ui_post("/ui/image", "view", V_PW, "brightness=10");
	expect("viewer may not POST image", r, "403 Forbidden");
	check("... nothing saved", camcfg_calls == calls);
	/* orientation, day/night thresholds, shutter limits */
	r = ui_get("/ui/image", "op", O_PW);
	expect("image page: groups", r, "<h2>Picture</h2>");
	expect("... Orientation", r, "<h2>Orientation</h2>");
	expect("... Day/night", r, "<h2>Day/night</h2>");
	expect("... Exposure", r, "<h2>Exposure</h2>");
	expect("... mirror Off/On", r, "<label>Mirror (left-right) <select name=\"mirror\"><option value=\"0\" selected>Off"
	       "</option><option value=\"1\">On</option></select></label>");
	expect("... flip", r, "<select name=\"flip\">");
	expect("... 90 degrees is #123", r, "issue #123");
	expect("... SSS area note", r, "Surveillance Station applies to the picture as it is shown");
	expect("... night threshold", r, "Switch to night below <input type=\"number\" name=\"night_below\" min=\"1\" "
	       "max=\"1000000\" value=\"15\">");
	expect("... day threshold", r, "Back to day above <input type=\"number\" name=\"day_above\" min=\"1\" "
	       "max=\"1000000\" value=\"1500\">");
	expect("... the score explained, and now", r, "Score now: 4321.");
	expect("... day shutter choices", r, "<select name=\"shutter_day\"><option value=\"0\" selected>Automatic (one frame)"
	       "</option><option value=\"40000\">1/25 s</option>");
	expect("... 1/10000 s", r, "<option value=\"100\">1/10000 s</option></select>");
	expect("... night shutter choices", r, "<select name=\"shutter_night\"><option value=\"0\" selected>Automatic "
	       "(1/20 s, as stock)</option><option value=\"40000\">1/25 s</option><option value=\"20000\">1/50 s</option>"
	       "<option value=\"10000\">1/100 s</option></select>");
	absent("... no 1/12 s at night", r, "1/12 s");
	*camcfg_log = 0;
	*set_log = 0;
	r = ui_post("/ui/image", "op", O_PW, "mirror=1&flip=0&shutter_day=1000&shutter_night=20000&night_below=15&day_above=1500");
	expect("orientation + shutter POST", r, "Saved and applied.");
	check("... saved with camcfg", !strcmp(camcfg_log, "image.mirror=1;image.shutter_day_max=1000;"
	      "image.shutter_night_max=20000;"));
	check("... and applied live", !strcmp(set_log, "set image.mirror 1;set image.shutter_day_max 1000;"
	      "set image.shutter_night_max 20000;"));
	expect("... page shows mirror on", r, "<option value=\"1\" selected>On</option>");
	expect("... and 1/1000 s", r, "<option value=\"1000\" selected>1/1000 s</option>");
	/* thresholds raised above the current day value: day_above goes first */
	*set_log = 0;
	fake_set_err = 0;
	r = ui_post("/ui/image", "op", O_PW, "night_below=2000&day_above=5000");
	expect("thresholds raised", r, "Saved and applied.");
	check("... day_above first", !strcmp(set_log, "set daynight.day_above 5000;set daynight.night_below 2000;") &&
	      !fake_set_err && fake_nb == 2000 && fake_da == 5000);
	*set_log = 0;
	r = ui_post("/ui/image", "op", O_PW, "night_below=5&day_above=10");
	expect("thresholds lowered", r, "Saved and applied.");
	check("... night_below first", !strcmp(set_log, "set daynight.night_below 5;set daynight.day_above 10;") &&
	      !fake_set_err && fake_nb == 5 && fake_da == 10);
	expect("... page shows them", r, "name=\"day_above\" min=\"1\" max=\"1000000\" value=\"10\"");
	/* a value camcfg set that isn't one of the choices stays selectable, so applying keeps it */
	fake_sh[0] = 3000;
	r = ui_get("/ui/image", "op", O_PW);
	expect("custom day shutter shown", r, "<option value=\"3000\" selected>3000 us (set elsewhere)</option>");
	*set_log = 0;
	r = ui_post("/ui/image", "op", O_PW, "shutter_day=3000&brightness=51");
	expect("... kept when the form is applied", r, "Saved and applied.");
	check("... only brightness sent", !strcmp(set_log, "set image.brightness 51;"));
	calls = camcfg_calls;
	static const char *const img_bad2[] = { "mirror=2", "flip=on", "mirror=", "night_below=0", "day_above=1000001",
		"night_below=1500&day_above=1500", "night_below=20", "day_above=abc", "shutter_day=1234",
		"shutter_night=83333", "shutter_night=50000", "shutter_day=-1", "night_below=99999999" };
	for (unsigned i = 0; i < sizeof img_bad2 / sizeof img_bad2[0]; i++) {
		r = ui_post("/ui/image", "op", O_PW, "%s", img_bad2[i]);
		expect(img_bad2[i], r, "400 Bad Request");
		expect("... with the reason", r, "class=\"msg err\"");
	}
	check("... nothing saved", camcfg_calls == calls);
	r = ui_post("/ui/image", "op", O_PW, "brightness=51&brightness_n=51&contrast=50&contrast_n=50&"
		    "saturation=50&saturation_n=50&sharpness=50&sharpness_n=50&exposure=50&exposure_n=50&mirror=1&"
		    "flip=0&mode=auto&night_below=5&day_above=10&irled=96&irled_n=96&shutter_day=3000&shutter_night=20000");
	expect("the whole form (20 fields with the token) parses", r, "200 OK");
	absent("... and is taken", r, "msg err");
	/* Advanced: NR 2D/3D, WDR (select + strength), BLC, mains, anti-flicker */
	r = ui_get("/ui/image", "op", O_PW);
	expect("Advanced group", r, "<h2>Advanced</h2>");
	expect("... 2D NR slider 0..255 at 128, marked as tuned", r, "2D noise reduction (128 = as tuned) <input type=\"range\" "
	       "name=\"nr2d\" min=\"0\" max=\"255\" value=\"128\"> <input type=\"number\" name=\"nr2d_n\" min=\"0\" "
	       "max=\"255\" value=\"128\">");
	expect("... 3D NR", r, "name=\"nr3d\" min=\"0\" max=\"255\" value=\"128\"");
	expect("... WDR select Off (as tuned)", r, "<select name=\"wdr_on\"><option value=\"0\" selected>Off (as tuned)"
	       "</option><option value=\"1\">On</option></select>");
	expect("... WDR strength 1..255 at 128", r, "name=\"wdr\" min=\"1\" max=\"255\" value=\"128\"");
	expect("... BLC 0..255 at 0", r, "name=\"blc\" min=\"0\" max=\"255\" value=\"0\"");
	expect("... mains 60 Hz", r, "<select name=\"mains\"><option value=\"50\">50 Hz</option><option value=\"60\" "
	       "selected>60 Hz</option></select>");
	expect("... anti-flicker off", r, "<select name=\"antiflicker\"><option value=\"0\" selected>Off</option>");
	expect("... inside the live form, before Apply", r, "only works with WDR off.</p><label>Mains");
	*camcfg_log = 0;
	*set_log = 0;
	r = ui_post("/ui/image", "op", O_PW, "nr2d=64&nr2d_n=64&nr3d=128&nr3d_n=200&wdr_on=1&wdr=180&wdr_n=180&blc=0&"
		    "blc_n=0&mains=50&antiflicker=1");
	expect("tuning POST", r, "Saved and applied.");
	check("... saved with camcfg", !strcmp(camcfg_log, "image.nr2d=64;image.nr3d=200;image.wdr=180;"
	      "image.mains_hz=50;image.antiflicker=1;"));
	check("... and applied live", !strcmp(set_log, "set image.nr2d 64;set image.nr3d 200;set image.wdr 180;"
	      "set image.mains_hz 50;set image.antiflicker 1;"));
	expect("... page shows WDR on", r, "<option value=\"1\" selected>On</option></select></label><label>WDR strength");
	expect("... at 180", r, "name=\"wdr\" min=\"1\" max=\"255\" value=\"180\"");
	expect("... 50 Hz", r, "<option value=\"50\" selected>50 Hz</option>");
	*set_log = 0;
	r = ui_post("/ui/image", "op", O_PW, "wdr_on=0&wdr=180&wdr_n=180&blc=90&blc_n=90");
	expect("WDR off, BLC 90", r, "Saved and applied.");
	check("... image.wdr 0 and image.blc 90", !strcmp(set_log, "set image.wdr 0;set image.blc 90;"));
	*set_log = 0;
	r = ui_post("/ui/image", "op", O_PW, "wdr=50&wdr_n=50&nr2d=64&nr2d_n=64");
	expect("strength moved with WDR off", r, "Nothing changed.");
	check("... nothing sent", !*set_log);
	calls = camcfg_calls;
	static const char *const tune_bad[] = { "nr2d=256", "nr3d=-1", "nr3d_n=1000", "wdr_on=2", "wdr_on=1&wdr=0",
		"blc=300", "mains=55", "antiflicker=on", "wdr=x" };
	for (unsigned i = 0; i < sizeof tune_bad / sizeof tune_bad[0]; i++) {
		r = ui_post("/ui/image", "op", O_PW, "%s", tune_bad[i]);
		expect(tune_bad[i], r, "400 Bad Request");
		expect("... with the reason", r, "class=\"msg err\"");
	}
	check("... nothing saved", camcfg_calls == calls);
	r = ui_post("/ui/image", "op", O_PW, "brightness=51&brightness_n=51&contrast=50&contrast_n=50&"
		    "saturation=50&saturation_n=50&sharpness=50&sharpness_n=50&exposure=50&exposure_n=50&mirror=1&"
		    "flip=0&mode=auto&night_below=5&day_above=10&irled=96&irled_n=96&shutter_day=3000&shutter_night=20000&"
		    "nr2d=64&nr2d_n=64&nr3d=200&nr3d_n=200&wdr_on=0&wdr=128&wdr_n=128&blc=90&blc_n=90&mains=50&antiflicker=1");
	expect("the whole form (31 fields with the token) parses", r, "200 OK");
	absent("... and is taken", r, "msg err");
	/* stock night tuning: a checkbox in the Day/night group */
	r = ui_get("/ui/image", "op", O_PW);
	expect("night tuning checkbox, off by default, in the Day/night group before Exposure", r,
	       "<label><input type=\"checkbox\" name=\"night_tuning\" value=\"1\"> Stock night tuning: stronger noise "
	       "reduction, softer sharpening, darker shadows at night</label><h2>Exposure</h2>");
	*camcfg_log = 0;
	*set_log = 0;
	r = ui_post("/ui/image", "op", O_PW, "night_tuning=1&mode=auto");
	expect("ticked", r, "Saved and applied.");
	check("... saved and applied live", !strcmp(camcfg_log, "image.night_tuning=1;") &&
	      !strcmp(set_log, "set image.night_tuning 1;") && fake_nt == 1);
	expect("... page shows it ticked", r, "name=\"night_tuning\" value=\"1\" checked>");
	*set_log = 0;
	r = ui_post("/ui/image", "op", O_PW, "night_tuning=1&mode=auto");
	expect("ticked again", r, "Nothing changed.");
	check("... nothing sent", !*set_log);
	r = ui_post("/ui/image", "op", O_PW, "mode=auto");
	expect("unticked (browsers leave it out)", r, "Saved and applied.");
	check("... turns it off", !strcmp(set_log, "set image.night_tuning 0;") && fake_nt == 0);
	calls = camcfg_calls;
	r = ui_post("/ui/image", "op", O_PW, "night_tuning=on");
	expect("a value no form sends", r, "400 Bad Request");
	check("... nothing saved", camcfg_calls == calls && fake_nt == 0);
	r = ui_post("/ui/image", "op", O_PW, "brightness=51&brightness_n=51&contrast=50&contrast_n=50&"
		    "saturation=50&saturation_n=50&sharpness=50&sharpness_n=50&exposure=50&exposure_n=50&mirror=1&"
		    "flip=0&mode=auto&night_below=5&day_above=10&irled=96&irled_n=96&night_tuning=1&"
		    "shutter_day=3000&shutter_night=20000&nr2d=64&nr2d_n=64&nr3d=200&nr3d_n=200&wdr_on=0&wdr=128&wdr_n=128&"
		    "blc=90&blc_n=90&mains=50&antiflicker=1");
	expect("the whole form with the box ticked (32 fields with the token) parses", r, "200 OK");
	absent("... and is taken", r, "msg err");
	check("... night tuning on", fake_nt == 1);
	/* night exposure: "Exposure at night" (same as day / own value) and its slider, Day/night group
	 * (night tuning off again, so the posts below without the box change only this) */
	fake_nt = 0;
	fake_img[4] = 60;
	r = ui_get("/ui/image", "op", O_PW);
	expect("night exposure select, same as day by default", r, "<label>Exposure at night <select name=\"exposure_night_mode\">"
	       "<option value=\"day\" selected>Same as day</option><option value=\"own\">Own value</option></select></label>");
	expect("... its slider showing the day value meanwhile", r, "name=\"exposure_night\" min=\"0\" max=\"100\" value=\"60\"");
	expect("... 30 suggested for street lights", r, "Try 30 where a street light");
	expect("... in the Day/night group, after the IR LED", r, "name=\"irled_n\" min=\"0\" max=\"100\" value=\"96\"></label>"
	       "<label>Exposure at night");
	*camcfg_log = 0;
	*set_log = 0;
	r = ui_post("/ui/image", "op", O_PW, "exposure_night_mode=day&exposure_night=60&exposure_night_n=60");
	expect("same as day again", r, "Nothing changed.");
	r = ui_post("/ui/image", "op", O_PW, "exposure_night_mode=own&exposure_night=30&exposure_night_n=60");
	expect("own value 30", r, "Saved and applied.");
	check("... saved and applied live", !strcmp(camcfg_log, "image.exposure_night=30;") &&
	      !strcmp(set_log, "set image.exposure_night 30;") && !strcmp(fake_en, "30"));
	expect("... page shows it", r, "<option value=\"own\" selected>Own value</option>");
	expect("... at 30", r, "name=\"exposure_night\" min=\"0\" max=\"100\" value=\"30\"");
	*set_log = 0;
	r = ui_post("/ui/image", "op", O_PW, "exposure_night=40&exposure_night_n=30");
	expect("slider moved without the select (kept as it was: own)", r, "Saved and applied.");
	check("... 40", !strcmp(set_log, "set image.exposure_night 40;"));
	*set_log = 0;
	r = ui_post("/ui/image", "op", O_PW, "exposure_night_mode=own&exposure_night=40&exposure_night_n=25");
	expect("number field typed", r, "Saved and applied.");
	check("... 25", !strcmp(set_log, "set image.exposure_night 25;"));
	*set_log = 0;
	r = ui_post("/ui/image", "op", O_PW, "exposure_night_mode=day&exposure_night=25&exposure_night_n=25");
	expect("back to the same as day", r, "Saved and applied.");
	check("... day", !strcmp(set_log, "set image.exposure_night day;") && !strcmp(fake_en, "day"));
	calls = camcfg_calls;
	static const char *const en_bad[] = { "exposure_night_mode=night", "exposure_night_mode=own&exposure_night=101",
		"exposure_night_n=-1", "exposure_night=abc&exposure_night_mode=day" };
	for (unsigned i = 0; i < sizeof en_bad / sizeof en_bad[0]; i++) {
		r = ui_post("/ui/image", "op", O_PW, "%s", en_bad[i]);
		expect(en_bad[i], r, "400 Bad Request");
		expect("... with the reason", r, "Exposure at night:");
	}
	check("... nothing saved", camcfg_calls == calls && !strcmp(fake_en, "day"));
	r = ui_post("/ui/image", "op", O_PW, "brightness=51&brightness_n=51&contrast=50&contrast_n=50&"
		    "saturation=50&saturation_n=50&sharpness=50&sharpness_n=50&exposure=60&exposure_n=60&mirror=1&"
		    "flip=0&mode=auto&night_below=5&day_above=10&irled=96&irled_n=96&exposure_night_mode=own&"
		    "exposure_night=30&exposure_night_n=30&night_tuning=1&shutter_day=3000&shutter_night=20000&nr2d=64&"
		    "nr2d_n=64&nr3d=200&nr3d_n=200&wdr_on=0&wdr=128&wdr_n=128&blc=90&blc_n=90&mains=50&antiflicker=1");
	expect("the whole form (35 fields with the token) parses", r, "200 OK");
	absent("... and is taken", r, "msg err");
	check("... night exposure 30", !strcmp(fake_en, "30"));
	snprintf(fake_en, sizeof fake_en, "day");
	fake_img[4] = 50;
	fake_nt = 0;
	for (int i = 0; i < 6; i++) fake_tune[i] = i < 2 ? 128 : i == 4 ? 60 : 0;
	/* back to the defaults for the tests below */
	fake_mirror = 0; fake_sh[0] = fake_sh[1] = 0; fake_nb = 15; fake_da = 1500; fake_img[1] = 50; strcpy(fake_mode, "auto");

	/* Streams */
	restarts = 0;
	*camcfg_log = 0;
	r = ui_get("/ui/streams", "op", O_PW);
	expect("streams page warns about the restart", r, "restarts the video");
	expect("streams page: main kbps", r, "name=\"main_kbps\" min=\"64\" max=\"16384\" value=\"6000\"");
	r = ui_post("/ui/streams", "op", O_PW, "main_codec=h264&main_kbps=6144&main_fps=20&main_gop=100&"
		    "main_profile=high&sub_codec=h264&sub_kbps=500&sub_fps=25&sub_gop=100&sub_profile=high");
	expect("streams POST", r, "The video restarts now");
	check("... saved key by key (the sub's 25 fps as the main's 20), restarted once", !strcmp(camcfg_log,
	      "stream.main.kbps=6144;stream.main.fps=20;stream.sub.fps=20;") && restarts == 1);
	r = ui_post("/ui/streams", "op", O_PW, "main_kbps=6144&main_fps=20");
	expect("same streams: nothing changed", r, "Nothing changed.");
	check("... no restart", restarts == 1);
	calls = camcfg_calls;
	static const char *const st_bad[] = { "main_fps=31", "main_kbps=63", "main_gop=0", "sub_profile=extended",
					      "sub_codec=mjpeg", "main_kbps=1e4", "main_size=640x360", "sub_size=1920x1080",
					      "sub_size=1280x720x", "main_size=" };
	for (size_t i = 0; i < sizeof st_bad / sizeof st_bad[0]; i++)
		expect(st_bad[i], ui_post("/ui/streams", "op", O_PW, "%s", st_bad[i]), "400 Bad Request");
	check("... nothing saved, no restart", camcfg_calls == calls && restarts == 1);
	camcfg_fail = 1;
	expect("camcfg failing -> 500", ui_post("/ui/streams", "op", O_PW, "main_fps=10"), "500");
	camcfg_fail = 0;
	check("... no restart", restarts == 1);
	/* Gate 3 #11: at most one rtspd restart per RESTART_GAP_MS; a change inside it is saved and its
	 * restart put off to the end of it, where later changes join it */
	r = ui_post("/ui/streams", "op", O_PW, "main_fps=21");
	expect("another change within 10 s of the restart: saved, the restart put off", r,
	       "Saved. The video restarted moments ago: it restarts again with these settings in 10 s.");
	check("... saved now, not restarted yet", strstr(camcfg_log, "stream.main.fps=21;") && restarts == 1 && restart_wanted);
	r = ui_post("/ui/streams", "op", O_PW, "main_fps=20");
	expect("... a third change joins that restart", r, "it restarts again with these settings in");
	restart_tick(mono_ms() + RESTART_GAP_MS - 1000);
	check("... nothing before the 10 s are up", restarts == 1);
	restart_tick(mono_ms() + RESTART_GAP_MS);
	check("... then one restart for both", restarts == 2 && !restart_wanted);
	restart_last = -RESTART_GAP_MS;                    /* as if long ago, for the tests below */
	/* sizes (owner 2026-10-25): a select per stream; an unset kbps shown as the size's default */
	r = ui_get("/ui/streams", "op", O_PW);
	expect("streams page: main size select", r, "<label>Size <select name=\"main_size\"><option value=\"2560x1440\" selected>"
	       "2560x1440</option><option value=\"2304x1296\">2304x1296</option><option value=\"1920x1080\">1920x1080</option>"
	       "<option value=\"1280x720\">1280x720</option></select></label>");
	expect("... sub size select", r, "<label>Size <select name=\"sub_size\"><option value=\"640x360\" selected>640x360"
	       "</option><option value=\"960x540\">960x540</option><option value=\"1280x720\">1280x720</option></select>");
	expect("... fps up to 30", r, "name=\"main_fps\" min=\"1\" max=\"30\" value=\"20\"");
	expect("... sub kbps unset: the size's default", r, "Bit rate (kbit/s, 64 to 16384; not set: the size's default) "
	       "<input type=\"number\" name=\"sub_kbps\" min=\"64\" max=\"16384\" value=\"500\">");
	expect("... the defaults explained", r, "sub 500, 900 or 1500 kbit/s");
	*camcfg_log = 0;
	r = ui_post("/ui/streams", "op", O_PW, "main_size=1920x1080&main_kbps=6144&sub_size=1280x720&sub_kbps=500");
	expect("sizes saved", r, "The video restarts now");
	check("... as stream.<main|sub>.size; the sub's kbps left at its default stays unset", !strcmp(camcfg_log,
	      "stream.main.size=1920x1080;stream.sub.size=1280x720;") && restarts == 3);
	restart_last = -RESTART_GAP_MS;
	r = ui_get("/ui/streams", "op", O_PW);
	expect("... read back", r, "<h2>Main stream, 1920x1080</h2>");
	expect("... the sub", r, "<h2>Sub stream, 1280x720</h2>");
	expect("... sub kbps now the 720p default", r, "name=\"sub_kbps\" min=\"64\" max=\"16384\" value=\"1500\"");
	expect("... main kbps as set", r, "name=\"main_kbps\" min=\"64\" max=\"16384\" value=\"6144\"");
	*camcfg_log = 0;
	r = ui_post("/ui/streams", "op", O_PW, "main_size=2560x1440&sub_size=640x360");
	check("sizes back", !strcmp(camcfg_log, "stream.main.size=2560x1440;stream.sub.size=640x360;") && restarts == 4);
	restart_last = -RESTART_GAP_MS;
	restarts = 2;                                      /* the counts below as before these two */

	/* OSD */
	*camcfg_log = *set_log = 0;
	*fake_osd = 0;
	fake_osd_set("osd.title.text", "<b>&\"x\"");
	r = ui_get("/ui/osd", "op", O_PW);
	expect("OSD page: a live form", r, "<form method=\"post\" action=\"/ui/osd\" data-live>");
	expect("... with the preview", r, "<img src=\"/snapshot.jpg\" data-refresh");
	expect("... the clock shown at the top left by default", r, "<option value=\"ul\" selected>Top left</option>");
	expect("... the title escaped in its field", r, "name=\"title\" maxlength=\"48\" value=\"&lt;b&gt;&amp;&quot;x&quot;\"");
	absent("... no UTC offset field (the zone is on the Time page)", r, "name=\"tz\"");
	expect("... a note that points there (no link for an operator)", r,
	       "the camera's local time: set the time zone on the Time page (admin).");
	expect("... with a link for an admin", ui_get("/ui/osd", "admin", A_PW), "<a href=\"/ui/time\">Time page</a>");
	r = ui_get("/ui/osd", "op", O_PW);
	absent("... no failure note", r, "overlay driver refused");
	r = ui_post("/ui/osd", "op", O_PW, "time_on=1&time_pos=custom&time_x=100&time_y=0&time_format=dd%%2FMM%%2Fyyyy&"
		    "clock=1&weekday=1&tz=-300&title_on=1&title=%s&title_pos=ur&title_x=0&title_y=0&size=large&"
		    "style=white-on-black", urlenc("Gate 2 & <yard>"));
	expect("OSD POST", r, "Saved and applied.");
	printf("   camcfg: %s\n", camcfg_log);
	check("... each change saved, the title switched on last; an old page's tz field ignored",
	      !strcmp(camcfg_log, "osd.time.pos=custom;osd.time.x=100;"
	      "osd.time.format=dd/MM/yyyy;osd.time.12h=1;osd.time.weekday=1;osd.title.pos=ur;"
	      "osd.title.text=Gate 2 & <yard>;osd.size=large;osd.style=white-on-black;osd.title.enabled=1;"));
	check("... and applied live", strstr(set_log, "set osd.title.text Gate 2 & <yard>;") &&
	      !strstr(set_log, "tz"));
	r = ui_get("/ui/osd", "op", O_PW);
	expect("... read back", r, "<option value=\"custom\" selected>Custom (below)</option>");
	expect("... title read back escaped", r, "value=\"Gate 2 &amp; &lt;yard&gt;\"");
	int ocalls = camcfg_calls;
	static const char *const osd_bad[] = { "time_pos=middle", "time_x=101", "size=huge",
		"style=red", "time_format=yy", "clock=2", "title_on=yes", "title=caf%C3%A9",
		"title=1234567890123456789012345678901234567890123456789", "title=a%09b" };
	for (size_t i = 0; i < sizeof osd_bad / sizeof osd_bad[0]; i++)
		expect(osd_bad[i], ui_post("/ui/osd", "op", O_PW, "%s", osd_bad[i]), "400 Bad Request");
	check("... nothing saved", camcfg_calls == ocalls);
	expect("viewer may not post to the OSD page", ui_post("/ui/osd", "view", V_PW, "size=small"), "403");
	expect("the same values again", ui_post("/ui/osd", "op", O_PW, "size=large"), "Nothing changed.");
	fake_osd_set("osd.status", "failed");
	expect("a failed OSD is shown", ui_get("/ui/osd", "op", O_PW), "overlay driver refused");
	*fake_osd = 0;

	/* Motion and audio */
	*camcfg_log = 0;
	r = ui_get("/ui/motion", "op", O_PW);
	expect("motion page: map from rtspd", r, "<pre>motion.map=change/10% 4x2");
	expect("... read-only, as text", r, "--01\n#9+-\n</pre>");
	expect("motion page: detection ticked", r, "name=\"motion\" value=\"1\" checked");
	r = ui_post("/ui/motion", "op", O_PW, "sensitivity=50&sensitivity_n=70&audio=1&gain=10&gain_n=14");
	expect("motion POST (detection unticked)", r, "The video restarts now");
	check("... saved", !strcmp(camcfg_log, "motion.enabled=0;motion.sensitivity=70;audio.gain=10;"));
	check("... sensitivity applied live, audio by a restart", strstr(set_log, "set motion.sensitivity 70;") &&
	      restarts == 3);
	calls = camcfg_calls;
	expect("gain 20", ui_post("/ui/motion", "op", O_PW, "gain=20&audio=1&motion=1"), "400");
	expect("checkbox value 2", ui_post("/ui/motion", "op", O_PW, "motion=2"), "400");
	expect("sensitivity 101", ui_post("/ui/motion", "op", O_PW, "sensitivity_n=101"), "400");
	check("... nothing saved", camcfg_calls == calls && restarts == 3);
	fake_down = 1;
	expect("motion page with rtspd down", ui_get("/ui/motion", "op", O_PW), "rtspd isn't answering");
	expect("status with rtspd down", ui_get("/ui/", "view", V_PW), "unknown (rtspd isn&#39;t answering)");
	fake_down = 0;

	/* Time */
	*camcfg_log = 0;
	r = ui_get("/ui/time", "admin", A_PW);
	expect("time page", r, "name=\"ntp\" maxlength=\"200\" value=\"time.cloudflare.com\"");
	r = ui_post("/ui/time", "admin", A_PW, "ntp=%s", urlenc("pool.ntp.org, 192.0.2.1"));
	expect("NTP saved", r, "ntpc uses them");
	check("... as time.ntp", !strcmp(camcfg_log, "time.ntp=pool.ntp.org,192.0.2.1;"));
	expect("... shown", r, "value=\"pool.ntp.org,192.0.2.1\"");
	calls = camcfg_calls;
	static const char *const ntp_bad[] = { "a;b", "300.1.1.1", "a,b,c,d", "-x.example", "bad_name",
					       "<script>alert(1)</script>" };
	for (int i = 0; i < 6; i++) {
		r = ui_post("/ui/time", "admin", A_PW, "ntp=%s", urlenc(ntp_bad[i]));
		expect(ntp_bad[i], r, "400 Bad Request");
		absent("... echoed escaped", r, "<script>alert");
	}
	expect("... escaped", r, "&lt;script&gt;alert(1)&lt;/script&gt;");
	check("... nothing saved", camcfg_calls == calls);
	r = ui_post("/ui/time", "admin", A_PW, "ntp=");
	expect("empty: NTP off", r, "NTP is off");
	check("... saved empty", strstr(camcfg_log, "time.ntp=;") != NULL);
	expect("operator may not set NTP", ui_post("/ui/time", "op", O_PW, "ntp=a"), "403");

	/* Time zone (time.tz) */
	*camcfg_log = *set_log = 0;
	r = ui_get("/ui/time", "admin", A_PW);
	expect("time page: a zone form", r, "<input type=\"hidden\" name=\"do\" value=\"zone\"><label>Time zone "
	       "<select name=\"zone\"><optgroup label=\"North America\"><option value=\"HST10\">");
	expect("... US Central as the owner wrote it", r,
	       "<option value=\"CST6CDT,M3.2.0,M11.1.0\">UTC&minus;6 US Central (CST/CDT)</option>");
	expect("... fixed offsets, escaped", r, "<option value=\"&lt;-12&gt;12\">UTC&minus;12 (no daylight saving)</option>");
	expect("... up to +14", r, "<option value=\"&lt;+14&gt;-14\">UTC+14 (no daylight saving)</option>");
	expect("... UTC selected by default", r, "<option value=\"UTC0\" selected>UTC (no daylight saving)</option>");
	expect("... a custom field, empty", r, "name=\"tz\" maxlength=\"64\" value=\"\"");
	expect("... local time = UTC", r, "<p>Local time: ");
	for (int i = 0; i < NTZ_PRESETS; i++) check(tz_presets[i].tz, tz_valid(tz_presets[i].tz) > 0);
	r = ui_post("/ui/time", "admin", A_PW, "do=zone&zone=%s&tz=", urlenc("CST6CDT,M3.2.0,M11.1.0"));
	expect("US Central saved", r, "Saved and applied. Local time now: ");
	check("... as time.tz", !strcmp(camcfg_log, "time.tz=CST6CDT,M3.2.0,M11.1.0;"));
	check("... applied live", strstr(set_log, "set time.tz CST6CDT,M3.2.0,M11.1.0;") != NULL);
	{
		time_t t = time(NULL);
		struct tm l;
		localtime_r(&t, &l);                       /* camhttpd set our TZ */
		expect("... the message says CDT or CST and whether DST is on", r,
		       l.tm_isdst > 0 ? " CDT (UTC-5, daylight saving time)." : " CST (UTC-6, standard time).");
		expect("... so does the page", r, l.tm_isdst > 0 ? " CDT (UTC-5, daylight saving time)</p>" :
		       " CST (UTC-6, standard time)</p>");
	}
	expect("... selected", r, "<option value=\"CST6CDT,M3.2.0,M11.1.0\" selected>");
	expect("... and on the Status page", ui_get("/ui/", "view", V_PW), "<th>Local time</th><td>");
	calls = camcfg_calls;
	expect("the same zone again", ui_post("/ui/time", "admin", A_PW, "do=zone&zone=%s", urlenc("CST6CDT,M3.2.0,M11.1.0")),
	       "Nothing changed.");
	r = ui_post("/ui/time", "admin", A_PW, "do=zone&zone=custom&tz=%s", urlenc("<+0545>-5:45"));
	expect("custom <+0545>-5:45 saved", r, "(UTC+5:45)");
	check("... as time.tz", strstr(camcfg_log, "time.tz=<+0545>-5:45;") != NULL);
	expect("... Custom selected, the field escaped", r, "<option value=\"custom\" selected>");
	expect("... the field", r, "name=\"tz\" maxlength=\"64\" value=\"&lt;+0545&gt;-5:45\"");
	r = ui_post("/ui/time", "admin", A_PW, "do=zone&zone=%s", urlenc("<-05>5"));
	expect("fixed UTC-5 saved", r, "(UTC-5)");
	absent("... no DST wording for a fixed offset", r, "standard time");
	calls = camcfg_calls;
	static const char *const zone_bad[] = { "zone=custom&tz=CST6CDT%3Breboot", "zone=custom&tz=%24%28reboot%29",
		"zone=custom&tz=%3A%2Fetc%2Flocaltime", "zone=custom&tz=", "zone=custom", "zone=America%2FChicago",
		"zone=CST6CDT%2CM3.2.0%2CM11.1.1", "zone=", "tz=UTC0",
		"zone=custom&tz=%3Cscript%3E", "zone=custom&tz=A23456789012345678901234567890123456789012345678901234567890123456" };
	for (size_t i = 0; i < sizeof zone_bad / sizeof zone_bad[0]; i++) {
		r = ui_post("/ui/time", "admin", A_PW, "do=zone&%s", zone_bad[i]);
		expect(zone_bad[i], r, "400 Bad Request");
		absent("... echoed escaped", r, "<script>");
	}
	check("... nothing saved", camcfg_calls == calls);
	expect("operator may not set the zone", ui_post("/ui/time", "op", O_PW, "do=zone&zone=UTC0"), "403");
	snprintf(b, sizeof b, "csrf=%s&do=zone&zone=UTC0", token("op", 0));          /* someone else's token */
	expect("zone POST with another user's token -> 403", run(ui_req("POST", "/ui/time", "admin", A_PW, SAME, b)), "403");
	snprintf(b, sizeof b, "csrf=%s&do=zone&zone=UTC0", token("admin", 0));
	expect("zone POST from another site -> 403",
	       run(ui_req("POST", "/ui/time", "admin", A_PW, "Origin: http://evil.example\r\n" FORM_CT, b)), "403");
	check("... nothing saved", camcfg_calls == calls);
	camcfg_fail = 1;
	expect("camcfg failing -> 500", ui_post("/ui/time", "admin", A_PW, "do=zone&zone=UTC0"), "500");
	camcfg_fail = 0;
	expect("back to UTC", ui_post("/ui/time", "admin", A_PW, "do=zone&zone=UTC0"), "Saved and applied. Local time now: ");

	/* CSRF */
	calls = camcfg_calls;
	snprintf(b, sizeof b, "csrf=%s&brightness_n=33", token("op", 0));
	static const struct { const char *hdrs, *want, *why; } cs[] = {
		{ FORM_CT, "403", "no Origin or Referer" },
		{ "Origin: http://evil.example\r\n" FORM_CT, "403", "a foreign Origin" },
		{ "Origin: null\r\n" FORM_CT, "403", "Origin null" },
		{ "Origin: https://192.0.2.10\r\n" FORM_CT, "403", "another scheme" },
		{ "Origin: http://192.0.2.10.evil.example\r\n" FORM_CT, "403", "our host as a prefix" },
		{ "Origin: http://192.0.2.10:8080\r\n" FORM_CT, "403", "another port" },
		{ "Origin: http://evil.example\r\nReferer: http://192.0.2.10/ui/image\r\n" FORM_CT, "403",
		  "a foreign Origin beats a good Referer" },
		{ "Referer: http://evil.example/ui/image\r\n" FORM_CT, "403", "a foreign Referer" },
		{ "Referer: http://192.0.2.10.evil.example/\r\n" FORM_CT, "403", "our host as a Referer prefix" },
		{ "Origin: http://192.0.2.10\r\nOrigin: http://192.0.2.10\r\n" FORM_CT, "403", "two Origins" },
		{ SAME "Content-Type: text/plain\r\n", "403", "two Content-Types" },
		{ "Origin: http://192.0.2.10\r\nContent-Type: text/plain\r\n", "415", "text/plain" },
		{ "Origin: http://192.0.2.10\r\n", "415", "no Content-Type" },
	};
	for (size_t i = 0; i < sizeof cs / sizeof cs[0]; i++) {
		if (!strcmp(cs[i].why, "two Content-Types")) continue;    /* hdr() counts it: see below */
		expect(cs[i].why, run(ui_req("POST", "/ui/image", "op", O_PW, cs[i].hdrs, b)), cs[i].want);
	}
	expect("two Content-Types -> 415", run(ui_req("POST", "/ui/image", "op", O_PW, cs[10].hdrs, b)), "415");
	check("... nothing saved", camcfg_calls == calls);
	r = run(ui_req("POST", "/ui/image", "op", O_PW, "Referer: http://192.0.2.10/ui/image\r\n" FORM_CT, b));
	expect("a same-host Referer without Origin is enough", r, "Saved and applied.");
	calls = camcfg_calls;
	r = run(ui_req("POST", "/ui/image", "op", O_PW, SAME, "brightness_n=34"));
	expect("no token -> 403", r, "403 Forbidden");
	snprintf(b, sizeof b, "csrf=%s&brightness_n=34", token("view", 0));
	expect("another user's token -> 403", run(ui_req("POST", "/ui/image", "op", O_PW, SAME, b)), "403");
	snprintf(b, sizeof b, "csrf=%s&brightness_n=34", token("op", 2));
	expect("a token two buckets old (30+ min) -> 403", run(ui_req("POST", "/ui/image", "op", O_PW, SAME, b)), "403");
	{
		const char *t = token("op", 0);                 /* always a different last digit */
		snprintf(b, sizeof b, "csrf=%.39s%c&brightness_n=34", t, t[39] == '0' ? '1' : '0');
	}
	expect("a changed token -> 403", run(ui_req("POST", "/ui/image", "op", O_PW, SAME, b)), "403");
	snprintf(b, sizeof b, "csrf=%s&brightness_n=34&csrf=%s", token("op", 0), token("op", 0));
	expect("the token twice -> 400 (duplicate name)", run(ui_req("POST", "/ui/image", "op", O_PW, SAME, b)), "400");
	check("... nothing saved", camcfg_calls == calls);
	snprintf(b, sizeof b, "csrf=%s&brightness_n=34", token("op", 1));
	expect("last bucket's token still works", run(ui_req("POST", "/ui/image", "op", O_PW, SAME, b)), "Saved");
	snprintf(b, sizeof b, "csrf=%s&brightness_n=35", token("op", 0));
	mono_adj += (long long)CSRF_BUCKET * 2000;
	expect("... a page left open 30 minutes -> 403", run(ui_req("POST", "/ui/image", "op", O_PW, SAME, b)), "403");
	mono_adj -= (long long)CSRF_BUCKET * 2000;
	static char big[UI_BODY_MAX + 200];
	snprintf(big, sizeof big, "csrf=%s&key=", token("admin", 0));
	memset(big + strlen(big), 'A', UI_BODY_MAX);
	big[UI_BODY_MAX + 1] = 0;
	expect("a form over 8 KiB -> 413", run(ui_req("POST", "/ui/ssh", "admin", A_PW, SAME, big)), "413");
	expect("malformed form -> 400", ui_post("/ui/image", "op", O_PW, "brightness=%%zz"), "400 Bad Request");
	auth_reset();

	/* Users */
	*exec_log = 0;
	r = ui_get("/ui/users", "admin", A_PW);
	expect("users listed", r, "<tr><td>op</td><td>operator</td></tr>");
	expect("the page loads the one script", r, "<script src=\"/ui.js\" defer></script>");
	absent("... and no inline script", r, "<script>");
	{
		const char *role = strstr(r, "<h2>Change a role</h2>"), *del = strstr(r, "<h2>Delete a user</h2>");
		check("role and delete forms offered", role && del);
		check("... never yourself or the last admin", role && !strstr(role, "<option>admin</option>") &&
		      strstr(role, "<option>op</option>"));
		check("... but your own password can be changed", strstr(r, "<option>admin</option>") &&
		      strstr(r, "<option>admin</option>") < role);
	}
	absent("no passwords on the page", r, O_PW);
	absent("invalid lines skipped", r, "rooty");
	r = ui_post("/ui/users", "admin", A_PW, "do=add&name=bob&role=viewer&pw=%s&pw2=%s", urlenc(P64), urlenc(P64 "x"));
	expect("two different passwords", r, "The two passwords differ.");
	check("... camcfg not run", !*exec_log);
	r = ui_post("/ui/users", "admin", A_PW, "do=add&name=bob&role=viewer&pw=%s&pw2=%s", urlenc(P64), urlenc(P64));
	expect("add a user with every symbol in the password", r, "User added.");
	check("... camcfg user add, the password on stdin only", !strcmp(exec_log, "user add bob viewer;") &&
	      !strcmp(exec_in, P64 "\n"));
	expect("... listed", r, "<tr><td>bob</td><td>viewer</td></tr>");
	r = ui_get("/ui/", "bob", P64);
	expect("bob logs in with HTTP Digest (64 characters, every symbol)", r, "200 OK");
	r = run(soap_req(DEV, wsse("bob", P64, time(NULL), 0, 0), B_INFO, NULL));
	expect("... and with a UsernameToken", r, "<tds:Model>");
	r = ui_get("/ui/", "bob", "Aa0!\"#$%&'()*+,-./:;<=>?@[\\]^_ `{|}~Zz9bcdefghijklmnopqrstuvwxy");
	expect("... but not with it cut to 63", r, "401");
	auth_reset();
	r = ui_post("/ui/users", "admin", A_PW, "do=role&name=admin&role=operator");
	expect("changing your own role (the last admin)", r, "You can&#39;t change your own role.");
	r = ui_post("/ui/users", "admin", A_PW, "do=del&name=admin");
	expect("deleting yourself", r, "You can&#39;t delete yourself.");
	r = ui_post("/ui/users", "admin", A_PW, "do=passwd&name=%s&pw=abcdefgh1&pw2=abcdefgh1", urlenc("<script>x</script>"));
	expect("an unknown user, echoed escaped", r, "No user &quot;&lt;script&gt;x&lt;/script&gt;&quot;.");
	absent("... never raw", r, "<script>x");
	*exec_log = 0;
	r = ui_post("/ui/users", "admin", A_PW, "do=role&name=bob&role=admin");
	expect("make bob admin", r, "Role changed.");
	check("... camcfg user role", !strcmp(exec_log, "user role bob admin;"));
	r = ui_post("/ui/users", "admin", A_PW, "do=passwd&name=bob&pw=new+pass+1&pw2=new+pass+1");
	expect("change bob's password", r, "Password changed.");
	check("... on stdin", !strcmp(exec_in, "new pass 1\n"));
	expect("... bob logs in with it", ui_get("/ui/users", "bob", "new pass 1"), "200 OK");
	r = ui_post("/ui/users", "bob", "new pass 1", "do=role&name=admin&role=operator");
	expect("with two admins, one may be demoted", r, "Role changed.");
	expect("... admin is an operator now", ui_get("/ui/users", "admin", A_PW), "403");
	r = ui_post("/ui/users", "bob", "new pass 1", "do=role&name=bob&role=viewer");
	expect("bob can't change his own role", r, "You can&#39;t change your own role.");
	r = ui_post("/ui/users", "bob", "new pass 1", "do=role&name=admin&role=admin");
	r = ui_post("/ui/users", "admin", A_PW, "do=del&name=bob");
	expect("delete bob", r, "User deleted.");
	exec_fail = 1;
	r = ui_post("/ui/users", "admin", A_PW, "do=add&name=carol&role=viewer&pw=short&pw2=short");
	expect("camcfg refusing: its message, escaped", r, "<p class=\"msg err\">&lt;b&gt;refused&lt;/b&gt; &amp; logged</p>");
	expect("... as a 400", r, "400 Bad Request");
	exec_fail = 0;
	expect("incomplete form", ui_post("/ui/users", "admin", A_PW, "do=add&name=carol"), "Incomplete form.");
	expect("unknown action", ui_post("/ui/users", "admin", A_PW, "do=frob&name=op"), "Incomplete form.");
	b[0] = 0;
	for (int i = 0; i < MAX_USERS; i++)
		snprintf(b + strlen(b), sizeof b - strlen(b), "u%d:%s:password%d\n", i, i ? "viewer" : "admin", i);
	write_file(users_path, b);
	*exec_log = 0;
	r = ui_post("/ui/users", "u0", "password0", "do=add&name=x&role=viewer&pw=abcdefgh&pw2=abcdefgh");
	expect("a 17th user is refused (camhttpd reads 16)", r, "At most 16 users.");
	check("... camcfg not run", !*exec_log);
	r = ui_post("/ui/users", "u1", "password1", "do=add&name=x&role=viewer&pw=abcdefgh&pw2=abcdefgh");
	expect("only admins manage users", r, "403");
	write_file(users_path, users_txt);
	auth_reset();

	/* SSH keys */
	nfake_keys = 0;
	snprintf(fake_keys[nfake_keys++], sizeof fake_keys[0], "ssh-ed25519\tSHA256:abc+/def\t<script>alert(1)</script>");
	snprintf(fake_keys[nfake_keys++], sizeof fake_keys[0], "ssh-rsa\tSHA256:rsa\tlaptop");
	r = ui_get("/ui/ssh", "admin", A_PW);
	expect("keys listed, the comment escaped", r, "<td>&lt;script&gt;alert(1)&lt;/script&gt;</td>");
	absent("... never raw", r, "<script>alert");
	expect("... with the fingerprint", r, "<td>SHA256:abc+/def</td>");
	expect("... and a delete form", r, "name=\"fp\" value=\"SHA256:rsa\"");
	*exec_log = 0;
	r = ui_post("/ui/ssh", "admin", A_PW, "do=add&key=%s", urlenc("ssh-ed25519 AAAAC3Nza me@host"));
	expect("add a key", r, "Key added.");
	check("... the line on stdin", !strcmp(exec_log, "sshkey list;sshkey add;") || !strcmp(exec_log, "sshkey add;sshkey list;"));
	check("... whole", !strcmp(exec_in, "ssh-ed25519 AAAAC3Nza me@host\n"));
	*exec_log = 0;
	r = ui_post("/ui/ssh", "admin", A_PW, "do=del&n=2&fp=SHA256:other");
	expect("delete with a stale fingerprint", r, "The key list has changed");
	check("... nothing deleted", !strstr(exec_log, "del"));
	r = ui_post("/ui/ssh", "admin", A_PW, "do=del&n=2&fp=%s", urlenc("SHA256:rsa"));
	expect("delete key 2", r, "Key deleted.");
	check("... camcfg sshkey del 2", strstr(exec_log, "sshkey del 2;") != NULL);
	expect("delete key 99", ui_post("/ui/ssh", "admin", A_PW, "do=del&n=99&fp=x"), "has changed");
	expect("empty key", ui_post("/ui/ssh", "admin", A_PW, "do=add&key="), "Paste a public key line.");
	exec_fail = 1;
	expect("camcfg refusing a key: its message", ui_post("/ui/ssh", "admin", A_PW, "do=add&key=x"), "&lt;b&gt;refused");
	exec_fail = 0;
	nfake_keys = 0;
	expect("no keys: SSH is off", ui_get("/ui/ssh", "admin", A_PW), "nobody can log in over SSH");
	expect("operator: no SSH page", ui_post("/ui/ssh", "op", O_PW, "do=add&key=x"), "403");

	/* System */
	r = ui_get("/ui/system", "admin", A_PW);
	expect("system page: the reboot note (we run from flash now)", r, "The camera is back in about a minute.");
	absent("... not the RAM-test warning", r, "back on the stock firmware");
	expect("... firmware version", r, "1.2.3-test");
	r = ui_post("/ui/system", "admin", A_PW, "do=reboot");
	expect("reboot without the box", r, "Tick the box");
	check("... no reboot", !reboot_at);
	r = ui_post("/ui/system", "admin", A_PW, "do=reboot&confirm=1");
	expect("reboot", r, "Rebooting now.");
	check("... asked, not done yet", reboot_at && !reboots);
	cl.fd = 99;                                         /* the reply still going out */
	reboot_check(mono_ms());
	check("... waits for the reply", !reboots);
	cl.fd = -1;
	reboot_check(mono_ms());
	check("... then reboots once the reply is out", reboots == 1 && !reboot_at);
	r = ui_post("/ui/system", "admin", A_PW, "do=reboot&confirm=1");
	cl.fd = 99;
	mono_adj += 3001;
	reboot_check(mono_ms());
	mono_adj -= 3001;
	cl.fd = -1;
	check("... or after 3 s anyway", reboots == 2);

	/* the real camcfg (TEST_CAMCFG): its rules, its messages, through the form */
	if (getenv("TEST_CAMCFG")) {
		camcfg_bin = getenv("TEST_CAMCFG");
		real_exec = 1;
		r = ui_post("/ui/users", "admin", A_PW, "do=add&name=carol&role=viewer&pw=%s&pw2=%s", urlenc(P64), urlenc(P64));
		expect("real camcfg: add with every symbol", r, "User added.");
		char users[2048];
		FILE *f = fopen(users_path, "r");
		size_t n = f ? fread(users, 1, sizeof users - 1, f) : 0;
		users[n] = 0;
		if (f) fclose(f);
		check("... stored whole", strstr(users, "\ncarol:viewer:" P64 "\n") != NULL);
		expect("... carol logs in with Digest", ui_get("/ui/", "carol", P64), "200 OK");
		expect("... and a UsernameToken", run(soap_req(DEV, wsse("carol", P64, time(NULL), 0, 0), B_INFO, NULL)),
		       "<tds:Model>");
		char p300[301];
		memset(p300, 'y', 300);
		p300[300] = 0;
		static const struct { const char *pw, *why; } pb[] = {
			{ "Short7!", "at least 8 characters" }, { P64 "Q", "at most 64" }, { NULL, "at most 64" },
			{ "tab\tinside1", "ASCII" }, { "caf\xc3\xa9-latte", "ASCII" }, { " leading-space", "start or end" },
			{ "trailing-space ", "start or end" }, { "DAVE-the-cam", "user name" }, { "line\nbreak99", "one line" },
		};
		for (size_t i = 0; i < sizeof pb / sizeof pb[0]; i++) {
			const char *pw = pb[i].pw ? pb[i].pw : p300, *m;
			r = ui_post("/ui/users", "admin", A_PW, "do=add&name=dave-the-cam&role=viewer&pw=%s&pw2=%s",
				    urlenc(pw), urlenc(pw));
			m = strstr(r, "msg err\">");
			printf("   camcfg says: %.*s\n", m ? (int)strcspn(m + 9, "<") : 1, m ? m + 9 : "?");
			expect("real camcfg refuses, the UI shows why", r, pb[i].why);
		}
		f = fopen(users_path, "r");
		n = f ? fread(b, 1, sizeof b - 1, f) : 0;
		b[n] = 0;
		if (f) fclose(f);
		check("... nothing stored (300 characters not cut to 64)", !strcmp(b, users) && !strstr(b, "dave"));
		r = ui_post("/ui/users", "admin", A_PW, "do=passwd&name=carol&pw=%s&pw2=%s", urlenc("short"), urlenc("short"));
		expect("real camcfg: passwd refused too", r, "at least 8");
		r = ui_post("/ui/users", "admin", A_PW, "do=del&name=carol");
		expect("real camcfg: delete", r, "User deleted.");
		r = ui_post("/ui/ssh", "admin", A_PW, "do=add&key=%s", urlenc("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAECAwQFBgcICQoLD"
			    "A0ODxAREhMUFRYXGBkaGxwdHh8g <script>me</script>"));
		expect("real camcfg: add a key", r, "Key added.");
		expect("... listed with ssh-keygen's fingerprint", r, "<td>SHA256:mKqU+0K8OhKmA8bBQi9Rz0Q5l7/g160hIP+rJYSTNj4</td>");
		expect("... the comment escaped", r, "&lt;script&gt;me&lt;/script&gt;");
		r = ui_post("/ui/ssh", "admin", A_PW, "do=add&key=%s", urlenc("ssh-dss AAAAB3NzaC1kc3MAAAABcAAAAAFxAAAAAWcAAAABeQ=="));
		expect("real camcfg: a DSA key refused with its reason", r, "key type: ssh-ed25519");
		r = ui_post("/ui/ssh", "admin", A_PW, "do=del&n=1&fp=%s", urlenc("SHA256:mKqU+0K8OhKmA8bBQi9Rz0Q5l7/g160hIP+rJYSTNj4"));
		expect("real camcfg: delete the key", r, "Key deleted.");
		snprintf(path, sizeof path, "%s/ssh/authorized_keys", dir);
		unlink(path);
		snprintf(path, sizeof path, "%s/ssh", dir);
		rmdir(path);
		snprintf(path, sizeof path, "%s/.lock", dir);
		unlink(path);
		real_exec = 0;
		camcfg_bin = "/nonexistent/camcfg";
	} else {
		printf("skip: the real camcfg behind the UI (set TEST_CAMCFG)\n");
	}
	write_file(users_path, users_txt);
	auth_reset();
}

/* ---- first-boot claim and admin recovery (#128) ----------------------------------------------- */

static void set_uptime(const char *v) { write_file(uptime_path, v); }

/* camhttpd's log (stderr) while a request runs: to check what it says and what it never says. */
static char logbuf[16384], log_file[700];
static int log_saved = -1;
static void log_start(void)
{
	char d[256];
	dir_of(users_path, d, sizeof d);
	snprintf(log_file, sizeof log_file, "%s/log.txt", d);
	fflush(stderr);
	int fd = open(log_file, O_WRONLY | O_CREAT | O_TRUNC, 0600);
	if (fd < 0) { perror(log_file); exit(1); }
	log_saved = dup(2);
	dup2(fd, 2);
	close(fd);
}
static const char *log_stop(void)
{
	fflush(stderr);
	dup2(log_saved, 2);
	close(log_saved);
	FILE *f = fopen(log_file, "r");
	size_t n = f ? fread(logbuf, 1, sizeof logbuf - 1, f) : 0;
	logbuf[n] = 0;
	if (f) fclose(f);
	unlink(log_file);
	fputs(logbuf, stderr);                             /* still in the test's log */
	return logbuf;
}

/* A /setup or /recover form POST from the camera's own page: csrf=<the path's token>& and the rest. */
static const char *claim_post(const char *path, const char *fmt, ...)
{
	static char body[3 * UI_BODY_MAX];
	va_list ap;
	int n = snprintf(body, sizeof body, "csrf=%s&", token(path, 0));
	va_start(ap, fmt);
	vsnprintf(body + n, sizeof body - (size_t)n, fmt, ap);
	va_end(ap);
	return run(ui_req("POST", path, NULL, NULL, SAME, body));
}

static void claim_rate_reset(void)
{
	memset(&claim_rate, 0, sizeof claim_rate);
	memset(&mon_claim_rate, 0, sizeof mon_claim_rate);   /* the monitor's own (mon_claim) */
}

/* The recovery code on a page, or "". */
static const char *page_code_of(const char *r)
{
	static char c[40];
	const char *p = strstr(r, "<p class=\"code\" id=\"code\">");
	*c = 0;
	if (p) snprintf(c, sizeof c, "%.*s", (int)strcspn(p + 26, "<"), p + 26);
	return c;
}

#define KEYLINE "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8g me@laptop"
#define OWNER_PW "Owner-pass-1"

static void test_claim(const char *dir)
{
	const char *r, *lg;
	char path[700], b[1024];
	int calls;
	auth_reset();
	claim_rate_reset();
	nfake_keys = 0;
	*exec_log = 0;

	/* unclaimed, outside the window: one page, whatever is asked */
	write_file(users_path, "");
	set_uptime("90061.50 12345.00\n");
	static const char *const paths[] = { "/", "/ui/", "/ui/users", "/setup", "/recover", "/ui.css", "/ui.js", "/x" };
	for (size_t i = 0; i < sizeof paths / sizeof paths[0]; i++) {
		r = ui_get(paths[i], NULL, NULL);
		if (!strstr(r, "503 Service Unavailable") || !strstr(r, "setup is closed") ||
		    !strstr(r, "Power-cycle the camera") || !strstr(r, "http://192.0.2.10/setup") ||
		    !strstr(r, "Content-Security-Policy")) {
			fprintf(stderr, "FAIL unclaimed after the window: %s\n%s\n", paths[i], r);
			exit(1);
		}
	}
	printf("ok: unclaimed after the window: every page is the power-cycle page (503, CSP)\n");
	r = claim_post("/setup", "name=evil&pw=Evil-pass-1&pw2=Evil-pass-1");
	expect("... a setup POST too", r, "setup is closed");
	check("... and camcfg isn't run", !*exec_log);
	r = ui_get("/snapshot.jpg", "admin", A_PW);
	expect("... snapshot: 503", r, "503 Service Unavailable");
	set_uptime("garbage\n");
	expect("an unreadable uptime counts as outside the window", ui_get("/setup", NULL, NULL), "setup is closed");
	set_uptime("1800.00 1.00\n");
	expect("... and so does exactly 30 minutes", ui_get("/setup", NULL, NULL), "setup is closed");
	unlink(uptime_path);
	expect("... and no /proc/uptime", ui_get("/setup", NULL, NULL), "setup is closed");

	/* unclaimed, inside the window */
	set_uptime("100.00 50.00\n");
	r = ui_get("/ui/", NULL, NULL);
	expect("unclaimed: /ui/ redirects to /setup", r, "302 Found");
	expect("... Location /setup", r, "Location: /setup\r\n");
	expect("... / too", ui_get("/", "admin", A_PW), "Location: /setup\r\n");
	expect("... /recover too (no code exists yet)", ui_get("/recover", NULL, NULL), "Location: /setup\r\n");
	expect("... /ui.js too", ui_get("/ui.js", NULL, NULL), "Location: /setup\r\n");
	r = ui_get("/ui.css", NULL, NULL);
	expect("/ui.css is served for the setup page", r, "text/css");
	r = ui_get("/setup", NULL, NULL);
	expect("GET /setup: the form", r, "200 OK");
	expect("... claim it on a network only you use", r, "network only you use");
	expect("... minutes left (1800 - 100 s)", r, "(29 min left)");
	expect("... with a /setup token", r, token("/setup", 0));
	expect("... the password fields", r, "name=\"pw2\"");
	expect("... the optional key", r, "name=\"key\"");
	expect("... CSP", r, "Content-Security-Policy: default-src 'none'");
	expect("... no cache", r, "Cache-Control: no-store");
	expect("snapshot: 503 while unclaimed", ui_get("/snapshot.jpg", NULL, NULL), "503 Service Unavailable");
	expect("preview: 503 while unclaimed", ui_get("/preview.mjpg", "admin", A_PW), "503 Service Unavailable");
	for (size_t i = 0; i < sizeof ops / sizeof ops[0]; i++) {     /* PRE_AUTH ones included */
		char body[200], nonce[NONCE_LEN + 1];
		snprintf(body, sizeof body, "<tds:%s/>", ops[i].name);
		r = run(soap_req(DEV, NULL, body, NULL));
		if (!strstr(r, "400 Bad Request") || !strstr(r, "ter:NotAuthorized") || !strstr(r, "not set up yet")) {
			fprintf(stderr, "FAIL unclaimed: %s without credentials\n%s", ops[i].name, r);
			exit(1);
		}
		nonce_make((unsigned long)mono(), ++ui_ctr, nonce);
		r = run(soap_req(MED, wsse("admin", A_PW, time(NULL), 0, 0), body, digest("admin", A_PW, "POST", MED, nonce, 1)));
		if (!strstr(r, "ter:NotAuthorized") || !strstr(r, "not set up yet")) {
			fprintf(stderr, "FAIL unclaimed: %s with credentials\n%s", ops[i].name, r);
			exit(1);
		}
	}
	printf("ok: unclaimed: every ONVIF operation (PRE_AUTH too) answers ter:NotAuthorized \"not set up\"\n");
	write_file(users_path, "view:viewer:V1ew:Pass&\n");
	r = ui_get("/ui/", "view", V_PW);
	expect("a users file without an admin is unclaimed too (a viewer's login doesn't help)", r, "Location: /setup\r\n");
	expect("... ONVIF too", run(soap_req(DEV, wsse("view", V_PW, time(NULL), 0, 0), B_INFO, NULL)), "not set up yet");
	write_file(users_path, "");

	/* the Host must be the camera's address (DNS rebinding) */
	r = run("GET /setup HTTP/1.1\r\nHost: camera.attacker.example\r\n\r\n");
	expect("GET /setup by another Host name: 421", r, "421 Misdirected Request");
	expect("... with a link to the camera's address", r, "href=\"http://192.0.2.10/setup\"");
	absent("... and no form token", r, "name=\"csrf\"");
	snprintf(b, sizeof b, "POST /setup HTTP/1.1\r\nHost: rebound.example\r\nOrigin: http://rebound.example\r\n" FORM_CT
		 "Content-Length: %zu\r\n\r\ncsrf=%s&name=x&pw=Evil-pass-1&pw2=Evil-pass-1",
		 strlen("csrf=&name=x&pw=Evil-pass-1&pw2=Evil-pass-1") + 40, token("/setup", 0));
	r = run(b);
	expect("POST /setup by a rebound name (Origin = Host): 421", r, "421 Misdirected Request");
	expect("GET /setup at 192.0.2.10:80 is fine", run("GET /setup HTTP/1.1\r\nHost: 192.0.2.10:80\r\n\r\n"), "200 OK");
	check("... camcfg never ran", !*exec_log);

	/* CSRF: Origin/Referer, the token (the /setup key: not a user's, not /recover's), the body */
	char body[400];
	snprintf(body, sizeof body, "csrf=%s&name=owner&pw=%s&pw2=%s", token("/setup", 0), OWNER_PW, OWNER_PW);
	r = run(ui_req("POST", "/setup", NULL, NULL, FORM_CT, body));
	expect("setup POST without Origin or Referer: 403", r, "403 Forbidden");
	r = run(ui_req("POST", "/setup", NULL, NULL, "Origin: http://evil.example\r\n" FORM_CT, body));
	expect("... with another site's Origin: 403", r, "403 Forbidden");
	r = run(ui_req("POST", "/setup", NULL, NULL, "Referer: http://192.0.2.10/setup\r\n" FORM_CT, body));
	check("... (a Referer of this host instead of Origin passes this check)", !strstr(r, "403 Forbidden"));
	write_file(users_path, "");                         /* undo that claim */
	*exec_log = 0;
	claim_rate_reset();
	snprintf(body, sizeof body, "csrf=%s&name=owner&pw=%s&pw2=%s", token("admin", 0), OWNER_PW, OWNER_PW);
	expect("... a user's UI token: 403", run(ui_req("POST", "/setup", NULL, NULL, SAME, body)), "403 Forbidden");
	snprintf(body, sizeof body, "csrf=%s&name=owner&pw=%s&pw2=%s", token("/recover", 0), OWNER_PW, OWNER_PW);
	expect("... /recover's token: 403", run(ui_req("POST", "/setup", NULL, NULL, SAME, body)), "403 Forbidden");
	snprintf(body, sizeof body, "csrf=%s&name=owner&pw=%s&pw2=%s", token("/setup", 2), OWNER_PW, OWNER_PW);
	expect("... a stale token (two buckets ago): 403", run(ui_req("POST", "/setup", NULL, NULL, SAME, body)), "403 Forbidden");
	snprintf(body, sizeof body, "name=owner&pw=%s&pw2=%s", OWNER_PW, OWNER_PW);
	expect("... no token: 403", run(ui_req("POST", "/setup", NULL, NULL, SAME, body)), "403 Forbidden");
	snprintf(body, sizeof body, "csrf=%s&name=owner&pw=%s&pw2=%s", token("/setup", 0), OWNER_PW, OWNER_PW);
	expect("... not a form: 415", run(ui_req("POST", "/setup", NULL, NULL, "Origin: http://192.0.2.10\r\n"
	       "Content-Type: text/plain\r\n", body)), "415");
	expect("... a malformed form: 400", claim_post("/setup", "name=owner&pw=%%zz"), "400 Bad Request");
	check("... camcfg never ran", !*exec_log);
	claim_rate_reset();
	r = claim_post("/setup", "name=owner&pw=%s&pw2=%s", OWNER_PW, "Owner-pass-2");
	expect("two different passwords: refused", r, "The two passwords differ.");
	r = claim_post("/setup", "name=owner&pw=Owner%%0Apass&pw2=Owner%%0Apass");
	expect("a newline in the password (it would start camcfg's key line): refused", r, "must be one line");
	r = claim_post("/setup", "name=owner&pw=%s&pw2=%s&key=ssh-ed25519+AAAA%%0Ax", OWNER_PW, OWNER_PW);
	expect("... in the key too", r, "must be one line");
	r = claim_post("/setup", "name=%%3Cb%%3E&pw=%s", OWNER_PW);
	expect("an incomplete form, the name echoed escaped", r, "value=\"&lt;b&gt;\"");
	expect("... Incomplete form.", r, "Incomplete form.");
	check("... camcfg never ran", !*exec_log);
	exec_fail = 1;
	r = claim_post("/setup", "name=owner&pw=%s&pw2=%s", OWNER_PW, OWNER_PW);
	expect("camcfg refusing the claim: its message, escaped", r, "&lt;b&gt;refused&lt;/b&gt; &amp; logged");
	expect("... 400", r, "400 Bad Request");
	exec_fail = 0;
	expect("... still unclaimed", ui_get("/ui/", NULL, NULL), "Location: /setup");

	/* rate limit: CLAIM_POSTS a minute that passed Origin and token (Gate 3 #5: refused ones, which
	 * another site can send at will, don't use it up) */
	claim_rate_reset();
	for (int i = 0; i < 3 * CLAIM_POSTS; i++) {
		run(ui_req("POST", "/setup", NULL, NULL, SAME, "name=x"));                       /* no token */
		run(ui_req("POST", "/setup", NULL, NULL, "Origin: http://evil.example\r\n" FORM_CT, "name=x"));
	}
	check("posts refused for Origin or token count nothing", claim_rate.n == 0);
	for (int i = 0; i < CLAIM_POSTS; i++) claim_post("/setup", "name=x");                  /* incomplete */
	*exec_log = 0;
	r = claim_post("/setup", "name=owner&pw=%s&pw2=%s", OWNER_PW, OWNER_PW);
	expect("the 11th setup POST in a minute: 429", r, "429 Too Many Requests");
	check("... camcfg not run", !*exec_log);
	mono_adj += 61000;
	expect("... a minute on, GET still works", ui_get("/setup", NULL, NULL), "200 OK");

	/* the claim */
	log_start();
	r = claim_post("/setup", "name=owner&pw=%s&pw2=%s&key=%s", urlenc(OWNER_PW), urlenc(OWNER_PW), urlenc(KEYLINE));
	lg = log_stop();
	expect("claim: 200", r, "200 OK");
	expect("... camcfg claim NAME", exec_log, "claim owner;");
	check("... password and key on stdin, one line each", !strcmp(exec_in, OWNER_PW "\n" KEYLINE "\n"));
	expect("... the recovery code shown (camcfg's notes around it skipped)", r,
	       "<p class=\"code\" id=\"code\">ABCD-EFGH-IJKL-MNOP-QRST-UVWX-YZ</p>");
	expect("... shown once", r, "shown only this once");
	expect("... a link on to the UI", r, "href=\"/ui/\"");
	expect("... no cache", r, "Cache-Control: no-store");
	absent("... and no password on the page", r, OWNER_PW);
	expect("... logged: address, admin, key", lg, "192.0.2.50: camera claimed: admin owner, SSH key added");
	absent("... the log has no password", lg, OWNER_PW);
	absent("... and no code", lg, "ABCD-EFGH");
	absent("... in any form", lg, "ABCDEFGH");
	check("... the SSH key went to camcfg", nfake_keys == 1);
	r = ui_get("/setup", NULL, NULL);
	expect("claimed: GET /setup is a 404", r, "404 Not Found");
	absent("... the code is never shown again", r, "ABCD");
	*exec_log = 0;
	r = claim_post("/setup", "name=evil&pw=Evil-pass-1&pw2=Evil-pass-1");
	expect("claimed: POST /setup is a 404", r, "404 Not Found");
	check("... camcfg not run", !*exec_log);
	expect("claimed: the UI asks for a login", ui_get("/ui/", NULL, NULL), "401 Unauthorized");
	expect("... and the new admin gets in", ui_get("/ui/users", "owner", OWNER_PW), "200 OK");
	expect("claimed: ONVIF works again", run(soap_req(DEV, wsse("owner", OWNER_PW, time(NULL), 0, 0), B_INFO, NULL)),
	       "GetDeviceInformationResponse");
	set_uptime("90061.50 12345.00\n");
	expect("claimed, after the window: the UI as usual", ui_get("/ui/users", "owner", OWNER_PW), "200 OK");
	expect("... /setup still 404", ui_get("/setup", NULL, NULL), "404 Not Found");

	/* recovery */
	r = ui_get("/recover", NULL, NULL);
	expect("/recover after the window: closed (403)", r, "403 Forbidden");
	expect("... power-cycle", r, "Power-cycle the camera");
	r = claim_post("/recover", "code=ABCDEFGHIJKLMNOPQRSTUVWXYZ&pw=New-pass-123&pw2=New-pass-123");
	expect("... a POST too", r, "Recovery is closed");
	check("... camcfg not run", !*exec_log);
	set_uptime("600.00 1.00\n");
	r = ui_get("/recover", NULL, NULL);
	expect("/recover in the window: the form", r, "200 OK");
	expect("... (20 min left)", r, "(20 min left)");
	expect("... a /recover token", r, token("/recover", 0));
	expect("... no login needed", r, "name=\"code\"");
	expect("GET /recover by another Host: 421", run("GET /recover HTTP/1.1\r\nHost: cam.example\r\n\r\n"), "421");
	claim_rate_reset();
	snprintf(body, sizeof body, "csrf=%s&code=ABCDEFGHIJKLMNOPQRSTUVWXYZ&pw=New-pass-123&pw2=New-pass-123", token("/setup", 0));
	expect("recover with /setup's token: 403", run(ui_req("POST", "/recover", NULL, NULL, SAME, body)), "403 Forbidden");
	snprintf(body, sizeof body, "csrf=%s&code=ABCDEFGHIJKLMNOPQRSTUVWXYZ&pw=New-pass-123&pw2=New-pass-123", token("/recover", 0));
	expect("... without Origin: 403", run(ui_req("POST", "/recover", NULL, NULL, FORM_CT, body)), "403 Forbidden");
	r = claim_post("/recover", "code=ABCDEFGHIJKLMNOPQRSTUVWXYZ&pw=New-pass-123&pw2=New-pass-124");
	expect("... different passwords: refused before camcfg", r, "The two passwords differ.");
	check("... camcfg never ran", !*exec_log);
	auth_reset();
	log_start();
	for (int i = 0; i < FAIL_MAX; i++) {
		r = claim_post("/recover", "code=ZZZZ-ZZZZ-ZZZZ-ZZZZ-ZZZZ-ZZZZ-ZZ&pw=New-pass-123&pw2=New-pass-123");
		if (!strstr(r, "403 Forbidden") || !strstr(r, "Wrong recovery code.")) {
			fprintf(stderr, "FAIL wrong code %d:\n%s\n", i, r);
			exit(1);
		}
	}
	lg = log_stop();
	printf("ok: %d wrong codes: 403 \"Wrong recovery code.\" each\n", FAIL_MAX);
	expect("... logged, the last one blocked", lg, "192.0.2.50: wrong recovery code, blocked");
	absent("... the codes aren't logged", lg, "ZZZZ");
	absent("... nor the password", lg, "New-pass-123");
	calls = (int)strlen(exec_log);
	r = claim_post("/recover", "code=%s&pw=New-pass-123&pw2=New-pass-123", fake_code);
	expect("then even the right code is refused: the address is locked", r, "429 Too Many Requests");
	expect("... saying so", r, "Too many wrong codes");
	check("... camcfg not run", (int)strlen(exec_log) == calls);
	r = ui_get("/ui/users", "owner", OWNER_PW);
	expect("... the same lockout as logins: the admin's own login is refused too", r, "401 Unauthorized");
	mono_adj += (FAIL_WINDOW + 1) * 1000LL;
	claim_rate_reset();
	r = claim_post("/recover", "name=view&code=%s&pw=New-pass-123&pw2=New-pass-123", fake_code);
	expect("the code can't reset a non-admin: camcfg's message", r, "no admin view");
	expect("... 400", r, "400 Bad Request");
	log_start();
	r = claim_post("/recover", "code=%s&pw=%s&pw2=%s", urlenc("abcd efgh-ijkl-mnop-qrst-uvwx-yz"), "New-pass-123",
		       "New-pass-123");
	lg = log_stop();
	expect("the right code (as typed: lower case, spaces): 200", r, "200 OK");
	expect("... camcfg recover, no name: the code's admin", exec_log, "recover;");
	check("... code and password on stdin", !strcmp(exec_in, "abcd efgh-ijkl-mnop-qrst-uvwx-yz\nNew-pass-123\n"));
	expect("... the new code shown once", r, "<p class=\"code\" id=\"code\">BCDE-FGHI-JKLM-NOPQ-RSTU-VWXY-ZA</p>");
	expect("... logged with the admin's name", lg, "192.0.2.50: admin owner's password reset with the recovery code");
	absent("... not the password", lg, "New-pass-123");
	absent("... nor either code", lg, "BCDE");
	expect("... the old password is gone", ui_get("/ui/users", "owner", OWNER_PW), "401 Unauthorized");
	auth_reset();
	expect("... the new one works", ui_get("/ui/users", "owner", "New-pass-123"), "200 OK");
	r = claim_post("/recover", "code=ABCDEFGHIJKLMNOPQRSTUVWXYZ&pw=Newer-pass-1&pw2=Newer-pass-1");
	expect("the old code no longer works", r, "Wrong recovery code.");
	auth_reset();
	claim_rate_reset();

	/* the real camcfg: claim and recover end to end, its hash and its rules */
	if (getenv("TEST_CAMCFG")) {
		char code[40], code2[40];
		camcfg_bin = getenv("TEST_CAMCFG");
		real_exec = 1;
		write_file(users_path, "");
		set_uptime("100.00 50.00\n");
		r = claim_post("/setup", "name=owner&pw=short&pw2=short");
		expect("real camcfg: a short password refused with its reason", r, "at least 8 characters");
		r = claim_post("/setup", "name=owner&pw=%s&pw2=%s&key=%s", urlenc(OWNER_PW), urlenc(OWNER_PW), urlenc("ssh-dss AAAA"));
		expect("real camcfg: a DSA key refused (nothing written)", r, "key type");
		expect("... still unclaimed", ui_get("/ui/", NULL, NULL), "Location: /setup");
		r = claim_post("/setup", "name=owner&pw=%s&pw2=%s&key=%s", urlenc(OWNER_PW), urlenc(OWNER_PW), urlenc(KEYLINE));
		expect("real camcfg: claim", r, "200 OK");
		snprintf(code, sizeof code, "%s", page_code_of(r));
		check("... a 26-character code in groups of 4", strlen(code) == 32 &&
		      strspn(code, "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567-") == 32 && code[4] == '-');
		FILE *f = fopen(users_path, "r");
		size_t n = f ? fread(b, 1, sizeof b - 1, f) : 0;
		b[n] = 0;
		if (f) fclose(f);
		check("... the admin in the users file", !strcmp(b, "owner:admin:" OWNER_PW "\n"));
		snprintf(path, sizeof path, "%s/recovery", dir);
		f = fopen(path, "r");
		n = f ? fread(b, 1, sizeof b - 1, f) : 0;
		b[n] = 0;
		if (f) fclose(f);
		check("... the recovery file holds a hash, not the code", strstr(b, "algo=pbkdf2-sha256") && !strstr(b, code) &&
		      strstr(b, "user=owner"));
		expect("... /setup is gone", ui_get("/setup", NULL, NULL), "404 Not Found");
		r = claim_post("/recover", "code=%s&pw=Recov-pass-1&pw2=Recov-pass-1", "AAAA-AAAA-AAAA-AAAA-AAAA-AAAA-AA");
		expect("real camcfg: a wrong code", r, "Wrong recovery code.");
		r = claim_post("/recover", "code=%s&pw=short&pw2=short", code);
		expect("real camcfg: the right code, a short password: its reason", r, "at least 8 characters");
		r = claim_post("/recover", "code=%s&pw=Recov-pass-1&pw2=Recov-pass-1", code);
		expect("real camcfg: recover", r, "200 OK");
		snprintf(code2, sizeof code2, "%s", page_code_of(r));
		check("... a new code", strlen(code2) == 32 && strcmp(code, code2));
		auth_reset();
		expect("... the admin logs in with the new password", ui_get("/ui/users", "owner", "Recov-pass-1"), "200 OK");
		r = claim_post("/recover", "code=%s&pw=Recov-pass-2&pw2=Recov-pass-2", code);
		expect("... the old code no longer works", r, "Wrong recovery code.");
		r = claim_post("/recover", "code=%s&pw=Recov-pass-2&pw2=Recov-pass-2", code2);
		expect("... the new one does", r, "200 OK");
		unlink(path);
		snprintf(path, sizeof path, "%s/ssh/authorized_keys", dir);
		unlink(path);
		snprintf(path, sizeof path, "%s/ssh", dir);
		rmdir(path);
		snprintf(path, sizeof path, "%s/.lock", dir);
		unlink(path);
		real_exec = 0;
		camcfg_bin = "/nonexistent/camcfg";
	} else {
		printf("skip: the real camcfg behind /setup and /recover (set TEST_CAMCFG)\n");
	}
	set_uptime("90061.50 12345.00\n");
	write_file(users_path, users_txt);
	nfake_keys = 0;
	auth_reset();
	claim_rate_reset();
}

/* Read what the camera sent on a socketpair. */
static const char *drain(int fd)
{
	static char buf[8192];
	size_t n = 0;
	ssize_t k;
	while (n < sizeof buf - 1 && (k = recv(fd, buf + n, sizeof buf - 1 - n, MSG_DONTWAIT)) > 0) n += (size_t)k;
	buf[n] = 0;
	return buf;
}

static void test_preview(void)
{
	const char *r;
	int sv[2];
	for (int i = 0; i < MAX_CLIENTS; i++) {
		if (clients[i].fd >= 0) close(clients[i].fd);
		clients[i].fd = clients[i].file_fd = -1;
		clients[i].state = 0;
	}
	expect("preview without credentials -> 401", ui_get("/preview.mjpg", NULL, NULL), "401");
	expect("preview: POST -> 405", run(ui_req("POST", "/preview.mjpg", "view", V_PW, SAME, "a=1")), "405");
	if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv)) {
		printf("skip: preview stream (socketpair: %s)\n", strerror(errno));
		return;
	}
	struct client *c = &clients[0];
	const char *req = ui_req("GET", "/preview.mjpg", "view", V_PW, NULL, NULL);
	client_reset(c, sv[0]);
	inet_pton(AF_INET, peer_ip, &c->peer);
	strcpy(c->local, "192.0.2.10");
	memcpy(c->in, req, strlen(req));
	c->in_len = strlen(req);
	http_feed(c);
	check("preview: the connection streams", c->state == 3);
	client_write(c);
	r = drain(sv[1]);
	expect("preview: multipart head", r, "HTTP/1.1 200 OK\r\n");
	expect("... boundary", r, "Content-Type: multipart/x-mixed-replace; boundary=camframe\r\n\r\n--camframe\r\n");
	expect("... security headers", r, "X-Frame-Options: DENY\r\n");
	absent("... no Content-Length on the stream", r, "Content-Length");
	r = ui_get("/preview.mjpg", "admin", A_PW);
	expect("a second preview -> 503", r, "503 Service Unavailable");
	expect("... saying why", r, "one preview at a time");

	write_file(snap_path, "\xff\xd8JPEGDATA\xff\xd9");
	fake_ctl = "ok 12\n";
	snap_asked = mono_ms() - SNAP_REUSE_MS;
	preview_tick(mono_ms());
	client_write(c);
	r = drain(sv[1]);
	expect("preview: a part per JPEG", r, "Content-Type: image/jpeg\r\nContent-Length: 12\r\n\r\n\xff\xd8JPEGDATA\xff\xd9"
	       "\r\n--camframe\r\n");
	check("... exactly one", count(r, "Content-Length") == 1 && c->file_fd < 0 && c->state == 3);
	int asks = ctl_calls;
	preview_tick(mono_ms());
	check("preview: no second frame within the second", ctl_calls == asks && !*drain(sv[1]));
	mono_adj += 1000;
	preview_tick(mono_ms());
	client_write(c);
	check("preview: the same JPEG isn't sent again a second later", ctl_calls == asks + 1 && !*drain(sv[1]));
	mono_adj += 2000;
	preview_tick(mono_ms());
	client_write(c);
	expect("... but after 3 s it is", drain(sv[1]), "Content-Length: 12\r\n");
	mono_adj += 1000;
	write_file(snap_path, "\xff\xd8NEWJPEGDATA\xff\xd9");
	fake_ctl = "ok 15\n";
	preview_tick(mono_ms());
	client_write(c);
	expect("preview: a new JPEG goes out", drain(sv[1]), "Content-Length: 15\r\n\r\n\xff\xd8NEWJPEGDATA\xff\xd9\r\n--camframe\r\n");
	mono_adj += 1000;
	fake_ctl = "err no recent snapshot\n";
	preview_tick(mono_ms());
	client_write(c);
	check("preview: nothing while rtspd has no fresh JPEG (older than 5 s)", !*drain(sv[1]) && c->file_fd < 0);
	mono_adj += 1000;
	fake_ctl = "ok 15\n";
	write_file(snap_path, "\xff\xd8NEWJPEGDATB\xff\xd9");
	c->out_len = 5;                                    /* the last frame still going out */
	c->out_off = 0;
	asks = ctl_calls;
	preview_tick(mono_ms());
	check("preview: a slow reader gets no second frame queued", c->out_len == 5 && c->file_fd < 0 && ctl_calls == asks);
	c->out_len = 0;

	/* the slot budget: two held pulls and the preview leave a slot for ONVIF */
	struct in_addr nvr, other;
	inet_pton(AF_INET, "192.0.2.77", &nvr);
	inet_pton(AF_INET, "192.0.2.78", &other);
	for (int i = 1; i <= 2; i++) {
		client_reset(&clients[i], open("/dev/null", O_RDONLY));
		clients[i].peer = nvr;
		clients[i].state = 2;
	}
	struct client *s = slot_for(nvr);
	check("an ONVIF request gets the free slot while a preview and two pulls run", s == &clients[3]);
	for (int i = 3; i < MAX_CLIENTS; i++) {               /* a browser's parallel requests, just opened */
		client_reset(&clients[i], open("/dev/null", O_RDONLY));
		clients[i].peer = other;
	}
	check("every slot taken by fresh connections: none is pushed out (they wait in the backlog)",
	      slot_for(nvr) == NULL && !can_accept() && clients[3].fd >= 0);
	clients[3].since -= HDR_GRACE_MS + 1;                 /* one stalls for its headers */
	check("... one stalled past HDR_GRACE_MS: accepting again", can_accept());
	s = slot_for(nvr);
	check("... and the stalled one goes, not the preview or a fresh one", s == &clients[3] &&
	      clients[0].fd >= 0 && clients[0].state == 3 && clients[4].fd >= 0);
	for (int i = 1; i < MAX_CLIENTS; i++) client_close(&clients[i]);

	mono_adj += PREVIEW_MS;
	preview_tick(mono_ms());
	client_write(c);
	check("preview: closed after 5 minutes", c->fd < 0);
	mono_adj -= PREVIEW_MS;
	expect("... then another may start", ui_get("/preview.mjpg", "view", V_PW), "multipart/x-mixed-replace");
	close(sv[1]);
	fake_ctl = NULL;
	mono_adj -= 6000;
	unlink(snap_path);
}

/* ---- firmware update from the web UI (#104) ------------------------------------------------------ */

static char upd_test_dir[600];

/* A file of the test's own (rotating buffers: several per call). */
static const char *tfile(const char *name)
{
	static char p[4][700];
	static int k;
	k = (k + 1) % 4;
	snprintf(p[k], sizeof p[k], "%s/%s", upd_test_dir, name);
	return p[k];
}

static const char *slurp(const char *path)
{
	static char b[16384];
	FILE *f = fopen(path, "r");
	size_t n = f ? fread(b, 1, sizeof b - 1, f) : 0;
	b[n] = 0;
	if (f) fclose(f);
	return b;
}

static long fsize(const char *p)
{
	struct stat st;
	return lstat(p, &st) ? -1 : (long)st.st_size;
}

/* The stand-in for camupdate: logs its argv, parent, the size of its package ("-": its stdin,
 * which the monitor opened) and its environment to stub-calls; --check answers as stub-mode says
 * (camupdate.c's own lines); an install waits for stub-go (5 s at most), then ends without
 * rebooting, as a camupdate that failed before its write would. */
static void stub_write(const char *path)
{
	char s[2048];
	snprintf(s, sizeof s,
		 "#!/bin/sh\n"
		 "d='%s'\n"
		 "for a; do f=$a; done\n"
		 "if [ \"$f\" = - ]; then n=$(wc -c | tr -d ' '); else n=$(wc -c < \"$f\" | tr -d ' '); fi\n"
		 "{ echo \"ARGS: $* PPID:$PPID SIZE:$n\"; env | sort | sed 's/^/ENV:/'; } >> \"$d/stub-calls\"\n"
		 "if [ \"$1\" = --check ]; then\n"
		 "  case $(cat \"$d/stub-mode\") in\n"
		 "  ok) echo 'camupdate: OK: version 20261025.1 for MCA40E-IFADO, 3506176 bytes, signed by cam-firmware nano';;\n"
		 "  down) echo 'camupdate: OK: version 20261001.1 for MCA40E-IFADO, 3506176 bytes, signed by cam-firmware nano"
		 " (downgrade allowed)';;\n"
		 "  refuse) echo 'camupdate: REFUSED: package is for another device' >&2; exit 1;;\n"
		 "  html) echo 'camupdate: REFUSED: <script>alert(1)</script> & co' >&2; exit 1;;\n"
		 "  garbage) echo 'all good';;\n"
		 "  hang) exec sleep 30;;\n"
		 "  esac\n"
		 "  exit 0\n"
		 "fi\n"
		 "i=0\n"
		 "while [ ! -f \"$d/stub-go\" ] && [ $i -lt 100 ]; do sleep 0.05; i=$((i+1)); done\n"
		 "echo \"camupdate: can't take the watchdog (No such file or directory); continuing\"\n"
		 "echo 'camupdate: no mtd \"rootfs\"'\n"
		 "exit 1\n", upd_test_dir);
	write_file(path, s);
	chmod(path, 0700);
}

static void stub_mode(const char *m) { write_file(tfile("stub-mode"), m); }

static char pkg[UPD_MAX + 64];                       /* the bytes uploaded (the stub only counts them) */

/* An upload's head: Digest as user (NULL: none), then hdrs; clen (size_t)-1: no Content-Length. */
static const char *upd_head(const char *user, const char *pw, const char *hdrs, size_t clen)
{
	static char buf[4096];
	char nonce[NONCE_LEN + 1], cl_line[48] = "";
	nonce_make((unsigned long)mono(), ++ui_ctr, nonce);
	if (clen != (size_t)-1) snprintf(cl_line, sizeof cl_line, "Content-Length: %zu\r\n", clen);
	snprintf(buf, sizeof buf, "POST " UPD_PATH " HTTP/1.1\r\nHost: 192.0.2.10\r\n%s%s%s%s%s\r\n",
		 user ? "Authorization: " : "", user ? digest(user, pw, "POST", UPD_PATH, nonce, 1) : "",
		 user ? "\r\n" : "", hdrs, cl_line);
	return buf;
}

/* The headers /ui.js sends, with user's token. */
static const char *js_hdrs(const char *user)
{
	static char h[300];
	snprintf(h, sizeof h, "Origin: http://192.0.2.10\r\nContent-Type: application/octet-stream\r\n"
		 "X-CSRF-Token: %s\r\n", token(user, 0));
	return h;
}

/* camupdate --check runs beside the loop: tick until it has answered (5 s at most). */
static void upd_wait(int from)
{
	for (int i = 0; i < 500 && upd.state == from; i++) {
		upd_tick(mono_ms());
		usleep(10000);
	}
}

/* The head and the first `first` body bytes in one piece, as one recv would bring them. */
static void upd_start(struct client *c, const char *user, const char *pw, const char *hdrs, size_t clen, size_t first)
{
	const char *h = upd_head(user, pw, hdrs, clen);
	size_t hl = strlen(h);
	client_reset(c, -1);
	inet_pton(AF_INET, peer_ip, &c->peer);
	strcpy(c->local, "192.0.2.10");
	memcpy(c->in, h, hl);
	if (clen != (size_t)-1 && first > clen) first = clen;
	memcpy(c->in + hl, pkg, first);
	c->in_len = hl + first;
	http_feed(c);
}

/* A whole upload of n bytes on cl (1000 with the head, then 4 KiB pieces): the reply. */
static const char *upd_send(const char *user, const char *pw, const char *hdrs, size_t n)
{
	size_t first = n < 1000 ? n : 1000;
	upd_start(&cl, user, pw, hdrs, n, first);
	for (size_t off = first; cl.state == ST_UPLOAD && off < n; off += 4096)
		upd_take(&cl, pkg + off, n - off < 4096 ? n - off : 4096);
	upd_wait(UPD_CHECK);
	return reply_of(&cl);
}

static void no_upload(const char *what)
{
	char m[200];
	snprintf(m, sizeof m, "%s: nothing staged", what);
	check(m, fsize(tfile("fw/" UPD_FILE)) < 0 && upd.state == UPD_NONE);
}

#define BOSS_PW "B0ssPass!x"

static void test_firmware(const char *dir)
{
	const char *r, *lg, *staged, *calls;
	char h[600], want[400], old_id[17];
	static char ud[600];
	int sv[2];
	snprintf(upd_test_dir, sizeof upd_test_dir, "%s", dir);
	snprintf(ud, sizeof ud, "%s/fw", dir);
	if (mkdir(ud, 0700)) { perror(ud); exit(1); }
	upd_dir = ud;
	static char staged_buf[700];
	snprintf(staged_buf, sizeof staged_buf, "%s", tfile("fw/" UPD_FILE));
	staged = staged_buf;
	static char stub[700];
	snprintf(stub, sizeof stub, "%s", tfile("camupdate-stub"));
	stub_write(stub);
	camupdate_bin = stub;
	stub_mode("ok");
	setenv("CU_KEYS", "/tmp/not-the-owners-keys", 1);   /* camupdate's test-build overrides: never passed on */
	setenv("CAMHTTPD_TEST_LEAK", "1", 1);
	for (size_t i = 0; i < sizeof pkg; i++) pkg[i] = (char)(i * 7 + 3);
	write_file(users_path, "admin:admin:Adm1nPass!\nop:operator:0perPass\nview:viewer:V1ew:Pass&\n"
		   "boss:admin:" BOSS_PW "\n");
	auth_reset();
	for (int i = 0; i < MAX_CLIENTS; i++) {
		if (clients[i].fd >= 0) close(clients[i].fd);
		clients[i].fd = clients[i].file_fd = -1;
		clients[i].state = 0;
	}

	/* the page and the script */
	r = ui_get("/ui/system", "admin", A_PW);
	snprintf(want, sizeof want, "<form method=\"post\" action=\"/ui/firmware\" data-upload data-max=\"%d\"><input "
		 "type=\"hidden\" name=\"csrf\" value=\"%s\">", UPD_MAX, token("admin", 0));
	expect("system page: the upload form, with the page's token", r, want);
	expect("... a .camfw file field", r, "<input type=\"file\" name=\"file\" accept=\".camfw\">");
	expect("... says what happens without the script", r, "<noscript>");
	absent("... the RAM-test warning is gone (we run from flash)", r, "nothing of ours is on the flash");
	expect("... the reboot form stays", r, "Yes, reboot the camera");
	expect("... with a true note", r, "The camera is back in about a minute.");
	expect("... the CSP unchanged", r, "Content-Security-Policy: default-src 'none'; img-src 'self'; style-src 'self'; "
	       "script-src 'self'; connect-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'");
	r = run("GET /ui.js HTTP/1.1\r\nHost: 192.0.2.10\r\n\r\n");
	expect("/ui.js: the file as the raw body", r, "fetch(f.action, { method: 'POST', body: file, credentials: 'same-origin',");
	expect("... octet-stream, the token in a header", r,
	       "headers: { 'Content-Type': 'application/octet-stream', 'X-CSRF-Token': f.elements.csrf.value }");
	r = ui_get("/ui/system", "op", O_PW);
	expect("operator: no System page", r, "403 Forbidden");

	/* GET /ui/firmware: what /ui.js asks first */
	expect("GET /ui/firmware: ready, for an admin", ui_get(UPD_PATH, "admin", A_PW), "ready: up to 5242880 bytes");
	expect("... 403 for an operator", ui_get(UPD_PATH, "op", O_PW), "403 Forbidden");
	expect("... 401 without credentials", ui_get(UPD_PATH, NULL, NULL), "401 Unauthorized");
	expect("... other methods 405", run(ui_req("PUT", UPD_PATH, "admin", A_PW, NULL, NULL)), "405");

	/* refused from the headers, before any of the body is taken */
	r = upd_send(NULL, NULL, js_hdrs("admin"), 4096);
	expect("upload without credentials -> 401", r, "401 Unauthorized");
	expect("... a Digest challenge, with the UI's headers", r, "X-Frame-Options: DENY");
	no_upload("... 401");
	log_start();
	r = upd_send("op", O_PW, js_hdrs("op"), 4096);
	lg = log_stop();
	expect("an operator's upload (own valid token) -> 403", r, "403 Forbidden");
	expect("... logged", lg, "192.0.2.50: user op may not post to /ui/firmware");
	no_upload("... operator");
	expect("a viewer's upload -> 403", upd_send("view", V_PW, js_hdrs("view"), 4096), "403 Forbidden");
	no_upload("... viewer");
	log_start();
	r = upd_send("admin", A_PW, "Origin: http://192.0.2.10\r\nContent-Type: application/octet-stream\r\n", 4096);
	lg = log_stop();
	expect("no X-CSRF-Token -> 403", r, "403 Forbidden");
	expect("... logged with the reason", lg, "POST /ui/firmware by admin refused: missing, stale or foreign form token");
	no_upload("... no token");
	static const char *const bad_tok[] = { "0123456789abcdef0123456789abcdef01234567", "x", "" };
	for (int i = 0; i < 3; i++) {
		snprintf(h, sizeof h, "Origin: http://192.0.2.10\r\nContent-Type: application/octet-stream\r\nX-CSRF-Token: %s\r\n",
			 bad_tok[i]);
		expect("a wrong token -> 403", upd_send("admin", A_PW, h, 4096), "403 Forbidden");
	}
	snprintf(h, sizeof h, "Origin: http://192.0.2.10\r\nContent-Type: application/octet-stream\r\nX-CSRF-Token: %s\r\n",
		 token("boss", 0));
	expect("another admin's token -> 403", upd_send("admin", A_PW, h, 4096), "403 Forbidden");
	snprintf(h, sizeof h, "Origin: http://192.0.2.10\r\nContent-Type: application/octet-stream\r\nX-CSRF-Token: %s\r\n",
		 token("admin", 2));
	expect("a token 30 minutes old -> 403", upd_send("admin", A_PW, h, 4096), "403 Forbidden");
	snprintf(h, sizeof h, "%sX-CSRF-Token: %s\r\n", js_hdrs("admin"), token("admin", 0));
	expect("two tokens -> 403", upd_send("admin", A_PW, h, 4096), "403 Forbidden");
	snprintf(h, sizeof h, "Origin: http://evil.example\r\nContent-Type: application/octet-stream\r\nX-CSRF-Token: %s\r\n",
		 token("admin", 0));
	expect("another site's Origin (with a valid token) -> 403", upd_send("admin", A_PW, h, 4096), "403 Forbidden");
	snprintf(h, sizeof h, "Content-Type: application/octet-stream\r\nX-CSRF-Token: %s\r\n", token("admin", 0));
	expect("no Origin or Referer -> 403", upd_send("admin", A_PW, h, 4096), "403 Forbidden");
	no_upload("... CSRF refusals");
	static const char *const bad_ct[] = { "application/x-www-form-urlencoded", "multipart/form-data; boundary=x",
					      "application/octet-stream; x=1", "text/plain" };
	for (int i = 0; i < 4; i++) {
		snprintf(h, sizeof h, "Origin: http://192.0.2.10\r\nContent-Type: %s\r\nX-CSRF-Token: %s\r\n", bad_ct[i],
			 token("admin", 0));
		expect("not application/octet-stream -> 415", upd_send("admin", A_PW, h, 4096), "415 Unsupported Media Type");
	}
	snprintf(h, sizeof h, "Origin: http://192.0.2.10\r\nX-CSRF-Token: %s\r\n", token("admin", 0));
	expect("no Content-Type -> 415", upd_send("admin", A_PW, h, 4096), "415");
	upd_start(&cl, "admin", A_PW, js_hdrs("admin"), (size_t)-1, 0);
	expect("no Content-Length -> 411", reply_of(&cl), "411 Length Required");
	expect("Content-Length 0 -> 411", upd_send("admin", A_PW, js_hdrs("admin"), 0), "411");
	snprintf(h, sizeof h, "%sContent-Length: 12x\r\n", js_hdrs("admin"));
	upd_start(&cl, "admin", A_PW, h, (size_t)-1, 0);
	expect("a malformed Content-Length -> 400 (the usual parser)", reply_of(&cl), "400 Bad Request");
	snprintf(h, sizeof h, "%sContent-Length: 10\r\n", js_hdrs("admin"));
	expect("two Content-Lengths -> 400", upd_send("admin", A_PW, h, 10), "400 Bad Request");
	snprintf(h, sizeof h, "%sTransfer-Encoding: chunked\r\n", js_hdrs("admin"));
	expect("chunked -> 501", upd_send("admin", A_PW, h, 10), "501");
	snprintf(h, sizeof h, "%sExpect: 100-continue\r\n", js_hdrs("admin"));
	log_start();
	upd_start(&cl, "admin", A_PW, h, UPD_MAX + 1, 0);
	lg = log_stop();
	r = reply_of(&cl);
	expect("over 5 MiB -> 413 from the Content-Length, before the body", r, "413 Content Too Large");
	expect("... saying why", r, "The file is larger than 5 MiB: not a camera package.");
	absent("... no 100 Continue: the body is never asked for", r, "100 Continue");
	expect("... logged", lg, "firmware upload by admin refused: 5242881 bytes, over 5242880");
	no_upload("... 413");
	snprintf(h, sizeof h, "%sContent-Length: 99999999\r\n", js_hdrs("admin"));
	upd_start(&cl, "admin", A_PW, h, (size_t)-1, 0);
	expect("an 8-digit Content-Length -> 400", reply_of(&cl), "400 Bad Request");

	/* memory: MemAvailable must hold the file twice (camupdate reads it into RAM) and 2 MiB */
	write_file(meminfo_path, "MemTotal: 65536 kB\nMemFree: 1024 kB\nMemAvailable: 9215 kB\n");
	r = upd_send("admin", A_PW, js_hdrs("admin"), 3670016);
	expect("3.5 MiB with 9215 KiB available -> 507", r, "507 Insufficient Storage");
	expect("... with the numbers", r, "9216 KiB needed, 9215 KiB available");
	no_upload("... 507");
	write_file(meminfo_path, "MemTotal: 65536 kB\nMemFree: 1024 kB\n");
	expect("... MemAvailable unreadable: refused", upd_send("admin", A_PW, js_hdrs("admin"), 4096), "507");
	write_file(meminfo_path, "MemTotal:          65536 kB\nMemFree:            1024 kB\nMemAvailable:      32768 kB\n");
	upd_dir = "/nonexistent/fw";
	expect("no staging tmpfs -> 503", upd_send("admin", A_PW, js_hdrs("admin"), 4096), "The camera has no upload area");
	upd_dir = ud;
	no_upload("... 503");

	/* OK: camupdate --check's verdict, the file kept */
	unlink(tfile("stub-calls"));
	log_start();
	r = upd_send("admin", A_PW, js_hdrs("admin"), 300000);
	lg = log_stop();
	expect("upload: 200 with camupdate's verdict", r, "HTTP/1.1 200 OK");
	expect("... version, device, size, signer", r,
	       "OK: version 20261025.1 for MCA40E-IFADO, 3506176 bytes, signed by cam-firmware nano.");
	expect("... and the installed version", r, "Installed now: 1.2.3-test.");
	expect("... plain text with the UI's headers", r, "X-Content-Type-Options: nosniff");
	expect("... (text/plain)", r, "Content-Type: text/plain");
	check("... staged whole, as sent", fsize(staged) == 300000 && upd.state == UPD_READY && cl.state == 1);
	calls = slurp(tfile("stub-calls"));
	/* Gate 3: the monitor opens the staged file (O_NOFOLLOW) and gives it as stdin */
	expect("camupdate --check -: the upload on its stdin, no shell", calls, "ARGS: --check - PPID:");
	expect("... it read every byte", calls, "SIZE:300000\n");
	expect("... an environment of PATH only", calls, "ENV:PATH=/usr/sbin:/usr/bin:/sbin:/bin\n");
	absent("... no CU_KEYS (camupdate's test-build override)", calls, "CU_KEYS");
	absent("... nothing else of ours", calls, "CAMHTTPD_TEST_LEAK");
	expect("log: the upload", lg, "192.0.2.50: firmware upload by admin: 300000 bytes");
	expect("log: the verdict", lg, "firmware upload by admin checked OK: version 20261025.1 for MCA40E-IFADO, "
	       "3506176 bytes, signed by cam-firmware nano");
	r = ui_get("/ui/system", "admin", A_PW);
	expect("system page: the installed version", r, "<tr><th>Installed</th><td>1.2.3-test</td></tr>");
	expect("... the new one", r, "<tr><th>New version</th><td>20261025.1</td></tr>");
	expect("... device", r, "<tr><th>Device</th><td>MCA40E-IFADO</td></tr>");
	expect("... signer", r, "<tr><th>Signed by</th><td>cam-firmware nano</td></tr>");
	expect("... size", r, "<tr><th>Size</th><td>3506176 bytes (the package 300000)</td></tr>");
	expect("... who uploaded it", r, "<tr><th>Uploaded by</th><td>admin</td></tr>");
	snprintf(want, sizeof want, "<input type=\"hidden\" name=\"do\" value=\"install\"><input type=\"hidden\" name=\"fw\" "
		 "value=\"%s\">", upd.id);
	expect("... Install, bound to this upload's id", r, want);
	expect("... behind a confirm box", r, "Yes, install this firmware and reboot the camera");
	expect("... Discard", r, "<input type=\"hidden\" name=\"do\" value=\"discard\">");
	absent("... no second upload form meanwhile", r, "data-upload");
	check("... the id is 16 hex digits", strlen(upd.id) == 16 && strspn(upd.id, "0123456789abcdef") == 16);
	r = ui_get("/ui/system", "boss", BOSS_PW);
	expect("another admin sees it, can't install it", r, "admin uploaded it: only they can install it.");
	absent("... no Install for them", r, "value=\"install\"");

	/* Install refused: no box, another upload's id, another admin, CSRF, roles */
	snprintf(old_id, sizeof old_id, "%s", upd.id);
	r = ui_post("/ui/system", "admin", A_PW, "do=install&fw=%s", upd.id);
	expect("install without the box", r, "Tick the box to confirm.");
	r = ui_post("/ui/system", "admin", A_PW, "do=install&confirm=1&fw=0123456789abcdef");
	expect("install with another upload's id -> 409", r, "409 Conflict");
	expect("... saying so", r, "This page showed another upload: reload it and check the version again.");
	expect("install with no id -> 409", ui_post("/ui/system", "admin", A_PW, "do=install&confirm=1"), "409 Conflict");
	r = ui_post("/ui/system", "boss", BOSS_PW, "do=install&confirm=1&fw=%s", upd.id);
	expect("another admin's install -> 403", r, "403 Forbidden");
	expect("... saying whose it is", r, "admin uploaded this package: only they can install it.");
	snprintf(want, sizeof want, "csrf=%s&do=install&confirm=1&fw=%s", token("boss", 0), upd.id);
	expect("install with another user's form token -> 403", run(ui_req("POST", "/ui/system", "admin", A_PW, SAME, want)),
	       "403 Forbidden");
	snprintf(want, sizeof want, "csrf=%s&do=install&confirm=1&fw=%s", token("admin", 0), upd.id);
	expect("install from another site -> 403", run(ui_req("POST", "/ui/system", "admin", A_PW, "Origin: http://evil.example\r\n"
	       FORM_CT, want)), "403 Forbidden");
	expect("an operator's install -> 403", ui_post("/ui/system", "op", O_PW, "do=install&confirm=1&fw=%s", upd.id),
	       "403 Forbidden");
	check("... none of them started anything", upd.state == UPD_READY && !strstr(slurp(tfile("stub-calls")), "ARGS: /"));

	/* a new upload replaces it: the old page's id is stale */
	log_start();
	r = upd_send("admin", A_PW, js_hdrs("admin"), 200000);
	lg = log_stop();
	expect("a new upload replaces the checked one", r, "200 OK");
	expect("... logged", lg, "firmware upload by admin replaced by a new upload");
	check("... a new id, the new file", strcmp(old_id, upd.id) && fsize(staged) == 200000);
	r = ui_post("/ui/system", "admin", A_PW, "do=install&confirm=1&fw=%s", old_id);
	expect("install from the page of the replaced upload -> 409", r, "This page showed another upload");
	check("... nothing started", upd.state == UPD_READY);

	/* Discard (any admin), then Install has nothing to install */
	snprintf(old_id, sizeof old_id, "%s", upd.id);
	log_start();
	r = ui_post("/ui/system", "boss", BOSS_PW, "do=discard&fw=%s", upd.id);
	lg = log_stop();
	expect("discard", r, "The upload was discarded.");
	expect("... logged", lg, "firmware upload by admin discarded by boss");
	no_upload("... discard");
	r = ui_post("/ui/system", "admin", A_PW, "do=install&confirm=1&fw=%s", old_id);
	expect("install with nothing staged -> 409", r, "No checked upload is waiting: upload the package again.");
	expect("discard with nothing staged -> 409", ui_post("/ui/system", "admin", A_PW, "do=discard&fw=%s", old_id), "409");
	r = ui_get("/ui/system", "admin", A_PW);
	expect("... the upload form is back", r, "data-upload");

	/* the staged file changed after the check: not installed */
	expect("upload", upd_send("admin", A_PW, js_hdrs("admin"), 100000), "200 OK");
	int fd = open(staged, O_WRONLY);
	check("... (the file changed on the camera)", fd >= 0 && pwrite(fd, "X", 1, 5000) == 1);
	close(fd);
	r = ui_post("/ui/system", "admin", A_PW, "do=install&confirm=1&fw=%s", upd.id);
	expect("install of a changed file -> refused", r, "The uploaded file changed after the check: upload it again.");
	no_upload("... and deleted");

	/* REFUSED: the reason shown, the file deleted */
	stub_mode("refuse");
	log_start();
	r = upd_send("admin", A_PW, js_hdrs("admin"), 100000);
	lg = log_stop();
	expect("camupdate refuses -> 422", r, "422 Unprocessable Content");
	expect("... with its reason", r, "REFUSED: package is for another device");
	no_upload("... refused");
	expect("... logged", lg, "firmware upload by admin refused by camupdate: package is for another device");
	r = ui_get("/ui/system", "admin", A_PW);
	expect("... the page says so", r, "The last upload was refused: package is for another device.");
	expect("... and offers the upload again", r, "data-upload");
	stub_mode("html");
	upd_send("admin", A_PW, js_hdrs("admin"), 5000);
	r = ui_get("/ui/system", "admin", A_PW);
	expect("a reason with markup: escaped on the page", r, "refused: &lt;script&gt;alert(1)&lt;/script&gt; &amp; co.");
	absent("... never raw", r, "<script>alert");
	no_upload("... html");
	stub_mode("garbage");
	expect("exit 0 without camupdate's OK line -> refused", upd_send("admin", A_PW, js_hdrs("admin"), 5000),
	       "REFUSED: camupdate's answer wasn't understood");
	no_upload("... garbage");
	camupdate_bin = "/nonexistent/camupdate";
	expect("camupdate missing -> refused", upd_send("admin", A_PW, js_hdrs("admin"), 5000), "REFUSED: camupdate isn't installed");
	no_upload("... missing");
	camupdate_bin = stub;
	stub_mode("hang");
	upd_start(&cl, "admin", A_PW, js_hdrs("admin"), 5000, 5000);
	upd_tick(mono_ms());
	check("a hung check: the loop goes on, the upload's connection waits", upd.state == UPD_CHECK && cl.state == ST_CHECK);
	expect("... meanwhile a second upload -> 409", upd_send("boss", BOSS_PW, js_hdrs("boss"), 5000), "409 Conflict");
	check("... (which left the first alone)", upd.state == UPD_CHECK);
	mono_adj += UPD_CHECK_MS;
	upd_tick(mono_ms());
	mono_adj -= UPD_CHECK_MS;
	no_upload("... killed after 60 s");
	expect("... the page says so", ui_get("/ui/system", "admin", A_PW), "camupdate --check took longer than 60 s");
	stub_mode("down");
	r = upd_send("admin", A_PW, js_hdrs("admin"), 5000);
	expect("a package signed to allow a downgrade: refused in the web UI", r, "422 Unprocessable Content");
	expect("... with the reason", r, "is signed to allow a downgrade");
	no_upload("... and deleted");
	expect("... the page says so", ui_get("/ui/system", "admin", A_PW), "the web UI doesn&#39;t install those, use SSH");
	stub_mode("ok");

	/* one upload at a time; bytes past Content-Length never reach the file */
	struct client *a = &clients[0];
	upd_start(a, "admin", A_PW, js_hdrs("admin"), 100000, 1000);
	check("upload A: receiving, its first bytes on file", a->state == ST_UPLOAD && upd.state == UPD_RECV && upd.c == a &&
	      fsize(staged) == 1000);
	r = upd_send("boss", BOSS_PW, js_hdrs("boss"), 5000);
	expect("a second upload meanwhile -> 409", r, "409 Conflict");
	expect("... saying why", r, "Another firmware upload is being received or checked");
	check("... A untouched", fsize(staged) == 1000 && upd.c == a && a->state == ST_UPLOAD);
	expect("GET /ui/firmware says so too", ui_get(UPD_PATH, "admin", A_PW), "409 Conflict");
	expect("the System page meanwhile", ui_get("/ui/system", "boss", BOSS_PW), "admin is uploading a package");
	unlink(tfile("stub-calls"));
	upd_take(a, pkg + 1000, 110000);                    /* more than Content-Length */
	upd_wait(UPD_CHECK);
	check("... A checked on exactly its Content-Length", fsize(staged) == 100000 && upd.state == UPD_READY &&
	      strstr(slurp(tfile("stub-calls")), "SIZE:100000\n") != NULL);
	expect("... A's verdict on A's connection", reply_of(a), "200 OK");
	FILE *f = fopen(staged, "rb");
	static char back[100000];
	check("... the staged bytes are the ones sent", f && fread(back, 1, sizeof back, f) == sizeof back &&
	      !memcmp(back, pkg, sizeof back));
	if (f) fclose(f);
	upd_drop(NULL);

	/* cancelled mid-body (the browser went away, or the loop's timeout closed it) */
	log_start();
	upd_start(a, "admin", A_PW, js_hdrs("admin"), 409600, 1000);
	check("deadline: 30 s without a byte, within BODY_RATE overall", upd.body_end == mono() + 5 + 100 &&
	      a->deadline >= mono() + UPD_IDLE - 1 && a->deadline <= mono() + UPD_IDLE);
	a->fd = open("/dev/null", O_RDONLY);                /* a live connection, long past its headers */
	a->since -= 10 * HDR_GRACE_MS;
	check("... an upload is never the slot a newcomer takes", slot_victim() == NULL);
	client_close(a);
	lg = log_stop();
	no_upload("cancelled mid-body");
	expect("... logged", lg, "firmware upload by admin cancelled after 1000 of 409600 bytes (closed or timed out)");
	expect("... the page says so", ui_get("/ui/system", "admin", A_PW), "The last upload stopped after 1000 of 409600 bytes");
	expect("... and a new upload may start", ui_get(UPD_PATH, "admin", A_PW), "ready");

	/* a write failing mid-stream (as a full tmpfs would) */
	upd_start(a, "admin", A_PW, js_hdrs("admin"), 100000, 1000);
	int ro = open("/dev/null", O_RDONLY);
	dup2(ro, upd.fd);
	close(ro);
	upd_take(a, pkg + 1000, 4096);
	expect("a write failing mid-stream -> 507", reply_of(a), "507 Insufficient Storage");
	no_upload("... the partial file deleted");
	client_close(a);

	/* expiry: a checked upload not installed within 15 minutes */
	upd_send("admin", A_PW, js_hdrs("admin"), 5000);
	check("checked", upd.state == UPD_READY);
	mono_adj += UPD_KEEP_MS - 1000;
	upd_tick(mono_ms());
	check("... kept for 15 minutes", upd.state == UPD_READY);
	mono_adj += 2000;
	upd_tick(mono_ms());
	mono_adj -= UPD_KEEP_MS + 1000;
	no_upload("... then deleted");
	expect("... the page says so", ui_get("/ui/system", "admin", A_PW), "it wasn&#39;t installed within 15 minutes");

	/* the real recv path (client_read) over a socketpair: 100-continue, then the body, the verdict */
	if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv)) {
		printf("skip: the upload over a socket (socketpair: %s)\n", strerror(errno));
	} else {
		fcntl(sv[0], F_SETFL, fcntl(sv[0], F_GETFL) | O_NONBLOCK);
		client_reset(a, sv[0]);
		inet_pton(AF_INET, peer_ip, &a->peer);
		strcpy(a->local, "192.0.2.10");
		snprintf(h, sizeof h, "%sExpect: 100-continue\r\n", js_hdrs("admin"));
		const char *hd = upd_head("admin", A_PW, h, 50000);
		check("socket: the head", send(sv[1], hd, strlen(hd), 0) == (ssize_t)strlen(hd));
		client_read(a);
		check("... the upload starts", a->state == ST_UPLOAD && upd.state == UPD_RECV);
		client_write(a);
		expect("... 100 Continue once accepted", drain(sv[1]), "HTTP/1.1 100 Continue\r\n\r\n");
		for (size_t off = 0; off < 50000;) {
			ssize_t k = send(sv[1], pkg + off, 50000 - off < 4096 ? 50000 - off : 4096, 0);
			if (k <= 0) break;
			off += (size_t)k;
			client_read(a);
		}
		check("... all of it through client_read", a->state == ST_CHECK && fsize(staged) == 50000);
		upd_wait(UPD_CHECK);
		client_write(a);
		r = drain(sv[1]);
		expect("... the verdict on the socket", r, "HTTP/1.1 200 OK");
		expect("... camupdate's line", r, "OK: version 20261025.1");
		check("... then the connection closes", a->fd < 0 && upd.state == UPD_READY);
		close(sv[1]);
		check("socket: a new upload", !socketpair(AF_UNIX, SOCK_STREAM, 0, sv));
		fcntl(sv[0], F_SETFL, fcntl(sv[0], F_GETFL) | O_NONBLOCK);
		client_reset(a, sv[0]);
		inet_pton(AF_INET, peer_ip, &a->peer);
		strcpy(a->local, "192.0.2.10");
		hd = upd_head("admin", A_PW, js_hdrs("admin"), 50000);
		send(sv[1], hd, strlen(hd), 0);
		send(sv[1], pkg, 3000, 0);
		client_read(a);
		check("... replaced the checked one, receiving", a->state == ST_UPLOAD && fsize(staged) == 3000);
		close(sv[1]);                                    /* the browser goes away */
		client_read(a);
		check("... the browser leaves mid-body: closed", a->fd < 0);
		no_upload("... and the file deleted");
	}

	/* Install: the reply first, then camupdate detached with a clean environment */
	upd_send("admin", A_PW, js_hdrs("admin"), 300000);
	check("checked", upd.state == UPD_READY);
	unlink(tfile("stub-calls"));
	unlink(tfile("stub-go"));
	log_start();
	r = ui_post("/ui/system", "admin", A_PW, "do=install&confirm=1&fw=%s", upd.id);
	expect("install: the reply first", r, "Installing 20261025.1. The camera writes it and reboots by itself in about "
	       "1 to 2 minutes; reload this page then. Settings, users and keys are kept.");
	expect("... the page says it installs", r, "<p class=\"warn\">Installing firmware 20261025.1");
	absent("... no forms meanwhile", r, "name=\"do\" value=\"reboot\"");
	check("... camupdate not started yet", upd.state == UPD_PENDING && fsize(tfile("stub-calls")) < 0);
	cl.fd = 99;                                         /* the reply still going out */
	upd_tick(mono_ms());
	check("... waits for its reply", upd.state == UPD_PENDING);
	cl.fd = -1;
	upd_tick(mono_ms());
	check("... then starts camupdate", upd.state == UPD_RUNNING && upd.pid > 0);
	expect("while it installs: uploads -> 409", upd_send("admin", A_PW, js_hdrs("admin"), 5000), "The camera is installing firmware");
	expect("... GET /ui/firmware -> 409", ui_get(UPD_PATH, "admin", A_PW), "409");
	r = ui_post("/ui/system", "admin", A_PW, "do=reboot&confirm=1");
	expect("... a reboot -> 409", r, "Firmware is being installed: the camera reboots by itself.");
	check("... (none asked)", !reboot_at);
	expect("... a second install -> 409", ui_post("/ui/system", "admin", A_PW, "do=install&confirm=1&fw=%s", upd.id),
	       "No checked upload is waiting");
	for (int i = 0; i < 300 && !strstr(slurp(tfile("stub-calls")), "ENV:"); i++) usleep(10000);
	calls = slurp(tfile("stub-calls"));
	expect("camupdate - (no --check): the upload on its stdin", calls, "ARGS: - PPID:");
	expect("... it read every byte", calls, "SIZE:300000\n");
	const char *pp = strstr(calls, "PPID:");
	check("... detached: camhttpd isn't its parent (double fork; camupdate SIGSTOPs us)", pp && atoi(pp + 5) != getpid() &&
	      atoi(pp + 5) > 0);
	expect("... an environment of PATH only", calls, "ENV:PATH=/usr/sbin:/usr/bin:/sbin:/bin\n");
	absent("... no CU_KEYS", calls, "CU_KEYS");
	absent("... nothing else of ours", calls, "CAMHTTPD_TEST_LEAK");
	check("... still running: nothing noticed", (upd_tick(mono_ms()), upd.state == UPD_RUNNING));
	/* Gate 3 #13: its end is EOF on a pipe only camupdate holds, not kill(pid, 0): a pid that now
	 * names a live process (reused, or a zombie) doesn't hide it */
	check("... watched through its pipe", upd.end >= 0);
	upd.pid = getpid();
	write_file(tfile("stub-go"), "");                  /* it ends without a reboot */
	for (int i = 0; i < 500 && upd.state == UPD_RUNNING; i++) {
		upd_tick(mono_ms());
		usleep(10000);
	}
	lg = log_stop();
	no_upload("camupdate ended without rebooting: noticed");
	expect("log: confirmed", lg, "192.0.2.50: firmware 20261025.1 (signed by cam-firmware nano) install confirmed by admin");
	expect("log: started", lg, "firmware 20261025.1: camupdate started (pid ");
	expect("log: ended", lg, "firmware 20261025.1: camupdate ended without rebooting: camupdate: no mtd \"rootfs\"");
	expect("its output went to the log in the tmpfs", slurp(tfile("fw/" UPD_LOG)), "can't take the watchdog");
	r = ui_get("/ui/system", "admin", A_PW);
	expect("the page says what happened", r, "The install of 20261025.1 ended without a reboot, before writing the "
	       "flash. camupdate said: camupdate: no mtd &quot;rootfs&quot;");
	expect("... and offers the upload again", r, "data-upload");

	/* the install starts after 3 s even if its reply is still going out */
	upd_send("admin", A_PW, js_hdrs("admin"), 5000);
	ui_post("/ui/system", "admin", A_PW, "do=install&confirm=1&fw=%s", upd.id);
	cl.fd = 99;
	mono_adj += UPD_START_MS;
	upd_tick(mono_ms());
	mono_adj -= UPD_START_MS;
	cl.fd = -1;
	check("install: started after 3 s anyway", upd.state == UPD_RUNNING);
	for (int i = 0; i < 500 && upd.state == UPD_RUNNING; i++) {
		upd_tick(mono_ms());
		usleep(10000);
	}
	no_upload("... (ended)");
	r = ui_post("/ui/system", "admin", A_PW, "do=reboot&confirm=1");
	expect("reboot pending: an upload -> 409", upd_send("admin", A_PW, js_hdrs("admin"), 5000), "rebooting");
	reboot_at = 0;

	camupdate_bin = "/nonexistent/camupdate";
	unsetenv("CU_KEYS");
	unsetenv("CAMHTTPD_TEST_LEAK");
	*upd.note = 0;
	unlink(tfile("stub-calls"));
	unlink(tfile("stub-go"));
	unlink(tfile("stub-mode"));
	unlink(stub);
	unlink(tfile("fw/" UPD_LOG));
	write_file(users_path, users_txt);
	auth_reset();
}

/* Random mutations of valid requests and plain garbage: nothing may crash or overrun (ASan/UBSan). */
static void test_fuzz(void)
{
	long long now = time(NULL);
	char nonce[NONCE_LEN + 1];
	nonce_make((unsigned long)mono(), 99999, nonce);
#define NSEEDS 22
	const char *seeds[NSEEDS];
	static char store[NSEEDS][8192];
	snprintf(store[0], 8192, "%s", soap_req(DEV, wsse("admin", "Adm1nPass!", now, 0, 0), B_USERS, NULL));
	snprintf(store[1], 8192, "%s", soap_req(MED, NULL, "<trt:GetStreamUri><trt:ProfileToken>Profile_1"
						 "</trt:ProfileToken></trt:GetStreamUri>",
						 digest("view", "V1ew:Pass&", "POST", MED, nonce, 1)));
	snprintf(store[2], 8192, "GET /snapshot.jpg HTTP/1.1\r\nHost: 192.0.2.10\r\nAuthorization: %s\r\n\r\n",
		 digest("view", "V1ew:Pass&", "GET", "/snapshot.jpg", nonce, 1));
	snprintf(store[3], 8192, "%s", soap_req(DEV, wsse("admin", "Adm1nPass!", now, 0, 0),
						 "<tds:SetSystemDateAndTime><tds:DateTimeType>Manual</tds:DateTimeType>"
						 "<tds:UTCDateTime><tt:Date><tt:Year>2026</tt:Year><tt:Month>1</tt:Month>"
						 "<tt:Day>2</tt:Day></tt:Date><tt:Time><tt:Hour>3</tt:Hour><tt:Minute>4"
						 "</tt:Minute><tt:Second>5</tt:Second></tt:Time></tds:UTCDateTime>"
						 "</tds:SetSystemDateAndTime>", NULL));
	snprintf(store[4], 8192, "%s", soap_req(MED, wsse("view", "V1ew:Pass&", now, 0, 0),
						 "<trt:GetVideoEncoderConfigurationOptions/>", NULL));
	snprintf(store[5], 8192, "<s:Envelope xmlns:s=\"x\" xmlns:dn=\"" NS_DN "\"><s:Header><a:MessageID>"
		 "uuid:1</a:MessageID></s:Header><s:Body><d:Probe><d:Types>dn:NetworkVideoTransmitter"
		 "</d:Types><d:Scopes MatchBy=\"rfc3986\">onvif://www.onvif.org/</d:Scopes></d:Probe></s:Body></s:Envelope>");
	snprintf(store[6], 8192, "%s", soap_req(MED, wsse("op", "0perPass", now, 0, 0),
						 setvec(1, "H264", 640, 360, 15, 1, 300, 50, "Main"), NULL));
	snprintf(store[7], 8192, "%s", store[5]);
	snprintf(store[5], 8192, "%s", soap_req(DEV, wsse("admin", "Adm1nPass!", now, 0, 0), ntp_body(
		"false", "<tds:NTPManual><tt:Type>DNS</tt:Type><tt:DNSname>pool.ntp.org</tt:DNSname></tds:NTPManual>"
		"<tds:NTPManual><tt:Type>IPv4</tt:Type><tt:IPv4Address>192.0.2.1</tt:IPv4Address></tds:NTPManual>"), NULL));
	snprintf(store[11], 8192, "%s", store[7]);
	snprintf(store[7], 8192, "%s", soap_req(IMG, wsse("op", "0perPass", now, 0, 0), imaging_body("VideoSource_1",
		 "<tt:Brightness>55.5</tt:Brightness><tt:IrCutFilter>AUTO</tt:IrCutFilter><tt:Exposure><tt:Mode>AUTO"
		 "</tt:Mode></tt:Exposure>"), NULL));
	snprintf(store[8], 8192, "%s", soap_req(EV, wsse("view", "V1ew:Pass&", now, 0, 0), SUBSCRIBE(
		 "tns1:RuleEngine//.|tns1:VideoSource/MotionAlarm", "PT30S"), NULL));
	run(store[8]);
	char path[128];
	sub_path(resp, path, sizeof path);
	snprintf(store[9], 8192, "%s", soap_req(path, wsse("view", "V1ew:Pass&", now, 0, 0), pull_body("PT1S", 5), NULL));
	snprintf(store[10], 8192, "%s", soap_req(path, wsse("view", "V1ew:Pass&", now, 0, 0),
		 "<wsnt:Renew><wsnt:TerminationTime>PT45S</wsnt:TerminationTime></wsnt:Renew>", NULL));
	snprintf(store[13], 8192, "%s", store[11]);
	uint8_t fm[MASK_BYTES];
	memset(fm, 0, sizeof fm);
	fm[5] = 0x3c;
	snprintf(store[11], 8192, "%s", soap_req(AN, wsse("op", "0perPass", now, 0, 0), rules_body("ModifyRules",
		 RULE_NAME, "tt:CellMotionDetector", cells_of(fm), "3"), NULL));
	snprintf(store[12], 8192, "%s", soap_req(AN, wsse("op", "0perPass", now, 0, 0), modules_body(MODULE_NAME,
		 "45", 32, 32), NULL));
	snprintf(store[15], 8192, "%s", store[13]);
	snprintf(store[13], 8192, "%s", soap_req(MED, wsse("op", "0perPass", now, 0, 0),
		 setaec_body("AudioEncoderConfig_1", "G711", "64", "8"), NULL));
	snprintf(store[14], 8192, "%s", soap_req(MED, wsse("view", "V1ew:Pass&", now, 0, 0),
		 "<trt:GetAudioEncoderConfigurationOptions><trt:ConfigurationToken>AudioEncoderConfig_1"
		 "</trt:ConfigurationToken><trt:ProfileToken>Profile_1</trt:ProfileToken>"
		 "</trt:GetAudioEncoderConfigurationOptions>", NULL));
	snprintf(store[17], 8192, "%s", store[15]);
	snprintf(store[15], 8192, "%s", soap_req(MED, wsse("op", "0perPass", now, 0, 0),
		 setaoc_body("AudioOutputConfig_1", "AudioOutput_1", "www.onvif.org/ver20/HalfDuplex/Auto", "80"), NULL));
	snprintf(store[16], 8192, "%s", soap_req(MED, wsse("view", "V1ew:Pass&", now, 0, 0),
		 "<trt:GetAudioDecoderConfigurationOptions><trt:ConfigurationToken>AudioDecoderConfig_1"
		 "</trt:ConfigurationToken><trt:ProfileToken>Profile_1</trt:ProfileToken>"
		 "</trt:GetAudioDecoderConfigurationOptions>", NULL));
	/* the web UI: a page, an image form, a users form (each nonce goes stale after one use, so
	 * mostly framing and refusals are fuzzed here; the form parser is fuzzed directly below) */
	snprintf(store[18], 8192, "%s", ui_req("GET", "/ui/image", "op", O_PW, NULL, NULL));
	snprintf(store[19], 8192, "%s", ui_req("POST", "/ui/image", "op", O_PW, SAME, "csrf=0123456789abcdef0123456789"
		 "abcdef01234567&brightness=60&brightness_n=50&mode=night"));
	snprintf(store[20], 8192, "%s", ui_req("POST", "/ui/users", "admin", A_PW, SAME, "csrf=x&do=add&name=bob&"
		 "role=viewer&pw=A%21b%3Ac+d&pw2=A%21b%3Ac+d"));
	char fwh[300];                                     /* a firmware upload as /ui.js sends it */
	snprintf(fwh, sizeof fwh, "Origin: http://192.0.2.10\r\nContent-Type: application/octet-stream\r\n"
		 "X-CSRF-Token: %s\r\n", token("admin", 0));
	snprintf(store[21], 8192, "%s", ui_req("POST", "/ui/firmware", "admin", A_PW, fwh, "magic=camfw1\n"
		 "device=MCA40E-IFADO\npart=rootfs\nversion=20261025.1\n\n-----BEGIN SSH SIGNATURE-----\nhsqs"));
	for (int i = 0; i < NSEEDS; i++) seeds[i] = store[i];
	int saved = dup(2), devnull = open("/dev/null", O_WRONLY);
	dup2(devnull, 2);                                  /* the server logs every bad credential */
	srand(1);
	static char m[REQ_CAP + 16];
	for (int it = 0; it < 30000; it++) {
		const char *s = seeds[it % NSEEDS];
		size_t n = strlen(s);
		memcpy(m, s, n);
		int edits = 1 + rand() % 8;
		for (int e = 0; e < edits; e++) {
			size_t at = (size_t)rand() % n;
			switch (rand() % 4) {
			case 0: m[at] = (char)(rand() & 0xff); break;
			case 1: m[at] = "<>/:\"'= &\r\n\0"[rand() % 12]; break;
			case 2: n = at + 1; break;                        /* truncate */
			default: memmove(m + at, m + at + 1, n - at - 1); if (n > 1) n--; break;
			}
		}
		if (it % NSEEDS == 17) disco_probe(m, n, "192.0.2.10");
		else run_n(m, n, 1 + (size_t)rand() % 2000);
	}
	for (int it = 0; it < 3000; it++) {
		size_t n = (size_t)rand() % 3000;
		for (size_t i = 0; i < n; i++) m[i] = (char)(rand() & 0xff);
		run_n(m, n, 512);
		disco_probe(m, n, "192.0.2.10");
	}
	/* the form parser: mutated forms, then the lookups a handler makes */
	static const char *const fseeds[] = {
		"csrf=0123456789abcdef0123456789abcdef01234567&brightness=60&brightness_n=50&mode=night",
		"csrf=x&do=add&name=bob&role=viewer&pw=A%21b%3Ac+d%25e%22%5C&pw2=A%21b%3Ac+d%25e%22%5C",
		"csrf=x&do=add&key=ssh-ed25519+AAAAC3NzaC1lZDI1NTE5AAAAIAECAwQ%3D+me%40host",
		"csrf=x&ntp=pool.ntp.org%2C+192.0.2.1&main_kbps=6144&sub_profile=high",
	};
	for (int it = 0; it < 20000; it++) {
		const char *s = fseeds[it % 4];
		size_t n = strlen(s);
		memcpy(m, s, n);
		for (int e = 1 + rand() % 6; e > 0; e--) {
			size_t at = (size_t)rand() % n;
			switch (rand() % 4) {
			case 0: m[at] = (char)(rand() & 0xff); break;
			case 1: m[at] = "%&=+\0 ;0aF"[rand() % 10]; break;
			case 2: n = at + 1; break;
			default: memmove(m + at, m + at + 1, n - at - 1); if (n > 1) n--; break;
			}
		}
		if (!form_parse(m, n))
			for (int i = 0; i < form.n; i++)
				if (strlen(form.v[i]) > n || !form_get(form.k[i])) { fprintf(stderr, "FAIL form fuzz\n"); exit(1); }
	}
	memset(&form, 0, sizeof form);
	for (int i = 0; i < 500 && upd.state == UPD_CHECK; i++) {   /* a fuzzed upload that got through */
		upd_tick(mono_ms());
		usleep(10000);
	}
	client_reset(&cl, -1);
	if (upd.state != UPD_NONE) upd_drop(NULL);
	dup2(saved, 2);
	close(saved);
	close(devnull);
	auth_reset();
	seen_floor = -1;                                   /* a fuzzed SetSystemDateAndTime raised it */
	printf("ok: 33000 mutated/garbage requests and probes and 20000 mutated forms, no crash\n");
}

static void test_discovery(void)
{
	char p[4096];
	size_t n;
	const char *head = "<?xml version=\"1.0\" encoding=\"utf-8\"?><s:Envelope "
		"xmlns:s=\"http://www.w3.org/2003/05/soap-envelope\" "
		"xmlns:a=\"http://schemas.xmlsoap.org/ws/2004/08/addressing\"><s:Header><a:Action "
		"s:mustUnderstand=\"1\">http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe</a:Action>"
		"<a:MessageID>%s</a:MessageID><a:To s:mustUnderstand=\"1\">urn:schemas-xmlsoap-org:ws:2005:"
		"04:discovery</a:To></s:Header><s:Body><Probe xmlns=\"http://schemas.xmlsoap.org/ws/2005/04/"
		"discovery\">%s</Probe></s:Body></s:Envelope>";
#define PROBE(id, inner) (snprintf(p, sizeof p, head, id, inner), disco_probe(p, strlen(p), "192.0.2.10"))
	n = PROBE("uuid:6c7d1e0a-1b2c-4d5e-8f90-a1b2c3d4e5f6", "<d:Types xmlns:d=\"http://schemas.xmlsoap."
		  "org/ws/2005/04/discovery\" xmlns:dp0=\"" NS_DN "\">dp0:NetworkVideoTransmitter</d:Types>");
	sb[n] = 0;
	expect("Probe NVT -> ProbeMatches", sb, "/discovery/ProbeMatches</wsa:Action>");
	expect("ProbeMatches RelatesTo", sb, "<wsa:RelatesTo>uuid:6c7d1e0a-1b2c-4d5e-8f90-a1b2c3d4e5f6</wsa:RelatesTo>");
	expect("ProbeMatches XAddrs", sb, "<d:XAddrs>http://192.0.2.10/onvif/device_service</d:XAddrs>");
	expect("ProbeMatches EPR", sb, epr);
	if (strlen(epr) != 45 || strncmp(epr, "urn:uuid:", 9) || strstr(epr, "020000000001") || epr[23] != '5') {
		fprintf(stderr, "FAIL epr %s\n", epr);
		exit(1);
	}
	char e1[46];
	memcpy(e1, epr, sizeof e1);
	epr_make();
	if (strcmp(e1, epr)) { fprintf(stderr, "FAIL epr not stable\n"); exit(1); }
	printf("ok: EndpointReference stable, v5, no MAC in it (%s)\n", epr);
	n = PROBE("uuid:2", "<d:Types xmlns:d=\"x\" xmlns:tds=\"" NS_TDS "\">tds:Device</d:Types>");
	expect("Probe tds:Device -> match", n ? "y" : "", "y");
	n = PROBE("uuid:3", "");
	expect("Probe without Types -> match", n ? "y" : "", "y");
	n = PROBE("uuid:4", "<d:Types xmlns:d=\"x\" xmlns:wsdp=\"http://schemas.xmlsoap.org/ws/2006/02/devprof\">wsdp:Device</d:Types>");
	expect("Probe wsdp:Device (Windows) -> no reply", n ? "" : "y", "y");
	n = PROBE("uuid:5", "<d:Types xmlns:d=\"x\" xmlns:dn=\"http://example.com/other\">dn:NetworkVideoTransmitter</d:Types>");
	expect("Probe NVT in another namespace -> no reply", n ? "" : "y", "y");
	n = PROBE("uuid:x&lt;/a&gt;", "");
	expect("MessageID with markup -> no reply", n ? "" : "y", "y");
	n = PROBE("uuid:6", "<d:Scopes xmlns:d=\"x\">onvif://www.onvif.org/name</d:Scopes>");
	expect("Probe scope prefix -> match", n ? "y" : "", "y");
	n = PROBE("uuid:7", "<d:Scopes xmlns:d=\"x\">onvif://www.onvif.org/na</d:Scopes>");
	expect("Probe partial segment -> no reply", n ? "" : "y", "y");
	n = PROBE("uuid:8", "<d:Scopes xmlns:d=\"x\" MatchBy=\"http://schemas.xmlsoap.org/ws/2005/04/discovery/strcmp0\">"
		  "onvif://www.onvif.org/Profile/Streaming</d:Scopes>");
	expect("Probe strcmp0 scope -> match", n ? "y" : "", "y");
	n = PROBE("uuid:9", "<d:Scopes xmlns:d=\"x\">onvif://www.onvif.org/location/elsewhere</d:Scopes>");
	expect("Probe other scope -> no reply", n ? "" : "y", "y");
	snprintf(p, sizeof p, "<e:Envelope><e:Header><a:MessageID>uuid:1</a:MessageID></e:Header><e:Body>"
		 "<d:ProbeMatches/></e:Body></e:Envelope>");
	expect("ProbeMatches from another camera -> no reply", disco_probe(p, strlen(p), "x") ? "" : "y", "y");
}

/* Regression checks for the security review of 2026-10-23 (numbers as in the review). Work is
 * measured in bytes scanned or hashed, not in wall-clock time, where that is possible. */
static void test_review(void)
{
	long long now = time(NULL);
	const char *r;
	char nonce[NONCE_LEN + 1], ip[32];
	static char req[REQ_CAP + 16], h1[2048], h2[2048];
	struct in_addr a, nw;
	static const char *const set_body = "<tds:SetSystemDateAndTime><tds:DateTimeType>Manual"
		"</tds:DateTimeType><tds:UTCDateTime><tt:Date><tt:Year>2030</tt:Year><tt:Month>1</tt:Month>"
		"<tt:Day>1</tt:Day></tt:Date><tt:Time><tt:Hour>0</tt:Hour><tt:Minute>0</tt:Minute>"
		"<tt:Second>0</tt:Second></tt:Time></tds:UTCDateTime></tds:SetSystemDateAndTime>";
	auth_reset();

	/* #1: hostile bodies cost linear work, unauthenticated; so does a Probe */
	static const char *const fills[] = { "<", "</", "<a" };
	for (int f = 0; f < 3; f++) {
		int bl = REQ_CAP - 100, hl = snprintf(req, sizeof req, "POST " DEV " HTTP/1.1\r\n"
						      "Content-Type: application/soap+xml\r\nContent-Length: %d\r\n\r\n", bl);
		const char *pre = f == 1 ? "<Body><GetUsers>" : "";
		size_t pl = strlen(pre), fl = strlen(fills[f]);
		memcpy(req + hl, pre, pl);
		for (size_t i = 0; i + pl < (size_t)bl; i++) req[(size_t)hl + pl + i] = fills[f][i % fl];
		scan_bytes = 0;
		clock_t t0 = clock();
		run_n(req, (size_t)(hl + bl), 1 << 20);
		double cpu = (double)(clock() - t0) / CLOCKS_PER_SEC;
		printf("   64 KiB body of \"%s\": %llu bytes scanned, %.3f s CPU\n", fills[f], scan_bytes, cpu);
		check("#1 XML scans of a hostile body stay linear", scan_bytes < 8ULL * REQ_CAP && cpu < 0.25);
	}
	static char pb[8192];
	memset(pb, '<', sizeof pb - 1);
	scan_bytes = 0;
	disco_probe(pb, sizeof pb - 1, "192.0.2.10");
	check("#1 a Probe full of '<' is scanned linearly", scan_bytes < 8ULL * sizeof pb);

	/* #2: rotating addresses can't outrun the lockout */
	r = run(soap_req(DEV, wsse("op", "0perPass", now, 0, 0), B_INFO, NULL));
	expect("#2 the NVR logs in (an operator)", r, "200 OK");
	for (int i = 0; i < 40; i++) {
		snprintf(ip, sizeof ip, "198.51.100.%d", i + 1);
		peer_ip = ip;
		for (int k = 0; k < 3; k++) run(soap_req(DEV, wsse("admin", "guess", now, 0, 0), B_INFO, NULL));
	}
	check("#2 120 guesses from 40 addresses: only FAIL_GLOBAL were checked", gfail.n == FAIL_GLOBAL);
	peer_ip = "198.51.100.200";
	r = run(soap_req(DEV, wsse("admin", "Adm1nPass!", now, 0, 0), B_INFO, NULL));
	expect("#2 then the right password from a new address is refused too", r, "400 Bad Request");
	peer_ip = "192.0.2.50";
	r = run(soap_req(DEV, wsse("op", "0perPass", now, 0, 0), B_INFO, NULL));
	expect("#2 while the address that logged in recently still works", r, "200 OK");
	auth_reset();
	time_t t = mono();
	for (int i = 0; i < FAIL_SLOTS; i++) {
		a.s_addr = htonl(0xc6336400u + (uint32_t)i);
		for (int k = 0; k < FAIL_MAX; k++) auth_failed(a, t);
	}
	a.s_addr = htonl(0xc6336400u);
	nw.s_addr = htonl(0xc63364ffu);
	auth_failed(nw, t);
	gfail.n = 0;                                       /* the per-address table alone */
	check("#2 a table full of locked addresses: nothing evicted, newcomers count as locked",
	      auth_blocked(a, t) && auth_blocked(nw, t));
	check("#2 locks end with the window", !auth_blocked(a, t + FAIL_WINDOW + 1));
	auth_reset();
	long checked = 0;
	for (long k = 0; k < 3600L * 100; k++) {           /* an hour at 100 guesses/s, 32 addresses */
		a.s_addr = htonl(0xc6336400u + (uint32_t)(k % 32));
		time_t tk = t + (time_t)(k / 100);
		if (!auth_blocked(a, tk)) { checked++; auth_failed(a, tk); }
	}
	printf("   an hour of guessing at 100/s from 32 addresses: %ld checked\n", checked);
	check("#2 at most FAIL_GLOBAL guesses a minute get checked", checked <= 61L * FAIL_GLOBAL);
	auth_reset();

	/* #3: no UsernameToken replay across restarts or while the clock is unset */
	build_epoch = now + 1000;
	r = run(soap_req(DEV, wsse("admin", "Adm1nPass!", now, 0, 0), B_INFO, NULL));
	expect("#3 clock unset: UsernameToken refused with a Digest challenge", r, "WWW-Authenticate: Digest");
	nonce_of(r, nonce);
	r = run(soap_req(DEV, NULL, B_INFO, digest("admin", "Adm1nPass!", "POST", DEV, nonce, 1)));
	expect("#3 clock unset: HTTP Digest works", r, "200 OK");
	build_epoch = BUILD_EPOCH;
	r = run(soap_req(DEV, wsse("admin", "Adm1nPass!", now, 0, 0), B_INFO, NULL));
	expect("#3 clock just became valid: tokens from before are refused", r, "401 Unauthorized");
	check("#3 the floor is the moment the clock became valid", seen_floor >= now);
	seen_floor = -1;
	snprintf(h1, sizeof h1, "%s", wsse("admin", "Adm1nPass!", now - 1, 0, 0));
	r = run(soap_req(DEV, h1, B_INFO, NULL));
	expect("#3 a token before a restart", r, "200 OK");
	int calls = set_calls;
	auth_init();                                       /* = camhttpd respawned */
	r = run(soap_req(DEV, h1, set_body, NULL));
	expect("#3 replayed after the restart with another body: refused", r, "401 Unauthorized");
	check("#3 ... and the time was not set", set_calls == calls);
	seen_floor = -1;
	check("#3 refusals before a password check count no failure", gfail.n == 0);

	/* #4: slowloris can't hold every slot */
	inet_pton(AF_INET, "192.0.2.60", &a);
	inet_pton(AF_INET, "192.0.2.99", &nw);
	for (int i = 0; i < MAX_CLIENTS; i++) {
		client_reset(&clients[i], open("/dev/null", O_RDONLY));
		if (i < PER_PEER) clients[i].peer = a;
		else clients[i].peer.s_addr = htonl(0xc0000240u + (uint32_t)i);
		clients[i].since = 1000 - i;
	}
	clients[0].state = 1;                              /* answering */
	clients[MAX_CLIENTS - 1].hdr_len = 10;             /* in its body */
	check("#4 one more connection from an address at PER_PEER is refused", slot_for(a) == NULL);
	for (int k = MAX_CLIENTS - 2; k >= 1; k--) {
		check("#4 a newcomer takes the slot of the longest wait for headers",
		      slot_for(nw) == &clients[k] && clients[k].fd < 0);
		client_reset(&clients[k], open("/dev/null", O_RDONLY));
		clients[k].hdr_len = 10;
	}
	check("#4 nobody in headers: the newcomer is refused", slot_for(nw) == NULL);
	for (int i = 0; i < MAX_CLIENTS; i++) client_close(&clients[i]);

	/* #5: no floor poisoning */
	auth_reset();
	int refused = 0;
	for (int i = 0; i < SEEN_PER_USER + 1; i++) {
		r = run(soap_req(DEV, wsse("view", "V1ew:Pass&", now + FUTURE_MAX - 1, 0, 0), B_INFO, NULL));
		refused += strstr(r, "200 OK") == NULL;
	}
	check("#5 one user fills only its share of the replay cache", refused == 1);
	check("#5 ... without raising a floor or counting failures", seen_floor == -1 && gfail.n == 0);
	r = run(soap_req(DEV, wsse("admin", "Adm1nPass!", now, 0, 0), B_INFO, NULL));
	expect("#5 other users' fresh tokens still work", r, "200 OK");
	memset(seen, 0, sizeof seen);
	unsigned long t0 = (unsigned long)mono();
	for (int i = 0; i < NCS_N + 1; i++) nc_use(1000 + (unsigned long)i, t0, 1, (time_t)t0);
	check("#5 Digest: a nonce counted out after a churn is fine", nc_use(5000, t0, 1, (time_t)t0) == 0);
	check("#5 Digest: the oldest churned nonce turns stale", nc_use(1000, t0, 2, (time_t)t0) == -1);
	memset(ncs, 0, sizeof ncs);
	nc_floor_set = 0;

	/* #6: discovery answers only its subnet, a few a second */
	disco_joined = 1;
	inet_pton(AF_INET, "192.0.2.10", &disco_ip);
	inet_pton(AF_INET, "255.255.255.0", &disco_mask);
	time_t ts = mono() + 100000;
	inet_pton(AF_INET, "198.51.100.7", &a);
	check("#6 another subnet gets no reply", !disco_allow(a, ts));
	inet_pton(AF_INET, "192.0.2.77", &a);
	int n3 = disco_allow(a, ts) + disco_allow(a, ts) + disco_allow(a, ts);
	check("#6 at most WSD_PER_SRC replies a second to one address", n3 == WSD_PER_SRC);
	check("#6 ... and more the next second", disco_allow(a, ts + 1));
	int nall = 0;
	for (int i = 0; i < 30; i++) { a.s_addr = htonl(0xc0000264u + (uint32_t)i); nall += disco_allow(a, ts + 2); }
	check("#6 a flood of sources is capped", nall > 0 && nall <= WSD_ALL);
	disco_joined = 0;
	const char *tiny = "<MessageID>a</MessageID><Probe>";
	check("#6 a tiny Probe gets nothing (no amplification)", disco_probe(tiny, strlen(tiny), "192.0.2.10") == 0);

	/* #9: an unknown user costs the same hashing */
	auth_reset();
	snprintf(h1, sizeof h1, "%s", wsse("view", "Wrong-Pass", now, 0, 0));
	snprintf(h2, sizeof h2, "%s", wsse("nosuchuser", "Wrong-Pass", now, 0, 0));
	hash_bytes = 0;
	run(soap_req(DEV, h1, B_INFO, NULL));
	unsigned long long known = hash_bytes;
	hash_bytes = 0;
	run(soap_req(DEV, h2, B_INFO, NULL));
	printf("   UsernameToken hashing: known user %llu bytes, unknown %llu\n", known, hash_bytes);
	check("#9 UsernameToken: unknown user hashed like a known one",
	      known > 36 && hash_bytes + 16 > known && known + 16 > hash_bytes);
	r = run(soap_req(DEV, NULL, B_INFO, NULL));
	nonce_of(r, nonce);
	snprintf(h1, sizeof h1, "%s", digest("view", "Wrong-Pass", "POST", DEV, nonce, 1));
	snprintf(h2, sizeof h2, "%s", digest("nosuchuser", "Wrong-Pass", "POST", DEV, nonce, 2));
	hash_bytes = 0;
	run(soap_req(DEV, NULL, B_INFO, h1));
	known = hash_bytes;
	hash_bytes = 0;
	run(soap_req(DEV, NULL, B_INFO, h2));
	printf("   Digest hashing: known user %llu bytes, unknown %llu\n", known, hash_bytes);
	check("#9 Digest: unknown user hashed like a known one",
	      known > 100 && hash_bytes + 32 > known && known + 32 > hash_bytes);
	auth_reset();

	/* #10: nonces don't show the uptime, and still verify */
	auth_init();
	seen_floor = -1;
	r = run(soap_req(DEV, NULL, B_INFO, NULL));
	nonce_of(r, nonce);
	unsigned long up = (unsigned long)mono() & 0xffffffffUL, lead = strtoul((char[9]){ nonce[0], nonce[1],
		nonce[2], nonce[3], nonce[4], nonce[5], nonce[6], nonce[7], 0 }, NULL, 16);
	check("#10 a Digest nonce doesn't carry the uptime", lead != up && lead != up - 1);
	r = run(soap_req(DEV, NULL, B_INFO, digest("view", "V1ew:Pass&", "POST", DEV, nonce, 1)));
	expect("#10 ... and still verifies", r, "200 OK");

	/* #11: xtext leaves "" on every failure */
	char out[8];
	const char *x1 = "<a>x&bogus;</a>", *x2 = "<a>0123456789</a>";
	memcpy(out, "garbage", 8);
	check("#11 bad entity -> \"\"", xtext(x1, x1 + strlen(x1), "a", out, sizeof out) < 0 && !*out);
	memcpy(out, "garbage", 8);
	check("#11 overlong value -> \"\"", xtext(x2, x2 + strlen(x2), "a", out, sizeof out) < 0 && !*out);
	memcpy(out, "garbage", 8);
	check("#11 missing element -> \"\"", xtext(x2, x2 + strlen(x2), "b", out, sizeof out) < 0 && !*out);

	/* #12: another Authorization scheme is ignored */
	auth_reset();
	r = run(soap_req(DEV, wsse("view", "V1ew:Pass&", now, 0, 0), B_INFO, "Basic dmlldzpWMWV3"));
	expect("#12 pre-emptive Basic next to a valid UsernameToken: ignored", r, "200 OK");
	r = run(soap_req(DEV, NULL, B_INFO, "Basic dmlldzpWMWV3"));
	expect("#12 Basic alone: a Digest challenge", r, "401 Unauthorized");
	check("#12 ... and no failure counted", gfail.n == 0);
	auth_reset();
}

/* An ONVIF POST as soap_req builds it, with `hdrs` in place of its Content-Type line. */
static const char *onvif_with(const char *hdrs, const char *header, const char *body)
{
	static char buf[REQ_CAP];
	static const char ct[] = "Content-Type: application/soap+xml; charset=utf-8\r\n";
	const char *s = soap_req(DEV, header, body, NULL), *at = strstr(s, ct);
	snprintf(buf, sizeof buf, "%.*s%s%s", (int)(at - s), s, hdrs, at + sizeof ct - 1);
	return buf;
}

/* A Digest login on a fresh nonce for DEV. */
static const char *dev_digest(const char *user, const char *pw, unsigned nc)
{
	char nonce[NONCE_LEN + 1];
	nonce_of(run(soap_req(DEV, NULL, B_INFO, NULL)), nonce);
	return run(soap_req(DEV, NULL, B_INFO, digest(user, pw, "POST", DEV, nonce, nc)));
}

static int good_has(struct in_addr a)
{
	for (int i = 0; i < GOOD_SLOTS; i++)
		if (good[i].t && good[i].ip.s_addr == a.s_addr) return 1;
	return 0;
}

static void stub_script(const char *path, const char *body)
{
	char s[1024];
	snprintf(s, sizeof s, "#!/bin/sh\n%s\n", body);
	write_file(path, s);
	chmod(path, 0700);
}

/* Regression checks for the Gate 3 review (#38), numbered as its findings (#4: Host checks;
 * #5: test_claim's rate limit; #11: test_sss and the streams page; #13: test_firmware). */
static void test_gate3(const char *dir)
{
	long long now = time(NULL);
	const char *r, *lg;
	char p[700], nonce[NONCE_LEN + 1], old[NONCE_LEN + 1];
	static char q[4096];
	struct in_addr a;
	static const char *const set_body = "<tds:SetSystemDateAndTime><tds:DateTimeType>Manual"
		"</tds:DateTimeType><tds:UTCDateTime><tt:Date><tt:Year>2030</tt:Year><tt:Month>1</tt:Month>"
		"<tt:Day>1</tt:Day></tt:Date><tt:Time><tt:Hour>0</tt:Hour><tt:Minute>0</tt:Minute>"
		"<tt:Second>0</tt:Second></tt:Time></tds:UTCDateTime></tds:SetSystemDateAndTime>";
	auth_reset();

	/* #1: ONVIF from another site's page, which the browser sends with its cached Digest login */
	static const char *const foreign[] = { "Origin: http://evil.example\r\n", "Origin: null\r\n",
		"Origin: http://192.0.2.10:8080\r\n", "Origin: https://192.0.2.10\r\n",
		"Origin: http://192.0.2.10\r\nOrigin: http://192.0.2.10\r\n", "Sec-Fetch-Site: cross-site\r\n",
		"Sec-Fetch-Site: same-site\r\n", "Origin: http://192.0.2.10\r\nSec-Fetch-Site: cross-site\r\n",
		"Sec-Fetch-Site: none\r\nSec-Fetch-Site: none\r\n" };
	int calls = set_calls;
	for (size_t i = 0; i < sizeof foreign / sizeof foreign[0]; i++) {
		snprintf(q, sizeof q, "%sContent-Type: application/soap+xml; charset=utf-8\r\n", foreign[i]);
		r = run(onvif_with(q, wsse("admin", A_PW, now, 0, 0), set_body));
		char hs[160];
		snprintf(hs, sizeof hs, "%s", foreign[i]);
		for (char *e; (e = strstr(hs, "\r\n"));) {
			if (e[2]) { e[0] = ';'; e[1] = ' '; }
			else *e = 0;
		}
		snprintf(p, sizeof p, "#1 SetSystemDateAndTime with %s: 403", hs);
		expect(p, r, "403 Forbidden");
	}
	check("#1 ... and the time was never set", set_calls == calls);
	r = run(onvif_with("Origin: http://evil.example\r\nContent-Type: application/soap+xml\r\n",
			   wsse("admin", "guess", now, 0, 0), B_INFO));
	check("#1 refused before the credentials: a wrong password there counts no failure",
	      strstr(r, "403 Forbidden") && gfail.n == 0);
	static const char *const bad_ct[] = { "", "Content-Type: text/plain\r\n",
		"Content-Type: application/x-www-form-urlencoded\r\n", "Content-Type: multipart/form-data; boundary=x\r\n",
		"Content-Type: application/soap+xmlx\r\n", "Content-Type: text/xml2\r\n",
		"Content-Type: application/soap+xml\r\nContent-Type: text/plain\r\n" };
	log_start();
	for (size_t i = 0; i < sizeof bad_ct / sizeof bad_ct[0]; i++) {
		const char *ct = *bad_ct[i] ? bad_ct[i] + 14 : "";
		r = run(onvif_with(bad_ct[i], wsse("admin", A_PW, now, 0, 0), set_body));
		snprintf(p, sizeof p, "#1 Content-Type \"%.*s\"%s: 415", (int)strcspn(ct, "\r"), ct, strstr(ct, "\nContent-Type") ?
			 " and another" : "");
		expect(p, r, "415 Unsupported Media Type");
	}
	r = run(onvif_with("Content-Type: text/plain\r\n", NULL, "<tds:GetSystemDateAndTime/>"));
	expect("#1 ... PRE_AUTH operations too", r, "415 Unsupported Media Type");
	lg = log_stop();
	check("#1 ... the time was never set", set_calls == calls);
	expect("#1 the refused type is logged (to see what a client sends)", lg,
	       "192.0.2.50: POST /onvif/device_service refused: Content-Type \"text/plain\"");
	static const char *const ok_hdrs[] = {
		("Content-Type: application/soap+xml; charset=utf-8; action=\"http://www.onvif.org/ver10/device/wsdl/"
		 "GetDeviceInformation\"\r\n"), "Content-Type: text/xml; charset=utf-8\r\n", "Content-Type: application/xml\r\n",
		"Content-Type: Application/SOAP+XML\r\n", "Content-Type: application/soap+xml ; charset=utf-8\r\n",
		"Origin: http://192.0.2.10\r\nContent-Type: application/soap+xml\r\n",
		"Sec-Fetch-Site: same-origin\r\nContent-Type: application/soap+xml\r\n",
		"Sec-Fetch-Site: none\r\nContent-Type: application/soap+xml\r\n" };
	for (size_t i = 0; i < sizeof ok_hdrs / sizeof ok_hdrs[0]; i++) {
		r = run(onvif_with(ok_hdrs[i], wsse("view", V_PW, now, 0, 0), B_INFO));
		snprintf(p, sizeof p, "#1 an NVR's request (%.*s): 200", (int)strcspn(ok_hdrs[i], "\r"), ok_hdrs[i]);
		expect(p, r, "200 OK");
	}

	/* #2: a body that stalls can't hold its slot; two unfinished bodies per address at most */
	for (int i = 0; i < MAX_CLIENTS; i++) {
		client_reset(&clients[i], open("/dev/null", O_RDONLY));
		clients[i].peer.s_addr = htonl(0xc6336400u + (uint32_t)i);
		clients[i].hdr_len = 200;                      /* POST, Content-Length 60000: in its body */
		clients[i].body_len = 60000;
	}
	inet_pton(AF_INET, "203.0.113.9", &a);
	check("#2 six bodies coming in: no slot for a newcomer", !can_accept() && slot_for(a) == NULL);
	mono_adj += BODY_IDLE_MS + 1;
	clients[3].last_rx -= 500;                         /* stalled longest */
	clients[5].last_rx = mono_ms();                    /* a byte just came */
	check("#2 2 s without a byte: the slot of the body stalled longest is taken",
	      can_accept() && slot_for(a) == &clients[3] && clients[3].fd < 0);
	client_reset(&clients[3], open("/dev/null", O_RDONLY));
	static const int busy[MAX_CLIENTS] = { 1, 2, 3, ST_UPLOAD, ST_CHECK, 1 };
	for (int i = 0; i < MAX_CLIENTS; i++) {
		clients[i].state = busy[i];
		clients[i].hdr_len = 200;
		clients[i].last_rx = clients[i].since = 0;
	}
	check("#2 a reply, a held pull, a preview, an upload or its check is never taken", slot_for(a) == NULL);
	for (int i = 0; i < MAX_CLIENTS; i++) client_close(&clients[i]);
	mono_adj -= BODY_IDLE_MS + 1;
	static char part[512];
	snprintf(part, sizeof part, "POST " DEV " HTTP/1.1\r\nHost: 192.0.2.10\r\nContent-Type: application/soap+xml\r\n"
		 "Content-Length: 60000\r\n\r\n<s:Envelope>");
	peer_ip = "198.51.100.77";
	run_on(&clients[0], part);
	run_on(&clients[1], part);
	check("#2 two unfinished bodies from one address", !clients[0].state && clients[0].hdr_len &&
	      !clients[1].state && clients[1].hdr_len);
	expect("#2 a third from it: 429", run_on(&clients[2], part), "429 Too Many Requests");
	peer_ip = "198.51.100.78";
	run_on(&clients[3], part);
	check("#2 ... another address still gets its own", !clients[3].state && clients[3].hdr_len);
	for (int i = 0; i < MAX_CLIENTS; i++) if (clients[i].fd >= 0) client_close(&clients[i]);
	peer_ip = "192.0.2.50";

	/* #3: only an operator's or admin's login exempts its address from FAIL_GLOBAL, an entry is
	 * never pushed out early, and the exempt addresses can't add more than one guess each */
	auth_reset();
	inet_pton(AF_INET, peer_ip, &a);
	expect("#3 a viewer logs in", run(soap_req(DEV, wsse("view", V_PW, now, 0, 0), B_INFO, NULL)), "200 OK");
	check("#3 ... and that exempts nothing", !good_has(a));
	expect("#3 an operator logs in", run(soap_req(DEV, wsse("op", O_PW, now, 0, 0), B_INFO, NULL)), "200 OK");
	check("#3 ... and that exempts its address", good_has(a));
	for (int i = 0; i < 25; i++) {
		struct in_addr g = { htonl(0xc6336400u + (uint32_t)i) };
		auth_failed(g, mono());
	}
	expect("#3 FAIL_GLOBAL spent elsewhere: the operator's address still logs in",
	       run(soap_req(DEV, wsse("op", O_PW, now, 0, 0), B_INFO, NULL)), "200 OK");
	expect("#3 ... a wrong password from it is checked", run(soap_req(DEV, wsse("op", "guess", now, 0, 0), B_INFO, NULL)),
	       "400 Bad Request");
	check("#3 ... and ends its exemption", !good_has(a) && auth_blocked(a, mono()));
	auth_reset();
	time_t t = mono();
	struct in_addr ex[GOOD_SLOTS];
	for (int i = 0; i < GOOD_SLOTS; i++) {
		ex[i].s_addr = htonl(0xcb007100u + (uint32_t)i);   /* 203.0.113.i */
		auth_good(ex[i], t);
	}
	inet_pton(AF_INET, "203.0.113.200", &a);
	auth_good(a, t + 5);
	int kept = 1;
	for (int i = 0; i < GOOD_SLOTS; i++) kept &= good_has(ex[i]);
	check("#3 a ninth login doesn't push out an entry younger than GOOD_KEEP (it isn't exempt)", kept && !good_has(a));
	auth_good(a, t + GOOD_KEEP + 1);
	check("#3 ... once one is older, it takes that one", good_has(a));
	auth_reset();
	for (int i = 0; i < GOOD_SLOTS; i++) auth_good(ex[i], t);
	long checked = 0, first = -1;
	for (long k = 0; k < 3600L * 100; k++) {           /* an hour at 100 guesses/s, 8 of 40 addresses exempt */
		uint32_t i = (uint32_t)(k % 40);               /* (the exempt ones last: past FAIL_GLOBAL) */
		a.s_addr = i >= 40 - GOOD_SLOTS ? ex[i - (40 - GOOD_SLOTS)].s_addr : htonl(0xc6336400u + i);
		time_t tk = t + (time_t)(k / 100);
		if (!auth_blocked(a, tk)) { checked++; auth_failed(a, tk); }
		if (k == 100L * FAIL_WINDOW) first = checked;
	}
	printf("   guessing from 40 addresses, 8 of them exempt: %ld checked in the first minute, %ld in an hour\n",
	       first, checked);
	check("#3 at most FAIL_GLOBAL + one per exempt address in a minute", first <= FAIL_GLOBAL + GOOD_SLOTS);
	check("#3 ... and FAIL_GLOBAL a minute after that", checked <= 61L * FAIL_GLOBAL + GOOD_SLOTS);
	auth_reset();

	/* #4: the web UI and the images answer only by the camera's address (DNS rebinding) */
	static const char *const paths[] = { "/ui/", "/ui/image", "/ui/system", "/ui/firmware", "/snapshot.jpg", "/preview.mjpg" };
	for (size_t i = 0; i < sizeof paths / sizeof paths[0]; i++) {
		snprintf(q, sizeof q, "GET %s HTTP/1.1\r\nHost: camera.attacker.example\r\n\r\n", paths[i]);
		r = run(q);
		snprintf(p, sizeof p, "#4 GET %s by another name: 421 before any login", paths[i]);
		expect(p, r, "421 Misdirected Request");
		absent(p, r, "WWW-Authenticate");
	}
	gfail.n = 0;
	r = run(ui_req("GET", "/ui/", "admin", A_PW, NULL, NULL));
	expect("#4 ... by the address: the page", r, "200 OK");
	snprintf(q, sizeof q, "%s", ui_req("GET", "/snapshot.jpg", "view", V_PW, NULL, NULL));
	memcpy(strstr(q, "Host: 192.0.2.10"), "Host: 192.0.2.99", 16);
	expect("#4 a snapshot with credentials, another address as Host: 421", run(q), "421");
	check("#4 ... no password was even checked", gfail.n == 0);
	snprintf(q, sizeof q, "%s", ui_req("POST", "/ui/image", "op", O_PW, "Origin: http://rebound.ex\r\n" FORM_CT,
					   "brightness=1"));
	memcpy(strstr(q, "Host: 192.0.2.10"), "Host: rebound.ex", 16);
	expect("#4 a form POST by a rebound name (Origin = Host): 421", run(q), "421");
	snprintf(q, sizeof q, "POST " UPD_PATH " HTTP/1.1\r\nHost: rebound.example\r\nContent-Length: 10\r\n\r\n");
	expect("#4 a firmware upload by another name: 421 at its headers", run(q), "421");
	expect("#4 GET by the address with :80", run("GET /ui.css HTTP/1.1\r\nHost: 192.0.2.10:80\r\n\r\n"), "200 OK");
	expect("#4 /ui.css holds nothing and stays open", run("GET /ui.css HTTP/1.1\r\nHost: x.example\r\n\r\n"), "200 OK");
	snprintf(q, sizeof q, "%s", soap_req(DEV, wsse("view", V_PW, now, 0, 0), B_INFO, NULL));
	memcpy(strstr(q, "Host: 192.0.2.10"), "Host: nvr.lan:80", 16);
	expect("#4 ONVIF takes any Host (NVRs send odd ones)", run(q), "GetDeviceInformationResponse");

	/* #6: the Digest nonce counter wraps without making every nonce stale for good */
	nonce_ctr = 0xffffffffUL - 1;
	nc_floor = 0xfffffff0UL;                           /* a churned nc cache near the top */
	nc_floor_set = 1;
	nonce_of(run(soap_req(DEV, NULL, B_INFO, NULL)), old);
	expect("#6 the last nonce before the wrap", old, "ffffffff");
	uint8_t sec[20];
	memcpy(sec, secret, sizeof sec);
	log_start();
	nonce_of(run(soap_req(DEV, NULL, B_INFO, NULL)), nonce);
	lg = log_stop();
	check("#6 at the wrap: a new nonce key, the nc cache and floor cleared, counting from 1",
	      memcmp(sec, secret, sizeof sec) && !nc_floor_set && !strncmp(nonce + 8, "00000001", 8));
	expect("#6 ... logged", lg, "Digest nonce counter wrapped");
	r = run(soap_req(DEV, NULL, B_INFO, digest("view", V_PW, "POST", DEV, nonce, 1)));
	expect("#6 a login on the new count works", r, "200 OK");
	r = run(soap_req(DEV, NULL, B_INFO, digest("view", V_PW, "POST", DEV, nonce, 2)));
	expect("#6 ... and the next nc on it", r, "200 OK");
	r = run(soap_req(DEV, NULL, B_INFO, digest("view", V_PW, "POST", DEV, old, 1)));
	expect("#6 a nonce from before the wrap is foreign now: a new challenge", r, "401 Unauthorized");
	absent("#6 ... not stale", r, "stale=true");
	check("#6 ... and no failure counted", gfail.n == 0);
	memset(secret, 0x42, sizeof secret);

	/* #7: a token the replay cache forgot can't come back when the clock is stepped back */
	auth_reset();
	memset(seen, 0, sizeof seen);
	seen_floor = -1;
	time_hw = -1;
	static char h1[2048];
	snprintf(h1, sizeof h1, "%s", wsse("admin", A_PW, now - 10, 0, 0));
	expect("#7 a token", run(soap_req(DEV, h1, B_INFO, NULL)), "200 OK");
	memset(seen, 0, sizeof seen);                      /* the clock passed its Created + skew: forgotten */
	time_hw = now + 400;                               /* and then ntpc set it back by 400 s */
	expect("#7 replayed after the clock went back: refused", run(soap_req(DEV, h1, B_INFO, NULL)), "401 Unauthorized");
	expect("#7 ... so is a new token made before the mark", run(soap_req(DEV, wsse("admin", A_PW, now, 0, 0), B_INFO, NULL)),
	       "401 Unauthorized");
	time_hw = now + 20;
	expect("#7 ... a token made after the mark works", run(soap_req(DEV, wsse("admin", A_PW, now + 25, 0, 0), B_INFO, NULL)),
	       "200 OK");
	memset(seen, 0, sizeof seen);
	time_hw = -1;
	expect("#7 (without the mark the replay would have worked: the finding)", run(soap_req(DEV, h1, B_INFO, NULL)), "200 OK");
	check("#7 Digest meanwhile: unaffected", (time_hw = now + 400, strstr(dev_digest("admin", A_PW, 1), "200 OK") != NULL));
	char tf[700], v[32];
	snprintf(tf, sizeof tf, "%s/" TIME_FLOOR, dir);
	unlink(tf);
	time_hw = now + 100;
	hw_saved = -1;
	hw_saved_at = mono();
	hw_save(0);
	check("#7 not saved within an hour of the start", fsize(tf) < 0);
	mono_adj += FLOOR_SAVE_S * 1000LL;
	hw_save(0);
	struct stat sb;
	snprintf(v, sizeof v, "%lld\n", now + 100);
	check("#7 saved after an hour: the mark, mode 0600", !strcmp(slurp(tf), v) && !stat(tf, &sb) && (sb.st_mode & 0777) == 0600);
	time_hw = now + 105;
	hw_save(0);
	check("#7 ... not again within the hour (NAND)", !strcmp(slurp(tf), v));
	hw_save(1);
	snprintf(v, sizeof v, "%lld\n", now + 105);
	check("#7 ... but at a clean exit or a reboot", !strcmp(slurp(tf), v));
	mono_adj -= FLOOR_SAVE_S * 1000LL;
	auth_init();                                       /* = a respawn or a reboot */
	time_hw = hw_saved = -1;
	hw_load();
	check("#7 read at start: the floor and the mark", seen_floor == now + 105 && time_hw == now + 105);
	expect("#7 ... a token made before it is refused after the restart",
	       run(soap_req(DEV, wsse("admin", A_PW, now + 25, 0, 0), B_INFO, NULL)), "401 Unauthorized");
	build_epoch = now + 1000000;
	time_hw = now + 200;
	hw_save(1);
	check("#7 an unset clock is never saved", !strcmp(slurp(tf), v));
	build_epoch = BUILD_EPOCH;
	write_file(tf, "12x\n");
	log_start();
	seen_floor = -1;
	hw_load();
	lg = log_stop();
	check("#7 a damaged file is ignored (logged)", seen_floor == -1 && strstr(lg, "not a time"));
	unlink(tf);
	seen_floor = -1;
	time_hw = hw_saved = -1;
	memset(secret, 0x42, sizeof secret);
	memset(ui_key, 0x24, sizeof ui_key);

	/* #8: lower roles can't use up an operator's or admin's room in the replay cache */
	memset(seen, 0, sizeof seen);
	uint8_t n8[16] = { 0 };
	unsigned ctr = 0;
#define TOKEN(user, role) (ctr++, memcpy(n8, &ctr, sizeof ctr), replayed(n8, sizeof n8, now, now, user, role))
	int ok = 0;
	for (int i = 0; i < 2 * SEEN_PER_USER; i++) ok += !TOKEN(10 + i % 2, L_VIEWER);
	check("#8 two viewers hold their shares (half the cache)", ok == 2 * SEEN_PER_USER);
	check("#8 ... a third viewer gets no room", TOKEN(12, L_VIEWER) < 0 && TOKEN(10, L_VIEWER) < 0);
	ok = 0;
	for (int i = 0; i < SEEN_PER_USER; i++) ok += !TOKEN(1, L_OPERATOR);
	check("#8 an operator still has its whole share", ok == SEEN_PER_USER && TOKEN(1, L_OPERATOR) < 0);
	check("#8 ... a second operator has none left (viewers and operators: three quarters)", TOKEN(13, L_OPERATOR) < 0);
	ok = 0;
	for (int i = 0; i < SEEN_PER_USER; i++) ok += !TOKEN(0, L_ADMIN);
	check("#8 an admin still has its whole share", ok == SEEN_PER_USER && TOKEN(0, L_ADMIN) < 0);
	memset(seen, 0, sizeof seen);
	ok = 0;
	for (int i = 0; i < 3 * SEEN_PER_USER; i++) ok += !TOKEN(20 + i % 3, L_OPERATOR);
	check("#8 three operators: three quarters", ok == 3 * SEEN_PER_USER && TOKEN(23, L_OPERATOR) < 0);
	ok = 0;
	for (int i = 0; i < SEEN_PER_USER; i++) ok += !TOKEN(0, L_ADMIN);
	check("#8 ... the admin's quarter is left", ok == SEEN_PER_USER);
#undef TOKEN
	memset(seen, 0, sizeof seen);

	/* #9: the EndpointReference is keyed with a per-camera secret: no OUI sweep finds the MAC */
	char ep[700], e1[46];
	uint8_t key[64], mac[6], hh[20], m[18 + 6];       /* "openlens-fw/onvif/" + MAC */
	struct in_addr ip4, mask;
	int mtu;
	data_path(EPR_SECRET, ep, sizeof ep);
	unlink(ep);
	epr_keyed = -1;
	log_start();
	epr_make();
	lg = log_stop();
	expect("#9 made on the first start (logged)", lg, "made ");
	check("#9 ... 32 bytes, mode 0600", fsize(ep) == 32 && !stat(ep, &sb) && (sb.st_mode & 0777) == 0600);
	FILE *kf = fopen(ep, "rb");
	size_t kn = kf ? fread(key, 1, sizeof key, kf) : 0;
	if (kf) fclose(kf);
	if_info(mac, &ip4, &mask, &mtu);
	memcpy(m, "openlens-fw/onvif/", 18);
	memcpy(m + 18, mac, 6);
	hmac_sha1_k(key, kn, m, sizeof m, hh);
	char u[37];
	uuid_str(hh, 5, u);
	snprintf(e1, sizeof e1, "urn:uuid:%s", u);
	check("#9 EPR = HMAC-SHA1(the secret, prefix + MAC) as a v5 UUID", kn == 32 && !strcmp(e1, epr));
	sha1(m, sizeof m, hh);
	uuid_str(hh, 5, u);
	snprintf(e1, sizeof e1, "urn:uuid:%s", u);
	check("#9 ... not the old unkeyed hash (it changes once)", strcmp(e1, epr) != 0);
	snprintf(q, sizeof q, "%s", epr);
	epr_keyed = -1;
	*epr = 0;
	epr_make();
	check("#9 stable over a restart (the file is read, not remade)", !strcmp(q, epr) && fsize(ep) == 32);
	write_file(ep, "short");
	epr_keyed = -1;
	log_start();
	epr_make();
	epr_make();
	lg = log_stop();
	check("#9 a damaged secret: the unkeyed hash, logged once, the file left alone",
	      !strcmp(e1, epr) && count(lg, "can't be read or written") == 1 && fsize(ep) == 5);
	const char *up = users_path;
	users_path = "/nonexistent/dir/users";
	epr_keyed = -1;
	epr_make();
	check("#9 no place to keep it: the unkeyed hash", !strcmp(e1, epr) && epr_keyed == 0);
	users_path = up;
	unlink(ep);
	epr_keyed = -1;
	*epr = 0;

	/* #10: a subscription belongs to the user who made it */
	memset(subs, 0, sizeof subs);
	char sa[128], sbp[128], sc[128];
	sub_path(run(soap_req(EV, wsse("op", O_PW, now, 0, 0), "<tev:CreatePullPointSubscription/>", NULL)), sa, sizeof sa);
	r = run(soap_req(sa, wsse("view", V_PW, now, 0, 0), pull_body("PT0S", 10), NULL));
	expect("#10 another user's PullMessages: as unknown", r, "ResourceUnknownFault");
	r = run(soap_req(sa, wsse("admin", A_PW, now, 0, 0), "<wsnt:Renew><wsnt:TerminationTime>PT10S</wsnt:TerminationTime>"
			 "</wsnt:Renew>", NULL));
	expect("#10 ... Renew (even an admin's)", r, "ResourceUnknownFault");
	r = run(soap_req(sa, wsse("view", V_PW, now, 0, 0), "<wsnt:Unsubscribe/>", NULL));
	expect("#10 ... Unsubscribe", r, "ResourceUnknownFault");
	expect("#10 the owner's pull still works", run(soap_req(sa, wsse("op", O_PW, now, 0, 0), pull_body("PT0S", 10), NULL)),
	       "<tev:PullMessagesResponse>");
	sub_path(run(soap_req(EV, wsse("view", V_PW, now, 0, 0), "<tev:CreatePullPointSubscription/>", NULL)), sbp, sizeof sbp);
	sub_path(run(soap_req(EV, wsse("view", V_PW, now, 0, 0), "<tev:CreatePullPointSubscription/>", NULL)), sc, sizeof sc);
	expect("#10 a viewer's second subscription took its own first one's place",
	       run(soap_req(sbp, wsse("view", V_PW, now, 0, 0), pull_body("PT0S", 10), NULL)), "ResourceUnknownFault");
	expect("#10 ... never the NVR's", run(soap_req(sa, wsse("op", O_PW, now, 0, 0), pull_body("PT0S", 10), NULL)),
	       "<tev:PullMessagesResponse>");
	memset(subs, 0, sizeof subs);
	sub_path(run(soap_req(EV, wsse("view", V_PW, now, 0, 0), "<tev:CreatePullPointSubscription/>", NULL)), sbp, sizeof sbp);
	sub_path(run(soap_req(EV, wsse("view", V_PW, now, 0, 0), "<tev:CreatePullPointSubscription/>", NULL)), sc, sizeof sc);
	expect("#10 every subscription another user's: refused, none taken",
	       run(soap_req(EV, wsse("op", O_PW, now, 0, 0), "<tev:CreatePullPointSubscription/>", NULL)),
	       "Every subscription is in use");
	mono_adj += (SUB_DEFAULT + 1) * 1000LL;
	expect("#10 ... an expired one is reused",
	       run(soap_req(EV, wsse("op", O_PW, now, 0, 0), "<tev:CreatePullPointSubscription/>", NULL)), "event_service?sub=");
	mono_adj -= (SUB_DEFAULT + 1) * 1000LL;
	memset(subs, 0, sizeof subs);

	/* #12: discovery answers no one when the netmask would make "the subnet" most of the Internet */
	disco_joined = 1;
	inet_pton(AF_INET, "192.0.2.10", &disco_ip);
	time_t ts = mono() + 200000;
	inet_pton(AF_INET, "192.0.2.77", &a);
	log_start();
	disco_mask.s_addr = 0;
	int n0 = disco_allow(a, ts) + disco_allow(a, ts + 1);
	inet_pton(AF_INET, "254.0.0.0", &disco_mask);
	int n7 = disco_allow(a, ts + 2);
	lg = log_stop();
	check("#12 netmask 0 or /7: no Probe answered", !n0 && !n7);
	check("#12 ... logged once", count(lg, "wider than /8") == 1);
	inet_pton(AF_INET, "255.0.0.0", &disco_mask);
	check("#12 /8 still answers its subnet", disco_allow(a, ts + 3));
	disco_joined = 0;

	/* #14: camcfg runs with PATH only and is killed after CAMCFG_MS */
	char stub[700], envf[700], out[512];
	snprintf(stub, sizeof stub, "%s/camcfg-stub", dir);
	snprintf(envf, sizeof envf, "%s/camcfg-env", dir);
	setenv("CAMHTTPD_TEST_LEAK", "1", 1);
	snprintf(q, sizeof q, "env > '%s'", envf);
	stub_script(stub, q);
	const char *saved = camcfg_bin;
	camcfg_bin = stub;
	check("#14 run_camcfg: the stub ran", !run_camcfg("stream.main.fps", "20"));
	expect("#14 ... with PATH", slurp(envf), "PATH=/usr/sbin:/usr/bin:/sbin:/bin\n");
	absent("#14 ... and nothing of ours", slurp(envf), "CAMHTTPD_TEST_LEAK");
	stub_script(stub, "env");
	static const char *const args[] = { "user", "list", NULL };
	check("#14 camcfg_exec: the same", !camcfg_exec(dir, args, "x\n", out, sizeof out) &&
	      strstr(out, "PATH=/usr/sbin:/usr/bin:/sbin:/bin") && !strstr(out, "CAMHTTPD_TEST_LEAK"));
	stub_script(stub, "exec sleep 30");
	long long t0 = mono_ms();
	log_start();
	int rc = run_camcfg("stream.main.fps", "20");
	long long t1 = mono_ms();
	int rc2 = camcfg_exec(dir, args, "x\n", out, sizeof out);
	long long t2 = mono_ms();
	lg = log_stop();
	printf("   a hung camcfg: run_camcfg back after %lld ms, camcfg_exec after %lld ms\n", t1 - t0, t2 - t1);
	check("#14 a hung camcfg is killed after CAMCFG_MS: run_camcfg fails",
	      rc != 0 && t1 - t0 >= CAMCFG_MS && t1 - t0 < CAMCFG_MS + 2000);
	check("#14 ... and camcfg_exec", rc2 == -1 && t2 - t1 >= CAMCFG_MS && t2 - t1 < CAMCFG_MS + 2000);
	check("#14 ... logged", count(lg, "killed") == 2);
	camcfg_bin = saved;
	unsetenv("CAMHTTPD_TEST_LEAK");
	unlink(stub);
	unlink(envf);
	auth_reset();
}

/* ---- privilege separation (Gate 3, docs/CAMHTTPD-PRIVSEP.md): the monitor's own checks -------- */

/* Every reply the worker gets (mon_call's MON_REPLY_SEEN, and mreq below): no test password and no
 * HA1 of one, in any test. */
static const char *const secrets[][2] = { { "admin", "Adm1nPass!" }, { "op", "0perPass" }, { "view", "V1ew:Pass&" },
					  { "boss", "B0ssPass!x" }, { "owner", "Owner-pass-1" }, { "bob", P64 } };
#define NSECRETS (sizeof secrets / sizeof secrets[0])
static unsigned long replies_seen;
static void reply_seen(const char *p, size_t n)
{
	static char ha1[NSECRETS][33];
	char b[256];
	if (!*ha1[0])
		for (size_t i = 0; i < NSECRETS; i++) {      /* md5_hex: md5_str would count as auth hashing */
			int k = snprintf(b, sizeof b, "%s:" REALM ":%s", secrets[i][0], secrets[i][1]);
			md5_hex(b, (size_t)k, ha1[i]);
		}
	replies_seen++;
	for (size_t i = 0; i < NSECRETS; i++)
		if (memmem(p, n, secrets[i][1], strlen(secrets[i][1])) || memmem(p, n, ha1[i], 32)) {
			fprintf(stderr, "FAIL: a reply to the worker holds %s's %s:\n%.*s\n", secrets[i][0],
				memmem(p, n, ha1[i], 32) ? "HA1" : "password", (int)n, p);
			exit(1);
		}
}

/* A request framed as mon_call frames it. */
static size_t mframe(char *buf, uint32_t op, uint64_t grant, int nf, const char *const *f)
{
	size_t n = MON_HDR;
	for (int i = 0; i < nf; i++) {
		size_t l = strlen(f[i]) + 1;
		memcpy(buf + n, f[i], l);
		n += l;
	}
	uint32_t len = (uint32_t)(n - MON_HDR);
	memcpy(buf, &op, 4);
	memcpy(buf + 4, &grant, 8);
	memcpy(buf + 12, &len, 4);
	return n;
}

/* ... straight to the dispatcher: its status, the text in mtext, the fd in *fd (NULL: closed). A
 * well-formed request taken as malformed fails the test. */
static char mtext[MON_MSG];
static int mreq(uint32_t op, uint64_t grant, int nf, const char *const *f, int *fd)
{
	static char m[MON_MSG], rep[MON_MSG];
	size_t rn, n = mframe(m, op, grant, nf, f);
	int rfd;
	int32_t st;
	uint32_t tl;
	if (mon_dispatch(m, n, rep, &rn, &rfd)) { fprintf(stderr, "FAIL: a well-formed %u taken as malformed\n", op); exit(1); }
	memcpy(&st, rep, 4);
	memcpy(&tl, rep + 4, 4);
	if (tl != rn - MON_RHDR) { fprintf(stderr, "FAIL: a reply's length\n"); exit(1); }
	memcpy(mtext, rep + MON_RHDR, tl);
	mtext[tl] = 0;
	reply_seen(mtext, tl);
	if (fd) *fd = rfd;
	else if (rfd >= 0) close(rfd);
	return st;
}

static struct grant *grant_of(uint64_t id)
{
	for (int i = 0; i < GRANT_N; i++)
		if (grants[i].id == id) return &grants[i];
	return NULL;
}

/* An upload's check through the monitor: upd-begin, then upd-check on the same grant. */
static int mcheck(int *fd)
{
	struct in_addr a;
	inet_pton(AF_INET, peer_ip, &a);
	uint64_t g = grant_issue(L_ADMIN, "admin", a);
	if (mreq(MON_UPD_BEGIN, g, 0, NULL, NULL)) { fprintf(stderr, "FAIL: upd-begin\n"); exit(1); }
	return mreq(MON_UPD_CHECK, g, 0, NULL, fd);
}

/* The check's record off its pipe, until EOF (5 s at most): its length. */
static size_t record_of(int fd, char *rec, size_t cap)
{
	size_t n = 0;
	for (int i = 0; i < 500; i++) {
		ssize_t k = read(fd, rec + n, cap - n);
		if (k > 0) { n += (size_t)k; continue; }
		if (k == 0) break;
		usleep(10000);
	}
	close(fd);
	return n;
}

static void test_monitor(const char *dir)
{
	struct in_addr pa;
	char now_s[24], p[700], q[700], nonce[NONCE_LEN + 1], rec[700];
	static char big[MON_MSG + 64];
	const char *r;
	int fd, st;
	long long floor0 = seen_floor;
	int sc = set_calls, rb = reboots;
	inet_pton(AF_INET, peer_ip, &pa);
	write_file(users_path, users_txt);
	auth_reset();
	claim_rate_reset();
	camcfg_fail = exec_fail = 0;
	check("in-process: no socket to a monitor", mon_fd < 0);

	/* the worker's account list: names and roles, nothing else */
	users_load();
	check("users: names and roles from the monitor", nusers == 3 && !strcmp(users[0].name, "admin") &&
	      users[0].role == L_ADMIN && users[2].role == L_VIEWER);
	check("... no password in the worker's list", !memmem(users, sizeof users, A_PW, strlen(A_PW)) &&
	      !memmem(users, sizeof users, O_PW, strlen(O_PW)));
	st = mreq(MON_USERS, 0, 0, NULL, NULL);
	check("users: \"ROLE NAME\" lines only", st == 0 && !strcmp(mtext, "3 admin\n2 op\n1 view\n"));

	/* each privileged op's role (upd-install: in an empty upload directory) */
	snprintf(p, sizeof p, "%s/fwmon", dir);
	mkdir(p, 0700);
	const char *saved_dir = upd_dir;
	upd_dir = p;
	snprintf(now_s, sizeof now_s, "%lld", (long long)time(NULL));
	struct { int op, nf; const char *f[4]; int need; const char *what; } t[] = {
		{ MON_SET, 2, { "image.brightness", "51" }, L_OPERATOR, "set image.brightness" },
		{ MON_SET, 2, { "time.ntp", "pool.example" }, L_ADMIN, "set time.ntp" },
		{ MON_SET, 2, { "time.tz", "UTC0" }, L_ADMIN, "set time.tz" },
		{ MON_USER, 4, { "del", "nosuchuser", "", "" }, L_ADMIN, "user" },
		{ MON_SSHKEY, 2, { "list", "" }, L_ADMIN, "sshkey" },
		{ MON_SETTIME, 2, { now_s, "0" }, L_ADMIN, "settime" },
		{ MON_REBOOT, 0, { NULL }, L_ADMIN, "reboot" },
		{ MON_UPD_BEGIN, 0, { NULL }, L_ADMIN, "upd-begin" },
		{ MON_UPD_INSTALL, 0, { NULL }, L_ADMIN, "upd-install" },
	};
	for (size_t i = 0; i < sizeof t / sizeof t[0]; i++) {
		int ok = 1;
		for (int role = L_VIEWER; role <= L_ADMIN; role++) {
			uint64_t g = grant_issue(role, role_name[role], pa);
			st = mreq((uint32_t)t[i].op, g, t[i].nf, t[i].f, NULL);
			ok &= (st == MON_DENIED) == (role < t[i].need);
		}
		snprintf(q, sizeof q, "role table: %s needs %s", t[i].what, role_name[t[i].need]);
		check(q, ok);
	}
	check("... the allowed ones ran (settime, reboot)", set_calls == sc + 1 && reboots == rb + 1);
	seen_floor = floor0;

	/* grants: none, forged, on an op that takes none */
	const char *setf[2] = { "image.brightness", "52" };
	uint64_t g = grant_issue(L_ADMIN, "admin", pa);
	check("no grant -> denied", mreq(MON_SET, 0, 2, setf, NULL) == MON_DENIED);
	check("a forged grant -> denied", mreq(MON_SET, 0x0123456789abcdefULL, 2, setf, NULL) == MON_DENIED &&
	      mreq(MON_SET, g + 1, 2, setf, NULL) == MON_DENIED && mreq(MON_SET, ~g, 2, setf, NULL) == MON_DENIED);
	check("a grant on conf (it takes none) -> denied, no fd", mreq(MON_CONF, g, 0, NULL, &fd) == MON_DENIED && fd < 0);
	check("conf: an fd of cam.conf", mreq(MON_CONF, 0, 0, NULL, &fd) == 0 && fd >= 0);
	FILE *cf = fdopen(fd, "r");
	char line[200] = "";
	if (cf && fgets(line, sizeof line, cf)) {}
	if (cf) fclose(cf);
	check("... readable through it", strchr(line, '=') != NULL);
	check("a grant on auth -> denied", mreq(MON_AUTH, g, 5, (const char *const[]){ peer_ip, "GET", "/", "", "" },
						 NULL) == MON_DENIED);

	/* expiry: 30 s */
	g = grant_issue(L_OPERATOR, "op", pa);
	mono_adj += 29000;
	check("a grant 29 s old works", mreq(MON_SET, g, 2, setf, NULL) == 0);
	mono_adj += 2000;
	check("... 31 s old: expired", mreq(MON_SET, g, 2, setf, NULL) == MON_DENIED && strstr(mtext, "expired"));
	mono_adj -= 31000;

	/* budget: 48 privileged ops */
	g = grant_issue(L_OPERATOR, "op", pa);
	int calls = camcfg_calls;
	for (int i = 0; i < GRANT_OPS; i++) mreq(MON_SET, g, 2, setf, NULL);
	check("48 ops on one grant (the Image form saves 35)", camcfg_calls == calls + GRANT_OPS);
	check("... the 49th: used up", mreq(MON_SET, g, 2, setf, NULL) == MON_DENIED && strstr(mtext, "used-up") &&
	      camcfg_calls == calls + GRANT_OPS);

	/* a refused request changes nothing: not the grant, not the file */
	g = grant_issue(L_OPERATOR, "op", pa);
	calls = camcfg_calls;
	const char *badkey[2] = { "users.admin", "x" }, *ctl[2] = { "image.brightness", "5\x01" },
		   *nl[4] = { "passwd", "op", "", "new\npass" };
	check("set: a key camhttpd doesn't set -> refused", mreq(MON_SET, g, 2, badkey, NULL) == 1);
	check("set: a control character -> refused", mreq(MON_SET, g, 2, ctl, NULL) == 1);
	check("... nothing ran, the grant unspent", camcfg_calls == calls && grant_of(g) && grant_of(g)->uses == 0);
	g = grant_issue(L_ADMIN, "admin", pa);
	check("user: a newline inside the password -> refused", mreq(MON_USER, g, 4, nl, NULL) == 1 &&
	      grant_of(g)->uses == 0);
	const char *rolebad[4] = { "add", "x", "", "longpassword" };
	check("user add without a role -> refused", mreq(MON_USER, g, 4, rolebad, NULL) == 1 && grant_of(g)->uses == 0);

	/* a login's grant: that user, role and address */
	nonce_make((unsigned long)mono(), ++ui_ctr, nonce);
	const char *af[5] = { peer_ip, "GET", "/ui/", digest("op", O_PW, "GET", "/ui/", nonce, 1), "" };
	st = mreq(MON_AUTH, 0, 5, af, NULL);
	struct grant *lg = grant_of(strtoull(mtext, NULL, 16));
	check("auth: the operator's role and a grant bound to op at this address", st == L_OPERATOR && lg &&
	      lg->role == L_OPERATOR && !strcmp(lg->user, "op") && lg->peer.s_addr == pa.s_addr && lg->uses == 0);
	const char *uf[4] = { "del", "view", "", "" };
	check("... which can't run an admin's op", mreq(MON_USER, lg->id, 4, uf, NULL) == MON_DENIED);
	nonce_make((unsigned long)mono(), ++ui_ctr, nonce);
	af[3] = digest("op", "wrong-pass", "GET", "/ui/", nonce, 1);
	log_start();
	st = mreq(MON_AUTH, 0, 5, af, NULL);
	r = log_stop();
	size_t gl = strlen(mtext);
	check("auth: a wrong password -> a challenge with a fresh nonce, no grant", st == -1 && !strcmp(mtext, "0") &&
	      strlen(mtext + gl + 1) == NONCE_LEN);
	expect("... logged by the monitor", r, "192.0.2.50: wrong password for \"op\"");
	auth_reset();

	/* the upload's grant: pinned for one check, however long the body took */
	g = grant_issue(L_ADMIN, "admin", pa);
	check("upd-check on a grant that wasn't pinned -> denied", mreq(MON_UPD_CHECK, g, 0, NULL, NULL) == MON_DENIED);
	check("upd-begin pins it", mreq(MON_UPD_BEGIN, g, 0, NULL, NULL) == 0);
	mono_adj += 600000;                                /* a slow upload: 10 minutes */
	check("... upd-check 10 min later still takes it (nothing staged: refused by the file check)",
	      mreq(MON_UPD_CHECK, g, 0, NULL, NULL) == 1 && strstr(mtext, "can't be opened"));
	check("... once", mreq(MON_UPD_CHECK, g, 0, NULL, NULL) == MON_DENIED);
	check("... and nothing else after 30 s", mreq(MON_SET, g, 2, setf, NULL) == MON_DENIED);
	mono_adj -= 600000;

	/* the staged file as the monitor opens it: O_NOFOLLOW, regular, one link, 1..UPD_MAX */
	char real[700], staged[700];
	snprintf(real, sizeof real, "%s/real", p);
	snprintf(staged, sizeof staged, "%s/" UPD_FILE, p);
	write_file(real, "not a package\n");
	if (symlink(real, staged)) { perror("symlink"); exit(1); }
	check("upd-check: a symlink -> refused", mcheck(NULL) == 1 && strstr(mtext, "symlink"));
	g = grant_issue(L_ADMIN, "admin", pa);
	check("upd-install: a symlink -> refused", mreq(MON_UPD_INSTALL, g, 0, NULL, NULL) == 1 && strstr(mtext, "symlink"));
	unlink(staged);
	if (link(real, staged)) { perror("link"); exit(1); }
	check("... a hard link -> refused", mcheck(NULL) == 1 && strstr(mtext, "regular file"));
	unlink(staged);
	if (mkfifo(staged, 0600)) { perror("mkfifo"); exit(1); }
	check("... a FIFO -> refused (and nothing blocks)", mcheck(NULL) == 1);
	unlink(staged);
	write_file(staged, "");
	check("... an empty file -> refused", mcheck(NULL) == 1);
	if (truncate(staged, UPD_MAX + 1)) { perror("truncate"); exit(1); }
	check("... over 5 MiB -> refused", mcheck(NULL) == 1);
	if (truncate(staged, 1000)) { perror("truncate"); exit(1); }
	/* camupdate that hangs: closing the record's pipe (the worker giving up) kills it at once */
	char pidf[700], body[900];
	snprintf(pidf, sizeof pidf, "%s/hang.pid", p);
	snprintf(q, sizeof q, "%s/hang.sh", p);
	snprintf(body, sizeof body, "echo $$ > '%s'\nexec sleep 30", pidf);
	stub_script(q, body);
	const char *saved_cu = camupdate_bin;
	camupdate_bin = q;
	check("... a regular file: the check starts, a pipe back", mcheck(&fd) == 0 && fd >= 0);
	long hp = 0;
	for (int i = 0; i < 300 && (hp = atol(slurp(pidf))) <= 0; i++) usleep(10000);
	close(fd);
	int gone = 0;
	for (int i = 0; i < 300 && !(gone = kill((pid_t)hp, 0) && errno == ESRCH); i++) usleep(10000);
	check("... the worker closing it kills camupdate", hp > 0 && gone);
	/* a camupdate that can't run: the record still comes, with its status */
	camupdate_bin = "/nonexistent/camupdate";
	check("... a missing camupdate: started", mcheck(&fd) == 0);
	size_t rl = record_of(fd, rec, sizeof rec);
	int ws = 0;
	if (rl >= 5) memcpy(&ws, rec + 1, sizeof ws);
	check("... its record: not killed, exit 127", rl >= 5 && !rec[0] && WIFEXITED(ws) && WEXITSTATUS(ws) == 127);
	camupdate_bin = saved_cu;
	unlink(staged);
	unlink(real);
	unlink(pidf);
	unlink(q);
	rmdir(p);
	upd_dir = saved_dir;

	/* claim and recover: the monitor's own window, state and rate */
	const char *cl4[4] = { peer_ip, "owner", OWNER_PW, "" }, *rc4[4] = { peer_ip, "", "WRONG-CODE", OWNER_PW };
	write_file(users_path, "");
	set_uptime("100.00 1.00\n");
	claim_rate_reset();
	check("claim: unclaimed, in the window -> camcfg claim", mreq(MON_CLAIM, 0, 4, cl4, NULL) == 0 &&
	      strstr(mtext, "recovery-code: "));
	check("... claimed now: refused", mreq(MON_CLAIM, 0, 4, cl4, NULL) == MON_CLOSED);
	write_file(users_path, "");
	set_uptime("1800.00 1.00\n");
	check("... after 30 min: refused", mreq(MON_CLAIM, 0, 4, cl4, NULL) == MON_CLOSED && strstr(mtext, "30 minutes"));
	set_uptime("100.00 1.00\n");
	claim_rate_reset();
	exec_fail = 1;                                     /* camcfg says no: each attempt still counts */
	int nr = 0;
	for (int i = 0; i < CLAIM_POSTS; i++) nr += mreq(MON_CLAIM, 0, 4, cl4, NULL) == 1;
	check("claim: CLAIM_POSTS attempts a minute reach camcfg", nr == CLAIM_POSTS);
	check("... the next: refused by the monitor's rate", mreq(MON_CLAIM, 0, 4, cl4, NULL) == MON_CLOSED &&
	      strstr(mtext, "Too many"));
	exec_fail = 0;
	claim_rate_reset();
	write_file(users_path, users_txt);
	auth_reset();
	int wrong = 0;
	for (int i = 0; i < FAIL_MAX; i++) wrong += mreq(MON_RECOVER, 0, 4, rc4, NULL) == WRONG_CODE;
	check("recover: wrong codes count as failed logins", wrong == FAIL_MAX && auth_blocked(pa, mono()));
	check("... then the address is locked out", mreq(MON_RECOVER, 0, 4, rc4, NULL) == MON_BLOCKED);
	auth_reset();
	claim_rate_reset();
	set_uptime("4000.00 1.00\n");
	check("recover: after the window -> refused", mreq(MON_RECOVER, 0, 4, rc4, NULL) == MON_CLOSED);
	write_file(users_path, "");
	set_uptime("100.00 1.00\n");
	check("recover: nobody to recover -> refused", mreq(MON_RECOVER, 0, 4, rc4, NULL) == MON_CLOSED);
	write_file(users_path, users_txt);
	set_uptime("90061.50 12345.00\n");
	auth_reset();
	claim_rate_reset();

	/* malformed: the dispatcher says so (the loop then kills the worker) */
	size_t rn;
	int rfd;
	static char rep[MON_MSG];
	size_t n = mframe(big, MON_SET, g, 2, setf);
	check("well formed", !mon_dispatch(big, n, rep, &rn, &rfd));
	check("malformed: short of a header", mon_dispatch(big, MON_HDR - 1, rep, &rn, &rfd) == -1);
	check("malformed: a length that doesn't match", mon_dispatch(big, n - 1, rep, &rn, &rfd) == -1);
	big[n - 1] = 'x';
	check("malformed: the last field unterminated", mon_dispatch(big, n, rep, &rn, &rfd) == -1);
	n = mframe(big, MON_SET, g, 1, setf);
	check("malformed: too few fields for the op", mon_dispatch(big, n, rep, &rn, &rfd) == -1);
	const char *six[6] = { "a", "b", "c", "d", "e", "f" };
	n = mframe(big, MON_SET, g, 3, six);
	check("malformed: too many for the op", mon_dispatch(big, n, rep, &rn, &rfd) == -1);
	n = mframe(big, MON_AUTH, 0, 6, six);
	check("malformed: more than any op takes", mon_dispatch(big, n, rep, &rn, &rfd) == -1);
	memset(big + MON_HDR, 'a', MON_MSG + 1 - MON_HDR - 1);
	big[MON_MSG] = 0;
	uint32_t bl = MON_MSG + 1 - MON_HDR;
	memcpy(big + 12, &bl, 4);
	check("malformed: over MON_MSG", mon_dispatch(big, MON_MSG + 1, rep, &rn, &rfd) == -1);
	check("unknown op 0 -> refused, not malformed", mreq(0, 0, 0, NULL, NULL) == MON_DENIED);
	check("unknown op 99 -> refused", mreq(99, 0, 0, NULL, NULL) == MON_DENIED);

	/* fuzz: mutations of well-formed requests of every op, and garbage; never a crash, every reply
	 * well formed, no grant spent and nothing privileged run */
	uint64_t live = grant_issue(L_ADMIN, "admin", pa);
	int uses0 = grant_of(live)->uses, bad = 0, answered = 0;
	int sc2 = set_calls, rb2 = reboots;
	set_uptime("90061.50 12345.00\n");                 /* claim and recover: closed */
	srand(4242);
	for (int it = 0; it < 30000; it++) {
		uint32_t op = (uint32_t)(rand() % (MON_NOPS + 2));
		const char *ff[MON_NF] = { "192.0.2.50", "GET", "/", "", "" };
		int nf = op < MON_NOPS ? mon_ops[op].nf : rand() % 6;
		n = mframe(big, op, rand() % 4 ? 0 : (uint64_t)rand() << 32 | (uint64_t)rand(), nf, ff);
		int muts = rand() % 4;
		for (int k = 0; k < muts; k++) {
			switch (rand() % 4) {
			case 0: if (n) big[(size_t)rand() % n] = (char)rand(); break;
			case 1: n = (size_t)rand() % (n + 1); break;
			case 2: if (n < sizeof big - 64) { size_t e = (size_t)(rand() % 40); for (size_t i = 0; i < e; i++) big[n++] = (char)rand(); } break;
			case 3: { uint32_t l = (uint32_t)rand() % 200; memcpy(big + 12, &l, 4); } break;
			}
		}
		uint32_t mop = 0;
		memcpy(&mop, big, n >= 4 ? 4 : 0);
		if (n >= MON_HDR && rand() % 3 == 0 && (mop == MON_SET || mop == MON_USER || mop == MON_SSHKEY ||
							  mop == MON_SETTIME))
			memcpy(big + 4, &live, 8);              /* a real grant on ops with fields: their shape fails */
		rfd = -1;
		if (mon_dispatch(big, n, rep, &rn, &rfd)) { bad++; continue; }
		int32_t s;
		uint32_t tl;
		memcpy(&s, rep, 4);
		memcpy(&tl, rep + 4, 4);
		if (rn < MON_RHDR || tl != rn - MON_RHDR || rn > MON_MSG) { fprintf(stderr, "FAIL: fuzz: a reply's frame\n"); exit(1); }
		reply_seen(rep + MON_RHDR, tl);
		if (rfd >= 0) close(rfd);
		answered++;
	}
	printf("   monitor fuzz: %d malformed, %d answered\n", bad, answered);
	check("monitor fuzz: 30000 requests, no crash, both kinds seen", bad > 1000 && answered > 1000);
	check("... no privileged op ran on the real grant",
	      grant_of(live) && grant_of(live)->uses == uses0 && reboots == rb2 && set_calls == sc2);
	auth_reset();
	claim_rate_reset();
	write_file(users_path, users_txt);

	/* one real fork: the monitor in a child, this process as the worker over the socket pair */
	int sv[2];
	if (mon_socketpair(sv)) {
		printf("skip: socketpair (%s): no fork test here\n", strerror(errno));
	} else {
		log_start();                                   /* the monitor's log too (its stderr) */
		pid_t m = fork();
		if (m < 0) { perror("fork"); exit(1); }
		if (m == 0) {
			close(sv[1]);
			_exit(mon_serve(sv[0], 0));
		}
		close(sv[0]);
		mon_fd = sv[1];
		r = run(soap_req(DEV, NULL, B_USERS, NULL));
		nonce_of(r, nonce);
		r = run(soap_req(DEV, NULL, B_USERS, digest("admin", A_PW, "POST", DEV, nonce, 1)));
		expect("fork: GetUsers through the monitor process", r, "<tt:Username>op</tt:Username>");
		r = ui_post("/ui/time", "admin", A_PW, "ntp=fork.example");
		expect("fork: a setting saved by the monitor (camcfg set)", r, "Saved. ntpc uses them");
		r = ui_get("/ui/time", "admin", A_PW);
		expect("fork: ... and read back through the fd it passes (cam.conf)", r, "fork.example");
		expect("fork: a wrong password is refused there", run(ui_req("GET", "/ui/", "admin", "nope", NULL, NULL)),
		       "401 Unauthorized");
		check("fork: the monitor's lockout is its own (this process saw no failure)", !fails[0].n && !gfail.n);
		check("fork: a malformed message...", send(sv[1], "\1\0\0", 3, 0) == 3);
		int ms = -1;
		for (int i = 0; i < 300 && waitpid(m, &ms, WNOHANG) == 0; i++) usleep(10000);
		r = log_stop();
		check("... ends the monitor (status 1)", WIFEXITED(ms) && WEXITSTATUS(ms) == 1);
		expect("... which says why", r, "monitor: a malformed message from the worker");
		close(sv[1]);
		mon_fd = -1;
	}
	check("replies scanned for passwords and HA1s (every test)", replies_seen > 5000);
	printf("   %lu replies to the worker scanned: no password, no HA1\n", replies_seen);
	write_file(users_path, users_txt);
	auth_reset();
}

/* ---- HTTPS (docs/PLAN-TLS.md B): camtls's socket, the PROXY line, the scheme, port 80 ------------ */

#define PX "PROXY TCP4 192.0.2.60 192.0.2.10 51234 443\r\n"
#define HTTPS_SAME "Origin: https://192.0.2.10\r\n" FORM_CT

static void tls_clients_reset(void)
{
	for (int i = 0; i < MAX_CLIENTS; i++) {
		if (clients[i].fd >= 0) close(clients[i].fd);
		clients[i].fd = clients[i].file_fd = -1;
		clients[i].state = 0;
		clients[i].peer.s_addr = 0;
	}
}

/* A connection from camtls on a socketpair (sv[1] is camtls's end), through client_attach. */
static struct client *tls_attach(int sv[2])
{
	if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv)) { perror("socketpair"); exit(1); }
	return client_attach(sv[0], C_TLS);            /* which closes sv[0] if it refuses */
}

/* camtls sends bytes; camhttpd reads once (client_read, as the loop). */
static void tls_send(struct client *c, int fd, const char *bytes)
{
	if (send(fd, bytes, strlen(bytes), 0) != (ssize_t)strlen(bytes)) { perror("send"); exit(1); }
	client_read(c);
}

/* Whether camhttpd has closed its end (EOF at camtls's), after what it sent. */
static int tls_closed(int fd)
{
	char b[8192];
	ssize_t k;
	while ((k = recv(fd, b, sizeof b, MSG_DONTWAIT)) > 0) {}
	return k == 0;
}

static int fails_for(const char *ip)
{
	struct in_addr a;
	inet_pton(AF_INET, ip, &a);
	for (int i = 0; i < FAIL_SLOTS; i++)
		if (fails[i].n && fails[i].ip.s_addr == a.s_addr) return fails[i].n;
	return 0;
}

static void test_proxy_parse(void)
{
	static const struct { const char *in; int want; const char *src, *dst; int sp, dp; } t[] = {
		{ PX, 44, "192.0.2.60", "192.0.2.10", 51234, 443 },
		{ PX "GET / HTTP/1.1\r\n\r\n", 44, "192.0.2.60", "192.0.2.10", 51234, 443 },   /* the request follows */
		{ "PROXY TCP4 255.255.255.255 255.255.255.255 65535 65535\r\n", 56, "255.255.255.255", "255.255.255.255", 65535, 65535 },
		{ "PROXY TCP4 0.0.0.0 192.0.2.1 1 1\r\n", 34, "0.0.0.0", "192.0.2.1", 1, 1 },
		{ "", 0, NULL, NULL, 0, 0 }, { "P", 0, NULL, NULL, 0, 0 }, { "PROXY TCP", 0, NULL, NULL, 0, 0 },
		{ "PROXY TCP4 192.0.2.60 192.0.", 0, NULL, NULL, 0, 0 },
		{ "PROXY TCP4 192.0.2.60 192.0.2.10 51234 443\r", 0, NULL, NULL, 0, 0 },
		{ "GET / HTTP/1.1\r\n", -1, NULL, NULL, 0, 0 }, { "G", -1, NULL, NULL, 0, 0 },
		{ "proxy tcp4 192.0.2.60 192.0.2.10 51234 443\r\n", -1, NULL, NULL, 0, 0 },
		{ "PROXY TCP6 2001:db8::1 2001:db8::2 51234 443\r\n", -1, NULL, NULL, 0, 0 },
		{ "PROXY UNKNOWN\r\n", -1, NULL, NULL, 0, 0 },
		{ "PROXY UNKNOWN 192.0.2.60 192.0.2.10 51234 443\r\n", -1, NULL, NULL, 0, 0 },
		{ "PROXY TCP4  192.0.2.60 192.0.2.10 51234 443\r\n", -1, NULL, NULL, 0, 0 },
		{ "PROXY TCP4 192.0.2.60  192.0.2.10 51234 443\r\n", -1, NULL, NULL, 0, 0 },
		{ "PROXY TCP4 192.0.2.60 192.0.2.10 51234 443 \r\n", -1, NULL, NULL, 0, 0 },
		{ "PROXY TCP4 192.0.2.60 192.0.2.10 51234\t443\r\n", -1, NULL, NULL, 0, 0 },
		{ "PROXY TCP4 192.0.2.60 192.0.2.10 51234 443\n", -1, NULL, NULL, 0, 0 },
		{ "PROXY TCP4 192.0.2.60 192.0.2.10 51234 443\r\r\n", -1, NULL, NULL, 0, 0 },
		{ "PROXY TCP4 192.0.2.60 192.0.2.10 51234 443 1\r\n", -1, NULL, NULL, 0, 0 },
		{ "PROXY TCP4 192.0.2.60 192.0.2.10 51234\r\n", -1, NULL, NULL, 0, 0 },
		{ "PROXY TCP4 192.0.2.60 192.0.2.10 0 443\r\n", -1, NULL, NULL, 0, 0 },
		{ "PROXY TCP4 192.0.2.60 192.0.2.10 51234 0\r\n", -1, NULL, NULL, 0, 0 },
		{ "PROXY TCP4 192.0.2.60 192.0.2.10 65536 443\r\n", -1, NULL, NULL, 0, 0 },
		{ "PROXY TCP4 192.0.2.60 192.0.2.10 051234 443\r\n", -1, NULL, NULL, 0, 0 },
		{ "PROXY TCP4 192.0.2.60 192.0.2.10 51234 0443\r\n", -1, NULL, NULL, 0, 0 },
		{ "PROXY TCP4 192.0.2.60 192.0.2.10 +5123 443\r\n", -1, NULL, NULL, 0, 0 },
		{ "PROXY TCP4 192.0.2.60 192.0.2.10 -1 443\r\n", -1, NULL, NULL, 0, 0 },
		{ "PROXY TCP4 192.0.2.060 192.0.2.10 51234 443\r\n", -1, NULL, NULL, 0, 0 },
		{ "PROXY TCP4 01.0.2.60 192.0.2.10 51234 443\r\n", -1, NULL, NULL, 0, 0 },
		{ "PROXY TCP4 192.0.2 192.0.2.10 51234 443\r\n", -1, NULL, NULL, 0, 0 },
		{ "PROXY TCP4 192.0.2.256 192.0.2.10 51234 443\r\n", -1, NULL, NULL, 0, 0 },
		{ "PROXY TCP4 192.0.2.60.1 192.0.2.10 51234 443\r\n", -1, NULL, NULL, 0, 0 },
		{ "PROXY TCP4 192..2.60 192.0.2.10 51234 443\r\n", -1, NULL, NULL, 0, 0 },
		{ "PROXY TCP4 0x7f.0.0.1 192.0.2.10 51234 443\r\n", -1, NULL, NULL, 0, 0 },
		{ "PROXY TCP4 camera 192.0.2.10 51234 443\r\n", -1, NULL, NULL, 0, 0 },
		{ "PROXY TCP4 192.0.2.60 192.0.2.10 51234 443x\r\n", -1, NULL, NULL, 0, 0 },
		{ "PROXY TCP4 \r\n", -1, NULL, NULL, 0, 0 }, { "PROXY TCP4\r\n", -1, NULL, NULL, 0, 0 },
		{ "PROXY TCP4 255.255.255.255 255.255.255.255 65535 655350\r\n", -1, NULL, NULL, 0, 0 },   /* 57 bytes */
		{ "PROXY TCP4 255.255.255.255 255.255.255.255 65535 65535  ", -1, NULL, NULL, 0, 0 },     /* 56, no end */
	};
	struct in_addr s, d;
	char a[INET_ADDRSTRLEN], b[INET_ADDRSTRLEN];
	for (size_t i = 0; i < sizeof t / sizeof t[0]; i++) {
		int sp = -2, dp = -2, n = proxy_parse(t[i].in, strlen(t[i].in), &s, &d, &sp, &dp);
		int ok = n == t[i].want;
		if (ok && n > 0) {
			inet_ntop(AF_INET, &s, a, sizeof a);
			inet_ntop(AF_INET, &d, b, sizeof b);
			ok = !strcmp(a, t[i].src) && !strcmp(b, t[i].dst) && sp == t[i].sp && dp == t[i].dp;
		}
		if (!ok) {
			fprintf(stderr, "FAIL proxy_parse(\"%s\") = %d, want %d\n", t[i].in, n, t[i].want);
			exit(1);
		}
	}
	static const char nul[] = "PROXY TCP4 192.0.2.60 192.0.2.10 5\0 443\r\n";
	check("proxy_parse: a NUL inside the line is refused", proxy_parse(nul, sizeof nul - 1, &s, &d, &(int){ 0 }, &(int){ 0 }) == -1);
	printf("ok: proxy_parse: %zu lines (fields, single spaces, CRLF, ports 1..65535 without leading zeros, dotted quads, "
	       "TCP6/UNKNOWN, 56 bytes, incomplete)\n", sizeof t / sizeof t[0]);

	/* fuzz: mutations of good lines never crash, and whatever is accepted is exactly the canonical
	 * line it parsed to (so nothing loose gets through) */
	static const char *const seeds[] = { PX "GET /", "PROXY TCP4 255.255.255.255 255.255.255.255 65535 65535\r\n",
					     "PROXY TCP4 1.2.3.4 5.6.7.8 1 9\r\n" };
	static const char alpha[] = "0123456789. \r\nPROXYTCP4x\0";
	unsigned seed = 12345, taken = 0;
	char buf[96], canon[96];
	for (int it = 0; it < 200000; it++) {
		const char *sd = seeds[it % 3];
		size_t n = strlen(sd);
		memcpy(buf, sd, n);
		for (int m = 1 + (int)((seed = seed * 1103515245u + 12345u) >> 16) % 3; m > 0; m--) {
			unsigned r = (seed = seed * 1103515245u + 12345u) >> 8;
			size_t at = n ? r % n : 0;
			switch (r % 4) {
			case 0: buf[at] = alpha[(r >> 8) % (sizeof alpha - 1)]; break;           /* replace */
			case 1: if (n < sizeof buf - 1) { memmove(buf + at + 1, buf + at, n - at); buf[at] = alpha[(r >> 8) % (sizeof alpha - 1)]; n++; } break;
			case 2: if (n > 1) { memmove(buf + at, buf + at + 1, n - at - 1); n--; } break;   /* delete */
			default: n = at; break;                                                   /* truncate */
			}
		}
		int sp = 0, dp = 0, k = proxy_parse(buf, n, &s, &d, &sp, &dp);
		if (k > 0) {
			inet_ntop(AF_INET, &s, a, sizeof a);
			inet_ntop(AF_INET, &d, b, sizeof b);
			int cn = snprintf(canon, sizeof canon, "PROXY TCP4 %s %s %d %d\r\n", a, b, sp, dp);
			if (cn != k || memcmp(canon, buf, (size_t)k) || k > PROXY_MAX) {
				fprintf(stderr, "FAIL proxy_parse accepted a non-canonical line: %.*s\n", k, buf);
				exit(1);
			}
			taken++;
		} else if (k < -1 || (k == 0 && n >= PROXY_MAX)) {
			fprintf(stderr, "FAIL proxy_parse: %d for %zu bytes\n", k, n);
			exit(1);
		}
	}
	check("proxy_parse fuzz: some mutations still parse (and only canonically)", taken > 100);
	printf("ok: proxy_parse fuzz: 200000 mutated lines, %u accepted, each byte-exact canonical\n", taken);
	for (int it = 0; it < 50000; it++) {                  /* random bytes, any length up to 96 */
		size_t n = ((seed = seed * 1103515245u + 12345u) >> 16) % sizeof buf;
		for (size_t i = 0; i < n; i++) buf[i] = (char)((seed = seed * 1103515245u + 12345u) >> 16);
		if (n > 11 && it % 2) memcpy(buf, "PROXY TCP4 ", 11);
		int sp, dp;
		if (proxy_parse(buf, n, &s, &d, &sp, &dp) > 0 && memcmp(buf, "PROXY TCP4 ", 11)) {
			fprintf(stderr, "FAIL proxy_parse accepted random bytes\n");
			exit(1);
		}
	}
	printf("ok: proxy_parse: 50000 random inputs, no crash\n");
}

/* Stage D, while HTTPS is up (the caller set tfd and the ready file): every ONVIF address follows
 * the connection, rtsps:// for HTTPS (or for everyone with net.plain=0), HTTPS in the protocols,
 * both XAddrs in discovery, and net.plain=0 closing port 80's ONVIF and snapshot. */
static void test_onvif_tls(void)
{
	static char conf_was[16384];
	const char *r;
	char rq[REQ_CAP];
	snprintf(conf_was, sizeof conf_was, "%s", slurp(conf_path));
	static const struct { const char *path, *body; int auth; const char *https, *http; } u[] = {
		{ DEV, "<tds:GetCapabilities><tds:Category>All</tds:Category></tds:GetCapabilities>", 0,
		  "<tt:XAddr>https://192.0.2.10/onvif/media_service</tt:XAddr>", "<tt:XAddr>http://192.0.2.10/onvif/media_service<" },
		{ DEV, "<tds:GetServices><tds:IncludeCapability>false</tds:IncludeCapability></tds:GetServices>", 0,
		  "<tds:XAddr>https://192.0.2.10/onvif/event_service</tds:XAddr>", "<tds:XAddr>http://192.0.2.10/onvif/event_service<" },
		{ MED, PT("GetSnapshotUri", "Profile_1"), 1, "<tt:Uri>https://192.0.2.10/snapshot.jpg</tt:Uri>",
		  "<tt:Uri>http://192.0.2.10/snapshot.jpg</tt:Uri>" },
		{ MED, PT("GetStreamUri", "Profile_1"), 1, "<tt:Uri>rtsps://192.0.2.10:322/</tt:Uri>",
		  "<tt:Uri>rtsp://192.0.2.10:554/</tt:Uri>" },
		{ MED, PT("GetStreamUri", "Profile_2"), 1, "<tt:Uri>rtsps://192.0.2.10:322/sub</tt:Uri>",
		  "<tt:Uri>rtsp://192.0.2.10:554/sub</tt:Uri>" },
		{ EV, SUBSCRIBE("tns1:RuleEngine/CellMotionDetector/Motion", "PT60S"), 1,
		  "<wsa:Address>https://192.0.2.10/onvif/event_service?sub=", "<wsa:Address>http://192.0.2.10/onvif/event_service?sub=" },
	};
	for (int tls = 0; tls < 2; tls++)
		for (size_t i = 0; i < sizeof u / sizeof u[0]; i++) {
			as_tls = tls;
			snprintf(rq, sizeof rq, "%s", soap_req(u[i].path, u[i].auth ? wsse("admin", A_PW, time(NULL), 0, 0) : NULL,
							       u[i].body, NULL));
			r = run(rq);
			if (!strstr(r, tls ? u[i].https : u[i].http) || strstr(r, tls ? u[i].http : u[i].https)) {
				fprintf(stderr, "FAIL ONVIF URL over %s: %s\n%s\n", tls ? "HTTPS" : "port 80", u[i].body, r);
				exit(1);
			}
		}
	memset(subs, 0, sizeof subs);
	printf("ok: while HTTPS is up, GetCapabilities, GetServices, GetSnapshotUri, the PullPoint address are https:// "
	       "and GetStreamUri rtsps://ADDRESS:322/ over HTTPS; http:// and rtsp://ADDRESS:554/ on port 80\n");
	as_tls = 0;
	/* SSS's "HTTPS: Supported" comes from these (bench on cam #1, 2026-10-25: "Not Supported"
	 * while they said false) */
	r = run(soap_req(DEV, NULL, "<tds:GetCapabilities><tds:Category>All</tds:Category></tds:GetCapabilities>", NULL));
	expect("GetCapabilities while HTTPS is up: Security TLS1.2 true", r, "<tt:TLS1.1>false</tt:TLS1.1><tt:TLS1.2>true</tt:TLS1.2>");
	r = run(soap_req(DEV, NULL, "<tds:GetServiceCapabilities/>", NULL));
	expect("GetServiceCapabilities (device) while HTTPS is up: TLS1.2=\"true\"", r, "TLS1.1=\"false\" TLS1.2=\"true\"");
	r = run(soap_req(DEV, wsse("view", V_PW, time(NULL), 0, 0), "<tds:GetNetworkProtocols/>", NULL));
	expect("GetNetworkProtocols while HTTPS is up: HTTPS 443", r, "<tt:Name>HTTPS</tt:Name><tt:Enabled>true</tt:Enabled>"
	       "<tt:Port>443</tt:Port>");
	expect("... HTTP 80 kept", r, "<tt:Name>HTTP</tt:Name><tt:Enabled>true</tt:Enabled><tt:Port>80</tt:Port>");
	expect("... RTSP 554 kept", r, "<tt:Name>RTSP</tt:Name><tt:Enabled>true</tt:Enabled><tt:Port>554</tt:Port>");
	sbn = 0;
	sbover = 0;
	disco_target("192.0.2.10");
	sb[sbn] = 0;
	expect("WS-Discovery XAddrs while HTTPS is up: both, http:// first", sb,
	       "<d:XAddrs>http://192.0.2.10/onvif/device_service https://192.0.2.10/onvif/device_service</d:XAddrs>");

	/* net.plain=0: SSS has moved */
	write_file(conf_path, "net.plain=0\n");
	log_start();
	r = run(soap_req(DEV, wsse("admin", A_PW, time(NULL), 0, 0), "<tds:GetDeviceInformation/>", NULL));
	char was[2048];
	snprintf(was, sizeof was, "%s", r);
	r = run(soap_req(MED, NULL, PT("GetStreamUri", "Profile_1"), NULL));
	const char *lg = log_stop();
	expect("net.plain=0: ONVIF on port 80 is 403", was, "HTTP/1.1 403 Forbidden");
	expect("... a SOAP fault saying why", was, "Plain HTTP is off on this camera (net.plain=0)");
	absent("... before any login", was, "WWW-Authenticate");
	absent("... and nothing answered", was, "GetDeviceInformationResponse");
	expect("... without credentials too", r, "403 Forbidden");
	expect("... logged", lg, "192.0.2.50: /onvif/device_service on port 80 refused: net.plain=0");
	check("... once a minute", count(lg, "refused: net.plain=0") == 1);
	r = ui_get("/snapshot.jpg", "view", V_PW);
	expect("... /snapshot.jpg on port 80: 403", r, "403 Forbidden");
	absent("... no JPEG, no challenge", r, "WWW-Authenticate");
	expect("... the browser's pages still redirect", ui_get("/ui/", NULL, NULL), "Location: https://192.0.2.10/ui/\r\n");
	expect("... /ui.css still served", run("GET /ui.css HTTP/1.1\r\nHost: 192.0.2.10\r\n\r\n"), "text/css");
	as_tls = 1;
	r = run(soap_req(MED, wsse("view", V_PW, time(NULL), 0, 0), PT("GetStreamUri", "Profile_1"), NULL));
	expect("... over HTTPS: rtsps://", r, "<tt:Uri>rtsps://192.0.2.10:322/</tt:Uri>");
	expect("... /snapshot.jpg over HTTPS is served", ui_get("/snapshot.jpg", NULL, NULL), "401 Unauthorized");
	as_tls = 0;
	sbn = 0;
	disco_target("192.0.2.10");
	sb[sbn] = 0;
	expect("... discovery names https:// only", sb, "<d:XAddrs>https://192.0.2.10/onvif/device_service</d:XAddrs>");
	unlink(tls_ready);                                     /* HTTPS down: plain again, whatever net.plain says */
	r = run(soap_req(MED, wsse("view", V_PW, time(NULL), 0, 0), PT("GetStreamUri", "Profile_1"), NULL));
	expect("net.plain=0 but HTTPS down: port 80's ONVIF works (the fallback)", r, "<tt:Uri>rtsp://192.0.2.10:554/</tt:Uri>");
	r = run(soap_req(DEV, wsse("view", V_PW, time(NULL), 0, 0), "<tds:GetNetworkProtocols/>", NULL));
	absent("... GetNetworkProtocols without HTTPS", r, "HTTPS");
	r = run(soap_req(DEV, NULL, "<tds:GetCapabilities><tds:Category>All</tds:Category></tds:GetCapabilities>", NULL));
	expect("... GetCapabilities: TLS1.2 false", r, "<tt:TLS1.2>false</tt:TLS1.2>");
	r = run(soap_req(DEV, NULL, "<tds:GetServiceCapabilities/>", NULL));
	expect("... GetServiceCapabilities: TLS1.2=\"false\"", r, "TLS1.2=\"false\"");
	sbn = 0;
	disco_target("192.0.2.10");
	sb[sbn] = 0;
	expect("... discovery: http:// only", sb, "<d:XAddrs>http://192.0.2.10/onvif/device_service</d:XAddrs>");
	write_file(tls_ready, "");
	write_file(conf_path, conf_was);
	plain_noted = -TLS_NOTE_MS;
	expect("net.plain back to 1: port 80's ONVIF again", run(soap_req(DEV, NULL, "<tds:GetSystemDateAndTime/>", NULL)),
	       "GetSystemDateAndTimeResponse");
	sbn = 0;
	sbover = 0;
}

static void test_tls(const char *dir)
{
	const char *r, *lg;
	char ready[700], path[700], pw[700], gr[700], b[2048];
	int sv[2], sv2[2], buf = 0;
	socklen_t bl = sizeof buf;
	struct client *c;
	test_proxy_parse();
	tls_clients_reset();
	auth_reset();
	if (!getuid()) {                                     /* tls_uid 0 is refused by design */
		printf("skip: camtls connections (the test runs as root)\n");
		return;
	}

	/* the socket: -t's checks (bind is refused in the agent sandbox; as a user, chown to root is) */
	snprintf(path, sizeof path, "%s/tls.sock", dir);
	snprintf(pw, sizeof pw, "%s/passwd", dir);
	snprintf(gr, sizeof gr, "%s/group", dir);
	write_file(pw, "root:x:0:0::/root:/bin/sh\ncamtls:x:4243:4244::/:/bin/false\n");
	write_file(gr, "root:x:0:\ncamtls:x:4244:\n");
	log_start();
	check("-t: a relative path is refused", tls_listen("tls.sock:4242:4242", "/nonexistent", "/nonexistent") < 0);
	check("-t: no user", tls_listen("/run/x.sock", "/nonexistent", "/nonexistent") < 0);
	snprintf(b, sizeof b, "%s:nosuchuser", path);
	check("-t: an unknown user", tls_listen(b, pw, gr) < 0);
	snprintf(b, sizeof b, "%s:root", path);
	check("-t: root refused", tls_listen(b, pw, gr) < 0);
	snprintf(b, sizeof b, "%s:0:0", path);
	check("... as 0:0 too", tls_listen(b, pw, gr) < 0);
	write_file(path, "not a socket");
	snprintf(b, sizeof b, "%s:camtls", path);
	check("-t: a regular file at the path is refused...", tls_listen(b, pw, gr) < 0);
	check("... and left alone", !access(path, F_OK));
	unlink(path);
	int fd = tls_listen(b, pw, gr);
	lg = log_stop();
	if (fd >= 0) {                                        /* only as root */
		struct stat st;
		check("-t: the socket is 0660, group USER's", !stat(path, &st) && S_ISSOCK(st.st_mode) &&
		      (st.st_mode & 0777) == 0660 && st.st_gid == 4244 && st.st_uid == 0 && tls_uid == 4243);
		close(fd);
		unlink(path);
	} else {
		check("-t: a socket that couldn't be made (bind or chown refused here) leaves no file", access(path, F_OK));
	}
	expect("... each failure says camhttpd runs without HTTPS", lg, "; running without HTTPS");
	expect("... with drop_lookup's reason", lg, "no such user");
	unlink(pw);
	unlink(gr);
	tls_uid = 0;

	/* connections: the uid check */
	log_start();
	tls_uid = getuid() + 1;
	c = tls_attach(sv);
	lg = log_stop();
	check("a connection from another uid is refused before it takes a slot", !c && tls_closed(sv[1]));
	expect("... logged", lg, "camtls socket: a connection from uid");
	close(sv[1]);
	tls_uid = 0;
	c = tls_attach(sv);
	check("... tls_uid 0 (never set) takes nothing", !c && tls_closed(sv[1]));
	close(sv[1]);
	tls_uid = getuid();
	c = tls_attach(sv);
	check("camtls's uid: attached, waiting for its PROXY line, address 0.0.0.0", c && c->proxy && !c->tls &&
	      c->peer.s_addr == 0 && !strcmp(c->local, "0.0.0.0"));
	check("... SO_SNDBUF about 32 KiB", !getsockopt(sv[0], SOL_SOCKET, SO_SNDBUF, &buf, &bl) && buf >= TLS_SNDBUF &&
	      buf <= 2 * TLS_SNDBUF);
	check("... in the first free slot", c == &clients[0]);
	tls_send(c, sv[1], "PROXY TCP4 192.0.2.61 192.0.2");
	check("a PROXY line in pieces: still waiting after the first", c->fd >= 0 && c->proxy && !c->tls && c->in_len == 29);
	r = ui_req("GET", "/ui/", "admin", "wrong-pass", NULL, NULL);
	snprintf(b, sizeof b, ".10 50000 443\r\n%s", r);
	tls_send(c, sv[1], b);
	check("... then the client's address and the camera's", c->tls && !c->proxy && !strcmp(c->local, "192.0.2.10") &&
	      c->peer.s_addr == inet_addr("192.0.2.61"));
	client_write(c);
	r = drain(sv[1]);
	expect("... the request after it is answered (a wrong password: 401)", r, "401 Unauthorized");
	check("... and the lockout counts the client's address, not camtls's", fails_for("192.0.2.61") == 1 &&
	      !fails_for("0.0.0.0"));
	check("... closed after the reply", c->fd < 0 && tls_closed(sv[1]));
	close(sv[1]);
	auth_reset();

	c = tls_attach(sv);
	tls_send(c, sv[1], PX "GET /ui.css HTTP/1.1\r\nHost: 192.0.2.10\r\n\r\n");
	client_write(c);
	r = drain(sv[1]);
	expect("PROXY line and request in one read: served", r, "200 OK");
	expect("... /ui.css", r, "text/css");
	close(sv[1]);

	static const char *const bad[] = { "PROXY TCP6 2001:db8::1 2001:db8::2 51234 443\r\n", "GET / HTTP/1.1\r\n\r\n",
					   "PROXY TCP4 192.0.2.60 192.0.2.10 51234 443\n\r\n", "PROXY UNKNOWN\r\n" };
	for (size_t i = 0; i < sizeof bad / sizeof bad[0]; i++) {
		c = tls_attach(sv);
		log_start();
		tls_send(c, sv[1], bad[i]);
		lg = log_stop();
		if (c->fd >= 0 || !tls_closed(sv[1]) || !strstr(lg, "camtls: not a PROXY TCP4 line")) {
			fprintf(stderr, "FAIL a bad PROXY line isn't closed: %s\n", bad[i]);
			exit(1);
		}
		close(sv[1]);
	}
	printf("ok: a bad PROXY line (TCP6, none, LF only, UNKNOWN): closed, logged, nothing answered\n");
	tls_clients_reset();

	/* PROXY_MS, and evictable while waiting */
	c = tls_attach(sv);
	tls_tick(mono_ms());
	check("no PROXY line yet: kept within PROXY_MS", c->fd >= 0);
	mono_adj += PROXY_MS + 1;
	log_start();
	tls_tick(mono_ms());
	lg = log_stop();
	check("... closed after it", c->fd < 0 && tls_closed(sv[1]));
	expect("... logged", lg, "no PROXY line within 1000 ms");
	close(sv[1]);
	c = tls_attach(sv);
	for (int i = 1; i < MAX_CLIENTS; i++) {
		client_reset(&clients[i], open("/dev/null", O_RDONLY));
		inet_pton(AF_INET, "192.0.2.70", &clients[i].peer);
	}
	check("every slot taken by fresh connections: none can go", !slot_victim());
	c->since -= HDR_GRACE_MS + 1;
	check("... one from camtls waiting for its PROXY line past HDR_GRACE_MS is the one to go", slot_victim() == c);
	close(sv[1]);
	tls_clients_reset();

	/* the per-address limits: PER_PEER while the address is unknown (0.0.0.0), then the client's */
	int pend[PER_PEER + 1][2];
	for (int i = 0; i < PER_PEER; i++) check("pending camtls connection", tls_attach(pend[i]) != NULL);
	check("... at most PER_PEER without their PROXY line", !tls_attach(pend[PER_PEER]) && tls_closed(pend[PER_PEER][1]));
	for (int i = 0; i <= PER_PEER; i++) close(pend[i][1]);
	tls_clients_reset();
	for (int i = 0; i < PER_PEER; i++) {                    /* the client's own address, on port 80 */
		client_reset(&clients[i], open("/dev/null", O_RDONLY));
		inet_pton(AF_INET, "192.0.2.60", &clients[i].peer);
	}
	c = tls_attach(sv);
	log_start();
	tls_send(c, sv[1], PX "GET /ui.css HTTP/1.1\r\nHost: 192.0.2.10\r\n\r\n");
	lg = log_stop();
	check("PER_PEER applied to the client's address after PROXY: closed", c->fd < 0 && tls_closed(sv[1]));
	expect("... logged", lg, "192.0.2.60: over 4 connections from this address (HTTPS): closed");
	close(sv[1]);
	c = tls_attach(sv);
	tls_send(c, sv[1], "PROXY TCP4 192.0.2.62 192.0.2.10 51234 443\r\nGET /ui.css HTTP/1.1\r\nHost: 192.0.2.10\r\n\r\n");
	check("... another address is served", c->fd >= 0 && c->state == 1);
	client_write(c);
	close(sv[1]);
	tls_clients_reset();
	for (int i = 0; i < BODY_PER_PEER; i++) {               /* two unfinished bodies from 192.0.2.60 */
		client_reset(&clients[i], open("/dev/null", O_RDONLY));
		inet_pton(AF_INET, "192.0.2.60", &clients[i].peer);
		clients[i].hdr_len = 40;
	}
	c = tls_attach(sv);
	tls_send(c, sv[1], PX "POST /ui/time HTTP/1.1\r\nHost: 192.0.2.10\r\nContent-Length: 100\r\n\r\nabc");
	client_write(c);
	expect("BODY_PER_PEER counts the client's address after PROXY: 429", drain(sv[1]), "429 Too Many Requests");
	close(sv[1]);
	c = tls_attach(sv);
	tls_send(c, sv[1], "PROXY TCP4 192.0.2.62 192.0.2.10 51234 443\r\nPOST /ui/time HTTP/1.1\r\nHost: 192.0.2.10\r\n"
		 "Content-Length: 100\r\n\r\nabc");
	check("... another address's body goes on", c->fd >= 0 && !c->state && c->hdr_len);
	close(sv[1]);
	tls_clients_reset();
	check("a port-80 attach needs an IPv4 peer", !socketpair(AF_UNIX, SOCK_STREAM, 0, sv2) && !client_attach(sv2[0], C_TCP) &&
	      tls_closed(sv2[1]));
	close(sv2[1]);
	r = run(PX "GET /ui.css HTTP/1.1\r\nHost: 192.0.2.10\r\n\r\n");
	expect("a PROXY line on port 80 is just a bad request", r, "400 Bad Request");

	/* the scheme: Origin/Referer, Host, links, /onvif/ */
	int calls = camcfg_calls;
	as_tls = 1;
	snprintf(b, sizeof b, "csrf=%s&ntp=tls.example", token("admin", 0));
	r = run(ui_req("POST", "/ui/time", "admin", A_PW, HTTPS_SAME, b));
	expect("HTTPS: a form with Origin https://<Host> is taken", r, "Saved. ntpc uses them");
	check("... camcfg ran", camcfg_calls > calls);
	r = run(ui_req("POST", "/ui/time", "admin", A_PW, "Referer: https://192.0.2.10/ui/time\r\n" FORM_CT, b));
	expect("... or a Referer of it", r, "Saved. ntpc uses them");
	calls = camcfg_calls;
	r = run(ui_req("POST", "/ui/time", "admin", A_PW, SAME, b));
	expect("HTTPS: Origin http://<Host> refused", r, "403 Forbidden");
	r = run(ui_req("POST", "/ui/time", "admin", A_PW, "Origin: https://192.0.2.10:8443\r\n" FORM_CT, b));
	expect("... another port refused", r, "403 Forbidden");
	as_tls = 0;
	r = run(ui_req("POST", "/ui/time", "admin", A_PW, HTTPS_SAME, b));
	expect("port 80: Origin https://<Host> refused", r, "403 Forbidden");
	check("... camcfg never ran for those", camcfg_calls == calls);
	r = run("GET /ui/ HTTP/1.1\r\nHost: 192.0.2.10:443\r\n\r\n");
	expect("port 80: Host ADDRESS:443 is another host (421)", r, "421 Misdirected Request");
	expect("... the link is http://", r, "href=\"http://192.0.2.10/ui/\"");
	as_tls = 1;
	expect("HTTPS: Host ADDRESS:443 is us", run("GET /ui/ HTTP/1.1\r\nHost: 192.0.2.10:443\r\n\r\n"), "401 Unauthorized");
	r = run("GET /ui/ HTTP/1.1\r\nHost: 192.0.2.10:80\r\n\r\n");
	expect("HTTPS: Host ADDRESS:80 is not (421)", r, "421 Misdirected Request");
	expect("... the link is https://", r, "href=\"https://192.0.2.10/ui/\"");
	expect("HTTPS: ONVIF is served (stage D)", run(soap_req(DEV, NULL, "<tds:GetSystemDateAndTime/>", NULL)),
	       "GetSystemDateAndTimeResponse");
	r = run(soap_req(DEV, NULL, "<tds:GetCapabilities><tds:Category>All</tds:Category></tds:GetCapabilities>", NULL));
	expect("... its addresses follow the connection: https://", r, "<tt:XAddr>https://192.0.2.10/onvif/device_service<");
	absent("... none http://", r, "http://192.0.2.10/onvif");
	r = run(soap_req(MED, wsse("view", V_PW, time(NULL), 0, 0), PT("GetStreamUri", "Profile_1"), NULL));
	expect("... but no rtsps:// while camtls isn't up", r, "<tt:Uri>rtsp://192.0.2.10:554/</tt:Uri>");
	write_file(users_path, "");
	r = ui_get("/ui/", NULL, NULL);
	expect("HTTPS, unclaimed, after the window: the page names https://", r, "https://192.0.2.10/setup");
	set_uptime("100.00 50.00\n");
	expect("HTTPS, unclaimed: /ui/ redirects to /setup", ui_get("/ui/", NULL, NULL), "Location: /setup\r\n");
	expect("... /setup is the form", ui_get("/setup", NULL, NULL), "name=\"pw2\"");
	as_tls = 0;
	expect("port 80 unchanged: ONVIF", run(soap_req(DEV, NULL, "<tds:GetSystemDateAndTime/>", NULL)), "not set up yet");
	write_file(users_path, users_txt);
	set_uptime("90061.50 12345.00\n");

	/* port 80 while HTTPS is up (the ready file) */
	snprintf(ready, sizeof ready, "%s/ready", dir);
	tls_ready = ready;
	tls_spec = "/run/camhttpd/tls.sock:camtls";
	tfd = open("/dev/null", O_RDONLY);                     /* stands in for the socket */
	write_file(ready, "");
	static const char *const moved[] = { "/", "/ui", "/ui/", "/ui/users", "/ui/firmware", "/setup", "/recover",
					     "/preview.mjpg", "/ui/image?a=1&b=%20x" };
	for (int pass = 0; pass < 2; pass++) {
		if (pass) {                                       /* unclaimed, in the window: the same */
			write_file(users_path, "");
			set_uptime("100.00 50.00\n");
		}
		for (size_t i = 0; i < sizeof moved / sizeof moved[0]; i++) {
			snprintf(b, sizeof b, "GET %s HTTP/1.1\r\nHost: 192.0.2.10\r\n\r\n", moved[i]);
			r = run(b);
			char loc[300];
			snprintf(loc, sizeof loc, "Location: https://192.0.2.10%s\r\n", moved[i]);
			if (!strstr(r, "HTTP/1.1 302 Found") || !strstr(r, loc) || strstr(r, "WWW-Authenticate") ||
			    !strstr(r, "Content-Security-Policy")) {
				fprintf(stderr, "FAIL port 80 while HTTPS is up (%s): GET %s\n%s\n", pass ? "unclaimed" : "claimed",
					moved[i], r);
				exit(1);
			}
		}
	}
	printf("ok: port 80 while HTTPS is up: GET of /, /ui, /ui/*, /setup, /recover, /preview.mjpg -> 302 "
	       "https://<address><target>, no login asked (claimed and unclaimed)\n");
	r = run("GET /setup HTTP/1.1\r\nHost: rebound.example\r\n\r\n");
	expect("... by any Host name, to the address it came in on", r, "Location: https://192.0.2.10/setup\r\n");
	calls = (int)strlen(exec_log);
	log_start();
	r = claim_post("/setup", "name=owner&pw=%s&pw2=%s", OWNER_PW, OWNER_PW);
	lg = log_stop();
	expect("... a POST /setup: 403", r, "403 Forbidden");
	expect("... with the https link", r, "href=\"https://192.0.2.10/setup\"");
	check("... camcfg not run", (int)strlen(exec_log) == calls);
	expect("... logged", lg, "192.0.2.50: POST /setup over plain HTTP refused: HTTPS is up");
	absent("... not the password", lg, OWNER_PW);
	write_file(users_path, users_txt);
	set_uptime("90061.50 12345.00\n");
	r = run("HEAD /ui/ HTTP/1.1\r\nHost: 192.0.2.10\r\n\r\n");
	expect("HEAD /ui/: 302 too", r, "Location: https://192.0.2.10/ui/\r\n");
	expect("... without a body", r, "Content-Length: 0\r\n\r\n");
	expect("a target that isn't printable ASCII: 400", run("GET /ui/\x80 HTTP/1.1\r\nHost: 192.0.2.10\r\n\r\n"),
	       "400 Bad Request");
	expect("... DEL too", run("GET /ui/\x7f HTTP/1.1\r\nHost: 192.0.2.10\r\n\r\n"), "400 Bad Request");
	calls = camcfg_calls;
	r = ui_post("/ui/time", "admin", A_PW, "ntp=plain.example");
	expect("a UI form POST on port 80: 403", r, "403 Forbidden");
	expect("... a page linking to https://", r, "href=\"https://192.0.2.10/ui/time\"");
	absent("... no login asked", r, "WWW-Authenticate");
	check("... nothing saved", camcfg_calls == calls);
	r = run("POST /ui/firmware HTTP/1.1\r\nHost: 192.0.2.10\r\nContent-Type: application/octet-stream\r\n"
		"Content-Length: 3000000\r\n\r\n");
	expect("a firmware upload on port 80: 403 at its headers", r, "403 Forbidden");
	absent("... before any login (no 401)", r, "401");
	check("... nothing staged", upd.state == UPD_NONE && cl.state == 1);
	expect("unchanged: /ui.css", run("GET /ui.css HTTP/1.1\r\nHost: 192.0.2.10\r\n\r\n"), "text/css");
	expect("unchanged: /ui.js", run("GET /ui.js HTTP/1.1\r\nHost: 192.0.2.10\r\n\r\n"), "text/javascript");
	expect("unchanged: /snapshot.jpg (a login)", ui_get("/snapshot.jpg", NULL, NULL), "401 Unauthorized");
	expect("unchanged: ONVIF", run(soap_req(DEV, NULL, "<tds:GetSystemDateAndTime/>", NULL)), "GetSystemDateAndTimeResponse");
	expect("unchanged: anything else", ui_get("/x", NULL, NULL), "404 Not Found");
	as_tls = 1;
	expect("HTTPS while up: the pages as usual", ui_get("/ui/", NULL, NULL), "401 Unauthorized");
	expect("... with a login", ui_get("/ui/users", "admin", A_PW), "200 OK");
	as_tls = 0;
	test_onvif_tls();

	/* the owner's fallback: no ready file, or no socket: port 80 as before */
	unlink(ready);
	tls_noted = -TLS_NOTE_MS;
	expect("no ready file: the UI on port 80 as before", ui_get("/ui/", NULL, NULL), "401 Unauthorized");
	write_file(users_path, "");
	set_uptime("100.00 50.00\n");
	log_start();
	int form_ok = strstr(ui_get("/setup", NULL, NULL), "name=\"pw2\"") != NULL;
	ui_get("/setup", NULL, NULL);
	ui_get("/recover", NULL, NULL);
	lg = log_stop();
	check("... /setup works on port 80", form_ok);
	expect("... and the log says so", lg, "TLS not running: /setup over plain HTTP");
	check("... once a minute", count(lg, "TLS not running") == 1);
	mono_adj += TLS_NOTE_MS;
	log_start();
	expect("... unclaimed /ui/ goes to /setup", ui_get("/ui/", NULL, NULL), "Location: /setup\r\n");
	ui_get("/recover", NULL, NULL);
	lg = log_stop();
	expect("... a minute on, again", lg, "TLS not running: /recover over plain HTTP");
	write_file(ready, "");
	close(tfd);
	tfd = -1;
	tls_noted = -TLS_NOTE_MS;
	log_start();
	r = ui_get("/setup", NULL, NULL);
	lg = log_stop();
	expect("a ready file but no socket (-t failed): port 80 as before", r, "name=\"pw2\"");
	tls_spec = NULL;
	log_start();
	r = ui_get("/setup", NULL, NULL);
	lg = log_stop();
	absent("without -t: no TLS note", lg, "TLS not running");
	unlink(ready);
	tls_ready = "/run/camtls/ready";
	tls_uid = 0;
	write_file(users_path, users_txt);
	set_uptime("90061.50 12345.00\n");
	tls_clients_reset();
	auth_reset();
	claim_rate_reset();
}

/* #183: the System page's HTTPS part and the CA download (camtls-run's public files). */
static void test_ca(const char *dir)
{
	char ca[700], info[700], other[700], b[CA_MAX + 512];
	const char *r, *lg;
	static const char pem[] = "-----BEGIN CERTIFICATE-----\nMIIBcamtestcert\n-----END CERTIFICATE-----\n";
	static const char ok[] = "ok san=192.0.2.10 not_after=2027-11-26T00:00:00Z "
		"ca_fp=00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff "
		"fp=ffeeddccbbaa99887766554433221100ffeeddccbbaa99887766554433221100\n";
	snprintf(ca, sizeof ca, "%s/ca.crt", dir);
	snprintf(info, sizeof info, "%s/info", dir);
	snprintf(other, sizeof other, "%s/elsewhere.crt", dir);
	tls_ca_path = ca;
	tls_info_path = info;
	unlink(ca);
	unlink(info);
	auth_reset();
	r = ui_get("/ui/system", "admin", A_PW);
	expect("HTTPS off: the System page says so", r, "HTTPS is off: camtls hasn't published");
	absent("... no download link", r, "href=\"" CA_PATH "\"");
	r = ui_get(CA_PATH, "admin", A_PW);
	expect("HTTPS off: the download is 404", r, "HTTP/1.1 404");
	expect("... saying why", r, "HTTPS is off: camtls hasn't published the camera's CA certificate");

	write_file(ca, pem);
	write_file(info, ok);
	r = ui_get("/ui/system", "admin", A_PW);
	expect("System page: the download link", r, "<a href=\"/ui/ca.crt\">Download the camera's CA certificate</a>");
	expect("... the certificate's address", r, "<th>Certificate for</th><td>192.0.2.10</td>");
	expect("... its end", r, "<td>2027-11-26T00:00:00Z</td>");
	expect("... the CA fingerprint as pairs",
	       r, "<td>00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF</td>");
	expect("... the certificate's", r, "<td>FF:EE:DD:CC:BB:AA:99:88");
	expect("... camtls not serving now (no ready file)", r, "camtls isn't serving port 443 right now");
	expect("... check the fingerprint over a second channel", r, "<code>camcfg tls show</code>");
	expect("... macOS steps", r, "set \"Secure Sockets Layer (SSL)\" to Always Trust");
	expect("... Firefox steps", r, "Trust this CA to identify websites");
	absent("... no address warning over plain HTTP", r, "another address than this page's");

	r = ui_get(CA_PATH, "admin", A_PW);
	expect("download: 200", r, "HTTP/1.1 200 OK");
	expect("... as a CA certificate", r, "Content-Type: application/x-x509-ca-cert\r\n");
	expect("... a file named for the camera's address", r,
	       "Content-Disposition: attachment; filename=\"camera-ca-192.0.2.10.crt\"\r\n");
	expect("... not cached", r, "Cache-Control: no-store");
	snprintf(b, sizeof b, "Content-Length: %zu\r\n", sizeof pem - 1);
	expect("... its length", r, b);
	check("... the file's bytes, nothing after", strlen(r) > sizeof pem - 1 &&
	      !strcmp(r + strlen(r) - (sizeof pem - 1), pem));
	r = run(ui_req("GET", CA_PATH "?f=../../etc/passwd", "admin", A_PW, NULL, NULL));
	check("... a query names no file", strstr(r, "200 OK") && strstr(r, "MIIBcamtestcert") && !strstr(r, "root:"));
	static const char *const nf[] = { CA_PATH "/../../../etc/passwd", "/ui/../run/camtls/ca.crt", "/ui/ca.crt%2f..",
					  "/ui/CA.CRT", "/ui/ca.crt/" };
	for (size_t i = 0; i < sizeof nf / sizeof nf[0]; i++) {
		r = ui_get(nf[i], "admin", A_PW);
		snprintf(b, sizeof b, "no other path serves it: %s", nf[i]);
		check(b, !strstr(r, "200 OK") && !strstr(r, "BEGIN CERTIFICATE"));
	}

	log_start();
	r = ui_get(CA_PATH, "op", O_PW);
	lg = log_stop();
	expect("an operator may not download it", r, "403 Forbidden");
	absent("... nothing of it", r, "BEGIN CERTIFICATE");
	expect("... logged", lg, "user op may not open /ui/ca.crt");
	expect("a viewer neither", ui_get(CA_PATH, "view", V_PW), "403 Forbidden");
	r = ui_get(CA_PATH, NULL, NULL);
	expect("no login: 401", r, "401 Unauthorized");
	absent("... nothing of it", r, "BEGIN CERTIFICATE");
	expect("POST: 405", run(ui_req("POST", CA_PATH, "admin", A_PW, SAME, "a=1")), "405");
	expect("HEAD: 405", run(ui_req("HEAD", CA_PATH, "admin", A_PW, NULL, NULL)), "405");
	r = run("GET /ui/ca.crt HTTP/1.1\r\nHost: camera.example\r\n\r\n");
	expect("another Host: 421 (DNS rebinding)", r, "421 Misdirected Request");

	/* what's in /run/camtls is camtls's: only a plain, small, single PEM certificate is served */
	unlink(ca);
	write_file(other, pem);
	check("(a link)", !symlink(other, ca));
	expect("a link at ca.crt: not followed", ui_get(CA_PATH, "admin", A_PW), "404");
	expect("... the page says off", ui_get("/ui/system", "admin", A_PW), "HTTPS is off");
	unlink(ca);
	unlink(other);
	static const char *const bad[] = { "hello\n", "-----BEGIN CERTIFICATE-----\nMIIB\n",
		"-----BEGIN CERTIFICATE-----\nA\n-----END CERTIFICATE-----\n-----BEGIN CERTIFICATE-----\nB\n-----END CERTIFICATE-----\n",
		"-----BEGIN PRIVATE KEY-----\nMIIB\n-----END PRIVATE KEY-----\n", "" };
	for (size_t i = 0; i < sizeof bad / sizeof bad[0]; i++) {
		write_file(ca, bad[i]);
		snprintf(b, sizeof b, "not one PEM certificate (%zu): not served", i);
		expect(b, ui_get(CA_PATH, "admin", A_PW), "404");
	}
	memset(b, 'A', CA_MAX + 100);
	memcpy(b, "-----BEGIN CERTIFICATE-----\n", 28);
	strcpy(b + CA_MAX + 50, "\n-----END CERTIFICATE-----\n");
	write_file(ca, b);
	expect("over CA_MAX bytes: not served", ui_get(CA_PATH, "admin", A_PW), "404");
	write_file(ca, pem);

	static const char *const binfo[] = { "renew ip san=192.0.2.10 want=192.0.2.11\n", "bad server.crt\n", "",
		"ok san=192.0.2.10 not_after=2027-11-26T00:00:00Z ca_fp=0011 fp=ffee\n",
		"ok san=<b>x</b> not_after=2027-11-26T00:00:00Z ca_fp=00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff "
		"fp=ffeeddccbbaa99887766554433221100ffeeddccbbaa99887766554433221100\n",
		"ok san=192.0.2.10 not_after=<script> ca_fp=00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff "
		"fp=ffeeddccbbaa99887766554433221100ffeeddccbbaa99887766554433221100\n",
		"ok san=192.0.2.10 not_after=2027-11-26T00:00:00Z ca_fp=00112233445566778899AABBCCDDEEFF00112233445566778899aabbccddeeff "
		"fp=ffeeddccbbaa99887766554433221100ffeeddccbbaa99887766554433221100\n" };
	for (size_t i = 0; i < sizeof binfo / sizeof binfo[0]; i++) {
		write_file(info, binfo[i]);
		r = ui_get("/ui/system", "admin", A_PW);
		snprintf(b, sizeof b, "info not camtls check's ok line (%zu): said, no table", i);
		expect(b, r, "camtls's status (/run/camtls/info) can't be read");
		absent(b, r, "<th>Certificate for</th>");
		absent(b, r, "<script>");
		expect("... the download still offered", r, "href=\"/ui/ca.crt\"");
	}

	write_file(info, ok);
	as_tls = 1;
	absent("over HTTPS at the certificate's address: no warning", ui_get("/ui/system", "admin", A_PW),
	       "another address than this page's");
	write_file(info, "ok san=192.0.2.99 not_after=2027-11-26T00:00:00Z "
		   "ca_fp=00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff "
		   "fp=ffeeddccbbaa99887766554433221100ffeeddccbbaa99887766554433221100\n");
	expect("over HTTPS, the certificate for another address: a warning", ui_get("/ui/system", "admin", A_PW),
	       "The certificate is for another address than this page's");
	as_tls = 0;

	unlink(ca);
	unlink(info);
	tls_ca_path = "/run/camtls/ca.crt";
	tls_info_path = "/run/camtls/info";
	auth_reset();
}

/* ---- settings backup in the web UI (#172) and at setup (#173) ---- */

/* A multipart/form-data POST to path: parts "name=value" (text) in order, then the file part
 * (file NULL: none) of n bytes; `hdrs` the Origin and other headers. Its reply. */
static const char *mp_post(const char *path, const char *user, const char *pw, const char *hdrs,
			   const char *const *texts, int nt, const char *file, size_t n)
{
	static char body[REQ_CAP], req[REQ_CAP];
	char nonce[NONCE_LEN + 1];
	size_t bn = 0;
	for (int i = 0; i < nt; i++) {
		const char *eq = strchr(texts[i], '=');
		bn += (size_t)snprintf(body + bn, sizeof body - bn, "--XyZ\r\nContent-Disposition: form-data; "
				       "name=\"%.*s\"\r\n\r\n%s\r\n", (int)(eq - texts[i]), texts[i], eq + 1);
	}
	if (file) {
		bn += (size_t)snprintf(body + bn, sizeof body - bn, "--XyZ\r\nContent-Disposition: form-data; "
				       "name=\"file\"; filename=\"b.cambak\"\r\nContent-Type: application/octet-stream\r\n\r\n");
		if (n > sizeof body - bn - 64) n = sizeof body - bn - 64;
		memcpy(body + bn, file, n);
		bn += n;
		memcpy(body + bn, "\r\n", 2);
		bn += 2;
	}
	bn += (size_t)snprintf(body + bn, sizeof body - bn, "--XyZ--\r\n");
	nonce_make((unsigned long)mono(), ++ui_ctr, nonce);
	int hn = snprintf(req, sizeof req, "POST %s HTTP/1.1\r\nHost: 192.0.2.10\r\n%s%s%s%sContent-Length: %zu\r\n\r\n",
			  path, user ? "Authorization: " : "", user ? digest(user, pw, "POST", path, nonce, 1) : "",
			  user ? "\r\n" : "", hdrs, bn);
	if ((size_t)hn + bn > sizeof req) { fprintf(stderr, "FAIL mp_post: too large\n"); exit(1); }
	memcpy(req + hn, body, bn);
	return run_n(req, (size_t)hn + bn, 1 << 20);
}

#define MP_SAME "Origin: https://192.0.2.10\r\nContent-Type: multipart/form-data; boundary=XyZ\r\n"
#define MP_SAME80 "Origin: http://192.0.2.10\r\nContent-Type: multipart/form-data; boundary=XyZ\r\n"

/* The stand-in for camcfg backup: records its argv, its passphrase line and (import) the file on
 * its fd 3 in DIR/bk-*; bk-mode says what it does. */
static void bk_stub(const char *path, const char *d)
{
	char s[2048];
	snprintf(s, sizeof s,
		 "echo \"$@\" > %s/bk-args\n"
		 "IFS= read -r pp; printf '%%s' \"$pp\" > %s/bk-pp\n"
		 "mode=$(cat %s/bk-mode)\n"
		 "case \"$3 $4\" in\n"
		 "'backup export')\n"
		 "  case $mode in ok) printf 'cam-backup 1\\nfake\\000bytes'; echo 'camcfg: backup of 3 files, 23 bytes' >&2; exit 0;;\n"
		 "  *) echo 'camcfg: passphrase: at least 12 characters (the file holds the passwords and the CA key)' >&2; exit 1;; esac;;\n"
		 "'backup import')\n"
		 "  cat \"$5\" > %s/bk-got\n"
		 "  case $mode in ok) echo 'restored: 3 files from a backup made at 1 (Unix time, firmware x)'; exit 0;;\n"
		 "  wrong) echo 'camcfg: wrong passphrase, or the backup was changed' >&2; exit 3;;\n"
		 "  *) echo 'camcfg: this backup is from another camera: a backup restores only on the camera that made it' >&2; exit 1;; esac;;\n"
		 "esac\nexit 2", d, d, d, d);
	stub_script(path, s);
}

static void bk_reset(void)
{
	bk_rebooting = 0;
	mon_reboot_at = 0;
	auth_reset();
	claim_rate_reset();
}

static void test_mp_parse(void)
{
	struct mp m;
	size_t n;
	char out[64];
	static const char good[] = "--b\r\nContent-Disposition: form-data; name=\"csrf\"\r\n\r\ntok\r\n"
		"--b\r\nContent-Disposition: form-data; name=\"file\"; filename=\"x\"\r\nContent-Type: a/b\r\n\r\n"
		"\x01\r\n-\0z\r\n--b--\r\n";
	check("multipart: a form with a text and a binary part", !mp_parse(good, sizeof good - 1, "multipart/form-data; boundary=b", &m) &&
	      m.n == 2 && mp_text(&m, "csrf", out, sizeof out) == 1 && !strcmp(out, "tok") &&
	      mp_get(&m, "file", &n) && n == 6 && !memcmp(mp_get(&m, "file", &n), "\x01\r\n-\0z", 6));
	check("multipart: a quoted boundary", !mp_parse(good, sizeof good - 1, "multipart/form-data; boundary=\"b\"", &m));
	check("multipart: the binary part isn't text", mp_text(&m, "file", out, sizeof out) == -1);
	check("multipart: a missing part", mp_text(&m, "pp", out, sizeof out) == 0 && !mp_get(&m, "pp", &n));
	static const struct { const char *ct, *b; } bad[] = {
		{ "multipart/form-data", "--b\r\n\r\n--b--" },
		{ "text/plain; boundary=b", "--b--" },
		{ "multipart/form-data; boundary=", "--b--" },
		{ "multipart/form-data; boundary=b", "x--b--" },
		{ "multipart/form-data; boundary=b", "--b\r\nContent-Disposition: form-data; name=\"a\"\r\n\r\nv" },
		{ "multipart/form-data; boundary=b", "--b\r\nX: y\r\n\r\nv\r\n--b--" },
		{ "multipart/form-data; boundary=b", "--b\r\nContent-Disposition: attachment; name=\"a\"\r\n\r\nv\r\n--b--" },
		{ "multipart/form-data; boundary=b", "--b\r\nContent-Disposition: form-data; name=\"A\"\r\n\r\nv\r\n--b--" },
		{ "multipart/form-data; boundary=b", "--b\r\nContent-Disposition: form-data; name=\"\"\r\n\r\nv\r\n--b--" },
		{ "multipart/form-data; boundary=b", "--b\r\nContent-Disposition: form-data; name=\"a\"\r\n\r\nv\r\n"
		  "--b\r\nContent-Disposition: form-data; name=\"a\"\r\n\r\nw\r\n--b--" },
		{ "multipart/form-data; boundary=b", "--b\r\nContent-Disposition: form-data; name=\"a\"\r\n\r\nv\r\n--b--x" },
		{ "multipart/form-data; boundary=b", "--b\r\nContent-Disposition: form-data; filename=\"a\"\r\n\r\nv\r\n--b--" },
		{ "multipart/form-data; boundary=b", "--b\r\nContent-Disposition: form-data; name=\"a\r\n\r\nv\r\n--b--" },
	};
	for (size_t i = 0; i < sizeof bad / sizeof bad[0]; i++) {
		char w[96];
		snprintf(w, sizeof w, "multipart: malformed case %zu refused", i);
		check(w, mp_parse(bad[i].b, strlen(bad[i].b), bad[i].ct, &m) == -1);
	}
	uint32_t r = 7;
	int ok = 0;
	for (int it = 0; it < 20000; it++) {                  /* mutated: exact-size copies, ASan watches */
		size_t sl = sizeof good - 1;
		char *b = malloc(sl);
		memcpy(b, good, sl);
		for (int k = 0; k < 1 + it % 4 && sl; k++) {
			r = r * 1103515245 + 12345;
			size_t at = (r >> 8) % sl;
			r = r * 1103515245 + 12345;
			if ((r >> 16) % 3 == 0) sl = at;
			else b[at] = "\r\n-b\"=; xa\0"[(r >> 20) % 11];
		}
		char *e = malloc(sl ? sl : 1);
		memcpy(e, b, sl);
		ok += !mp_parse(e, sl, "multipart/form-data; boundary=b", &m);
		free(e);
		free(b);
	}
	printf("ok: multipart parser fuzzed, 20000 mutations (%d still parse)\n", ok);
}

static void test_backup(const char *dir)
{
	char stub[700], mode[700], args[700], ppf[700], got[700], mtd[700];
	static char ud[700], d[700], envv[800];            /* upd_dir, bk_tmp_dir and bk_env point here */
	const char *r, *lg;
	static char saved[16384], bk[8192];
	int sv_tfd = tfd;
	const char *sv_ready = tls_ready;
	struct in_addr pa;
	inet_pton(AF_INET, peer_ip, &pa);
	test_mp_parse();
	snprintf(d, sizeof d, "%s", dir);
	snprintf(stub, sizeof stub, "%s/camcfg-bk-stub", dir);
	snprintf(mode, sizeof mode, "%s/bk-mode", dir);
	snprintf(args, sizeof args, "%s/bk-args", dir);
	snprintf(ppf, sizeof ppf, "%s/bk-pp", dir);
	snprintf(got, sizeof got, "%s/bk-got", dir);
	snprintf(ud, sizeof ud, "%s/fw", dir);
	mkdir(ud, 0700);
	upd_dir = ud;
	bk_tmp_dir = d;
	bk_stub(stub, dir);
	camcfg_bin = stub;
	write_file(users_path, users_txt);
	set_uptime("90061.50 12345.00\n");
	bk_reset();

	/* the System page's part */
	as_tls = 1;
	r = ui_get("/ui/system", "admin", A_PW);
	expect("System page over HTTPS: the backup part", r, "<h2>Settings backup</h2>");
	expect("... the download form (do=backup, passphrase twice)", r, "name=\"do\" value=\"backup\"");
	expect("... the restore form, multipart, to " BK_PATH, r, "action=\"/ui/backup-restore\" enctype=\"multipart/form-data\"");
	expect("... asks for the admin's own password", r, "Your password (admin)");
	expect("... says the file is password-equivalent and a snapshot", r, "A backup is a snapshot");
	as_tls = 0;
	r = ui_get("/ui/system", "admin", A_PW);
	expect("System page over plain HTTP: backups need HTTPS", r, "Backups need HTTPS");
	absent("... and no backup forms", r, "name=\"do\" value=\"backup\"");

	/* download */
	write_file(mode, "ok");
	unlink(args);
	r = ui_post("/ui/system", "admin", A_PW, "do=backup&pp=%s&pp2=%s", "long+enough+pass", "long+enough+pass");
	expect("download over plain HTTP refused", r, "Backups need HTTPS");
	check("... camcfg not run", access(args, F_OK) != 0);
	as_tls = 1;
	r = run(ui_req("POST", "/ui/system", "admin", A_PW, "Origin: https://192.0.2.10\r\n" FORM_CT,
		       "do=backup&pp=long+enough+pass&pp2=long+enough+pass"));
	expect("download without a token: refused", r, "403");
	check("... camcfg not run", access(args, F_OK) != 0);
	char body[300];
	snprintf(body, sizeof body, "csrf=%s&do=backup&pp=long+enough+pass&pp2=other+enough+pass", token("admin", 0));
	r = run(ui_req("POST", "/ui/system", "op", "0perPass", "Origin: https://192.0.2.10\r\n" FORM_CT, body));
	expect("an operator can't download", r, "403");
	r = run(ui_req("POST", "/ui/system", "admin", A_PW, "Origin: https://192.0.2.10\r\n" FORM_CT, body));
	expect("passphrases that differ", r, "The two passphrases differ.");
	check("... camcfg not run", access(args, F_OK) != 0);
	snprintf(body, sizeof body, "csrf=%s&do=backup&pp=%s&pp2=%s", token("admin", 0), "long%20enough%C3%A9", "long%20enough%C3%A9");
	r = run(ui_req("POST", "/ui/system", "admin", A_PW, "Origin: https://192.0.2.10\r\n" FORM_CT, body));
	expect("the download: 200", r, "HTTP/1.1 200 OK");
	expect("... as a file", r, "Content-Type: application/octet-stream\r\n");
	time_t now = time(NULL);
	struct tm tm;
	char day[16], want[200];
	gmtime_r(&now, &tm);
	strftime(day, sizeof day, "%Y%m%d", &tm);
	snprintf(want, sizeof want, "Content-Disposition: attachment; filename=\"camera-192.0.2.10-%s.cambak\"", day);
	expect("... named for the camera and the day", r, want);
	expect("... not cached", r, "Cache-Control: no-store");
	expect("... its length", r, "Content-Length: 23\r\n");
	const char *hb = strstr(r, "\r\n\r\n");
	check("... camcfg's bytes, a NUL included", hb && !memcmp(hb + 4, "cam-backup 1\nfake\0bytes", 23));
	expect("... camcfg backup export, as the monitor runs it", slurp(args), " backup export");
	check("... the passphrase on its stdin, UTF-8 as sent", !strcmp(slurp(ppf), "long enough\xc3\xa9"));
	write_file(mode, "refuse");
	snprintf(body, sizeof body, "csrf=%s&do=backup&pp=short&pp2=short", token("admin", 0));
	r = run(ui_req("POST", "/ui/system", "admin", A_PW, "Origin: https://192.0.2.10\r\n" FORM_CT, body));
	expect("camcfg's refusal on the page", r, "passphrase: at least 12 characters");
	expect("... 400", r, "400 Bad Request");
	uint64_t g = grant_issue(L_OPERATOR, "op", pa);
	const char *f1[1] = { "long enough pass" };
	check("bk-export needs an admin's grant", mreq(MON_BK_EXPORT, g, 1, f1, NULL) == MON_DENIED &&
	      mreq(MON_BK_EXPORT, 0, 1, f1, NULL) == MON_DENIED);
	const char *f1n[1] = { "a\nb" };
	g = grant_issue(L_ADMIN, "admin", pa);
	check("bk-export: a passphrase with a newline refused by the monitor", mreq(MON_BK_EXPORT, g, 1, f1n, NULL) == 1);

	/* restore on the System page */
	static const char file[] = "cam-backup 1\nbinary\0\r\n--Xy\x01";
	const size_t fl = sizeof file - 1;
	const char *tx[3];
	char tk[60], ppw[60], pww[60];
	snprintf(tk, sizeof tk, "csrf=%s", token("admin", 0));
	snprintf(ppw, sizeof ppw, "pp=%s", "long enough pass");
	snprintf(pww, sizeof pww, "pw=%s", A_PW);
	tx[0] = tk; tx[1] = ppw; tx[2] = pww;
	write_file(mode, "ok");
	unlink(got);
	as_tls = 0;
	r = mp_post(BK_PATH, "admin", A_PW, MP_SAME80, tx, 3, file, fl);
	expect("restore over plain HTTP refused", r, "Backups need HTTPS");
	check("... camcfg not run", access(got, F_OK) != 0);
	as_tls = 1;
	r = mp_post(BK_PATH, "op", "0perPass", MP_SAME, tx, 3, file, fl);
	expect("an operator can't restore", r, "403");
	r = mp_post(BK_PATH, "admin", A_PW, "Origin: https://evil.example\r\nContent-Type: multipart/form-data; boundary=XyZ\r\n",
		    tx, 3, file, fl);
	expect("restore from another site's page refused", r, "403");
	r = mp_post(BK_PATH, "admin", A_PW, "Origin: https://192.0.2.10\r\n" FORM_CT, tx, 3, file, fl);
	expect("restore as a urlencoded form refused", r, "415");
	r = mp_post(BK_PATH, "admin", A_PW, "Origin: https://192.0.2.10\r\nContent-Type: multipart/form-data; boundary=Other\r\n",
		    tx, 3, file, fl);
	expect("restore with a boundary that isn't the body's refused", r, "400");
	r = mp_post(BK_PATH, "admin", A_PW, MP_SAME, tx + 1, 2, file, fl);
	expect("restore without a token refused", r, "403");
	r = mp_post(BK_PATH, "admin", A_PW, MP_SAME, tx, 3, NULL, 0);
	expect("restore without a file", r, "Choose the backup file");
	static char huge[BK_UP_MAX + 2];
	memset(huge, 'x', sizeof huge);
	r = mp_post(BK_PATH, "admin", A_PW, MP_SAME, tx, 3, huge, sizeof huge);
	expect("a file over 48 KiB: over SSH", r, "larger than 48 KiB");
	check("... camcfg not run", access(got, F_OK) != 0);
	char wpw[60];
	snprintf(wpw, sizeof wpw, "pw=%s", "Wrong-pass-1");
	const char *txw[3] = { tk, ppw, wpw };
	int before = fails_for(peer_ip);
	log_start();
	r = mp_post(BK_PATH, "admin", A_PW, MP_SAME, txw, 3, file, fl);
	lg = log_stop();
	expect("restore with a wrong password", r, "Wrong password: nothing was restored.");
	check("... counted as a failed login", fails_for(peer_ip) == before + 1);
	check("... camcfg not run", access(got, F_OK) != 0);
	absent("... the password isn't logged", lg, "Wrong-pass-1");
	write_file(mode, "wrong");
	r = mp_post(BK_PATH, "admin", A_PW, MP_SAME, tx, 3, file, fl);
	expect("camcfg's exit 3: a wrong passphrase", r, "Wrong passphrase, or the file was changed");
	check("... counted as a failed login", fails_for(peer_ip) == before + 2);
	check("... camcfg had the file on its fd 3, byte for byte", fsize(got) == (long)fl &&
	      !memcmp(slurp(got), file, 13));
	write_file(mode, "other");
	r = mp_post(BK_PATH, "admin", A_PW, MP_SAME, tx, 3, file, fl);
	expect("another camera's backup: camcfg's reason", r, "this backup is from another camera");
	check("... no reboot", !bk_rebooting && !mon_reboot_at);
	auth_reset();
	write_file(mode, "ok");
	int rb = reboots;
	log_start();
	r = mp_post(BK_PATH, "admin", A_PW, MP_SAME, tx, 3, file, fl);
	lg = log_stop();
	expect("restore: 200", r, "HTTP/1.1 200 OK");
	expect("... the page says it reboots", r, "Restored from the backup. The camera reboots now");
	absent("... no forms while it reboots", r, "name=\"do\" value=\"backup\"");
	expect("... logged", lg, "settings restored from a backup by admin");
	absent("... no passphrase in the log", lg, "long enough pass");
	expect("... camcfg backup import FILE, the file on fd 3", slurp(args), " backup import /dev/fd/3");
	check("... the passphrase on stdin", !strcmp(slurp(ppf), "long enough pass"));
	check("... the staged file deleted", access(tfile("fw/" BK_FILE), F_OK) != 0);
	check("... the body wiped from the connection", !memmem(cl.in, sizeof cl.in, "long enough pass", 16) &&
	      !memmem(cl.in, sizeof cl.in, "binary", 6));
	check("... no reboot yet (the reply first)", reboots == rb && mon_reboot_at);
	r = mp_post(BK_PATH, "admin", A_PW, MP_SAME, tx, 3, file, fl);
	expect("a second restore while it reboots: refused", r, "rebooting");
	mono_adj += BK_REBOOT_MS + 100;
	mon_tick();
	check("... the monitor reboots BK_REBOOT_MS later", reboots == rb + 1 && !mon_reboot_at);
	mono_adj = 0;
	bk_reset();
	expect("GET " BK_PATH " sends to the System page", ui_get(BK_PATH, "admin", A_PW), "Location: /ui/system");

	/* the monitor's own checks on the staged file */
	char sp[700];
	snprintf(sp, sizeof sp, "%s/" BK_FILE, ud);
	unlink(sp);
	if (!symlink(users_path, sp)) {
		const char *f3[3] = { peer_ip, A_PW, "long enough pass" };
		g = grant_issue(L_ADMIN, "admin", pa);
		check("bk-restore: a symlinked upload refused", mreq(MON_BK_RESTORE, g, 3, f3, NULL) == 1 &&
		      strstr(mtext, "symlink"));
		unlink(sp);
	}
	const char *f3o[3] = { peer_ip, "0perPass", "long enough pass" };
	g = grant_issue(L_OPERATOR, "op", pa);
	check("bk-restore needs an admin's grant", mreq(MON_BK_RESTORE, g, 3, f3o, NULL) == MON_DENIED);
	const char *f2[2] = { peer_ip, "long enough pass" };
	set_uptime("100.00 50.00\n");
	check("bk-setup on a claimed camera, in the window: closed", mreq(MON_BK_SETUP, 0, 2, f2, NULL) == MON_CLOSED &&
	      strstr(mtext, "claimed already"));
	set_uptime("90061.50 12345.00\n");
	check("bk-setup takes no grant", mreq(MON_BK_SETUP, grant_issue(L_ADMIN, "admin", pa), 2, f2, NULL) == MON_DENIED);

	/* #173: the claim offers a first backup; /setup restores one instead of a claim */
	write_file(users_path, "");
	set_uptime("100.00 50.00\n");
	bk_reset();
	r = ui_get("/setup", NULL, NULL);
	expect("/setup offers a restore", r, "Or restore this camera's backup");
	expect("... a multipart form to /setup/restore", r, "action=\"/setup/restore\" enctype=\"multipart/form-data\"");
	exec_fail = 0;
	nfake_keys = 0;
	snprintf(body, sizeof body, "csrf=%s&name=owner&pw=%s&pw2=%s", token("/setup", 0), urlenc(OWNER_PW), urlenc(OWNER_PW));
	r = run(ui_req("POST", "/setup", NULL, NULL, "Origin: https://192.0.2.10\r\n" FORM_CT, body));
	expect("a claim over HTTPS", r, "Recovery code");
	expect("... offers a backup right away", r, "Back up these first settings");
	expect("... the System page's download form", r, "action=\"/ui/system\"");
	snprintf(want, sizeof want, "name=\"csrf\" value=\"%s\"", token("owner", 0));
	expect("... with a token for the new admin", r, want);
	expect("... says it is a snapshot", r, "It is a snapshot");
	write_file(users_path, "");
	as_tls = 0;
	r = claim_post("/setup", "name=owner&pw=%s&pw2=%s", urlenc(OWNER_PW), urlenc(OWNER_PW));
	expect("a claim over plain HTTP (camtls down)", r, "Recovery code");
	expect("... points to the backup instead of a form", r, "camcfg backup export");
	absent("... no form over plain HTTP", r, "action=\"/ui/system\"");
	write_file(users_path, "");
	as_tls = 1;
	claim_rate_reset();
	snprintf(tk, sizeof tk, "csrf=%s", token("/setup", 0));
	const char *ts[2] = { tk, ppw };
	unlink(got);
	write_file(mode, "wrong");
	before = fails_for(peer_ip);
	r = mp_post(BK_SETUP_PATH, NULL, NULL, MP_SAME, ts, 2, file, fl);
	expect("setup restore: a wrong passphrase", r, "Wrong passphrase");
	check("... counted toward the lockout", fails_for(peer_ip) == before + 1);
	expect("... /setup's form again", r, "Create the camera's first admin");
	write_file(mode, "ok");
	r = mp_post(BK_SETUP_PATH, NULL, NULL, "Origin: https://evil.example\r\nContent-Type: multipart/form-data; boundary=XyZ\r\n",
		    ts, 2, file, fl);
	expect("setup restore from another site refused", r, "403");
	r = mp_post(BK_SETUP_PATH, NULL, NULL, MP_SAME, ts + 1, 1, file, fl);
	expect("setup restore without the token refused", r, "403");
	rb = reboots;
	r = mp_post(BK_SETUP_PATH, NULL, NULL, MP_SAME, ts, 2, file, fl);
	expect("setup restore: 200", r, "HTTP/1.1 200 OK");
	expect("... says it reboots, then log in with the backup's admin", r, "the backup's admin");
	check("... the file reached camcfg", fsize(got) == (long)fl);
	mono_adj += BK_REBOOT_MS + 100;
	mon_tick();
	check("... the monitor reboots", reboots == rb + 1);
	mono_adj = 0;
	bk_reset();
	for (int i = 0; i < CLAIM_POSTS; i++) claim_post_ok(&claim_rate, mono());
	r = mp_post(BK_SETUP_PATH, NULL, NULL, MP_SAME, ts, 2, file, fl);
	expect("setup restore: the claim pages' rate limit", r, "429");
	bk_reset();
	for (int i = 0; i < 5; i++) auth_failed(pa, mono());
	unlink(got);
	r = mp_post(BK_SETUP_PATH, NULL, NULL, MP_SAME, ts, 2, file, fl);
	expect("setup restore from a locked-out address", r, "429");
	check("... camcfg not run", access(got, F_OK) != 0);
	bk_reset();
	set_uptime("90061.50 12345.00\n");
	expect("setup restore after the window: setup is closed", mp_post(BK_SETUP_PATH, NULL, NULL, MP_SAME, ts, 2, file, fl),
	       "setup is closed");
	set_uptime("100.00 50.00\n");
	expect("GET /setup/restore sends to /setup", ui_get(BK_SETUP_PATH, NULL, NULL), "Location: /setup");
	/* port 80 while HTTPS is up: refused like /setup */
	static char ready[700];
	snprintf(ready, sizeof ready, "%s/bk-ready", dir);
	write_file(ready, "");
	tls_ready = ready;
	tfd = open("/dev/null", O_RDONLY);
	as_tls = 0;
	unlink(got);
	r = mp_post(BK_SETUP_PATH, NULL, NULL, MP_SAME80, ts, 2, file, fl);
	expect("setup restore on port 80 while HTTPS is up: 403", r, "403");
	check("... camcfg not run", access(got, F_OK) != 0);
	close(tfd);
	unlink(ready);
	/* camtls down: /setup's plain-HTTP fallback */
	snprintf(tk, sizeof tk, "csrf=%s", token("/setup", 0));
	r = mp_post(BK_SETUP_PATH, NULL, NULL, MP_SAME80, ts, 2, file, fl);
	expect("setup restore over plain HTTP while camtls is down (the claim's fallback)", r, "HTTP/1.1 200 OK");
	tfd = sv_tfd;
	tls_ready = sv_ready;
	write_file(users_path, users_txt);
	r = mp_post(BK_SETUP_PATH, NULL, NULL, MP_SAME, ts, 2, file, fl);
	expect("setup restore on a claimed camera: not found", r, "404");
	bk_reset();

	/* the real camcfg, end to end (TEST_CAMCFG; a fake mtd0 gives the device ID) */
	if (getenv("TEST_CAMCFG")) {
		static uint8_t img[0x40000];
		static const char env1[] = "\x12\x34\x56\x78" "a=1\0ethaddr=00:11:22:aa:bb:cc\0";
		static const char env2[] = "\x12\x34\x56\x78" "a=1\0ethaddr=00:11:22:aa:bb:cd\0";
		camcfg_bin = getenv("TEST_CAMCFG");
		as_tls = 1;
		snprintf(mtd, sizeof mtd, "%s/mtd0", dir);
		memset(img, 0xff, sizeof img);
		memcpy(img + 0x3F000, env1, sizeof env1);
		FILE *f = fopen(mtd, "wb");
		if (!f || fwrite(img, 1, sizeof img, f) != sizeof img) { perror(mtd); exit(1); }
		fclose(f);
		snprintf(envv, sizeof envv, "CAMCFG_MTD0=%s", mtd);
		bk_env[1] = envv;
		snprintf(saved, sizeof saved, "%s", slurp(conf_path));
		write_file(users_path, "owner:admin:" OWNER_PW "\nview:viewer:V1ew:Pass&\n");
		snprintf(body, sizeof body, "csrf=%s&do=backup&pp=real+passphrase&pp2=real+passphrase", token("owner", 0));
		r = run(ui_req("POST", "/ui/system", "owner", OWNER_PW, "Origin: https://192.0.2.10\r\n" FORM_CT, body));
		expect("real camcfg: a backup downloaded", r, "HTTP/1.1 200 OK");
		hb = strstr(r, "\r\n\r\n");
		long bl = hb ? strtol(strstr(r, "Content-Length: ") + 16, NULL, 10) : 0;
		check("... a .cambak for this camera", hb && bl > 100 && bl < (long)sizeof bk &&
		      !memcmp(hb + 4, "cam-backup 1\ndevice 2afc57ce8604f5b6fbd6c026517444da\n", 52));
		memcpy(bk, hb + 4, (size_t)bl);
		write_file(users_path, "owner:admin:" OWNER_PW "\nintruder:admin:Intruder-1\n");
		write_file(conf_path, "image.flip=1\n");
		snprintf(tk, sizeof tk, "csrf=%s", token("owner", 0));
		snprintf(pww, sizeof pww, "pw=%s", OWNER_PW);
		snprintf(ppw, sizeof ppw, "pp=%s", "real passphrase!");
		const char *rt[3] = { tk, ppw, pww };
		r = mp_post(BK_PATH, "owner", OWNER_PW, MP_SAME, rt, 3, bk, (size_t)bl);
		expect("real camcfg: a wrong passphrase", r, "Wrong passphrase");
		check("... nothing changed", strstr(slurp(users_path), "intruder") != NULL);
		auth_reset();
		memcpy(img + 0x3F000, env2, sizeof env2);
		f = fopen(mtd, "wb");
		if (!f || fwrite(img, 1, sizeof img, f) != sizeof img) { perror(mtd); exit(1); }
		fclose(f);
		snprintf(ppw, sizeof ppw, "pp=%s", "real passphrase");
		r = mp_post(BK_PATH, "owner", OWNER_PW, MP_SAME, rt, 3, bk, (size_t)bl);
		expect("real camcfg: on another camera, refused", r, "from another camera");
		check("... nothing changed", strstr(slurp(users_path), "intruder") != NULL);
		memcpy(img + 0x3F000, env1, sizeof env1);
		f = fopen(mtd, "wb");
		if (!f || fwrite(img, 1, sizeof img, f) != sizeof img) { perror(mtd); exit(1); }
		fclose(f);
		r = mp_post(BK_PATH, "owner", OWNER_PW, MP_SAME, rt, 3, bk, (size_t)bl);
		expect("real camcfg: restored", r, "Restored from the backup");
		check("... the users as backed up", !strcmp(slurp(users_path), "owner:admin:" OWNER_PW "\nview:viewer:V1ew:Pass&\n"));
		check("... cam.conf as backed up", !strcmp(slurp(conf_path), saved));
		bk_reset();
		write_file(users_path, "");
		snprintf(tk, sizeof tk, "csrf=%s", token("/setup", 0));
		const char *rs[2] = { tk, ppw };
		r = mp_post(BK_SETUP_PATH, NULL, NULL, MP_SAME, rs, 2, bk, (size_t)bl);
		expect("real camcfg: restored at setup", r, "HTTP/1.1 200 OK");
		check("... the camera is claimed again (its own backup)", strstr(slurp(users_path), "owner:admin:") != NULL);
		bk_reset();
		bk_env[1] = NULL;
		unlink(mtd);
		char q[700];
		static const char *const left[] = { ".lock", "recovery", "ssh/authorized_keys", "ssh", "tls" };
		for (size_t i = 0; i < sizeof left / sizeof left[0]; i++) {
			snprintf(q, sizeof q, "%s/%s", dir, left[i]);
			if (unlink(q)) rmdir(q);
		}
		write_file(conf_path, saved);
	} else {
		printf("skip: the real camcfg behind the backup forms (set TEST_CAMCFG)\n");
	}
	as_tls = 0;
	camcfg_bin = "/nonexistent/camcfg";
	bk_tmp_dir = "/run";
	unlink(stub); unlink(mode); unlink(args); unlink(ppf); unlink(got);
	write_file(users_path, users_txt);
	set_uptime("90061.50 12345.00\n");
	bk_reset();
}

/* ---- lock mode (#175): the lock page, the challenge, /unlock, the monitor's ops ---------------- */

/* A raw POST /unlock: the body (n bytes, NULs and all) with the action and challenge headers. */
static const char *unlock_post_req(const char *extra, const char *act, const char *ch, const char *body, size_t n)
{
	static char req[REQ_CAP];
	int hn = snprintf(req, sizeof req, "POST " UNLOCK_PATH " HTTP/1.1\r\nHost: 192.0.2.10\r\n%s"
			  "X-Unlock-Action: %s\r\nX-Unlock-Challenge: %s\r\nContent-Length: %zu\r\n\r\n",
			  extra, act, ch, n);
	memcpy(req + hn, body, n);
	return run_n(req, (size_t)hn + n, 1 << 20);
}

#define UL_SAME "Origin: https://192.0.2.10\r\nContent-Type: application/octet-stream\r\n"

static void test_lock(const char *dir)
{
	char stub[700], s[2048], mode[700], args[700], got[700], failed[700], hex[65], hex2[65], ready[700];
	const char *r, *lg;
	struct in_addr pa;
	inet_pton(AF_INET, peer_ip, &pa);
	snprintf(stub, sizeof stub, "%s/camcfg-ul-stub", dir);
	snprintf(mode, sizeof mode, "%s/ul-mode", dir);
	snprintf(args, sizeof args, "%s/ul-args", dir);
	snprintf(got, sizeof got, "%s/ul-got", dir);
	snprintf(failed, sizeof failed, "%s/data-failed", dir);
	snprintf(s, sizeof s,
		 "echo \"$@\" > %s\n"
		 "case \"$1 $2\" in\n"
		 "'unlock info') echo 'device 2afc57ce8604f5b6fbd6c026517444da'; echo 'firmware 20261026.1'; exit 0;;\n"
		 "'unlock restore'|'unlock erase') cat > %s\n"
		 "  case $(cat %s) in ok) echo 'restored: 3 files from a backup made at 1 (firmware x), signed by owner; reboot now'; exit 0;;\n"
		 "  bad) echo 'camcfg: recovery refused: bad signature' >&2; exit 3;;\n"
		 "  *) echo 'camcfg: erasing DATA failed' >&2; exit 1;; esac;;\n"
		 "esac\nexit 2", args, got, mode);
	stub_script(stub, s);
	const char *sv_bin = camcfg_bin, *sv_failed = data_failed_path;
	camcfg_bin = stub;
	data_failed_path = failed;
	write_file(users_path, "");
	set_uptime("100.00 50.00\n");
	bk_reset();
	unlock_until = 0;
	*unlock_id = 0;

	/* not locked: the ops refuse, the paths are ordinary */
	check("unlock-ch when not locked: closed", mreq(MON_UNLOCK_CH, 0, 0, NULL, NULL) == MON_CLOSED);
	r = ui_get("/", NULL, NULL);
	expect("not locked: an unclaimed camera still shows setup", r, "Location: /setup");

	/* locked */
	write_file(failed, "users: lost <b>it</b>\n");
	r = ui_get("/", NULL, NULL);
	expect("locked: / is the lock page (503)", r, "HTTP/1.1 503");
	expect("... the alert", r, "&#9888; This camera is locked");
	expect("... DATA is corrupt, with the reason escaped", r, "is corrupt: users: lost &lt;b&gt;it&lt;/b&gt;");
	expect("... in the web UI's style, with its script", r, "href=\"/ui.css\"><script src=\"/ui.js\" defer>");
	expect("... the form", r, "<form data-unlock action=\"/unlock\"");
	expect("... the device and firmware", r, "data-device=\"2afc57ce8604f5b6fbd6c026517444da\" data-firmware=\"20261026.1\"");
	expect("... the command line", r, "scripts/cam-recover.py 192.0.2.10 --backup");
	expect("... and over SSH", r, "camcfg unlock restore -");
	expect("... no backup: erase and claim", r, "No backup?");
	const char *ch = strstr(r, "data-challenge=\"");
	check("... a 64-hex challenge", ch && strspn(ch + 16, "0123456789abcdef") == 64);
	memcpy(hex, ch + 16, 64);
	hex[64] = 0;
	expect("/setup is the lock page too", ui_get("/setup", NULL, NULL), "This camera is locked");
	absent("... with no claim form", ui_get("/setup", NULL, NULL), "name=\"pw2\"");
	expect("/ui/ is the lock page", ui_get("/ui/", "admin", A_PW), "This camera is locked");
	expect("a POST elsewhere: 403", run(ui_req("POST", "/setup", NULL, NULL, FORM_CT, "name=x")), "403");
	r = run(soap_req(DEV, NULL, "<tds:GetDeviceInformation/>", NULL));
	expect("ONVIF: a fault saying it is locked", r, "The camera is locked: its storage failed");
	expect("/snapshot.jpg: 503", ui_get("/snapshot.jpg", NULL, NULL), "HTTP/1.1 503");
	expect("/ui.js is served (the page's script)", ui_get("/ui.js", NULL, NULL), "form[data-unlock]");
	expect("/ui.css is served", ui_get("/ui.css", NULL, NULL), "HTTP/1.1 200 OK");
	r = run("GET / HTTP/1.1\r\nHost: camera.example\r\n\r\n");
	expect("by a name: answered only at its address", r, "421");
	r = ui_get(UNLOCK_CH_PATH, NULL, NULL);
	expect("GET /unlock/challenge: text", r, "Content-Type: text/plain");
	expect("... not cached", r, "Cache-Control: no-store");
	snprintf(s, sizeof s, "challenge %s\ndevice 2afc57ce8604f5b6fbd6c026517444da\nfirmware 20261026.1\nexpires-in ", hex);
	expect("... the page's challenge, the device and firmware, its time left", r, s);
	expect("... again: the same challenge", ui_get(UNLOCK_CH_PATH, NULL, NULL), hex);
	expect("GET /unlock goes to the page", ui_get(UNLOCK_PATH, NULL, NULL), "Location: /");

	/* the monitor refuses what lock mode stops */
	const char *fc[4] = { peer_ip, "mallory", "Secret-pass1", "" }, *fs[2] = { peer_ip, "long enough pass" };
	check("claim while locked: closed", mreq(MON_CLAIM, 0, 4, fc, NULL) == MON_CLOSED && strstr(mtext, "locked"));
	check("setup restore while locked: closed", mreq(MON_BK_SETUP, 0, 2, fs, NULL) == MON_CLOSED && strstr(mtext, "locked"));

	/* POST /unlock: the worker's checks, before anything is staged */
	as_tls = 1;
	unlink(args);
	r = unlock_post_req("Content-Type: application/octet-stream\r\n", "erase", hex, "SIG\n", 4);
	expect("no Origin: refused", r, "Origin");
	r = unlock_post_req("Origin: https://192.0.2.10\r\nContent-Type: text/plain\r\n", "erase", hex, "SIG\n", 4);
	expect("not octet-stream: refused", r, "application/octet-stream");
	expect("a bad action: refused", unlock_post_req(UL_SAME, "wipe", hex, "SIG\n", 4), "restore or erase");
	expect("a bad challenge: refused", unlock_post_req(UL_SAME, "erase", "abc", "SIG\n", 4), "64 hex");
	expect("an empty body: refused", unlock_post_req(UL_SAME, "erase", hex, "", 0), "empty");
	check("... camcfg never ran", access(args, F_OK) != 0);
	memset(hex2, 'a', 64);
	hex2[64] = 0;
	r = unlock_post_req(UL_SAME, "erase", hex2, "SIG\n", 4);
	expect("another challenge: refused", r, "expired or was used");
	check("... camcfg not run", access(args, F_OK) != 0);
	r = ui_get(UNLOCK_CH_PATH, NULL, NULL);
	check("... and the challenge is spent: a new one", !strstr(r, hex) && strstr(r, "challenge "));
	memcpy(hex, strstr(r, "challenge ") + 10, 64);

	/* a refused signature counts as a failed login */
	write_file(mode, "bad");
	log_start();
	r = unlock_post_req(UL_SAME, "erase", hex, "SIG\n", 4);
	lg = log_stop();
	expect("a bad signature: 403 with camcfg's reason", r, "recovery refused: bad signature");
	expect("... logged", lg, "unlock (erase) refused");
	for (int i = 0; i < FAIL_MAX; i++) {
		r = ui_get(UNLOCK_CH_PATH, NULL, NULL);
		memcpy(hex, strstr(r, "challenge ") + 10, 64);
		claim_rate_reset();
		r = unlock_post_req(UL_SAME, "erase", hex, "SIG\n", 4);
	}
	expect("... until the address is locked out: 429", r, "429");
	bk_reset();

	/* the staged file: the monitor's own checks */
	char sp[700];
	snprintf(sp, sizeof sp, "%s/" UNLOCK_FILE, upd_dir);
	r = ui_get(UNLOCK_CH_PATH, NULL, NULL);
	memcpy(hex, strstr(r, "challenge ") + 10, 64);
	unlink(sp);
	if (!symlink(users_path, sp)) {
		const char *fu[3] = { peer_ip, "erase", hex };
		check("unlock: a symlinked upload refused", mreq(MON_UNLOCK, 0, 3, fu, NULL) == 1 && strstr(mtext, "symlink"));
		unlink(sp);
	}

	/* erase, then restore */
	write_file(mode, "ok");
	r = ui_get(UNLOCK_CH_PATH, NULL, NULL);
	memcpy(hex, strstr(r, "challenge ") + 10, 64);
	int rb = reboots;
	static const char esig[] = "-----BEGIN SSH SIGNATURE-----\nAAAA\n-----END SSH SIGNATURE-----\n";
	r = unlock_post_req(UL_SAME, "erase", hex, esig, sizeof esig - 1);
	expect("a signed erase: 200", r, "HTTP/1.1 200 OK");
	expect("... ok and camcfg's line", r, "ok: restored:");
	expect("... the camera reboots", r, "reboots now");
	snprintf(s, sizeof s, "unlock erase -c %s", hex);
	expect("... camcfg unlock erase -c CHALLENGE", slurp(args), s);
	check("... the body on its stdin", !strncmp(slurp(got), "-----BEGIN SSH SIGNATURE-----\nAAAA\n", 35));
	check("... the staged file deleted", access(sp, F_OK) != 0);
	check("... no reboot before the reply", reboots == rb && mon_reboot_at);
	mono_adj += BK_REBOOT_MS + 100;
	mon_tick();
	check("... then the monitor reboots", reboots == rb + 1 && !mon_reboot_at);
	mono_adj = 0;
	bk_reset();
	r = ui_get(UNLOCK_CH_PATH, NULL, NULL);
	memcpy(hex, strstr(r, "challenge ") + 10, 64);
	static const char body[] = "long enough pass\n-----BEGIN SSH SIGNATURE-----\nAAAA\n-----END SSH SIGNATURE-----\n"
				   "cam-backup 1\n\0binary";
	r = unlock_post_req(UL_SAME, "restore", hex, body, sizeof body - 1);
	expect("a signed restore: 200", r, "HTTP/1.1 200 OK");
	snprintf(s, sizeof s, "unlock restore -c %s -", hex);
	expect("... camcfg unlock restore -c CHALLENGE -", slurp(args), s);
	check("... the body wiped from the connection", !memmem(cl.in, sizeof cl.in, "long enough pass", 16));
	bk_reset();

	/* port 80 while HTTPS is up: the lock page's paths move to it */
	as_tls = 0;
	snprintf(ready, sizeof ready, "%s/ul-ready", dir);
	write_file(ready, "");
	const char *sv_ready = tls_ready;
	int sv_tfd = tfd;
	tls_ready = ready;
	tfd = open("/dev/null", O_RDONLY);
	expect("port 80 GET /unlock/challenge: to https", ui_get(UNLOCK_CH_PATH, NULL, NULL), "Location: https://");
	expect("port 80 POST /unlock: 403", unlock_post_req(UL_SAME, "erase", hex, "SIG\n", 4), "403");
	close(tfd);
	tfd = sv_tfd;
	tls_ready = sv_ready;
	unlink(ready);

	unlink(failed);
	unlink(mode);
	unlink(args);
	unlink(got);
	unlink(stub);
	camcfg_bin = sv_bin;
	data_failed_path = sv_failed;
	unlock_until = 0;
	*unlock_id = 0;
	write_file(users_path, users_txt);
	bk_reset();
}

int main(void)
{
	const char *tmp = getenv("TMPDIR");
	char dir[512], f[600];
	snprintf(dir, sizeof dir, "%s/camhttpd-test-%d", tmp && *tmp ? tmp : ".", (int)getpid());
	if (mkdir(dir, 0700)) { perror(dir); return 1; }
	setvbuf(stdout, NULL, _IOLBF, 0);                 /* keep "ok:" lines apart from the log */
	static char up[600], cp[600], sp[600];
	snprintf(up, sizeof up, "%s/users", dir);
	snprintf(cp, sizeof cp, "%s/cam.conf", dir);
	snprintf(sp, sizeof sp, "%s/snapshot.jpg", dir);
	write_file(up, "admin:admin:Adm1nPass!\nop:operator:0perPass\nview:viewer:V1ew:Pass&\n"
		   "x:rooty:whatever\n:viewer:nameless\n");
	write_file(cp, "image.brightness=55\nstream.main.kbps=6000\nstream.main.profile=main\n"
		   "stream.main.fps=99\nstream.sub.enabled=1\n");
	users_path = up;
	conf_path = cp;
	snap_path = sp;
	ctl_path = "/nonexistent/camd.sock";
	memset(secret, 0x42, sizeof secret);
	memset(ui_key, 0x24, sizeof ui_key);
	signal(SIGPIPE, SIG_IGN);                          /* as camhttpd: a camcfg that exits early */
	static const char *const sysf[5][2] = {           /* the status page's sources (documentation values) */
		{ "version", "1.2.3-test\n" }, { "uptime", "90061.50 12345.00\n" },
		{ "meminfo", "MemTotal:          65536 kB\nMemFree:            1024 kB\nMemAvailable:      32768 kB\n" },
		{ "route", "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n"
			   "eth0\t0002000A\t00000000\t0001\t0\t0\t0\t00FFFFFF\t0\t0\t0\n"
			   "eth0\t00000000\t010200C0\t0003\t0\t0\t0\t00000000\t0\t0\t0\n" },
		{ "resolv", "# by udhcpc\nnameserver 192.0.2.53\nnameserver 192.0.2.54\nnameserver ;rm\n" },
	};
	static char sysp[5][600];
	for (int i = 0; i < 5; i++) {
		snprintf(sysp[i], sizeof sysp[i], "%s/%s", dir, sysf[i][0]);
		write_file(sysp[i], sysf[i][1]);
	}
	version_path = sysp[0];
	uptime_path = sysp[1];
	meminfo_path = sysp[2];
	route_path = sysp[3];
	resolv_path = sysp[4];

	test_crypto();
	test_onvif();
	test_http(dir);
	test_discovery();
	test_review();
	test_sss(dir);
	test_imaging();
	test_osd();
	test_events();
	test_analytics();
	test_audio();
	test_talk();
	test_form();
	test_ui(dir);
	test_claim(dir);
	test_preview();
	test_firmware(dir);
	test_gate3(dir);
	test_monitor(dir);
	test_tls(dir);
	test_ca(dir);
	test_backup(dir);
	test_lock(dir);
	test_fuzz();

	write_file(cp, "stream.sub.enabled=0\n");
	const char *r = run(soap_req(MED, wsse("view", "V1ew:Pass&", time(NULL), 0, 0), B_PROFILES, NULL));
	expect("sub-stream off -> one profile", r, "Profile_1");
	absent("sub-stream off", r, "Profile_2");
	r = run(soap_req(MED, wsse("view", "V1ew:Pass&", time(NULL), 0, 0), "<trt:GetStreamUri>"
			 "<trt:ProfileToken>Profile_2</trt:ProfileToken></trt:GetStreamUri>", NULL));
	expect("sub-stream off -> NoProfile", r, "ter:NoProfile");

	snprintf(f, sizeof f, "%s/snapshot.jpg", dir);
	unlink(f);
	snprintf(f, sizeof f, "%s/fw/" UPD_FILE, dir);         /* test_firmware's tmpfs stand-in (the fuzz used it) */
	unlink(f);
	snprintf(f, sizeof f, "%s/fw/" UPD_LOG, dir);
	unlink(f);
	snprintf(f, sizeof f, "%s/fw", dir);
	rmdir(f);
	for (int i = 0; i < 5; i++) unlink(sysp[i]);
	snprintf(f, sizeof f, "%s/" EPR_SECRET, dir);         /* camhttpd's own files beside users */
	unlink(f);
	snprintf(f, sizeof f, "%s/" TIME_FLOOR, dir);
	unlink(f);
	unlink(up);
	unlink(cp);
	rmdir(dir);
	printf("all camhttpd tests passed\n");
	return 0;
}
