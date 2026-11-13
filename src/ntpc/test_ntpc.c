/* SPDX-License-Identifier: MIT */
/* Host test of ntpc: DNS query/answer, SNTP reply checks, servers from cam.conf (no network), and
 * Gate 3's drop.h: -U's user lookup, the capset words for CAP_SYS_TIME, the drop (real only as root). */
#define NTPC_NO_MAIN
#include "ntpc.c"

#include <assert.h>
#include <sys/wait.h>

static void put_ts(uint8_t *p, uint64_t v) { for (int i = 0; i < 8; i++) p[i] = (uint8_t)(v >> (56 - 8 * i)); }

static uint64_t to_ntp(double unix_s)
{
	double s = unix_s + (double)NTP_UNIX_DELTA;
	return (uint64_t)s << 32 | (uint64_t)((s - (double)(uint64_t)s) * 4294967296.0);
}

int main(void)
{
	char tmp[512];
	snprintf(tmp, sizeof tmp, "%s/test_ntpc.conf", getenv("TMPDIR") ? getenv("TMPDIR") : "/tmp");
	conf_path = tmp;

	/* servers: default, list, junk ignored, at most 3 */
	char s[3][64];
	unlink(tmp);
	assert(servers(s) == 1 && !strcmp(s[0], "time.cloudflare.com"));
	FILE *f = fopen(tmp, "w");
	fputs("image.contrast=50\ntime.ntp=198.51.100.36, time.cloudflare.com,bad host;rm,a.b,x.y,z\n", f);
	fclose(f);
	int n = servers(s);
	assert(n == 3 && !strcmp(s[0], "198.51.100.36") && !strcmp(s[1], "time.cloudflare.com"));
	f = fopen(tmp, "w"); fputs("time.ntp=;;;\n", f); fclose(f);
	assert(servers(s) == 0);                                 /* nothing valid: off */
	f = fopen(tmp, "w"); fputs("time.ntp=\n", f); fclose(f);
	assert(servers(s) == 0);                                 /* empty: NTP off (as camhttpd) */
	unlink(tmp);
	printf("ok: servers from cam.conf (default, list of 3, junk ignored, empty = off)\n");

	/* DNS query encoding and answer parsing */
	uint8_t q[300], r[512];
	int qn = dns_query("time.cloudflare.com", 0x1234, q, sizeof q);
	assert(qn == 12 + 21 + 4 && q[0] == 0x12 && q[1] == 0x34 && q[12] == 4 && !memcmp(q + 13, "time", 4));
	uint8_t q2[300];
	assert(dns_query("a..b", 1, q2, sizeof q2) < 0);
	/* reply: header, question copied, CNAME (compressed name) then A 162.159.200.1 */
	memcpy(r, q, (size_t)qn);
	r[2] = 0x81; r[3] = 0x80; r[7] = 2;                      /* QR RD RA, ANCOUNT 2 */
	size_t o = (size_t)qn;
	uint8_t cname[] = { 0xc0, 12, 0, 5, 0, 1, 0, 0, 0, 60, 0, 4, 1, 'x', 0xc0, 12 };
	memcpy(r + o, cname, sizeof cname); o += sizeof cname;
	uint8_t a[] = { 0xc0, 12, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 162, 159, 200, 1 };
	memcpy(r + o, a, sizeof a); o += sizeof a;
	struct in_addr ip;
	assert(!dns_answer(r, o, 0x1234, &ip) && ip.s_addr == inet_addr("162.159.200.1"));
	assert(dns_answer(r, o, 0x1235, &ip) < 0);               /* wrong id */
	assert(dns_answer(r, o - 1, 0x1234, &ip) < 0);           /* truncated rdata */
	r[3] = 0x83;                                             /* NXDOMAIN */
	assert(dns_answer(r, o, 0x1234, &ip) < 0);
	r[3] = 0x80;
	uint8_t loop[64];                                        /* a name pointing at itself */
	memcpy(loop, r, 12); loop[4] = 0; loop[5] = 1; loop[7] = 0; loop[12] = 0xc0; loop[13] = 12;
	assert(dns_answer(loop, 18, 0x1234, &ip) < 0 || 1);      /* must terminate, any result */
	for (int i = 0; i < 20000; i++) {                        /* garbage replies: no crash */
		uint8_t g[200];
		random_bytes(g, sizeof g);
		g[0] = 0x12; g[1] = 0x34; g[2] |= 0x80; g[3] &= 0xf0;
		(void)dns_answer(g, (size_t)(g[199] % 200), 0x1234, &ip);
	}
	printf("ok: DNS query, CNAME+A answer, wrong id / truncated / NXDOMAIN refused, fuzz\n");

	/* SNTP reply checks */
	uint8_t p[48];
	uint64_t xmt = 0x0123456789abcdefULL;
	double t1 = 1761200000.0, t4 = t1 + 0.040, srv = t1 + 100.0;   /* server 100 s ahead */
	memset(p, 0, sizeof p);
	p[0] = 0x24; p[1] = 2;                                   /* VN 4, mode 4, stratum 2 */
	put_ts(p + 24, xmt);
	put_ts(p + 32, to_ntp(srv + 0.010));
	put_ts(p + 40, to_ntp(srv + 0.011));
	double off;
	const char *why;
	assert(!sntp_check(p, 48, xmt, t1, t4, &off, &why) && off > 99.98 && off < 100.0);
	assert(sntp_check(p, 47, xmt, t1, t4, &off, &why) < 0);
	assert(sntp_check(p, 48, xmt + 1, t1, t4, &off, &why) < 0 && strstr(why, "origin"));
	p[0] = 0x23; assert(sntp_check(p, 48, xmt, t1, t4, &off, &why) < 0); p[0] = 0x24;
	p[1] = 0; assert(sntp_check(p, 48, xmt, t1, t4, &off, &why) < 0); p[1] = 2;
	p[0] = 0xe4; assert(sntp_check(p, 48, xmt, t1, t4, &off, &why) < 0); p[0] = 0x24;
	put_ts(p + 40, to_ntp(1000000000.0));                    /* 2001: before the build */
	assert(sntp_check(p, 48, xmt, t1, t4, &off, &why) < 0 && strstr(why, "before"));
	/* Gate 3: receive stamp 3 years before the build, transmit just after it (the offset would
	 * have put the clock ~1.5 years before the build) */
	double E = (double)BUILD_EPOCH;
	put_ts(p + 32, to_ntp(E - 3 * 365 * 86400.0));
	put_ts(p + 40, to_ntp(E + 1));
	assert(sntp_check(p, 48, xmt, t1, t4, &off, &why) < 0 && strstr(why, "before the firmware"));
	put_ts(p + 32, to_ntp(srv));                             /* receive and transmit 4.5 s apart */
	put_ts(p + 40, to_ntp(srv + 4.5));
	assert(sntp_check(p, 48, xmt, t1, t4, &off, &why) < 0 && strstr(why, "too far apart"));
	put_ts(p + 40, to_ntp(srv - 4.5));                       /* either order */
	assert(sntp_check(p, 48, xmt, t1, t4, &off, &why) < 0 && strstr(why, "too far apart"));
	put_ts(p + 40, to_ntp(srv + 3.9));                       /* within 4 s: fine */
	assert(!sntp_check(p, 48, xmt, t1, t4, &off, &why));
	put_ts(p + 32, to_ntp(E + 1));                           /* both just after the build, but */
	put_ts(p + 40, to_ntp(E + 1));                           /* our clock went back 200 s between */
	assert(sntp_check(p, 48, xmt, E + 100, E - 100, &off, &why) < 0 && strstr(why, "result before"));
	assert(!sntp_check(p, 48, xmt, 0.0, 0.05, &off, &why) && off > E);   /* boot clock at 1970: fine */
	printf("ok: SNTP: offset, short / origin / mode / stratum / leap / old time refused; receive "
	       "time before the build, receive/transmit > 4 s apart, a result before the build refused\n");

	/* Step guard: first sync since boot unrestricted, then a step over 1000 s needs a second
	 * answer agreeing within 5 s */
	struct in_addr A = { inet_addr("162.159.200.1") }, B = { inet_addr("162.159.200.123") };
	synced = 0; pending = 0;
	assert(step_gate(-3 * 365 * 86400.0, A) == 1 && !pending);   /* first sync: anything */
	synced = 1;
	assert(step_gate(999.0, A) == 1 && step_gate(-1000.0, A) == 1 && !pending);
	assert(step_gate(5000.0, A) == 0 && pending && pending_off == 5000.0 && pending_addr.s_addr == A.s_addr);
	assert(step_gate(5004.0, B) == 1 && !pending);                /* confirmed */
	assert(step_gate(-86400.0, A) == 0 && pending);               /* backwards too */
	assert(step_gate(86400.0, B) == 0 && pending && pending_off == 86400.0 && pending_addr.s_addr == B.s_addr);
	assert(step_gate(86406.0, A) == 0 && pending && pending_off == 86406.0);   /* 6 s off: held again */
	assert(step_gate(86401.0, A) == 1 && !pending);               /* same address may confirm */
	assert(step_gate(1e6, A) == 0 && step_gate(0.2, A) == 1 && !pending);  /* small one: drops it */
	assert(step_gate(1e6, A) == 0 && step_gate(1e6, A) == 1);
	/* the confirmation goes to another address when there is one */
	struct in_addr list[3] = { A, B, A };
	int other;
	pending = 0;
	assert(pick_addr(list, 3, &other) == 0 && other);
	pending = 1; pending_addr = A;
	assert(pick_addr(list, 3, &other) == 1 && other);
	pending_addr = B;
	assert(pick_addr(list, 3, &other) == 0 && other);
	assert(pick_addr(list, 1, &other) == 0 && other);
	pending_addr = A;
	assert(pick_addr(list, 1, &other) == 0 && !other);
	pending = 0;
	/* the marker for a respawned ntpc */
	char mk[512];
	snprintf(mk, sizeof mk, "%s/test_ntpc.synced", getenv("TMPDIR") ? getenv("TMPDIR") : "/tmp");
	unlink(mk);
	synced_path = mk;
	synced = 0;
	mark_synced();
	assert(synced && !access(mk, F_OK));
	unlink(mk);
	mark_synced();                                           /* already synced: not written again */
	assert(access(mk, F_OK) < 0);
	printf("ok: step guard: first sync free, +-1000 s free, bigger held until a 2nd answer agrees "
	       "within 5 s (another address first), marker for a respawn\n");

	/* every A record of a reply, at most max */
	uint8_t a2[] = { 0xc0, 12, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 162, 159, 200, 123 };
	memcpy(r + o, a2, sizeof a2);
	r[7] = 3;
	struct in_addr ips[4];
	assert(dns_answers(r, o + sizeof a2, 0x1234, ips, 4) == 2 &&
	       ips[0].s_addr == inet_addr("162.159.200.1") && ips[1].s_addr == inet_addr("162.159.200.123"));
	assert(dns_answers(r, o + sizeof a2, 0x1234, ips, 1) == 1);
	assert(dns_answers(r, o + sizeof a2 - 1, 0x1234, ips, 4) == 1);   /* cut short: the first */
	printf("ok: DNS: every A record, at most max\n");

	/* Gate 3 (drop.h): the user from passwd/group files, the capability kept, and the drop */
	char pw[512], gr[512];
	const char *td = getenv("TMPDIR") ? getenv("TMPDIR") : "/tmp";
	snprintf(pw, sizeof pw, "%s/test_ntpc.passwd", td);
	snprintf(gr, sizeof gr, "%s/test_ntpc.group", td);
	f = fopen(pw, "w");
	fputs("root:x:0:0:root:/root:/bin/sh\nrtspd:x:100:100:rtspd:/:/bin/false\nntpc:x:101:101:ntpc:/:/bin/false\n"
	      "rooty:x:0:5::/:/bin/false\nhalf:x:7\ncamhttpd:x:102:102:camhttpd:/:/bin/false\n", f);
	fclose(f);
	f = fopen(gr, "w");
	fputs("root:x:0:\nrtspd:x:100:\nntpc:x:101:\ncamctl:x:110:rtspd,camhttpd\nother:x:111:camhttpd2,xrtspd\n", f);
	fclose(f);
	struct drop_id id;
	const char *dwhy = "";
	assert(!drop_lookup("ntpc", pw, gr, &id, &dwhy) && id.uid == 101 && id.gid == 101 && id.ngroups == 1 &&
	       id.groups[0] == 101);
	assert(!drop_lookup("rtspd", pw, gr, &id, &dwhy) && id.uid == 100 && id.gid == 100 && id.ngroups == 2 &&
	       id.groups[1] == 110);                                   /* camctl, and not "xrtspd"'s */
	assert(!drop_lookup("101:101", pw, gr, &id, &dwhy) && id.uid == 101 && id.gid == 101 && id.ngroups == 1);
	assert(!drop_lookup("100:110", "/nonexistent", "/nonexistent", &id, &dwhy) && id.uid == 100 && id.gid == 110);
	const char *bad_users[] = { "root", "rooty", "half", "nosuch", "0:0", "100:0", "0:100", "1:x", "x:1", "-1:1",
				    "1:", ":1", "1:2:3", "99999999999:1", "", "ntp", "ntpc ", "4294967295:1" };
	for (size_t i = 0; i < sizeof bad_users / sizeof bad_users[0]; i++)
		assert(drop_lookup(bad_users[i], pw, gr, &id, &dwhy) < 0 && *dwhy);
	assert(drop_lookup("ntpc", "/nonexistent", gr, &id, &dwhy) < 0);
	assert(!drop_lookup("ntpc", pw, "/nonexistent", &id, &dwhy) && id.ngroups == 1);   /* no group file: primary only */
	gid_t g;
	assert(!drop_group("camctl", gr, &g, &dwhy) && g == 110);
	assert(!drop_group("110", "/nonexistent", &g, &dwhy) && g == 110);
	assert(drop_group("root", gr, &g, &dwhy) < 0 && drop_group("0", gr, &g, &dwhy) < 0 &&
	       drop_group("nosuch", gr, &g, &dwhy) < 0 && drop_group("", gr, &g, &dwhy) < 0);
	unlink(pw);
	unlink(gr);
	struct drop_cap_hdr ch;
	struct drop_cap_data cd[2];
	memset(cd, 0xff, sizeof cd);
	drop_cap_build(DROP_CAP_SYS_TIME, &ch, cd);
	assert(ch.version == 0x20080522u && ch.pid == 0 && sizeof cd == 24);
	assert(cd[0].effective == 1u << 25 && cd[0].permitted == 1u << 25 && !cd[0].inheritable);
	assert(!cd[1].effective && !cd[1].permitted && !cd[1].inheritable);
	drop_cap_build(33, &ch, cd);                                    /* the second word */
	assert(!cd[0].permitted && cd[1].permitted == 2 && cd[1].effective == 2);
	drop_cap_build(-1, &ch, cd);
	assert(!cd[0].permitted && !cd[1].permitted);
	/* the urandom fd stays open (it's root's on the camera) */
	uint8_t rb[4];
	assert(!random_bytes(rb, 4) && urandom_fd >= 0);
	int ufd = urandom_fd;
	assert(!random_bytes(rb, 4) && urandom_fd == ufd);
	if (geteuid() != 0) {
		/* not root: the drop must fail and change nothing (a real one needs root: skipped) */
		uid_t me = getuid();
		struct drop_id other = { .uid = me + 1, .gid = getgid() + 1, .ngroups = 1 };
		other.groups[0] = other.gid;
		assert(drop_to(&other, DROP_CAP_SYS_TIME, &dwhy) < 0 && *dwhy && getuid() == me && geteuid() == me);
		assert(drop_to(&other, -1, &dwhy) < 0 && getuid() == me);
		printf("ok: drop: user/group lookup (names, UID:GID, root and junk refused), the CAP_SYS_TIME "
		       "capset words, urandom kept open; a drop refused when not root (real drop SKIPPED: needs root)\n");
	} else {
		/* root (a Linux CI): drop in a child, keeping CAP_SYS_TIME, and check there's no way back */
		pid_t pid = fork();
		if (pid == 0) {
			struct drop_id nob = { .uid = 65534, .gid = 65534, .ngroups = 1 };
			nob.groups[0] = 65534;
			int keep = 0;
#ifdef __linux__
			keep = DROP_CAP_SYS_TIME;
#else
			keep = -1;
#endif
			_exit(drop_to(&nob, keep, &dwhy) || getuid() != 65534 || !setuid(0) ? 1 : 0);
		}
		int st;
		assert(pid > 0 && waitpid(pid, &st, 0) == pid && WIFEXITED(st) && WEXITSTATUS(st) == 0);
		printf("ok: drop: user/group lookup, the CAP_SYS_TIME capset words, urandom kept open; a real "
		       "drop (as root, in a child) to 65534 keeping CAP_SYS_TIME, setuid(0) refused after it\n");
	}
	printf("ALL OK\n");
	return 0;
}
