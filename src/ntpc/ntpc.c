/* SPDX-License-Identifier: MIT */
/*
 * ntpc: a small SNTP client for the camera (#78). The camera has no RTC, so every boot starts in
 * the past; camhttpd refuses WS-UsernameToken until the clock is valid, and recordings need the
 * time. Servers: cam.conf `time.ntp` (comma-separated host names or IPv4 addresses, at most 3;
 * default time.cloudflare.com, owner 2026-10-23; an empty value turns NTP off), re-read every poll, so an ONVIF SetNTP from
 * Surveillance Station takes effect at the next poll.
 *
 * Per poll: each server in turn, resolved with our own DNS A query (static glibc's getaddrinfo
 * needs NSS modules the image doesn't have) to the first nameserver in /etc/resolv.conf, one SNTP
 * v4 request with a random transmit timestamp (the reply must echo it as its origin), from a
 * connected UDP socket (replies from anywhere else are dropped by the kernel), mode 4, stratum
 * 1..15, leap != 3, and a sane time: the server's receive and transmit stamps both after
 * BUILD_EPOCH and at most SERVER_HOLD_S apart, and a result that doesn't put the clock before
 * BUILD_EPOCH. The first good answer is used: a step (settimeofday) if the offset is over STEP_S
 * or the clock was before BUILD_EPOCH, else a slew (adjtime). Polls every 64 s until the first
 * success, then every 1024 s.
 *
 * Plain NTP is unauthenticated: someone on the path (spoofed DNS from DHCP, ARP) can move the
 * clock. The first sync since boot is unrestricted (no RTC: the clock starts at a fixed old
 * time). After it (this process, or SYNCED_PATH left by an earlier ntpc this boot), a step over
 * GUARD_S either way is held, not applied, until the next poll (64 s later; a fresh query, to
 * another address when DNS or time.ntp gives one) agrees within AGREE_S. That stops a one-off
 * spoofed reply; an attacker who stays on the path for both answers still wins. NTS would fix
 * that; it's a TLS client, too big for now.
 *
 * Not root (Gate 3): with -U, ntpc opens /dev/urandom (root's under mdev) and leaves root for that
 * user before the first poll, keeping CAP_SYS_TIME only (settimeofday, adjtime; drop.h); it binds
 * no port (connected UDP sockets on ephemeral ports). It then can't read DATA (root only), so
 * ntpc-run gives it a world-readable copy of cam.conf's time.ntp line, /run/ntp.conf, made at
 * every start and kept in step by camcfg when time.ntp changes; ntpc re-reads that every poll as
 * before. Its marker is in /run/ntpc, a directory ntpc-run gives the user.
 *
 *   ntpc [-c cam.conf] [-U user|uid:gid] [-1] [-v]      -1: one poll, then exit (0 = clock set)
 */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#include "../rtspd/drop.h"

#ifndef BUILD_EPOCH
#define BUILD_EPOCH 1761091200LL       /* rootfs/SOURCE_DATE_EPOCH: a clock before it is unset */
#endif
#define DEFAULT_SERVERS "time.cloudflare.com"
#define NTP_UNIX_DELTA 2208988800ULL   /* 1900 -> 1970 */
#define STEP_S 0.5
#define SERVER_HOLD_S 4.0              /* a server's receive and transmit stamps: ms apart */
#define GUARD_S 1000.0                 /* after the first sync, a bigger step needs a 2nd answer */
#define AGREE_S 5.0                    /* ... agreeing this closely */
#define MAX_ADDRS 4                    /* A records kept per server name */
#define POLL_FAST 64
#define POLL_SLOW 1024
#define TIMEOUT_MS 2000

static const char *conf_path = "/mnt/nand/cam/cam.conf", *resolv_path = "/etc/resolv.conf";
static const char *synced_path = "/run/ntpc/synced";   /* SYNCED_PATH; tmpfs: gone next boot */
static int verbose;
static int synced;                     /* the clock has been set since boot */
static int pending;                    /* a step over GUARD_S waiting for a second answer */
static double pending_off;
static struct in_addr pending_addr;

#define LOG(...) do { fprintf(stderr, __VA_ARGS__); } while (0)

/* /dev/urandom stays open: mdev makes it root's (0660), and with -U ntpc isn't root when it polls */
static int urandom_fd = -1;

static int random_bytes(void *p, size_t n)
{
	if (urandom_fd < 0) urandom_fd = open("/dev/urandom", O_RDONLY | O_CLOEXEC);
	if (urandom_fd < 0) return -1;
	return read(urandom_fd, p, n) == (ssize_t)n ? 0 : -1;
}

/* ---- servers from cam.conf ------------------------------------------------------------ */

static int valid_host(const char *h)
{
	size_t n = strlen(h);
	if (n < 1 || n > 63 || h[0] == '-' || h[0] == '.') return 0;
	return strspn(h, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789.-") == n;
}

/* Up to 3 server names into out[]: the `time.ntp` list (comma-separated, as camhttpd's SetNTP
 * writes it); the default when the key is missing; none (NTP off) when it's empty or holds
 * nothing valid. */
static int servers(char out[3][64])
{
	char line[512], list[512] = DEFAULT_SERVERS;
	FILE *f = fopen(conf_path, "r");
	if (f) {
		while (fgets(line, sizeof line, f)) {
			line[strcspn(line, "\r\n")] = 0;
			if (!strncmp(line, "time.ntp=", 9)) snprintf(list, sizeof list, "%s", line + 9);
		}
		fclose(f);
	}
	int n = 0;
	for (char *save = NULL, *t = strtok_r(list, ", ", &save); t && n < 3; t = strtok_r(NULL, ", ", &save))
		if (valid_host(t)) snprintf(out[n++], 64, "%s", t);
		else LOG("ntpc: ignored server \"%.64s\"\n", t);
	return n;
}

/* ---- DNS: one A query over UDP to the first nameserver -------------------------------- */

static int nameserver(struct in_addr *ns)
{
	char line[256], ip[64];
	FILE *f = fopen(resolv_path, "r");
	if (!f) return -1;
	int ok = -1;
	while (ok && fgets(line, sizeof line, f))
		if (sscanf(line, "nameserver %63s", ip) == 1 && inet_pton(AF_INET, ip, ns) == 1) ok = 0;
	fclose(f);
	return ok;
}

/* Query for `name` (A, IN, RD) into q; its length, or -1. */
static int dns_query(const char *name, uint16_t id, uint8_t *q, size_t cap)
{
	size_t o = 12;
	memset(q, 0, 12);
	q[0] = (uint8_t)(id >> 8); q[1] = (uint8_t)id;
	q[2] = 0x01;                                            /* RD */
	q[5] = 1;                                               /* QDCOUNT */
	for (const char *p = name; *p;) {
		size_t l = strcspn(p, ".");
		if (l < 1 || l > 63 || o + l + 1 + 5 > cap) return -1;
		q[o++] = (uint8_t)l;
		memcpy(q + o, p, l);
		o += l;
		p += l;
		if (*p == '.') p++;
	}
	if (o + 5 > cap) return -1;
	q[o++] = 0;
	q[o++] = 0; q[o++] = 1;                                 /* QTYPE A */
	q[o++] = 0; q[o++] = 1;                                 /* QCLASS IN */
	return (int)o;
}

/* Skip a (possibly compressed) name at r[o]; the offset after it, or -1. */
static int dns_skip(const uint8_t *r, size_t n, size_t o)
{
	for (int hops = 0; o < n && hops < 128; hops++) {
		if (!r[o]) return (int)o + 1;
		if ((r[o] & 0xc0) == 0xc0) return o + 2 <= n ? (int)o + 2 : -1;
		if (r[o] & 0xc0) return -1;
		o += (size_t)r[o] + 1;
	}
	return -1;
}

/* The A records in reply r (id must match, no error), at most max into out[]; their number
 * (>= 1) or -1. */
static int dns_answers(const uint8_t *r, size_t n, uint16_t id, struct in_addr *out, int max)
{
	if (n < 12 || r[0] != (uint8_t)(id >> 8) || r[1] != (uint8_t)id || !(r[2] & 0x80) ||
	    (r[3] & 0x0f))
		return -1;
	unsigned qd = (unsigned)r[4] << 8 | r[5], an = (unsigned)r[6] << 8 | r[7];
	int o = 12;
	for (unsigned i = 0; i < qd; i++) {
		if ((o = dns_skip(r, n, (size_t)o)) < 0 || (size_t)o + 4 > n) return -1;
		o += 4;
	}
	int got = 0;
	for (unsigned i = 0; i < an && got < max; i++) {
		if ((o = dns_skip(r, n, (size_t)o)) < 0 || (size_t)o + 10 > n) return got ? got : -1;
		unsigned type = (unsigned)r[o] << 8 | r[o + 1], cls = (unsigned)r[o + 2] << 8 | r[o + 3];
		unsigned rdlen = (unsigned)r[o + 8] << 8 | r[o + 9];
		o += 10;
		if ((size_t)o + rdlen > n) return got ? got : -1;
		if (type == 1 && cls == 1 && rdlen == 4) memcpy(&out[got++].s_addr, r + o, 4);
		o += (int)rdlen;
	}
	return got ? got : -1;
}

/* The first A record in reply r; 0 or -1. */
static int __attribute__((unused)) dns_answer(const uint8_t *r, size_t n, uint16_t id, struct in_addr *out)
{
	return dns_answers(r, n, id, out, 1) == 1 ? 0 : -1;
}

/* One request/reply on a connected UDP socket to addr:port; reply length or -1. */
static int udp_ask(struct in_addr addr, int port, const void *q, size_t qn, void *r, size_t cap)
{
	int fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd < 0) return -1;
	struct sockaddr_in sa = { .sin_family = AF_INET, .sin_port = htons((uint16_t)port), .sin_addr = addr };
	int n = -1;
	if (!connect(fd, (struct sockaddr *)&sa, sizeof sa) && send(fd, q, qn, 0) == (ssize_t)qn) {
		struct pollfd p = { fd, POLLIN, 0 };
		if (poll(&p, 1, TIMEOUT_MS) == 1) n = (int)recv(fd, r, cap, 0);
	}
	close(fd);
	return n;
}

/* host's IPv4 addresses (a literal, or up to max A records) into out[]; their number or -1. */
static int resolve(const char *host, struct in_addr *out, int max)
{
	if (inet_pton(AF_INET, host, out) == 1) return 1;
	struct in_addr ns;
	uint8_t q[300], r[1500];
	uint16_t id;
	if (nameserver(&ns)) { LOG("ntpc: no nameserver in %s\n", resolv_path); return -1; }
	if (random_bytes(&id, sizeof id)) return -1;
	int qn = dns_query(host, id, q, sizeof q);
	if (qn < 0) return -1;
	int n = udp_ask(ns, 53, q, (size_t)qn, r, sizeof r), got = -1;
	if (n < 0 || (got = dns_answers(r, (size_t)n, id, out, max)) < 1) {
		LOG("ntpc: can't resolve %s\n", host);
		return -1;
	}
	return got;
}

/* ---- SNTP ------------------------------------------------------------------------------ */

static uint64_t ts_get(const uint8_t *p)
{
	uint64_t v = 0;
	for (int i = 0; i < 8; i++) v = v << 8 | p[i];
	return v;
}

static double ts_unix(uint64_t t) { return (double)(t >> 32) - (double)NTP_UNIX_DELTA + (double)(t & 0xffffffffu) / 4294967296.0; }

static double now_real(void)
{
	struct timespec t;
	clock_gettime(CLOCK_REALTIME, &t);
	return (double)t.tv_sec + t.tv_nsec / 1e9;
}

/* Validate an SNTP reply against our request's transmit stamp `xmt`; the offset from t1 (our
 * send time) and t4 (our receive time) into *off. 0 or -1 with a reason in *why. */
static int sntp_check(const uint8_t *r, int n, uint64_t xmt, double t1, double t4, double *off,
		      const char **why)
{
	if (n < 48) { *why = "short reply"; return -1; }
	int leap = r[0] >> 6, mode = r[0] & 7, stratum = r[1];
	if (mode != 4) { *why = "not a server reply"; return -1; }
	if (ts_get(r + 24) != xmt) { *why = "origin doesn't match our request"; return -1; }
	if (leap == 3 || stratum < 1 || stratum > 15) { *why = "server unsynchronised"; return -1; }
	uint64_t rx = ts_get(r + 32), tx = ts_get(r + 40);
	if (!rx || !tx) { *why = "zero timestamps"; return -1; }
	double t2 = ts_unix(rx), t3 = ts_unix(tx);
	if (t2 < (double)BUILD_EPOCH || t3 < (double)BUILD_EPOCH) { *why = "time before the firmware build"; return -1; }
	if (t3 - t2 > SERVER_HOLD_S || t2 - t3 > SERVER_HOLD_S) { *why = "receive and transmit times too far apart"; return -1; }
	double o = ((t2 - t1) + (t3 - t4)) / 2;
	if (t4 + o < (double)BUILD_EPOCH) { *why = "result before the firmware build"; return -1; }
	*off = o;
	return 0;
}

/* Whether to apply a good offset `off` from `addr` now (1) or hold it (0): the first sync since
 * boot and any step up to GUARD_S go through; after the first sync a bigger one goes through only
 * when it agrees within AGREE_S with the one held from the previous poll, else it is held. */
static int step_gate(double off, struct in_addr addr)
{
	double big = off < 0 ? -off : off, d = off - pending_off;
	if (!synced || big <= GUARD_S || (pending && (d < 0 ? -d : d) <= AGREE_S)) {
		pending = 0;
		return 1;
	}
	if (pending) LOG("ntpc: step %+.0f s doesn't confirm the held %+.0f s\n", off, pending_off);
	pending = 1;
	pending_off = off;
	pending_addr = addr;
	return 0;
}

static int sntp(struct in_addr addr, double *off, const char **why)
{
	uint8_t q[48] = { 0x23 }, r[128];                       /* LI 0, VN 4, mode 3 */
	uint64_t xmt;
	if (random_bytes(&xmt, sizeof xmt)) { *why = "no randomness"; return -1; }
	for (int i = 0; i < 8; i++) q[40 + i] = (uint8_t)(xmt >> (56 - 8 * i));
	double t1 = now_real();
	int n = udp_ask(addr, 123, q, sizeof q, r, sizeof r);
	double t4 = now_real();
	if (n < 0) { *why = "no reply"; return -1; }
	return sntp_check(r, n, xmt, t1, t4, off, why);
}

/* Step or slew by off seconds. */
static int apply(double off)
{
	double now = now_real();
	if (now < (double)BUILD_EPOCH || off > STEP_S || off < -STEP_S) {
		double t = now + off;
		struct timeval tv = { (time_t)t, (suseconds_t)((t - (double)(time_t)t) * 1e6) };
		if (settimeofday(&tv, NULL)) { LOG("ntpc: settimeofday: %s\n", strerror(errno)); return -1; }
		LOG("ntpc: clock stepped by %+.3f s\n", off);
	} else {
		struct timeval tv = { (time_t)off, (suseconds_t)((off - (double)(time_t)off) * 1e6) };
		if (adjtime(&tv, NULL)) { LOG("ntpc: adjtime: %s\n", strerror(errno)); return -1; }
		if (verbose) LOG("ntpc: slewing %+.3f s\n", off);
	}
	return 0;
}

/* The address to ask from a[0..n): the first, or while a step is held the first one that didn't
 * give it (a fresh source for the confirmation); *other = 0 when only the held one is there. */
static int pick_addr(const struct in_addr *a, int n, int *other)
{
	*other = 1;
	if (!pending) return 0;
	for (int i = 0; i < n; i++)
		if (a[i].s_addr != pending_addr.s_addr) return i;
	*other = 0;
	return 0;
}

static void mark_synced(void)
{
	if (synced) return;
	synced = 1;
	int fd = open(synced_path, O_WRONLY | O_CREAT | O_CLOEXEC | O_NOFOLLOW, 0600);
	if (fd >= 0) close(fd);
}

/* One poll: 0 = clock set or slewing, 1 = a big step held for the next poll, -1 = nothing set. */
static int __attribute__((unused)) poll_once(void)
{
	char srv[3][64];
	int n = servers(srv);
	static int off_logged;
	if (!n) {                                       /* time.ntp empty: NTP off */
		if (!off_logged++) LOG("ntpc: time.ntp is empty: NTP off\n");
		return -1;
	}
	off_logged = 0;
	struct in_addr a[3];
	int ok[3] = { 0 }, other[3] = { 0 };
	for (int i = 0; i < n; i++) {
		struct in_addr all[MAX_ADDRS];
		int k = resolve(srv[i], all, MAX_ADDRS);
		if (k < 1) continue;
		a[i] = all[pick_addr(all, k, &other[i])];
		ok[i] = 1;
	}
	/* while a step is held: servers at another address first, then the held one's */
	for (int pass = pending ? 0 : 1; pass < 2; pass++)
		for (int i = 0; i < n; i++) {
			if (!ok[i] || (pass == 0 && !other[i]) || (pass == 1 && pending && other[i])) continue;
			double off;
			const char *why = "";
			char ip[INET_ADDRSTRLEN];
			inet_ntop(AF_INET, &a[i], ip, sizeof ip);
			if (sntp(a[i], &off, &why)) { LOG("ntpc: %s (%s): %s\n", srv[i], ip, why); continue; }
			if (verbose) LOG("ntpc: %s (%s): offset %+.3f s\n", srv[i], ip, off);
			if (!step_gate(off, a[i])) {
				LOG("ntpc: %s (%s): step %+.0f s held until the next poll agrees\n", srv[i], ip, off);
				return 1;
			}
			if (apply(off)) return -1;
			mark_synced();
			return 0;
		}
	return -1;
}

#ifndef NTPC_NO_MAIN
int main(int argc, char **argv)
{
	int c, once = 0;
	const char *user = NULL, *why = "";
	while ((c = getopt(argc, argv, "c:U:1v")) != -1) {
		if (c == 'c') conf_path = optarg;
		else if (c == 'U') user = optarg;
		else if (c == '1') once = 1;
		else if (c == 'v') verbose++;
		else { fprintf(stderr, "usage: %s [-c cam.conf] [-U user|uid:gid] [-1] [-v]\n", argv[0]); return 2; }
	}
	if (user) {                                     /* Gate 3: CAP_SYS_TIME only, before any poll */
		struct drop_id who;
		uint8_t r1;
		if (drop_lookup(user, "/etc/passwd", "/etc/group", &who, &why)) {
			LOG("ntpc: -U %s: %s\n", user, why);
			return 2;
		}
		if (random_bytes(&r1, 1)) LOG("ntpc: /dev/urandom: %s\n", strerror(errno));   /* fd stays */
		if (drop_to(&who, DROP_CAP_SYS_TIME, &why)) {
			LOG("ntpc: can't leave root for %s: %s (%s)\n", user, why, strerror(errno));
			return 1;
		}
		LOG("ntpc: running as %s (uid %u) with CAP_SYS_TIME only\n", user, (unsigned)getuid());
	}
	synced = !access(synced_path, F_OK);            /* an earlier ntpc set the clock this boot */
	if (once) return poll_once() ? 1 : 0;
	LOG("ntpc: servers from %s (time.ntp; default %s)\n", conf_path, DEFAULT_SERVERS);
	for (;;) {
		int was = synced, r = poll_once();
		if (!r && !was) LOG("ntpc: clock set\n");
		sleep(synced && r != 1 ? POLL_SLOW : POLL_FAST);
	}
}
#endif
