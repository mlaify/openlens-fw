/* SPDX-License-Identifier: MIT */
/*
 * Host test for camtls (no camera, no network port): camtls.c is compiled in with CAMTLS_TEST, so
 * connections arrive as socketpairs with made-up addresses instead of from a listening socket,
 * camhttpd's socket is a socketpair too, and both clocks are the test's. Built and run by
 * src/camtls/test.sh (mbedTLS 3.6 host build, ASan/UBSan):
 *
 *   test_camtls                       the in-process tests below; exit status = failures
 *   test_camtls serve CTLFD KEY CERT  a server for test_camtls.py (443 http, 322 rtsp): CTLFD is a
 *                                     datagram socket; we send "ready" once set up, then
 *                                     "conn PEER PORT LOCAL LPORT" + an fd (SCM_RIGHTS) brings
 *                                     a client, "quit" ends; camtls's backend connections go
 *                                     back on it as "backend" + an fd
 *   test_camtls gen-ca|issue|check    the helpers (CAMTLS_TEST_NOW=seconds sets the wall clock)
 *
 * In-process checks (an mbedTLS client on the other end of each socketpair, the server's loop
 * run one pass at a time between client steps): TLS 1.3 and 1.2 handshakes and the suite chosen;
 * the PROXY line and a byte-exact relay both ways; back-pressure (camhttpd pushes 10 MB to a
 * client that doesn't read: camtls stops reading camhttpd, then everything arrives intact);
 * close_notify when camhttpd closes, and camhttpd's end closed when the client closes; the
 * handshake deadline (slowloris); the per-address, total and concurrent-handshake limits, the
 * waiting queue and its timeout, the token bucket; camhttpd's backlog full (retried every 50 ms,
 * then 503) and a late accept; a client that sends nothing after PLAY still gets a stream faster
 * than one pass moves, with no wait while camtls holds a chunk; a reused slot sends the new client
 * none of the last one's bytes and its own PROXY line first; resumption with a ticket (TLS 1.3, 2 tickets, and TLS 1.2); the
 * CA's nameConstraints parse only through our callback; the renew rule (address, expiry, unset
 * clock).
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>

static long long fake_mono = -1;       /* >= 0: the monotonic clock (ms) is this */
static long long test_mono(void);
#define MONO_MS() test_mono()
static long long test_wall(void);
#define WALL_NOW() test_wall()
static int test_backend(const char *path, int *fd);
#define BACKEND_CONNECT test_backend
#define CAMTLS_TEST
#include "camtls.c"

static int serving;                    /* serve mode: backends go to the control socket */
static int backend_eagain;             /* > 0: that many "backlog full" answers; < 0: always */
static int backend_tries, last_backend = -1;
static int fails, checks;

#define CHECK(cond, ...) do { checks++; if (!(cond)) { fails++; printf("FAIL %s:%d: ", __FILE__, __LINE__); \
	printf(__VA_ARGS__); printf("\n"); } } while (0)

static long long test_mono(void) { return fake_mono >= 0 ? fake_mono : mono_ms(); }

static long long test_wall(void)
{
	const char *e = getenv("CAMTLS_TEST_NOW");
	return e ? atoll(e) : (long long)time(NULL);
}

static void small_bufs(int fd)
{
	int v = 16384;
	setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &v, sizeof v);
	setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &v, sizeof v);
}

static int test_backend(const char *path, int *fd)
{
	(void)path;
	backend_tries++;
	if (backend_eagain) {
		if (backend_eagain > 0) backend_eagain--;
		return 1;
	}
	int sv[2];
	if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv)) return -1;
	small_bufs(sv[0]);
	small_bufs(sv[1]);
	set_nonblock(sv[0]);
	if (serving) {                                  /* hand the other end to test_camtls.py */
		char cbuf[CMSG_SPACE(sizeof(int))];
		struct iovec iov = { (void *)"backend", 7 };
		struct msghdr m;
		memset(&m, 0, sizeof m);
		memset(cbuf, 0, sizeof cbuf);
		m.msg_iov = &iov;
		m.msg_iovlen = 1;
		m.msg_control = cbuf;
		m.msg_controllen = sizeof cbuf;
		struct cmsghdr *cm = CMSG_FIRSTHDR(&m);
		cm->cmsg_level = SOL_SOCKET;
		cm->cmsg_type = SCM_RIGHTS;
		cm->cmsg_len = CMSG_LEN(sizeof(int));
		memcpy(CMSG_DATA(cm), &sv[1], sizeof(int));
		int r = (int)sendmsg(test_ctl_fd, &m, 0);
		close(sv[1]);
		if (r < 0) { close(sv[0]); return -1; }
	} else {
		if (last_backend >= 0) close(last_backend);
		last_backend = sv[1];
		set_nonblock(last_backend);
	}
	*fd = sv[0];
	return 0;
}

static int serve_quit;

/* "conn PEER PORT LOCAL LPORT" with the client's fd, or "quit" */
static void test_ctl_read(long long now)
{
	char buf[128], cbuf[CMSG_SPACE(sizeof(int))];
	struct iovec iov = { buf, sizeof buf - 1 };
	struct msghdr m;
	memset(&m, 0, sizeof m);
	m.msg_iov = &iov;
	m.msg_iovlen = 1;
	m.msg_control = cbuf;
	m.msg_controllen = sizeof cbuf;
	ssize_t n = recvmsg(test_ctl_fd, &m, 0);
	if (n <= 0) { serve_quit = 1; return; }
	buf[n] = 0;
	int fd = -1;
	struct cmsghdr *cm = CMSG_FIRSTHDR(&m);
	if (cm && cm->cmsg_type == SCM_RIGHTS) memcpy(&fd, CMSG_DATA(cm), sizeof fd);
	char pa[32], la[32];
	unsigned pp, lp;
	if (!strncmp(buf, "quit", 4)) { serve_quit = 1; if (fd >= 0) close(fd); return; }
	if (fd < 0 || sscanf(buf, "conn %31s %u %31s %u", pa, &pp, la, &lp) != 4) {
		LOG("test: bad control message\n");
		if (fd >= 0) close(fd);
		return;
	}
	struct sockaddr_in peer, local;
	memset(&peer, 0, sizeof peer);
	memset(&local, 0, sizeof local);
	peer.sin_family = local.sin_family = AF_INET;
	inet_pton(AF_INET, pa, &peer.sin_addr);
	inet_pton(AF_INET, la, &local.sin_addr);
	peer.sin_port = htons((uint16_t)pp);
	local.sin_port = htons((uint16_t)lp);
	for (int i = 0; i < nlst; i++)
		if (lst[i].port == (int)lp) { conn_accepted(i, fd, &peer, &local, now); return; }
	LOG("test: no listener on %u\n", lp);
	close(fd);
}

static int serve_main(int argc, char **argv)
{
	if (argc < 5) return 2;
	serving = 1;
	verbose = argc > 5 && !strcmp(argv[5], "-v");
	test_ctl_fd = atoi(argv[2]);
	signal(SIGPIPE, SIG_IGN);
	if (add_listener("443:/test/http.sock") || add_listener("322:/test/rtsp.sock")) return 1;
	if (tls_init(argv[3], argv[4], 1)) return 1;
	if (send(test_ctl_fd, "ready", 5, 0) != 5) return 1;   /* test_camtls.py waits for this */
	long long idle_until = mono_ms() + 120000;      /* a lost test_camtls.py doesn't leave us */
	while (!serve_quit && mono_ms() < idle_until)
		if (loop_once(1000) > 0) idle_until = mono_ms() + 120000;
	return 0;
}

/* ---- the in-process client ------------------------------------------------------------------ */

struct cli { int fd, port; mbedtls_ssl_context ssl; };
static mbedtls_x509_crt ca_crt;
static mbedtls_ssl_config cf13, cf13aes, cf12, cf12aes;

static const int cli_chacha[] = { MBEDTLS_TLS1_3_CHACHA20_POLY1305_SHA256, MBEDTLS_TLS1_3_AES_128_GCM_SHA256,
	MBEDTLS_TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256, MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, 0 };
static const int cli_aes[] = { MBEDTLS_TLS1_3_AES_128_GCM_SHA256, MBEDTLS_TLS1_3_CHACHA20_POLY1305_SHA256,
	MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, MBEDTLS_TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256, 0 };

static void cli_conf(mbedtls_ssl_config *cf, int ver, const int *cs)
{
	mbedtls_ssl_config_init(cf);
	mbedtls_ssl_config_defaults(cf, MBEDTLS_SSL_IS_CLIENT, MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT);
	mbedtls_ssl_conf_rng(cf, mbedtls_ctr_drbg_random, &drbg);
	mbedtls_ssl_conf_authmode(cf, MBEDTLS_SSL_VERIFY_REQUIRED);
	mbedtls_ssl_conf_ca_chain(cf, &ca_crt, NULL);
	mbedtls_ssl_conf_min_tls_version(cf, (mbedtls_ssl_protocol_version)ver);
	mbedtls_ssl_conf_max_tls_version(cf, (mbedtls_ssl_protocol_version)ver);
	mbedtls_ssl_conf_ciphersuites(cf, cs);
	mbedtls_ssl_conf_tls13_enable_signal_new_session_tickets(cf, MBEDTLS_SSL_TLS1_3_SIGNAL_NEW_SESSION_TICKETS_ENABLED);
}

static void step(void) { loop_once(0); }

/* A client from ip:port to 192.0.2.159:lport: the server end goes into camtls as if accepted. */
static void cli_new_on(struct cli *c, const char *ip, int port, const mbedtls_ssl_config *cf, int lport)
{
	int sv[2];
	if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv)) { perror("socketpair"); exit(1); }
	small_bufs(sv[0]);
	small_bufs(sv[1]);
	struct sockaddr_in peer, local;
	memset(&peer, 0, sizeof peer);
	memset(&local, 0, sizeof local);
	peer.sin_family = local.sin_family = AF_INET;
	inet_pton(AF_INET, ip, &peer.sin_addr);
	inet_pton(AF_INET, "192.0.2.159", &local.sin_addr);
	peer.sin_port = htons((uint16_t)port);
	local.sin_port = htons((uint16_t)lport);
	int li = 0;
	while (li < nlst - 1 && lst[li].port != lport) li++;
	conn_accepted(li, sv[1], &peer, &local, MONO_MS());
	c->fd = sv[0];
	c->port = port;
	set_nonblock(c->fd);
	mbedtls_ssl_init(&c->ssl);
	if (mbedtls_ssl_setup(&c->ssl, cf) || mbedtls_ssl_set_hostname(&c->ssl, "192.0.2.159")) { printf("client setup\n"); exit(1); }
	mbedtls_ssl_set_bio(&c->ssl, &c->fd, bio_send, bio_recv, NULL);
}

static void cli_new(struct cli *c, const char *ip, int port, const mbedtls_ssl_config *cf)
{
	cli_new_on(c, ip, port, cf, 443);
}

static void cli_free(struct cli *c)
{
	if (c->fd >= 0) close(c->fd);
	c->fd = -1;
	mbedtls_ssl_free(&c->ssl);
}

static int cli_hs(struct cli *c)
{
	for (int i = 0; i < 20000; i++) {
		int r = mbedtls_ssl_handshake(&c->ssl);
		if (!r) return 0;
		if (r != MBEDTLS_ERR_SSL_WANT_READ && r != MBEDTLS_ERR_SSL_WANT_WRITE) return r;
		step();
	}
	return -1;
}

/* the server's side of a test client */
static struct conn *srv(const struct cli *c)
{
	for (int i = 0; i < MAX_CONN; i++)
		if (conns[i].state != ST_FREE && ntohs(conns[i].peer.sin_port) == c->port) return &conns[i];
	return NULL;
}

static int waiting(const struct cli *c)
{
	for (int i = 0; i < nwait; i++) if (ntohs(waitq[i].peer.sin_port) == c->port) return 1;
	return 0;
}

/* camtls closed the client's socket (EOF), without reading TLS */
static int closed(int fd)
{
	char b[4096];
	for (;;) {
		ssize_t n = recv(fd, b, sizeof b, 0);
		if (n > 0) continue;
		return n == 0 || (errno != EAGAIN && errno != EWOULDBLOCK);
	}
}

static void settle(void)
{
	for (int i = 0; i < 50; i++) step();
}

/* close every client and wait until camtls has let go of all of them */
static void reset_all(struct cli *cs, int n)
{
	for (int i = 0; i < n; i++) cli_free(&cs[i]);
	backend_eagain = 0;
	if (last_backend >= 0) close(last_backend);
	last_backend = -1;
	for (int i = 0; i < 200 && (nwait || state_count(ST_FREE) != MAX_CONN); i++) step();
	if (nwait || state_count(ST_FREE) != MAX_CONN) {
		fake_mono += 200000;                    /* past every deadline */
		settle();
	}
	CHECK(!nwait && state_count(ST_FREE) == MAX_CONN, "camtls let go of every connection");
	fake_mono += 3000;                              /* the bucket full again */
}

static unsigned char pattern(size_t i) { return (unsigned char)(i * 31 + (i >> 9)); }

/* ---- tests ---------------------------------------------------------------------------------- */

static void t_handshakes(void)
{
	struct cli c[4];
	cli_new(&c[0], "192.0.2.20", 40001, &cf13);
	CHECK(cli_hs(&c[0]) == 0, "TLS 1.3 handshake");
	CHECK(!strcmp(mbedtls_ssl_get_version(&c[0].ssl), "TLSv1.3"), "1.3: %s", mbedtls_ssl_get_version(&c[0].ssl));
	CHECK(!strcmp(mbedtls_ssl_get_ciphersuite(&c[0].ssl), "TLS1-3-CHACHA20-POLY1305-SHA256"),
	      "1.3 ChaCha20 when offered first: %s", mbedtls_ssl_get_ciphersuite(&c[0].ssl));
	cli_new(&c[1], "192.0.2.20", 40002, &cf13aes);
	CHECK(cli_hs(&c[1]) == 0, "TLS 1.3 handshake, AES first");
	CHECK(!strcmp(mbedtls_ssl_get_ciphersuite(&c[1].ssl), "TLS1-3-AES-128-GCM-SHA256"),
	      "1.3 follows the client's order: %s", mbedtls_ssl_get_ciphersuite(&c[1].ssl));
	cli_new(&c[2], "192.0.2.20", 40003, &cf12);
	CHECK(cli_hs(&c[2]) == 0, "TLS 1.2 handshake");
	CHECK(!strcmp(mbedtls_ssl_get_version(&c[2].ssl), "TLSv1.2"), "1.2: %s", mbedtls_ssl_get_version(&c[2].ssl));
	CHECK(!strcmp(mbedtls_ssl_get_ciphersuite(&c[2].ssl), "TLS-ECDHE-ECDSA-WITH-CHACHA20-POLY1305-SHA256"),
	      "1.2 ChaCha20: %s", mbedtls_ssl_get_ciphersuite(&c[2].ssl));
	cli_new(&c[3], "192.0.2.20", 40004, &cf12aes);
	CHECK(cli_hs(&c[3]) == 0, "TLS 1.2 handshake, AES first");
	CHECK(!strcmp(mbedtls_ssl_get_ciphersuite(&c[3].ssl), "TLS-ECDHE-ECDSA-WITH-CHACHA20-POLY1305-SHA256"),
	      "1.2 takes our order (ChaCha20) over the client's: %s", mbedtls_ssl_get_ciphersuite(&c[3].ssl));
	CHECK(srv(&c[0]) && srv(&c[0])->state == ST_FIRST, "handshaken, waiting for the request");
	CHECK(last_backend < 0 && backend_tries == 0, "no backend before the first request byte");
	reset_all(c, 4);
}

/* move data both ways until done or stuck; returns 0 when every byte arrived as sent */
static void t_relay(void)
{
	struct cli c;
	cli_new(&c, "192.0.2.21", 40100, &cf13);
	CHECK(cli_hs(&c) == 0, "handshake");
	const size_t UP = 100000, DOWN = 1000000;
	char proxy[96];
	int pl = snprintf(proxy, sizeof proxy, "PROXY TCP4 192.0.2.21 192.0.2.159 40100 443\r\n");
	unsigned char *up = malloc(UP), *buf = malloc(65536);
	for (size_t i = 0; i < UP; i++) up[i] = pattern(i + 7);
	size_t up_sent = 0, up_got = 0, down_sent = 0, down_got = 0;
	int bad_up = 0, bad_down = 0, closed_notify = 0;
	for (int it = 0; it < 400000 && !closed_notify; it++) {
		if (up_sent < UP) {
			size_t n = UP - up_sent < 3000 ? UP - up_sent : 3000;
			int r = mbedtls_ssl_write(&c.ssl, up + up_sent, n);
			if (r > 0) up_sent += (size_t)r;
		}
		step();
		if (last_backend >= 0) {
			ssize_t n = recv(last_backend, buf, 65536, 0);
			for (ssize_t i = 0; i < n; i++, up_got++) {
				unsigned char want = up_got < (size_t)pl ? (unsigned char)proxy[up_got] : up[up_got - pl];
				bad_up |= buf[i] != want;
			}
			if (up_got == UP + (size_t)pl && down_sent < DOWN) {
				unsigned char out[8192];
				size_t k = DOWN - down_sent < sizeof out ? DOWN - down_sent : sizeof out;
				for (size_t i = 0; i < k; i++) out[i] = pattern(down_sent + i);
				ssize_t w = send(last_backend, out, k, 0);
				if (w > 0) down_sent += (size_t)w;
			}
			if (down_sent == DOWN && down_got == DOWN) { close(last_backend); last_backend = -1; }
		}
		int r = mbedtls_ssl_read(&c.ssl, buf, 65536);
		for (int i = 0; i < r; i++, down_got++) bad_down |= buf[i] != pattern(down_got);
		if (r == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY) closed_notify = 1;
	}
	CHECK(up_got == UP + (size_t)pl && !bad_up, "client -> camhttpd: PROXY line then %zu bytes exact (got %zu, bad %d)",
	      UP, up_got, bad_up);
	CHECK(down_got == DOWN && !bad_down, "camhttpd -> client: %zu bytes exact (got %zu, bad %d)", DOWN, down_got, bad_down);
	CHECK(closed_notify, "close_notify after camhttpd closed");
	settle();
	CHECK(!srv(&c), "connection gone after close_notify");
	cli_free(&c);

	/* the client closes (close_notify): camhttpd's end is closed */
	cli_new(&c, "192.0.2.21", 40101, &cf12);
	CHECK(cli_hs(&c) == 0, "handshake");
	mbedtls_ssl_write(&c.ssl, (const unsigned char *)"GET / HTTP/1.1\r\n", 16);
	settle();
	CHECK(last_backend >= 0, "backend connected on the first request byte");
	ssize_t n = recv(last_backend, buf, 65536, 0);
	CHECK(n == pl + 16 - 2 + 2 && !memcmp(buf, "PROXY TCP4 192.0.2.21 192.0.2.159 40101 443\r\nGET /", 50),
	      "PROXY line, then the request (%zd)", n);
	mbedtls_ssl_close_notify(&c.ssl);
	settle();
	CHECK(closed(last_backend), "camhttpd's end closed after the client's close_notify");
	CHECK(!srv(&c), "connection gone");
	free(up);
	free(buf);
	reset_all(&c, 1);
}

static void t_backpressure(void)
{
	struct cli c;
	cli_new(&c, "192.0.2.22", 40200, &cf13);
	CHECK(cli_hs(&c) == 0, "handshake");
	mbedtls_ssl_write(&c.ssl, (const unsigned char *)"GET /preview.mjpg HTTP/1.1\r\n\r\n", 30);
	settle();
	CHECK(last_backend >= 0, "backend connected");
	unsigned char drop[65536];
	while (recv(last_backend, drop, sizeof drop, 0) > 0) {}
	const size_t TOTAL = 10u << 20;
	unsigned char out[16384];
	size_t pushed = 0, at1000 = 0;
	for (int it = 0; it < 3000; it++) {             /* the client reads nothing */
		for (size_t i = 0; i < sizeof out; i++) out[i] = pattern(pushed + i);
		ssize_t w = send(last_backend, out, sizeof out, 0);
		if (w > 0) pushed += (size_t)w;
		step();
		if (it == 1000) at1000 = pushed;
	}
	struct conn *s = srv(&c);
	CHECK(pushed < (1u << 20) && pushed == at1000, "camtls stopped reading camhttpd: %zu bytes taken, %zu at pass 1000",
	      pushed, at1000);
	CHECK(s && s->b2c_len <= B2C_CAP && s->c2b_len <= C2B_CAP, "buffers bounded");
	size_t got = 0;
	int bad = 0;
	unsigned char in[16384];
	for (int it = 0; it < 4000000 && got < TOTAL; it++) {
		if (pushed < TOTAL) {
			size_t k = TOTAL - pushed < sizeof out ? TOTAL - pushed : sizeof out;
			for (size_t i = 0; i < k; i++) out[i] = pattern(pushed + i);
			ssize_t w = send(last_backend, out, k, 0);
			if (w > 0) pushed += (size_t)w;
		}
		step();
		int r = mbedtls_ssl_read(&c.ssl, in, sizeof in);
		for (int i = 0; i < r; i++, got++) bad |= in[i] != pattern(got);
	}
	CHECK(got == TOTAL && !bad, "then all 10 MB arrive intact (%zu, bad %d)", got, bad);
	reset_all(&c, 1);
}

static void t_deadline(void)
{
	struct cli c;
	cli_new(&c, "192.0.2.23", 40300, &cf13);
	send(c.fd, "\x16\x03\x01", 3, 0);               /* a ClientHello that never finishes */
	settle();
	CHECK(srv(&c) && srv(&c)->state == ST_HS, "handshaking");
	fake_mono += HS_MS - 1;
	settle();
	CHECK(srv(&c) != NULL, "still there just before the deadline");
	fake_mono += 2;
	settle();
	CHECK(!srv(&c) && closed(c.fd), "closed at the handshake deadline");
	reset_all(&c, 1);

	/* handshaken but no request: closed after FIRST_MS */
	cli_new(&c, "192.0.2.23", 40301, &cf13);
	CHECK(cli_hs(&c) == 0, "handshake");
	fake_mono += FIRST_MS + 1;
	settle();
	CHECK(!srv(&c) && closed(c.fd), "closed without a request");
	reset_all(&c, 1);

	/* https: relaying, nothing either way for HTTP_IDLE_MS: closed */
	cli_new(&c, "192.0.2.23", 40302, &cf13);
	CHECK(cli_hs(&c) == 0, "handshake");
	mbedtls_ssl_write(&c.ssl, (const unsigned char *)"GET / HTTP/1.1\r\n\r\n", 18);
	settle();
	CHECK(srv(&c) && srv(&c)->state == ST_RELAY, "relaying");
	fake_mono += HTTP_IDLE_MS - 1;
	settle();
	CHECK(srv(&c) != NULL, "not idle yet");
	fake_mono += 2;
	settle();
	CHECK(!srv(&c), "closed after %d s idle", HTTP_IDLE_MS / 1000);
	reset_all(&c, 1);
}

static void t_limits(void)
{
	struct cli a[5], b[3];
	char name[8];
	for (int i = 0; i < 5; i++) cli_new(&a[i], "192.0.2.10", 41000 + i, &cf13);
	settle();
	CHECK(state_count(ST_HS) == 2 && nwait == 3, "2 handshakes at a time, 3 wait (%d, %d)", state_count(ST_HS), nwait);
	CHECK(srv(&a[0]) && srv(&a[1]) && waiting(&a[2]), "oldest first");
	CHECK(cli_hs(&a[0]) == 0 && cli_hs(&a[1]) == 0, "first two handshakes");
	settle();
	CHECK(srv(&a[2]) && srv(&a[3]) && waiting(&a[4]), "next two start; the fifth from one address waits");
	for (int i = 0; i < 3; i++) cli_new(&b[i], "192.0.2.11", 42000 + i, &cf13);
	settle();
	CHECK(waiting(&b[0]) && waiting(&b[1]) && waiting(&b[2]), "others wait for a handshake slot");
	CHECK(cli_hs(&a[2]) == 0 && cli_hs(&a[3]) == 0, "a3, a4 handshakes");
	settle();
	CHECK(srv(&b[0]) && srv(&b[1]) && waiting(&b[2]) && waiting(&a[4]), "6 connections: b3 waits (total), a5 (per address)");
	CHECK(cli_hs(&b[0]) == 0 && cli_hs(&b[1]) == 0, "b1, b2 handshakes");
	settle();                                       /* TLS 1.3: the server reads the client's Finished */
	CHECK(state_count(ST_FIRST) == 6 && nwait == 2, "6 established, 2 waiting (%d, %d)", state_count(ST_FIRST), nwait);
	snprintf(name, sizeof name, "a1");
	cli_free(&a[0]);                                /* a1 goes: a5 (older) is next, not b3 */
	settle();
	CHECK(srv(&a[4]) && srv(&a[4])->state == ST_HS && waiting(&b[2]), "a5 starts when a1 leaves; b3 still waits");
	fake_mono += WAIT_MS;                           /* b3 waited 5 s; a5's handshake too */
	settle();
	CHECK(!waiting(&b[2]) && closed(b[2].fd), "a waiting connection is closed after %d ms", WAIT_MS);
	CHECK(!srv(&a[4]) && closed(a[4].fd), "a5 closed at its handshake deadline");
	CHECK(state_count(ST_FIRST) == 5, "the established ones stay");
	reset_all(a, 5);
	reset_all(b, 3);

	/* the token bucket: BUCKET_BURST handshakes at once, then BUCKET_RATE per second */
	unsigned long before = stat_admitted;
	struct cli t;
	int i;
	for (i = 0; i < BUCKET_BURST + 1; i++) {
		cli_new(&t, "192.0.2.12", 43000 + i, &cf13);
		settle();
		if (!srv(&t)) break;
		cli_free(&t);
		settle();
	}
	CHECK(i == BUCKET_BURST && stat_admitted - before == BUCKET_BURST && waiting(&t),
	      "a burst of %d, then the next waits (%d, %lu)", BUCKET_BURST, i, stat_admitted - before);
	fake_mono += 1000 / BUCKET_RATE - 1;
	settle();
	CHECK(waiting(&t), "not yet");
	fake_mono += 1;
	settle();
	CHECK(srv(&t) != NULL, "one more token %d ms later", 1000 / BUCKET_RATE);
	reset_all(&t, 1);
}

static void t_backend_busy(void)
{
	struct cli c;
	cli_new(&c, "192.0.2.24", 40400, &cf13);
	CHECK(cli_hs(&c) == 0, "handshake");
	backend_eagain = -1;
	backend_tries = 0;
	mbedtls_ssl_write(&c.ssl, (const unsigned char *)"GET / HTTP/1.1\r\n\r\n", 18);
	unsigned char buf[512];
	size_t got = 0;
	int notify = 0;
	for (int ms = 0; ms < BACKEND_WAIT_MS + 500 && !notify; ms += 10) {
		step();
		int r = mbedtls_ssl_read(&c.ssl, buf + got, sizeof buf - 1 - got);
		if (r > 0) got += (size_t)r;
		if (r == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY) notify = 1;
		fake_mono += 10;
	}
	buf[got] = 0;
	CHECK(backend_tries >= 95 && backend_tries <= 105, "retried every %d ms (%d tries)", BACKEND_RETRY_MS, backend_tries);
	CHECK(!strncmp((char *)buf, "HTTP/1.1 503 ", 13) && strstr((char *)buf, "\r\n\r\ncamera busy\n"), "503: %s", buf);
	CHECK(notify, "then close_notify");
	reset_all(&c, 1);

	/* the backlog clears after 3 tries: the request goes through */
	cli_new(&c, "192.0.2.24", 40401, &cf13);
	CHECK(cli_hs(&c) == 0, "handshake");
	backend_eagain = 3;
	backend_tries = 0;
	mbedtls_ssl_write(&c.ssl, (const unsigned char *)"GET / HTTP/1.1\r\n\r\n", 18);
	for (int ms = 0; ms < 500; ms += 10) { step(); fake_mono += 10; }
	CHECK(backend_tries == 4 && last_backend >= 0, "connected on the 4th try (%d)", backend_tries);
	ssize_t n = last_backend >= 0 ? recv(last_backend, buf, sizeof buf, 0) : -1;
	CHECK(n == 45 + 18 && !memcmp(buf + 45, "GET /", 5), "request delivered after the wait (%zd)", n);
	reset_all(&c, 1);
}

static void t_listeners(void)
{
	CHECK(nlst == 2 && lst[0].kind == K_HTTP && lst[1].kind == K_RTSP && lst[1].max == RTSP_MAX, "443 http, 322 rtsp");
	int n0 = nlst;
	CHECK(add_listener("443:/x") && add_listener("80") && add_listener("0:/x") && add_listener("8443:x") &&
	      add_listener("8443:/x:ftp") && add_listener("70000:/x") && nlst == n0, "bad -L refused");
	CHECK(add_listener("8443:/x:rtsp"), "no more than %d connections in all (6 + 4 + 4)", MAX_CONN);
	struct listener keep[MAX_LISTEN];
	memcpy(keep, lst, sizeof keep);
	nlst = 1;
	CHECK(!add_listener("8443:/x:rtsp") && nlst == 2 && lst[1].kind == K_RTSP && lst[1].port == 8443, "-L PORT:SOCKET:rtsp");
	if (nlst == 2) free((char *)lst[1].path);
	nlst = 0;
	CHECK(!add_listener("322:/y:http") && nlst == 1 && lst[0].kind == K_HTTP && lst[0].max == HTTP_MAX, "-L 322:SOCKET:http");
	if (nlst == 1) free((char *)lst[0].path);
	memcpy(lst, keep, sizeof keep);
	nlst = n0;
}

/* RTSPS (322): 4 connections, 2 per address until they relay; the shared handshake limit */
static void t_rtsp_limits(void)
{
	struct cli r[5];
	for (int i = 0; i < 3; i++) cli_new_on(&r[i], "192.0.2.30", 44000 + i, &cf13, 322);
	settle();
	CHECK(srv(&r[0]) && srv(&r[1]) && waiting(&r[2]), "2 at a time");
	CHECK(cli_hs(&r[0]) == 0 && cli_hs(&r[1]) == 0, "handshakes");
	settle();
	CHECK(waiting(&r[2]), "a third from one address waits while two aren't relaying");
	mbedtls_ssl_write(&r[0].ssl, (const unsigned char *)"OPTIONS rtsp://192.0.2.159/ RTSP/1.0\r\nCSeq: 1\r\n\r\n", 49);
	settle();
	CHECK(srv(&r[0]) && srv(&r[0])->state == ST_RELAY && srv(&r[2]), "once one relays, the third starts");
	unsigned char b[128];
	ssize_t n = last_backend >= 0 ? recv(last_backend, b, sizeof b, MSG_PEEK) : -1;
	CHECK(n == 45 + 49 && !memcmp(b, "PROXY TCP4 192.0.2.30 192.0.2.159 44000 322\r\nOPTIONS ", 53),
	      "the first write to rtspd: PROXY line naming port 322, then the request (%zd)", n);
	for (int i = 3; i < 5; i++) cli_new_on(&r[i], "192.0.2.31", 44010 + i, &cf13, 322);
	settle();
	CHECK(srv(&r[3]) && waiting(&r[4]), "4 in all on 322: the fifth waits");
	struct cli h;
	cli_new(&h, "192.0.2.31", 44020, &cf13);
	settle();
	CHECK(waiting(&h), "443 waits for the shared handshake limit (2 handshaking on 322)");
	CHECK(cli_hs(&r[2]) == 0 && cli_hs(&r[3]) == 0, "handshakes");
	settle();
	CHECK(srv(&h) != NULL, "443 isn't held back by 322's total");
	reset_all(r, 5);
	reset_all(&h, 1);
}

/* append an interleaved RTP-like frame ('$', channel, 16-bit length, payload) or, now and then,
 * an RTSP reply, to buf at *len */
static void rtp_frames(unsigned char *buf, size_t cap, size_t *len, unsigned seed, int ch)
{
	unsigned x = seed;
	while (*len + 1500 < cap) {
		x = x * 1103515245u + 12345u;
		if ((x >> 8) % 50 == 0) {
			*len += (size_t)snprintf((char *)buf + *len, cap - *len, "RTSP/1.0 200 OK\r\nCSeq: %u\r\n\r\n", x >> 20);
			continue;
		}
		size_t pl = 12 + (x >> 12) % 1388;
		buf[(*len)++] = '$';
		buf[(*len)++] = (unsigned char)(ch + ((x >> 4) & 1));
		buf[(*len)++] = (unsigned char)(pl >> 8);
		buf[(*len)++] = (unsigned char)pl;
		for (size_t i = 0; i < pl; i++) buf[(*len)++] = (unsigned char)(x >> (i % 24));
	}
}

static void t_rtsp_stream(void)
{
	struct cli c;
	cli_new_on(&c, "192.0.2.32", 44100, &cf13, 322);
	CHECK(cli_hs(&c) == 0, "handshake on 322");
	const char *play = "PLAY rtsp://192.0.2.159/ RTSP/1.0\r\nCSeq: 4\r\nSession: 1\r\n\r\n";
	const size_t DOWN_CAP = 4u << 20, UP_CAP = 200000;
	unsigned char *down = malloc(DOWN_CAP), *up = malloc(UP_CAP), *buf = malloc(65536);
	size_t DOWN = 0, UP = strlen(play);
	memcpy(up, play, UP);
	rtp_frames(down, DOWN_CAP, &DOWN, 7, 0);
	rtp_frames(up, UP_CAP, &UP, 11, 1);                 /* RTCP receiver reports and keepalives */
	char proxy[64];
	int pl = snprintf(proxy, sizeof proxy, "PROXY TCP4 192.0.2.32 192.0.2.159 44100 322\r\n");
	size_t up_sent = 0, up_got = 0, down_sent = 0, down_got = 0;
	int bad_up = 0, bad_down = 0, cut = 0;
	long long t0 = fake_mono;
	for (int it = 0; it < 2000000 && (down_got < DOWN || up_got < UP + (size_t)pl) && !cut; it++) {
		if (up_sent < UP && it % 4 == 0) {
			size_t k = UP - up_sent < 600 ? UP - up_sent : 600;
			int r = mbedtls_ssl_write(&c.ssl, up + up_sent, k);
			if (r > 0) up_sent += (size_t)r;
		}
		step();
		if (last_backend >= 0) {
			ssize_t n = recv(last_backend, buf, 65536, 0);
			for (ssize_t i = 0; i < n; i++, up_got++)
				bad_up |= buf[i] != (up_got < (size_t)pl ? (unsigned char)proxy[up_got] : up[up_got - pl]);
			if (down_sent < DOWN) {                 /* 2 KB a fake second: half an hour of stream */
				size_t k = DOWN - down_sent < 2048 ? DOWN - down_sent : 2048;  /* small, steady writes */
				ssize_t w = send(last_backend, down + down_sent, k, 0);
				if (w > 0) down_sent += (size_t)w;
			}
		}
		int r = mbedtls_ssl_read(&c.ssl, buf, 65536);
		for (int i = 0; i < r; i++, down_got++) bad_down |= buf[i] != down[down_got];
		if (r < 0 && r != MBEDTLS_ERR_SSL_WANT_READ && r != MBEDTLS_ERR_SSL_WANT_WRITE &&
		    r != MBEDTLS_ERR_SSL_RECEIVED_NEW_SESSION_TICKET) cut = 1;
		fake_mono += 1000;
	}
	CHECK(!cut && down_got == DOWN && !bad_down, "rtspd -> client: %zu bytes of interleaved frames exact (got %zu, bad %d)",
	      DOWN, down_got, bad_down);
	CHECK(up_got == UP + (size_t)pl && !bad_up, "client -> rtspd: PROXY line, PLAY, %zu bytes exact (got %zu)", UP, up_got);
	CHECK(fake_mono - t0 > 2 * RTSP_IDLE_MS && srv(&c) && srv(&c)->state == ST_RELAY,
	      "no idle cut while bytes flow (%lld s of stream)", (fake_mono - t0) / 1000);
	if (srv(&c)) fake_mono = srv(&c)->last_io + RTSP_IDLE_MS - 1000;   /* since the last byte */
	settle();
	CHECK(srv(&c) != NULL, "silent for less than %d s: kept", RTSP_IDLE_MS / 1000);
	fake_mono += 2000;
	settle();
	CHECK(!srv(&c), "silent both ways for %d s: closed", RTSP_IDLE_MS / 1000);
	free(down);
	free(up);
	free(buf);
	reset_all(&c, 1);

	/* rtspd's backlog full for 5 s: close_notify, no HTTP reply */
	cli_new_on(&c, "192.0.2.32", 44101, &cf13, 322);
	CHECK(cli_hs(&c) == 0, "handshake");
	backend_eagain = -1;
	mbedtls_ssl_write(&c.ssl, (const unsigned char *)play, strlen(play));
	unsigned char b[64];
	int r = 0, got = 0;
	for (int ms = 0; ms < BACKEND_WAIT_MS + 500 && r != MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY; ms += 10) {
		step();
		r = mbedtls_ssl_read(&c.ssl, b, sizeof b);
		if (r > 0) got += r;
		fake_mono += 10;
	}
	CHECK(r == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY && got == 0, "rtsp: busy backend -> close_notify only (%d bytes)", got);
	reset_all(&c, 1);
}

/* rtspd sends more than one pass moves (16 rounds of B2C_CAP) and the client sends nothing after
 * PLAY: camtls must never sit in select() holding a chunk it read from rtspd and hasn't written */
static void t_quiet_client(void)
{
	struct cli c;
	cli_new_on(&c, "192.0.2.33", 44200, &cf13, 322);
	CHECK(cli_hs(&c) == 0, "handshake");
	const char *play = "PLAY rtsp://192.0.2.159/ RTSP/1.0\r\nCSeq: 4\r\nSession: 1\r\n\r\n";
	mbedtls_ssl_write(&c.ssl, (const unsigned char *)play, strlen(play));
	settle();
	struct conn *s = srv(&c);
	CHECK(last_backend >= 0 && s && s->state == ST_RELAY, "relaying");
	if (last_backend < 0 || !s) { reset_all(&c, 1); return; }
	unsigned char *buf = malloc(65536), out[16384];
	while (recv(last_backend, buf, 65536, 0) > 0) {}
	int big = 1 << 20;                              /* room for more than a pass at every hop */
	setsockopt(last_backend, SOL_SOCKET, SO_SNDBUF, &big, sizeof big);
	setsockopt(s->bfd, SOL_SOCKET, SO_RCVBUF, &big, sizeof big);
	setsockopt(s->fd, SOL_SOCKET, SO_SNDBUF, &big, sizeof big);
	setsockopt(c.fd, SOL_SOCKET, SO_RCVBUF, &big, sizeof big);
	const size_t TOTAL = 4u << 20;
	size_t pushed = 0, got = 0;
	int bad = 0, stalls = 0;
	for (int it = 0; it < 100000 && got < TOTAL && stalls < 3; it++) {
		while (pushed < TOTAL) {
			size_t k = TOTAL - pushed < sizeof out ? TOTAL - pushed : sizeof out;
			for (size_t i = 0; i < k; i++) out[i] = pattern(pushed + i);
			ssize_t w = send(last_backend, out, k, 0);
			if (w <= 0) break;
			pushed += (size_t)w;
		}
		long long t = mono_ms();                /* real time: select's wait is real */
		loop_once(300);
		if (mono_ms() - t >= 250 && s->b2c_len > 0) stalls++;   /* waited, holding bytes */
		int r;
		while ((r = mbedtls_ssl_read(&c.ssl, buf, 65536)) > 0 || r == MBEDTLS_ERR_SSL_RECEIVED_NEW_SESSION_TICKET)
			for (int i = 0; i < r; i++, got++) bad |= buf[i] != pattern(got);
	}
	CHECK(!stalls && got == TOTAL && !bad, "a client that sends nothing gets the whole stream: %zu of %zu bytes, "
	      "%d waits holding a chunk, bad %d", got, TOTAL, stalls, bad);
	free(buf);
	reset_all(&c, 1);
}

/* a connection closed with a chunk not yet sent: the next one in its slot starts clean (none of
 * the last client's bytes, and its own PROXY line first) */
static void t_slot_reuse(void)
{
	struct cli a, b;
	cli_new_on(&a, "192.0.2.34", 44300, &cf13, 322);
	CHECK(cli_hs(&a) == 0, "handshake");
	const char *play = "PLAY rtsp://192.0.2.159/ RTSP/1.0\r\nCSeq: 4\r\nSession: 1\r\n\r\n";
	mbedtls_ssl_write(&a.ssl, (const unsigned char *)play, strlen(play));
	settle();
	struct conn *s = srv(&a);
	CHECK(last_backend >= 0 && s, "relaying");
	if (last_backend < 0 || !s) { reset_all(&a, 1); return; }
	unsigned char out[16384], buf[4096];
	memset(out, 0xd0, sizeof out);
	for (int it = 0; it < 200; it++) {              /* a reads nothing */
		send(last_backend, out, sizeof out, 0);
		step();
	}
	CHECK(s->b2c_len > s->b2c_off, "a chunk waits for the client (%zu bytes)", s->b2c_len - s->b2c_off);
	cli_free(&a);
	settle();
	CHECK(s->state == ST_FREE, "closed");
	cli_new_on(&b, "192.0.2.35", 44301, &cf13, 322);
	CHECK(cli_hs(&b) == 0, "handshake");
	CHECK(srv(&b) == s, "the same slot");
	int r, got = 0;
	for (int it = 0; it < 50; it++) {               /* the server's end of the handshake, tickets */
		step();
		while ((r = mbedtls_ssl_read(&b.ssl, buf, sizeof buf)) > 0 || r == MBEDTLS_ERR_SSL_RECEIVED_NEW_SESSION_TICKET)
			if (r > 0) got += r;
	}
	CHECK(got == 0, "nothing for the new client before it asks (got %d bytes)", got);
	while (mbedtls_ssl_write(&b.ssl, (const unsigned char *)play, strlen(play)) == MBEDTLS_ERR_SSL_RECEIVED_NEW_SESSION_TICKET) {}
	settle();
	char proxy[64];
	int pl = snprintf(proxy, sizeof proxy, "PROXY TCP4 192.0.2.35 192.0.2.159 44301 322\r\n");
	ssize_t n = last_backend >= 0 ? recv(last_backend, buf, sizeof buf, 0) : -1;
	CHECK(n == pl + (ssize_t)strlen(play) && !memcmp(buf, proxy, (size_t)pl) && !memcmp(buf + pl, play, strlen(play)),
	      "rtspd gets the new client's PROXY line and request (%zd bytes)", n);
	reset_all(&b, 1);
}

static void t_resume(void)
{
	mbedtls_ssl_session s13, s12;
	mbedtls_ssl_session_init(&s13);
	mbedtls_ssl_session_init(&s12);
	struct cli c;
	cli_new(&c, "192.0.2.25", 40500, &cf13);
	CHECK(cli_hs(&c) == 0, "handshake");
	int nt = 0;
	unsigned char b[16];
	for (int i = 0; i < 2000 && nt < 2; i++) {
		int r = mbedtls_ssl_read(&c.ssl, b, sizeof b);
		if (r == MBEDTLS_ERR_SSL_RECEIVED_NEW_SESSION_TICKET) {
			nt++;
			mbedtls_ssl_session_free(&s13);
			mbedtls_ssl_session_init(&s13);
			CHECK(mbedtls_ssl_get_session(&c.ssl, &s13) == 0, "get_session");
		} else
			step();
	}
	CHECK(nt == 2, "2 tickets per TLS 1.3 handshake (%d)", nt);
	reset_all(&c, 1);
	unsigned long r0 = stat_resumed;
	cli_new(&c, "192.0.2.25", 40501, &cf13);
	mbedtls_ssl_set_session(&c.ssl, &s13);
	CHECK(cli_hs(&c) == 0, "resumed handshake");
	CHECK(srv(&c) && srv(&c)->resumed && stat_resumed == r0 + 1, "TLS 1.3 resumed with a ticket");
	reset_all(&c, 1);

	cli_new(&c, "192.0.2.25", 40502, &cf12);
	CHECK(cli_hs(&c) == 0, "1.2 handshake");
	CHECK(mbedtls_ssl_get_session(&c.ssl, &s12) == 0, "1.2 session");
	reset_all(&c, 1);
	cli_new(&c, "192.0.2.25", 40503, &cf12);
	mbedtls_ssl_set_session(&c.ssl, &s12);
	CHECK(cli_hs(&c) == 0, "1.2 resumed handshake");
	CHECK(srv(&c) && srv(&c)->resumed && stat_resumed == r0 + 2, "TLS 1.2 resumed with a ticket");
	reset_all(&c, 1);
	mbedtls_ssl_session_free(&s13);
	mbedtls_ssl_session_free(&s12);
}

static void t_renew(void)
{
	char why[160];
	uint32_t ip;
	ip4_parse("192.0.2.159", &ip);
	CHECK(cert_ip == ip, "certificate's IP SAN read");
	long long now = cert_not_after - 100 * 86400LL;
	CHECK(!need_renew(now, 1, ip, why, sizeof why), "same address, 100 days left: keep");
	CHECK(!need_renew(now, 0, 0, why, sizeof why), "no address on eth0 yet: keep");
	CHECK(need_renew(now, 1, ip + 1, why, sizeof why) && strstr(why, "192.0.2.160"), "address changed: %s", why);
	CHECK(need_renew(cert_not_after - 29 * 86400LL, 1, ip, why, sizeof why), "29 days left: renew");
	CHECK(!need_renew(BUILD_EPOCH - 1, 1, ip, why, sizeof why), "clock unset: keep");
	CHECK(!need_renew(cert_not_after - 31 * 86400LL, 1, ip, why, sizeof why), "31 days left: keep");
}

static void t_ca_parse(const char *dir)
{
	char path[512];
	mbedtls_x509_crt x;
	mbedtls_x509_crt_init(&x);
	snprintf(path, sizeof path, "%s/ca.crt", dir);
	CHECK(mbedtls_x509_crt_parse_file(&x, path) != 0, "plain mbedTLS refuses the CA (critical nameConstraints)");
	mbedtls_x509_crt_free(&x);
	unsigned char der[128];
	const unsigned char *p;
	size_t n;
	static const unsigned char want[] = {
		0x30, 0x3d, 0xa0, 0x3b, 0x30, 0x0a, 0x87, 0x08, 192, 0, 2, 0, 255, 255, 255, 0, 0x30, 0x22, 0x87, 0x20,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
		0x30, 0x09, 0x82, 0x07, 'i', 'n', 'v', 'a', 'l', 'i', 'd' };
	CHECK(!nc_der(der, sizeof der, &p, &n) && n == sizeof want && !memcmp(p, want, n), "nameConstraints DER");
}

int main(int argc, char **argv)
{
	if (argc >= 2 && !strcmp(argv[1], "serve")) return serve_main(argc, argv);
	if (argc >= 2) return camtls_main(argc, argv);
	(void)backend_connect;                          /* the real one, unused here */
	setvbuf(stdout, NULL, _IOLBF, 0);
	signal(SIGPIPE, SIG_IGN);
	char dir[256], key[300], crt[300];
	snprintf(dir, sizeof dir, "%s/camtls-test.XXXXXX", getenv("TMPDIR") ? getenv("TMPDIR") : "/tmp");
	if (!mkdtemp(dir)) { perror("mkdtemp"); return 1; }
	CHECK(helper_gen_ca(dir) == 0, "gen-ca");
	CHECK(helper_issue(dir, "192.0.2.159", dir) == 0, "issue");
	CHECK(helper_check(dir, "192.0.2.159") == 0, "check");
	snprintf(key, sizeof key, "%s/server.key", dir);
	snprintf(crt, sizeof crt, "%s/server.crt", dir);
	fake_mono = 1000000;
	verbose = 1;
	if (add_listener("443:/test/http.sock") || add_listener("322:/test/rtsp.sock")) { printf("listeners\n"); return 1; }
	if (tls_init(key, crt, 0)) { printf("tls_init failed\n"); return 1; }
	const char *why;
	mbedtls_x509_crt_init(&ca_crt);
	CHECK(load_ca(dir, &ca_crt, &why) == 0, "load_ca");
	cli_conf(&cf13, MBEDTLS_SSL_VERSION_TLS1_3, cli_chacha);
	cli_conf(&cf13aes, MBEDTLS_SSL_VERSION_TLS1_3, cli_aes);
	cli_conf(&cf12, MBEDTLS_SSL_VERSION_TLS1_2, cli_chacha);
	cli_conf(&cf12aes, MBEDTLS_SSL_VERSION_TLS1_2, cli_aes);

	t_ca_parse(dir);
	t_renew();
	t_handshakes();
	t_relay();
	t_backpressure();
	t_deadline();
	t_limits();
	t_backend_busy();
	t_listeners();
	t_rtsp_limits();
	t_rtsp_stream();
	t_quiet_client();
	t_slot_reuse();
	t_resume();
	printf("%d checks, %d failed\n", checks, fails);
	return fails ? 1 : 0;
}
