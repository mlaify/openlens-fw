/* SPDX-License-Identifier: MIT */
/*
 * drop.h: leave root for a system user (Gate 3), shared by rtspd (-U, -G) and ntpc (-U). The
 * programs are static glibc and the camera has no NSS modules (getpwnam would need them), so the
 * ids come from our own read of /etc/passwd and /etc/group:
 *
 *   drop_lookup(spec)   spec "rtspd": its uid and primary gid from passwd, and every group in
 *                       group that lists it as a member; spec "UID:GID" (numbers): those ids
 *                       and no other group, for a bench test on an image whose passwd hasn't
 *                       got the user. Root (uid or gid 0) is refused either way.
 *   drop_group(spec)    a group name from group, or a number (not 0)
 *   drop_to(id, cap)    setgroups, setgid, setuid. cap >= 0 keeps that one capability, effective
 *                       and permitted only (PR_SET_KEEPCAPS before setuid, then capset with the
 *                       kernel's _LINUX_CAPABILITY_VERSION_3 structs, no libcap); -1 keeps none.
 *                       Then checks every id and that setuid(0) and setgid(0) fail: no way back.
 *
 * Header-only, so the build lines stay as they are. Capabilities need Linux; elsewhere (the host
 * tests on a Mac) drop_to with a capability says so and fails.
 */
#ifndef DROP_H
#define DROP_H

#include <errno.h>
#include <grp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>
#ifdef __linux__
#include <sys/prctl.h>
#include <sys/syscall.h>
#endif

#define DROP_MAX_GROUPS 16
#define DROP_CAP_SYS_TIME 25                    /* linux/capability.h CAP_SYS_TIME */
#define DROP_CAP_VERSION_3 0x20080522u          /* _LINUX_CAPABILITY_VERSION_3: 2 x 32 bits */

struct drop_id {
	uid_t uid;
	gid_t gid;
	int ngroups;                            /* supplementary groups (the primary one too) */
	gid_t groups[DROP_MAX_GROUPS];
	char name[33];                          /* the user name, or the numbers as given */
};

/* The kernel's capset/capget structs (linux/capability.h __user_cap_*_struct) */
struct drop_cap_hdr { unsigned version; int pid; };
struct drop_cap_data { unsigned effective, permitted, inheritable; };

/* A whole decimal id 1..2147483646 (not root, not -1); -1 if s is anything else. */
static inline long drop_num(const char *s)
{
	size_t n = strlen(s);
	if (n < 1 || n > 10 || strspn(s, "0123456789") != n) return -1;
	long long v = atoll(s);
	return v >= 1 && v <= 2147483646 ? (long)v : -1;
}

/* Field f (0-based) of a colon-separated line into out ("" if missing); 0, or -1 if too long. */
static inline int drop_field(const char *line, int f, char *out, size_t cap)
{
	const char *p = line;
	for (int i = 0; i < f; i++) {
		p = strchr(p, ':');
		if (!p) { *out = 0; return 0; }
		p++;
	}
	size_t n = strcspn(p, ":\r\n");
	if (n >= cap) return -1;
	memcpy(out, p, n);
	out[n] = 0;
	return 0;
}

/* Whether the comma-separated member list holds name */
static inline int drop_member(const char *list, const char *name)
{
	size_t nl = strlen(name);
	for (const char *p = list; *p; p += strcspn(p, ",") + (p[strcspn(p, ",")] == ','))
		if (strcspn(p, ",") == nl && !strncmp(p, name, nl)) return 1;
	return 0;
}

/* spec: a group name in group_path or a number; its gid into *gid: 0, or -1 with *why. */
static inline int drop_group(const char *spec, const char *group_path, gid_t *gid, const char **why)
{
	long v = drop_num(spec);
	if (v > 0) { *gid = (gid_t)v; return 0; }
	if (!strcmp(spec, "0") || !strcmp(spec, "root")) { *why = "group root refused"; return -1; }
	FILE *f = fopen(group_path, "r");
	if (!f) { *why = "can't read the group file"; return -1; }
	char line[1024], name[33], num[16];
	int found = 0;
	while (!found && fgets(line, sizeof line, f))
		if (!drop_field(line, 0, name, sizeof name) && !strcmp(name, spec) &&
		    !drop_field(line, 2, num, sizeof num) && drop_num(num) > 0) {
			*gid = (gid_t)drop_num(num);
			found = 1;
		}
	fclose(f);
	if (!found) *why = "no such group (or it is root's)";
	return found ? 0 : -1;
}

/* spec: a user name in passwd_path (with its groups from group_path) or "UID:GID"; 0, or -1
 * with *why. */
static inline int drop_lookup(const char *spec, const char *passwd_path, const char *group_path,
			      struct drop_id *id, const char **why)
{
	char line[1024], name[33], num[16], members[768];
	memset(id, 0, sizeof *id);
	if (strlen(spec) >= sizeof id->name) { *why = "user too long"; return -1; }
	snprintf(id->name, sizeof id->name, "%s", spec);
	const char *colon = strchr(spec, ':');
	if (colon) {                                    /* UID:GID */
		char u[16];
		size_t n = (size_t)(colon - spec);
		if (n >= sizeof u) { *why = "UID:GID wanted"; return -1; }
		memcpy(u, spec, n);
		u[n] = 0;
		long uv = drop_num(u), gv = drop_num(colon + 1);
		if (uv < 0 || gv < 0) { *why = "UID:GID wanted, both numbers, neither 0"; return -1; }
		id->uid = (uid_t)uv;
		id->gid = (gid_t)gv;
		id->groups[id->ngroups++] = id->gid;
		return 0;
	}
	FILE *f = fopen(passwd_path, "r");
	if (!f) { *why = "can't read the passwd file"; return -1; }
	int found = 0;
	while (!found && fgets(line, sizeof line, f)) {
		if (drop_field(line, 0, name, sizeof name) || strcmp(name, spec)) continue;
		long uv, gv;
		if (drop_field(line, 2, num, sizeof num) || (uv = drop_num(num)) < 0 ||
		    drop_field(line, 3, num, sizeof num) || (gv = drop_num(num)) < 0)
			break;                          /* root's ids, or no ids: refused */
		id->uid = (uid_t)uv;
		id->gid = (gid_t)gv;
		found = 1;
	}
	fclose(f);
	if (!found) { *why = "no such user (or it is root's)"; return -1; }
	id->groups[id->ngroups++] = id->gid;
	if (!(f = fopen(group_path, "r"))) return 0;    /* no group file: the primary group only */
	while (fgets(line, sizeof line, f)) {
		long gv;
		if (drop_field(line, 2, num, sizeof num) || (gv = drop_num(num)) < 0 ||
		    drop_field(line, 3, members, sizeof members) || !drop_member(members, spec))
			continue;
		int dup = 0;
		for (int i = 0; i < id->ngroups; i++) dup |= id->groups[i] == (gid_t)gv;
		if (!dup && id->ngroups < DROP_MAX_GROUPS) id->groups[id->ngroups++] = (gid_t)gv;
	}
	fclose(f);
	return 0;
}

/* The capset arguments that keep capability cap only: effective and permitted, nothing inheritable */
static inline void drop_cap_build(int cap, struct drop_cap_hdr *h, struct drop_cap_data d[2])
{
	h->version = DROP_CAP_VERSION_3;
	h->pid = 0;                                     /* this process */
	memset(d, 0, 2 * sizeof d[0]);
	if (cap >= 0 && cap < 64) {
		d[cap / 32].effective = 1u << (cap % 32);
		d[cap / 32].permitted = 1u << (cap % 32);
	}
}

/* After a drop: every id as asked and no way back to root. 0, or -1 with *why. */
static inline int drop_check(const struct drop_id *id, const char **why)
{
	if (getuid() != id->uid || geteuid() != id->uid || getgid() != id->gid || getegid() != id->gid) {
		*why = "ids not as asked after the drop";
		return -1;
	}
#ifdef __linux__
	uid_t r, e, s;
	gid_t rg, eg, sg;
	if (getresuid(&r, &e, &s) || s != id->uid || getresgid(&rg, &eg, &sg) || sg != id->gid) {
		*why = "saved ids not as asked after the drop";
		return -1;
	}
#endif
	if (!setuid(0) || !setgid(0)) { *why = "setuid(0) or setgid(0) still works"; return -1; }
	return 0;
}

/* Leave root for id, keeping capability cap (>= 0) or none (-1). 0, or -1 with *why (the
 * process may be half-way: the caller exits). */
static inline int drop_to(const struct drop_id *id, int cap, const char **why)
{
#ifdef __linux__
	if (cap >= 0 && prctl(PR_SET_KEEPCAPS, 1L, 0L, 0L, 0L)) { *why = "prctl(PR_SET_KEEPCAPS)"; return -1; }
#else
	if (cap >= 0) { *why = "keeping a capability needs Linux"; return -1; }
#endif
	if (setgroups(id->ngroups, id->groups)) { *why = "setgroups"; return -1; }
	if (setgid(id->gid)) { *why = "setgid"; return -1; }
	if (setuid(id->uid)) { *why = "setuid"; return -1; }
#ifdef __linux__
	if (cap >= 0) {
		struct drop_cap_hdr h;
		struct drop_cap_data d[2], got[2];
		drop_cap_build(cap, &h, d);
		if (syscall(SYS_capset, &h, d)) { *why = "capset"; return -1; }
		prctl(PR_SET_KEEPCAPS, 0L, 0L, 0L, 0L);
		memset(got, 0, sizeof got);
		h.pid = 0;
		if (syscall(SYS_capget, &h, got) || memcmp(got, d, sizeof d)) {
			*why = "capabilities not as asked after capset";
			return -1;
		}
	}
#endif
	return drop_check(id, why);
}

#endif
