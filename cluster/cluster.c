/*
 * cluster/cluster.c - cooperative cache sharing between unbound instances
 *
 * Copyright (c) 2026, NLnet Labs. All rights reserved.
 *
 * This software is open source.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 
 * Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 * 
 * Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 * 
 * Neither the name of the NLNET LABS nor the names of its contributors may
 * be used to endorse or promote products derived from this software without
 * specific prior written permission.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED
 * TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/**
 * \file
 *
 * This file contains a module that lets a set of cooperating unbound
 * instances act as one logical cache.  A cache miss for a name that is
 * owned by another member is sent to that member, see cluster.h.
 */

#include "config.h"
#ifdef USE_CLUSTER
#include "cluster/cluster.h"
#include "libunbound/worker.h"
#include "services/mesh.h"
#include "services/modstack.h"
#include "services/outbound_list.h"
#include "services/cache/dns.h"
#include "services/cache/infra.h"
#include "util/rtt.h"
#include "iterator/iterator.h"
#include "iterator/iter_scrub.h"
#include "iterator/iter_utils.h"
#include "util/config_file.h"
#include "util/net_help.h"
#include "util/log.h"
#include "util/alloc.h"
#include "util/regional.h"
#include "util/siphash.h"
#include "util/storage/slabhash.h"
#include "util/storage/lruhash.h"
#include "util/data/dname.h"
#include "util/data/msgparse.h"
#include "util/data/msgreply.h"
#include "sldns/str2wire.h"
#include "sldns/rrdef.h"
#include "sldns/sbuffer.h"
#include "sldns/wire2str.h"
#include "sldns/parseutil.h"

/**
 * The fixed seed for the hashes, the same on all nodes.  It is not a
 * secret, the node ids and scores only have to be the same everywhere.
 */
static const uint8_t cluster_seed[16] = {
	'u','n','b','o','u','n','d','-','c','l','u','s','t','e','r','1'
};

/** the zone name used for the queries to peers, the root */
static uint8_t cluster_zone[1] = {0};
/** the zone name for the infra cache entry of the resolve requests (step 2)
 * to a peer.  Their round trip time includes the recursion of the owner, so
 * the timeout of the outgoing step 2 query is taken from this entry, apart
 * from the entry of the fast cache probes (zone "."), whose timeout of tens
 * of msec would make step 2 time out before the owner can answer. */
static uint8_t cluster_zone_resolve[] = "\017cluster-resolve";

int
cluster_rto_floor(struct infra_cache* infra, struct sockaddr_storage* addr,
	socklen_t addrlen, time_t now, int min_rto)
{
	struct rtt_info rtt;
	int delay = 0, tA = 0, tAAAA = 0, tother = 0, rto, i;
	long long ttl;
	if(min_rto < UNKNOWN_SERVER_NICENESS)
		min_rto = UNKNOWN_SERVER_NICENESS;
	ttl = infra_get_host_rto(infra, addr, addrlen, cluster_zone_resolve,
		sizeof(cluster_zone_resolve), &rtt, &delay, now, &tA, &tAAAA,
		&tother);
	/* no entry, or an expired one that is initialised afresh */
	rto = (ttl >= 0)?rtt.rto:UNKNOWN_SERVER_NICENESS;
	/* The infra cache has no call to set the timeout; the backoff after
	 * a lost query doubles the timeout that the caller saw.  This entry
	 * is used for step 2 only; its timeout counters are not read.
	 * A step 2 reply in another thread may lower the timeout between
	 * the calls (the backoff is then ignored and the lower value
	 * returned), so continue from the returned value; that does not
	 * repeat without end, the number of rounds is limited. */
	for(i=0; i<16 && rto <= min_rto; i++) {
		int n = infra_rtt_update(infra, addr, addrlen,
			cluster_zone_resolve, sizeof(cluster_zone_resolve),
			LDNS_RR_TYPE_NULL, -1, rto, now);
		if(n <= 0 || n == rto)
			break; /* out of memory, or at infra-cache-max-rtt */
		rto = n;
	}
	return rto;
}

/** the maximum recursion depth when searching for peer queries in the
 * super states of a query */
#define CLUSTER_SUPER_DEPTH 8

/** free the exclude list */
static void
cluster_exclude_delete(struct cluster_exclude* e)
{
	struct cluster_exclude* n;
	while(e) {
		n = e->next;
		free(e->name);
		free(e);
		e = n;
	}
}

/** free the cluster env and its contents */
static void
cluster_env_delete(struct cluster_env* ce)
{
	size_t i;
	if(!ce)
		return;
	for(i=0; i<ce->num_peers; i++) {
		lock_basic_destroy(&ce->peers[i].lock);
		free(ce->peers[i].str);
	}
	free(ce->peers);
	free(ce->node_ids);
	free(ce->stats);
	free(ce->snap);
	if(ce->snap_lock_inited)
		lock_basic_destroy(&ce->snap_lock);
	if(ce->eject_lock_inited)
		lock_basic_destroy(&ce->eject_lock);
	cluster_exclude_delete(ce->excludes);
	free(ce);
}

/**
 * See if the address of a peer is one of the interface addresses that
 * this server listens on.
 * @param cfg: config with the interface: entries.
 * @param peer: peer to check.
 * @return true if the peer address is a listen address.
 */
static int
cluster_peer_is_interface(struct config_file* cfg, struct cluster_peer* peer)
{
	int i;
	for(i=0; i<cfg->num_ifs; i++) {
		struct sockaddr_storage addr;
		socklen_t addrlen;
		if(!extstrtoaddr(cfg->ifs[i], &addr, &addrlen, cfg->port))
			continue; /* an interface name or other non-address */
		if(sockaddr_cmp(&addr, addrlen, &peer->addr,
			peer->addrlen) == 0)
			return 1;
	}
	return 0;
}

/**
 * Determine which of the peers is this server.
 * With cluster-self, the peer with that address.  Otherwise the peer
 * addresses that are listed in interface: config.  If there is not exactly
 * one match the position is not known.
 * @param ce: cluster env, with the peers set, self is set.
 * @param cfg: the config.
 */
static void
cluster_find_self(struct cluster_env* ce, struct config_file* cfg)
{
	size_t i;
	int found = -1;
	size_t count = 0;
	ce->self = -1;
	if(ce->num_peers == 0)
		return; /* inert, the position does not matter */
	if(cfg->cluster_self && cfg->cluster_self[0]) {
		struct sockaddr_storage addr;
		socklen_t addrlen;
		if(!extstrtoaddr(cfg->cluster_self, &addr, &addrlen,
			cfg->port)) {
			log_warn("cluster: cannot parse cluster-self '%s', "
				"own position unknown", cfg->cluster_self);
			return;
		}
		for(i=0; i<ce->num_peers; i++) {
			if(sockaddr_cmp(&addr, addrlen, &ce->peers[i].addr,
				ce->peers[i].addrlen) == 0) {
				found = (int)i;
				count++;
			}
		}
		if(count != 1) {
			log_warn("cluster: cluster-self '%s' does not match "
				"exactly one cluster-peer, own position "
				"unknown", cfg->cluster_self);
			return;
		}
		ce->self = found;
		return;
	}
	for(i=0; i<ce->num_peers; i++) {
		if(cluster_peer_is_interface(cfg, &ce->peers[i])) {
			found = (int)i;
			count++;
		}
	}
	if(count != 1) {
		log_warn("cluster: %u cluster-peer addresses match interface "
			"entries, expected one; own position unknown, set "
			"cluster-self", (unsigned)count);
		return;
	}
	ce->self = found;
}

/**
 * Apply the config to the cluster env.
 * @param ce: cluster env.
 * @param cfg: config.
 * @return false on failure.
 */
static int
cluster_apply_cfg(struct cluster_env* ce, struct config_file* cfg)
{
	struct config_strlist* p;
	struct cluster_exclude** last = &ce->excludes;
	size_t n = 0, i = 0, j;
	if(cfg->cluster_local_ttl_max < 0) {
		log_err("cluster: cluster-local-ttl-max must not be negative");
		return 0;
	}
	if(cfg->cluster_timeout < 0) {
		log_err("cluster: cluster-timeout must not be negative");
		return 0;
	}
	for(p = cfg->cluster_peer; p; p = p->next)
		n++;
	if(n > 0) {
		ce->peers = (struct cluster_peer*)calloc(n,
			sizeof(struct cluster_peer));
		ce->node_ids = (uint64_t*)calloc(n, sizeof(uint64_t));
		if(!ce->peers || !ce->node_ids) {
			log_err("out of memory");
			return 0;
		}
	}
	for(p = cfg->cluster_peer; p; p = p->next) {
		struct cluster_peer* peer = &ce->peers[i];
		if(!extstrtoaddr(p->str, &peer->addr, &peer->addrlen,
			cfg->port)) {
			log_err("cluster: cannot parse cluster-peer '%s'",
				p->str);
			return 0;
		}
		/* drop duplicates, they would get a double share of names */
		for(j=0; j<i; j++) {
			if(sockaddr_cmp(&peer->addr, peer->addrlen,
				&ce->peers[j].addr, ce->peers[j].addrlen)
				== 0)
				break;
		}
		if(j < i) {
			log_warn("cluster: duplicate cluster-peer '%s' "
				"ignored", p->str);
			continue;
		}
		peer->str = strdup(p->str);
		if(!peer->str) {
			log_err("out of memory");
			return 0;
		}
		peer->node_id = cluster_node_id(&peer->addr, peer->addrlen);
		ce->node_ids[i] = peer->node_id;
		lock_basic_init(&peer->lock);
		peer->probe_ewma = CLUSTER_FP_ONE;
		peer->res_ewma = CLUSTER_FP_ONE;
		i++;
		ce->num_peers = i; /* count only fully set up entries */
	}
	ce->local_ttl_max = cfg->cluster_local_ttl_max;
	ce->timeout_ms = cfg->cluster_timeout;
	ce->res_eject_max = cluster_eject_cap(ce->num_peers);
	for(p = cfg->cluster_exclude; p; p = p->next) {
		struct cluster_exclude* e = (struct cluster_exclude*)calloc(1,
			sizeof(*e));
		if(!e) {
			log_err("out of memory");
			return 0;
		}
		e->namelen = 0;
		e->name = sldns_str2wire_dname(p->str, &e->namelen);
		if(!e->name) {
			log_err("cluster: cannot parse cluster-exclude '%s'",
				p->str);
			free(e);
			return 0;
		}
		e->labs = dname_count_labels(e->name);
		*last = e;
		last = &e->next;
	}
	cluster_find_self(ce, cfg);
	return 1;
}

/* ---- hashing ---- */

/** make the canonical text "ip@port" of an address */
static void
cluster_addr_text(struct sockaddr_storage* addr, socklen_t addrlen,
	char* text, size_t len)
{
	uint16_t port = 0;
	size_t l;
	addr_to_str(addr, addrlen, text, len-8);
	if(addr->ss_family == AF_INET6)
		port = ntohs(((struct sockaddr_in6*)addr)->sin6_port);
	else	port = ntohs(((struct sockaddr_in*)addr)->sin_port);
	l = strlen(text);
	snprintf(text+l, len-l, "@%u", (unsigned)port);
}

static void
cluster_peer_text(struct cluster_peer* peer, char* buf, size_t len)
{
	cluster_addr_text(&peer->addr, peer->addrlen, buf, len);
}

uint64_t
cluster_node_id(struct sockaddr_storage* addr, socklen_t addrlen)
{
	/* The canonical text of the address and port, "ip@port". It does
	 * not depend on how the address was spelled in the config. */
	char text[128];
	uint8_t out[8];
	int k;
	uint64_t id = 0;
	cluster_addr_text(addr, addrlen, text, sizeof(text));
	if(siphash((uint8_t*)text, strlen(text), cluster_seed, out, 8) != 0)
		return 0;
	/* the siphash value, the output bytes are little endian */
	for(k=7; k>=0; k--)
		id = (id<<8) | out[k];
	return id;
}

/**
 * Score of a node for a name that is lowercased already.
 * @param node_id: the node.
 * @param lcname: lowercased uncompressed wireformat name.
 * @param len: length of lcname, at most LDNS_MAX_DOMAINLEN.
 * @return the score.
 */
static uint64_t
cluster_hrw_score_lc(uint64_t node_id, uint8_t* lcname, size_t len)
{
	uint8_t buf[8 + LDNS_MAX_DOMAINLEN + 1];
	uint8_t out[8];
	uint64_t score = 0;
	int k;
	for(k=0; k<8; k++)
		buf[k] = (uint8_t)(node_id >> (56-8*k));
	memcpy(buf+8, lcname, len);
	if(siphash(buf, 8+len, cluster_seed, out, 8) != 0)
		return 0;
	for(k=7; k>=0; k--)
		score = (score<<8) | out[k];
	return score;
}

/**
 * Copy the name lowercased, the hash is over the lowercased name, ascii only.
 * @param lc: buffer of LDNS_MAX_DOMAINLEN+1 bytes.
 * @param qname: the name.
 * @param qname_len: length of qname, limited to the maximum here.
 * @return the length.
 */
static size_t
cluster_lowercase_name(uint8_t* lc, uint8_t* qname, size_t qname_len)
{
	if(qname_len > LDNS_MAX_DOMAINLEN)
		qname_len = LDNS_MAX_DOMAINLEN;
	memcpy(lc, qname, qname_len);
	lc[qname_len] = 0; /* for the case of a truncated name */
	query_dname_tolower(lc);
	return qname_len;
}

uint64_t
cluster_hrw_score(uint64_t node_id, uint8_t* qname, size_t qname_len)
{
	uint8_t lc[LDNS_MAX_DOMAINLEN + 1];
	qname_len = cluster_lowercase_name(lc, qname, qname_len);
	return cluster_hrw_score_lc(node_id, lc, qname_len);
}

int
cluster_hrw_select(const uint64_t* node_ids, size_t n, uint8_t* qname,
	size_t qname_len, const uint8_t* skip)
{
	size_t i;
	int best = -1;
	uint64_t best_score = 0;
	uint8_t lc[LDNS_MAX_DOMAINLEN + 1];
	qname_len = cluster_lowercase_name(lc, qname, qname_len);
	for(i=0; i<n; i++) {
		uint64_t sc;
		if(skip && skip[i])
			continue;
		sc = cluster_hrw_score_lc(node_ids[i], lc, qname_len);
		/* strictly greater, so a tie goes to the lowest index */
		if(best == -1 || sc > best_score) {
			best = (int)i;
			best_score = sc;
		}
	}
	return best;
}

/* ---- the CLUSTER edns option ---- */

void
cluster_opt_encode(uint8_t* buf, uint8_t flags, uint64_t node_id)
{
	int k;
	buf[0] = CLUSTER_OPT_VERSION;
	buf[1] = flags;
	for(k=0; k<8; k++)
		buf[2+k] = (uint8_t)(node_id >> (56-8*k));
}

int
cluster_opt_decode(struct edns_option* opt, uint8_t* flags, uint64_t* node_id)
{
	int k;
	if(!opt || opt->opt_len < 2 || !opt->opt_data)
		return 0;
	if(opt->opt_data[0] != CLUSTER_OPT_VERSION)
		return 0;
	if(opt->opt_len != CLUSTER_OPT_LEN)
		return 0;
	*flags = opt->opt_data[1];
	*node_id = 0;
	for(k=0; k<8; k++)
		*node_id = (*node_id << 8) | opt->opt_data[2+k];
	return 1;
}

int
cluster_edns_peer_check(struct edns_option* list)
{
	struct edns_option* o = edns_opt_list_find(list,
		LDNS_EDNS_UNBOUND_CLUSTER);
	uint8_t flags;
	uint64_t id;
	if(!o)
		return 0;
	if(!cluster_opt_decode(o, &flags, &id))
		return -1;
	if(!(flags & CLUSTER_FLAG_PEER))
		return -1;
	return 1;
}

int
cluster_addr_is_peer(struct cluster_env* ce, struct sockaddr_storage* addr,
	socklen_t addrlen)
{
	size_t i;
	for(i=0; i<ce->num_peers; i++) {
		if(sockaddr_cmp_addr(addr, addrlen, &ce->peers[i].addr,
			ce->peers[i].addrlen) == 0)
			return 1;
	}
	return 0;
}

/* ---- peer health ---- */

int32_t
cluster_ewma_update(int32_t ewma, int sample, int div)
{
	int64_t target = sample?CLUSTER_FP_ONE:0;
	int64_t e = ewma;
	/* e += (target - e)/div, rounded away from e so that the value
	 * reaches 0 and 1.0 exactly */
	int64_t d = target - e;
	if(d > 0)
		e += (d + div - 1)/div;
	else	e += -((-d + div - 1)/div);
	if(e < 0)
		e = 0;
	if(e > CLUSTER_FP_ONE)
		e = CLUSTER_FP_ONE;
	return (int32_t)e;
}

void
cluster_rtt_update(int32_t* srtt_us, int32_t* rttvar_us, int* samples,
	int32_t r_us)
{
	int64_t srtt, rttvar, err;
	if(r_us < 0)
		r_us = 0;
	if(r_us > 60000000)
		r_us = 60000000;
	if(*samples <= 0) {
		*srtt_us = r_us;
		*rttvar_us = r_us/2;
		*samples = 1;
		return;
	}
	srtt = *srtt_us;
	rttvar = *rttvar_us;
	err = srtt - r_us;
	if(err < 0)
		err = -err;
	/* the variation is updated with the old srtt, RFC 6298 (2.3) */
	rttvar = (3*rttvar + err)/4;
	srtt = (7*srtt + r_us)/8;
	*srtt_us = (int32_t)srtt;
	*rttvar_us = (int32_t)rttvar;
	if(*samples < 1000000)
		(*samples)++;
}

int
cluster_resolve_budget(int discard_timeout_ms, long long used_ms)
{
	long long left = CLUSTER_RESOLVE_MAX;
	if(discard_timeout_ms > 0) {
		left = (long long)discard_timeout_ms - used_ms;
		if(left > CLUSTER_RESOLVE_MAX)
			left = CLUSTER_RESOLVE_MAX;
	}
	if(left < CLUSTER_RESOLVE_MIN)
		left = CLUSTER_RESOLVE_MIN;
	return (int)left;
}

int
cluster_eject_cap(size_t num_peers)
{
	return (int)((num_peers*CLUSTER_EJECT_MAX_PCT)/100);
}

/** time in msec */
static long long
cluster_now_ms(struct module_env* env)
{
	return (long long)env->now_tv->tv_sec*1000 +
		(long long)env->now_tv->tv_usec/1000;
}

/** difference b - a in microseconds, clamped to the int32 range */
static int32_t
cluster_tv_diff_us(struct timeval* a, struct timeval* b)
{
	long long d = ((long long)b->tv_sec - (long long)a->tv_sec)*1000000 +
		((long long)b->tv_usec - (long long)a->tv_usec);
	if(d < 0)
		d = 0;
	if(d > 2000000000LL)
		d = 2000000000LL;
	return (int32_t)d;
}

/**
 * See if a query can be sent to the peer, and reserve a probe slot if the
 * peer is down but may be probed.
 * @param peer: the peer.
 * @param now_ms: current time.
 * @param probe: returns true if this is a probe query.
 * @return true if the peer can be used.  This counts the query as routed.
 */
static int
cluster_peer_acquire(struct cluster_peer* peer, long long now_ms, int* probe)
{
	int ok = 0;
	*probe = 0;
	lock_basic_lock(&peer->lock);
	if(!peer->down) {
		ok = 1;
	} else if(!peer->probe_busy && now_ms >= peer->next_probe_ms) {
		/* half open, one query is allowed through to try the peer */
		peer->probe_busy = 1;
		*probe = 1;
		ok = 1;
	}
	if(ok)
		peer->routed++;
	lock_basic_unlock(&peer->lock);
	return ok;
}

/** the query was not sent after all, undo the acquire */
static void
cluster_peer_release(struct cluster_peer* peer, int probe)
{
	lock_basic_lock(&peer->lock);
	if(probe)
		peer->probe_busy = 0;
	if(peer->routed > 0)
		peer->routed--;
	lock_basic_unlock(&peer->lock);
}

/** the query ended without a result, e.g. the state was deleted */
static void
cluster_peer_abort(struct cluster_peer* peer, int probe)
{
	if(!probe)
		return;
	lock_basic_lock(&peer->lock);
	peer->probe_busy = 0;
	lock_basic_unlock(&peer->lock);
}

/** release the slot of the peer under the limit on the number of
 * resolve-ejected peers, with the peer lock held */
static void
cluster_eject_slot_release_locked(struct cluster_env* ce,
	struct cluster_peer* peer)
{
	if(!peer->eject_slot)
		return;
	peer->eject_slot = 0;
	lock_basic_lock(&ce->eject_lock);
	if(ce->res_ejected_count > 0)
		ce->res_ejected_count--;
	lock_basic_unlock(&ce->eject_lock);
}

/**
 * The resolve ejection of a peer ends, or it is cleared.
 * @param ce: cluster env.
 * @param peer: the peer, lock held by the caller.
 */
static void
cluster_res_unreject_locked(struct cluster_env* ce, struct cluster_peer* peer)
{
	if(!peer->res_ejected)
		return;
	peer->res_ejected = 0;
	cluster_eject_slot_release_locked(ce, peer);
}

/**
 * Report the end of a step of a query to a peer.
 * @param ce: cluster env.
 * @param peer: the peer.
 * @param res: what happened.
 * @param probe: the query was a probe of a down peer, this releases the
 *	slot.  Only for the cache probe step.
 * @param step1: the report is for the cache probe step, the probe EWMA
 * 	and the recovery history are for that step only.
 * @param env: for the time.
 */
void
cluster_peer_report(struct cluster_env* ce, struct cluster_peer* peer,
	enum cluster_peer_result res, int probe, int step1,
	struct module_env* env)
{
	long long now_ms = cluster_now_ms(env);
	int alive = (res == PEER_ANSWERED || res == PEER_MISS ||
		res == PEER_REJECTED);
	lock_basic_lock(&peer->lock);
	if(alive) {
		peer->last_alive_ms = now_ms;
		peer->alive_seen = 1;
	}
	if(probe)
		peer->probe_busy = 0;
	if(res == PEER_ANSWERED)
		peer->answered++;
	else if(res != PEER_MISS)
		peer->failed++;
	if(step1 && res != PEER_STEP2_FAILED)
		peer->probe_ewma = cluster_ewma_update(peer->probe_ewma,
			alive, CLUSTER_PROBE_EWMA_DIV);
	if(res == PEER_STEP2_FAILED) {
		/* no change in health, only the probe decides */
	} else if(alive) {
		peer->consec_fail = 0;
		peer->last_success = *env->now;
		if(peer->down && probe) {
			unsigned mask = (1u<<CLUSTER_HEALTH_UP_OUT_OF)-1;
			unsigned v;
			int n = 0;
			peer->half_hist = ((peer->half_hist<<1)|1u)&mask;
			for(v = peer->half_hist; v; v >>= 1)
				n += (int)(v&1u);
			if(n >= CLUSTER_HEALTH_UP_NEED) {
				verbose(VERB_OPS, "cluster: peer %s is up",
					peer->str);
				peer->down = 0;
				peer->half_hist = 0;
				peer->backoff_ms = 0;
				peer->probe_ewma = CLUSTER_FP_ONE/2;
			} else {
				/* try again right away, to get to the
				 * number of successes needed */
				peer->next_probe_ms = now_ms;
			}
		}
	} else {
		if(!peer->down) {
			if(peer->consec_fail < CLUSTER_HEALTH_FAIL_MAX)
				peer->consec_fail++;
			/* A lossy peer under traffic keeps answering, and
			 * stays up; a silent peer has not replied to
			 * anything for the alive window. */
			if(peer->consec_fail >= CLUSTER_HEALTH_FAIL_MAX &&
				(!peer->alive_seen ||
				now_ms - peer->last_alive_ms >=
				CLUSTER_ALIVE_WINDOW)) {
				verbose(VERB_OPS, "cluster: peer %s is down",
					peer->str);
				peer->down = 1;
				peer->half_hist = 0;
				peer->backoff_ms = CLUSTER_PROBE_BACKOFF_MIN;
				peer->next_probe_ms = now_ms +
					peer->backoff_ms;
				/* a down peer is not asked at all, the
				 * resolve judgment starts afresh when it
				 * is back */
				cluster_res_unreject_locked(ce, peer);
				peer->res_ewma = CLUSTER_FP_ONE;
				peer->res_n = 0;
				peer->res_consec_charged = 0;
				peer->eject_count = 0;
				peer->trial_busy = 0;
				peer->trial_gen++;
			}
		} else if(probe) {
			/* the probe failed, wait longer */
			peer->half_hist = (peer->half_hist<<1)&
				((1u<<CLUSTER_HEALTH_UP_OUT_OF)-1);
			peer->backoff_ms *= 2;
			if(peer->backoff_ms > CLUSTER_PROBE_BACKOFF_MAX)
				peer->backoff_ms = CLUSTER_PROBE_BACKOFF_MAX;
			if(peer->backoff_ms < CLUSTER_PROBE_BACKOFF_MIN)
				peer->backoff_ms = CLUSTER_PROBE_BACKOFF_MIN;
			peer->next_probe_ms = now_ms + peer->backoff_ms;
		}
	}
	lock_basic_unlock(&peer->lock);
}

/** a valid reply to the cache probe: a round trip time sample, shown in
 * cluster_status */
static void
cluster_peer_rtt_sample(struct cluster_peer* peer, int32_t rtt_us)
{
	lock_basic_lock(&peer->lock);
	cluster_rtt_update(&peer->srtt_us, &peer->rttvar_us,
		&peer->rtt_samples, rtt_us);
	lock_basic_unlock(&peer->lock);
}

/**
 * Step 2 gate, at the cache probe miss.  A resolve-ejected owner is not
 * asked to resolve, except for one trial request after the ejection time.
 * When the ejection time is over, the slot of the peer under the limit on
 * the number of ejected peers is released at once, also if the trial is
 * busy; if the trial fails and the peer is ejected again it takes a slot
 * again, if there is one.
 * @param ce: cluster env.
 * @param peer: the peer.
 * @param now_ms: the time.
 * @param trial: set to true if this request is the trial; the caller holds
 * 	the trial slot and has to release it, see cluster_res_result.
 * @param gen: the generation of the trial, if trial.
 * @return false if the query must be resolved locally.
 */
int
cluster_res_gate(struct cluster_env* ce, struct cluster_peer* peer,
	long long now_ms, int* trial, unsigned* gen)
{
	int ok = 1;
	*trial = 0;
	lock_basic_lock(&peer->lock);
	if(peer->res_ejected) {
		if(now_ms >= peer->eject_until_ms) {
			cluster_eject_slot_release_locked(ce, peer);
			if(!peer->trial_busy) {
				peer->trial_busy = 1;
				peer->trial_gen++;
				*gen = peer->trial_gen;
				*trial = 1;
			} else {
				ok = 0;
			}
		} else {
			ok = 0;
		}
	}
	lock_basic_unlock(&peer->lock);
	return ok;
}

/**
 * If the limit on the number of resolve-ejected peers is reached, release
 * the slots of the peers whose ejection time is over (they wait for their
 * trial), so that they do not keep another peer from being ejected.  The
 * peers are locked one at a time, not nested with the lock of the caller.
 * @param ce: cluster env.
 * @param self: the peer of the caller, skipped.
 * @param now_ms: the time.
 */
static void
cluster_eject_sweep(struct cluster_env* ce, struct cluster_peer* self,
	long long now_ms)
{
	size_t i;
	int full;
	lock_basic_lock(&ce->eject_lock);
	full = ce->res_ejected_count >= ce->res_eject_max;
	lock_basic_unlock(&ce->eject_lock);
	if(!full)
		return;
	for(i=0; i<ce->num_peers; i++) {
		struct cluster_peer* p = &ce->peers[i];
		if(p == self)
			continue;
		lock_basic_lock(&p->lock);
		if(p->res_ejected && p->eject_slot &&
			now_ms >= p->eject_until_ms)
			cluster_eject_slot_release_locked(ce, p);
		lock_basic_unlock(&p->lock);
	}
}

/** resolve-eject the peer, with the peer lock held.  If it is ejected
 * already (a failed trial), the ejection time is extended.
 * @return false if the limit on the number of ejected peers prevents it. */
static int
cluster_res_eject_locked(struct cluster_env* ce, struct cluster_peer* peer,
	long long now_ms)
{
	long long dur;
	if(!peer->eject_slot) {
		int ok;
		lock_basic_lock(&ce->eject_lock);
		ok = ce->res_ejected_count < ce->res_eject_max;
		if(ok)
			ce->res_ejected_count++;
		lock_basic_unlock(&ce->eject_lock);
		if(!ok) {
			/* a failed trial of a peer that gave up its slot,
			 * and the others took all of them: it is no longer
			 * ejected */
			cluster_res_unreject_locked(ce, peer);
			return 0;
		}
		peer->eject_slot = 1;
	}
	peer->res_ejected = 1;
	if(peer->eject_count < 1000)
		peer->eject_count++;
	dur = (long long)CLUSTER_EJECT_BASE_MS*peer->eject_count;
	if(dur > CLUSTER_EJECT_MAX_MS)
		dur = CLUSTER_EJECT_MAX_MS;
	peer->eject_until_ms = now_ms + dur;
	peer->res_consec_charged = 0;
	verbose(VERB_OPS, "cluster: peer %s is resolve-ejected for %d s",
		peer->str, (int)(dur/1000));
	return 1;
}

/**
 * Report the outcome of the resolve step of a query, for the resolution
 * health of the peer.
 * @param ce: cluster env.
 * @param peer: the peer.
 * @param res: the outcome.
 * @param trial: this query holds the trial slot, it is released here.
 * @param gen: the generation of the trial.  If the peer has gone down or
 * 	another trial was granted since, the query is stale: it is a plain
 * 	result and does not touch the trial slot of the newer trial.
 * @param env: for the time.
 */
void
cluster_res_result(struct cluster_env* ce, struct cluster_peer* peer,
	enum cluster_res_result res, int trial, unsigned gen,
	struct module_env* env)
{
	long long now_ms = cluster_now_ms(env);
	if(res == RES_CHARGED)
		cluster_eject_sweep(ce, peer, now_ms);
	lock_basic_lock(&peer->lock);
	if(trial && gen != peer->trial_gen)
		trial = 0;
	if(trial)
		peer->trial_busy = 0;
	if(res == RES_SUCCESS) {
		peer->res_ewma = cluster_ewma_update(peer->res_ewma, 1,
			CLUSTER_RES_EWMA_DIV);
		if(peer->res_n < 1000000)
			peer->res_n++;
		peer->res_consec_charged = 0;
		if(trial && peer->res_ejected) {
			cluster_res_unreject_locked(ce, peer);
			peer->res_ewma = CLUSTER_RES_TRIAL_EWMA;
			if(peer->eject_count > 0)
				peer->eject_count--;
			verbose(VERB_OPS, "cluster: peer %s resolves again",
				peer->str);
		}
	} else if(res == RES_CHARGED) {
		peer->res_ewma = cluster_ewma_update(peer->res_ewma, 0,
			CLUSTER_RES_EWMA_DIV);
		if(peer->res_n < 1000000)
			peer->res_n++;
		peer->res_consec_charged++;
		if(trial && peer->res_ejected) {
			/* the trial failed */
			(void)cluster_res_eject_locked(ce, peer, now_ms);
		} else if(!peer->res_ejected &&
			(peer->res_consec_charged >= CLUSTER_RES_EJECT_CONSEC
			|| (peer->res_n >= CLUSTER_RES_EJECT_MIN_N &&
			peer->res_ewma < CLUSTER_RES_EJECT_EWMA))) {
			(void)cluster_res_eject_locked(ce, peer, now_ms);
		}
	}
	lock_basic_unlock(&peer->lock);
}

/** log once per peer that its answer to a probe had no cluster option */
static void
cluster_note_noopt(struct cluster_peer* peer)
{
	int first;
	lock_basic_lock(&peer->lock);
	first = !peer->noopt_logged;
	peer->noopt_logged = 1;
	lock_basic_unlock(&peer->lock);
	if(first)
		verbose(VERB_OPS, "cluster: peer %s answered a cache probe "
			"without the cluster option; it must run the cluster "
			"module and list the source address of the queries of "
			"this node as a cluster-peer", peer->str);
}

/** log once per peer that it answered REFUSED without the cluster option */
static void
cluster_note_refused(struct cluster_peer* peer)
{
	int first;
	lock_basic_lock(&peer->lock);
	first = !peer->refused_logged;
	peer->refused_logged = 1;
	lock_basic_unlock(&peer->lock);
	if(first)
		verbose(VERB_OPS, "cluster: peer %s answered REFUSED without "
			"the cluster option; its access-control must allow "
			"queries from this node, and it must run the cluster "
			"module", peer->str);
}

static void
cluster_get_peer_info(struct cluster_env* ce, size_t idx,
	struct cluster_peer_info* info, long long now_ms)
{
	struct cluster_peer* peer = &ce->peers[idx];
	lock_basic_lock(&peer->lock);
	info->down = peer->down;
	info->consec_fail = peer->consec_fail;
	info->backoff_ms = peer->backoff_ms;
	info->probe_busy = peer->probe_busy;
	info->last_success = peer->last_success;
	info->routed = peer->routed;
	info->answered = peer->answered;
	info->failed = peer->failed;
	info->probe_ewma = peer->probe_ewma;
	info->srtt_us = peer->rtt_samples>0?peer->srtt_us:-1;
	info->res_ewma = peer->res_ewma;
	info->res_ejected = peer->res_ejected;
	info->trial_busy = peer->trial_busy;
	info->eject_left_ms = 0;
	if(peer->res_ejected && peer->eject_until_ms > now_ms)
		info->eject_left_ms = peer->eject_until_ms - now_ms;
	lock_basic_unlock(&peer->lock);
}

/* ---- statistics ---- */

/** the statistics of the thread of this query */
static struct cluster_stats*
cluster_mystats(struct cluster_env* ce, struct module_env* env)
{
	int t = env->alloc?env->alloc->thread_num:0;
	if(t < 0 || t >= ce->num_stats)
		t = 0;
	return &ce->stats[t];
}

struct cluster_env*
cluster_env_find(struct module_stack* mods, struct module_env* env)
{
	int id = modstack_find(mods, "cluster");
	if(id < 0)
		return NULL;
	return (struct cluster_env*)env->modinfo[id];
}

/** add b to a */
static void
cluster_stats_add(struct cluster_stats* a, struct cluster_stats* b)
{
	a->routed += b->routed;
	a->answered += b->answered;
	a->answered_cachehit += b->answered_cachehit;
	a->failed += b->failed;
	a->timeout += b->timeout;
	a->resolve_timeout += b->resolve_timeout;
	a->fallback += b->fallback;
	a->self += b->self;
	a->excluded += b->excluded;
	a->charged += b->charged;
	a->resolve_ejected += b->resolve_ejected;
	a->nolive += b->nolive;
	a->served += b->served;
	a->version_mismatch += b->version_mismatch;
	a->probe_miss += b->probe_miss;
	a->served_probe_miss += b->served_probe_miss;
}

void
cluster_get_stats(struct cluster_env* ce, struct cluster_stats* total)
{
	int i;
	memset(total, 0, sizeof(*total));
	lock_basic_lock(&ce->snap_lock);
	for(i=0; i<ce->num_stats; i++)
		cluster_stats_add(total, &ce->snap[i]);
	lock_basic_unlock(&ce->snap_lock);
}

void
cluster_stats_snapshot(struct cluster_env* ce, int thread_num)
{
	if(thread_num < 0 || thread_num >= ce->num_stats)
		return;
	/* the live counters are only changed by this thread, so reading
	 * them here needs no lock */
	lock_basic_lock(&ce->snap_lock);
	ce->snap[thread_num] = ce->stats[thread_num];
	lock_basic_unlock(&ce->snap_lock);
}

void
cluster_stats_clear_thread(struct cluster_env* ce, int thread_num)
{
	if(thread_num < 0 || thread_num >= ce->num_stats)
		return;
	memset(&ce->stats[thread_num], 0, sizeof(ce->stats[thread_num]));
}

/* ---- status and lookup support ---- */

void
cluster_rank(struct cluster_env* ce, uint8_t* qname, size_t qname_len,
	size_t* order, uint64_t* scores)
{
	size_t i, j, n = ce->num_peers;
	uint8_t lc[LDNS_MAX_DOMAINLEN + 1];
	uint64_t sc;
	qname_len = cluster_lowercase_name(lc, qname, qname_len);
	/* insertion sort, descending score, a tie keeps the lowest index
	 * first like cluster_hrw_select */
	for(i=0; i<n; i++) {
		sc = cluster_hrw_score_lc(ce->node_ids[i], lc, qname_len);
		for(j=i; j>0 && scores[j-1] < sc; j--) {
			scores[j] = scores[j-1];
			order[j] = order[j-1];
		}
		scores[j] = sc;
		order[j] = i;
	}
}

/**
 * See if this node owns the name.  The score of this node is compared with
 * the others until one is higher, that is cheaper than the full selection
 * for the names of other nodes.  The tie rule is that of cluster_hrw_select.
 * @param ce: cluster env, self is known.
 * @param qname: the name.
 * @param qname_len: length of qname.
 * @return true if this node is the owner.
 */
static int
cluster_owned_by_self(struct cluster_env* ce, uint8_t* qname,
	size_t qname_len)
{
	uint8_t lc[LDNS_MAX_DOMAINLEN + 1];
	size_t i, lclen = cluster_lowercase_name(lc, qname, qname_len);
	uint64_t mine = cluster_hrw_score_lc(ce->node_ids[ce->self], lc,
		lclen), sc;
	for(i=0; i<ce->num_peers; i++) {
		if(i == (size_t)ce->self)
			continue;
		sc = cluster_hrw_score_lc(ce->node_ids[i], lc, lclen);
		if(sc > mine || (sc == mine && i < (size_t)ce->self))
			return 0;
	}
	return 1;
}

/** See if the qname is under one of the exclude zones */
static int
cluster_is_excluded(struct cluster_env* ce, uint8_t* qname)
{
	struct cluster_exclude* e;
	for(e = ce->excludes; e; e = e->next) {
		if(dname_subdomain_c(qname, e->name))
			return 1;
	}
	return 0;
}

/** results of the message cache scan */
struct cluster_cache_scan {
	/** number of entries */
	size_t total;
	/** entries for names owned by this node */
	size_t owned;
	/** entries for names owned by another node, not excluded */
	size_t nonowned;
	/** entries for names under a cluster-exclude zone, these are
	 * resolved locally on every node and counted only here */
	size_t excluded;
};

/**
 * Scan the message cache of the worker and count the entries by owner.
 * It walks the hash table one bin at a time like dump_cache, and gives up
 * the table lock every so many entries, so the workers continue.  The cost
 * is linear in the cache size; per entry the score of this node is
 * compared with the scores of the other nodes until one is higher, a few
 * hashes on average, at most one per node.
 * @param ce: cluster env, self must be known.
 * @param msg_cache: the message cache.
 * @param res: the result.
 */
static void
cluster_scan_msg_cache(struct cluster_env* ce, struct slabhash* msg_cache,
	struct cluster_cache_scan* res)
{
	/* Like dump_lruhash in the cache dump: process a number of entries
	 * of a table with its lock held, then give up the lock and carry on
	 * from the hash value of the next bin, the table may change in
	 * between. */
	size_t slab;
	const size_t max = 200;
	memset(res, 0, sizeof(*res));
	for(slab=0; slab<msg_cache->size; slab++) {
		struct lruhash* table = msg_cache->array[slab];
		int just_started = 1, not_done = 1;
		hashvalue_type hash = 0;
		while(not_done) {
			size_t i, num = 0;
			lock_quick_lock(&table->lock);
			if(just_started)
				i = 0;
			else	i = hash&table->size_mask;
			while(num < max) {
				struct lruhash_bin* bin = &table->array[i];
				struct lruhash_entry* e;
				int found = 0;
				lock_quick_lock(&bin->lock);
				for(e = bin->overflow_list; e;
					e = e->overflow_next) {
					/* the key does not change while
					 * the entry is in the table */
					struct query_info* k =
						(struct query_info*)e->key;
					res->total++;
					if(cluster_is_excluded(ce, k->qname))
						res->excluded++;
					else if(cluster_owned_by_self(ce,
						k->qname, k->qname_len))
						res->owned++;
					else	res->nonowned++;
					num++;
				}
				lock_quick_unlock(&bin->lock);
				i++;
				while(i < table->size) {
					bin = &table->array[i];
					lock_quick_lock(&bin->lock);
					if(bin->overflow_list) {
						hash = bin->overflow_list->hash;
						lock_quick_unlock(&bin->lock);
						found = 1;
						just_started = 0;
						break;
					}
					lock_quick_unlock(&bin->lock);
					i++;
				}
				if(!found) {
					not_done = 0;
					break;
				}
			}
			lock_quick_unlock(&table->lock);
		}
	}
}

/* ---- remote control commands ---- */

/** get the cluster env for the commands, or print the error */
static struct cluster_env*
cluster_cmd_env(struct module_env* env, cluster_print_cb cb, void* arg)
{
	struct cluster_env* ce = cluster_env_find(&env->mesh->mods, env);
	if(!ce || ce->num_peers == 0) {
		(void)cb(arg, "error cluster module not enabled\n");
		return NULL;
	}
	return ce;
}

/** the state of a peer as text */
static const char*
cluster_state_text(struct cluster_peer_info* pi)
{
	if(!pi->down)
		return "up";
	return pi->probe_busy?"probing":"down";
}

int
cluster_print_stats(struct module_env* env, cluster_print_cb cb, void* arg)
{
	struct cluster_stats t;
	struct cluster_env* ce = cluster_env_find(&env->mesh->mods, env);
	if(!ce)
		return 1;
	cluster_get_stats(ce, &t);
#define CLUSTER_STAT(name, val) \
	if(!cb(arg, "cluster." name "=%llu\n", (unsigned long long)(val))) \
		return 0;
	CLUSTER_STAT("routed", t.routed)
	CLUSTER_STAT("answered", t.answered)
	CLUSTER_STAT("answered.cachehit", t.answered_cachehit)
	CLUSTER_STAT("probe.miss", t.probe_miss)
	CLUSTER_STAT("failed", t.failed)
	CLUSTER_STAT("timeout", t.timeout)
	CLUSTER_STAT("resolve_timeout", t.resolve_timeout)
	CLUSTER_STAT("fallback", t.fallback)
	CLUSTER_STAT("charged", t.charged)
	CLUSTER_STAT("resolve_ejected", t.resolve_ejected)
	CLUSTER_STAT("self", t.self)
	CLUSTER_STAT("excluded", t.excluded)
	CLUSTER_STAT("nolive", t.nolive)
	CLUSTER_STAT("served", t.served)
	CLUSTER_STAT("served.probe_miss", t.served_probe_miss)
	CLUSTER_STAT("version_mismatch", t.version_mismatch)
#undef CLUSTER_STAT
	return 1;
}

void
cluster_cmd_status(struct module_env* env, cluster_print_cb cb, void* arg,
	int multiproc, int scan)
{
	struct cluster_env* ce = cluster_cmd_env(env, cb, arg);
	size_t i;
	char buf[160];
	time_t now = *env->now;
	long long now_ms = cluster_now_ms(env);
	struct cluster_cache_scan sc;
	if(!ce)
		return;
	if(multiproc)
		(void)cb(arg, "note multi-process operation, the peer "
			"table and caches shown are those of this process\n");
	if(ce->self >= 0) {
		cluster_peer_text(&ce->peers[ce->self], buf, sizeof(buf));
	} else {
		snprintf(buf, sizeof(buf), "unknown");
	}
	if(!cb(arg, "self=%s peers=%u timeout=%d local-ttl-max=%d\n",
		buf, (unsigned)ce->num_peers, ce->timeout_ms,
		ce->local_ttl_max))
		return;
	for(i=0; i<ce->num_peers; i++) {
		struct cluster_peer_info pi;
		char age[64], srtt[32], resst[48];
		cluster_get_peer_info(ce, i, &pi, now_ms);
		cluster_peer_text(&ce->peers[i], buf, sizeof(buf));
		if(pi.last_success == 0)
			snprintf(age, sizeof(age), "never");
		else	snprintf(age, sizeof(age), "%llds",
				(long long)(now>=pi.last_success?
				now-pi.last_success:0));
		if(pi.srtt_us < 0)
			snprintf(srtt, sizeof(srtt), "-");
		else	snprintf(srtt, sizeof(srtt), "%d.%d",
				(int)(pi.srtt_us/1000),
				(int)((pi.srtt_us%1000)/100));
		if(!pi.res_ejected)
			snprintf(resst, sizeof(resst), "ok");
		else if(pi.eject_left_ms > 0 )
			snprintf(resst, sizeof(resst), "ejected(%llds left)",
				(long long)((pi.eject_left_ms+999)/1000));
		else	snprintf(resst, sizeof(resst), "trial");
		if(!cb(arg, "peer=%s state=%s fails=%d last_ok=%s "
			"probe_backoff=%d routed=%llu answered=%llu "
			"failed=%llu probe_ok=%d%% srtt=%s res_ok=%d%% "
			"res_state=%s%s\n", buf, cluster_state_text(&pi),
			pi.consec_fail, age, pi.backoff_ms,
			(unsigned long long)pi.routed,
			(unsigned long long)pi.answered,
			(unsigned long long)pi.failed,
			(int)(((int64_t)pi.probe_ewma*100)/CLUSTER_FP_ONE),
			srtt,
			(int)(((int64_t)pi.res_ewma*100)/CLUSTER_FP_ONE),
			resst,
			(ce->self>=0 && i==(size_t)ce->self)?" self":""))
			return;
	}
	if(!scan)
		return;
	if(ce->self < 0) {
		(void)cb(arg, "cache.msg: this node is not in the "
			"peer list, owned entries are not known\n");
		return;
	}
	cluster_scan_msg_cache(ce, env->msg_cache, &sc);
	(void)cb(arg, "cache.msg.total=%llu cache.msg.owned=%llu "
		"cache.msg.nonowned=%llu cache.msg.excluded=%llu\n",
		(unsigned long long)sc.total, (unsigned long long)sc.owned,
		(unsigned long long)sc.nonowned,
		(unsigned long long)sc.excluded);
}

void
cluster_cmd_lookup(struct module_env* env, cluster_print_cb cb, void* arg,
	const char* name)
{
	struct cluster_env* ce = cluster_cmd_env(env, cb, arg);
	uint8_t nm[LDNS_MAX_DOMAINLEN+1];
	size_t nmlen = sizeof(nm), i;
	int status;
	size_t* order = NULL;
	uint64_t* scores = NULL;
	char buf[160], txt[LDNS_MAX_DOMAINLEN*4+1];
	uint16_t types[2] = { LDNS_RR_TYPE_A, LDNS_RR_TYPE_AAAA };
	long long now_ms;
	if(!ce)
		return;
	now_ms = cluster_now_ms(env);
	if(name[0] == '\0') {
		(void)cb(arg, "error: this option requires a domain name\n");
		return;
	}
	status = sldns_str2wire_dname_buf(name, nm, &nmlen);
	if(status != 0) {
		(void)cb(arg, "error cannot parse name %s at %d: %s\n", name,
			LDNS_WIREPARSE_OFFSET(status),
			sldns_get_errorstr_parse(status));
		return;
	}
	order = (size_t*)calloc(ce->num_peers, sizeof(size_t));
	scores = (uint64_t*)calloc(ce->num_peers, sizeof(uint64_t));
	if(!order || !scores) {
		(void)cb(arg, "error out of memory\n");
		goto done;
	}
	cluster_rank(ce, nm, nmlen, order, scores);
	sldns_wire2str_dname_buf(nm, nmlen, txt, sizeof(txt));
	if(!cb(arg, "name=%s owned=%s\n", txt,
		(ce->self>=0 && order[0]==(size_t)ce->self)?"yes":"no"))
		goto done;
	for(i=0; i<ce->num_peers; i++) {
		struct cluster_peer_info pi;
		cluster_get_peer_info(ce, order[i], &pi, now_ms);
		cluster_peer_text(&ce->peers[order[i]], buf, sizeof(buf));
		if(!cb(arg, "rank=%u peer=%s score=%08x%08x state=%s%s\n",
			(unsigned)i+1, buf, (unsigned)(scores[i]>>32),
			(unsigned)(scores[i]&0xffffffffu),
			cluster_state_text(&pi),
			(ce->self>=0 && order[i]==(size_t)ce->self)?
			" self":""))
			goto done;
	}
	for(i=0; i<2; i++) {
		struct msgreply_entry* e = msg_cache_lookup(env, nm, nmlen,
			types[i], LDNS_RR_CLASS_IN, 0, *env->now, 0);
		char tp[32];
		sldns_wire2str_type_buf(types[i], tp, sizeof(tp));
		if(e) {
			struct reply_info* d = (struct reply_info*)e->entry.data;
			long long ttl = (long long)(d->ttl-*env->now);
			lock_rw_unlock(&e->entry.lock);
			if(!cb(arg, "cache.%s=hit ttl=%lld\n", tp, ttl))
				goto done;
		} else {
			if(!cb(arg, "cache.%s=miss\n", tp))
				goto done;
		}
	}
done:
	free(order);
	free(scores);
}

/* ---- module setup ---- */

int
cluster_init(struct module_env* env, int id)
{
	struct cluster_env* ce = (struct cluster_env*)calloc(1,
		sizeof(struct cluster_env));
	if(!ce) {
		log_err("malloc failure");
		return 0;
	}
	ce->self = -1;
	env->modinfo[id] = (void*)ce;
	ce->num_stats = env->cfg->num_threads>0?env->cfg->num_threads:1;
	ce->stats = (struct cluster_stats*)calloc((size_t)ce->num_stats,
		sizeof(struct cluster_stats));
	ce->snap = (struct cluster_stats*)calloc((size_t)ce->num_stats,
		sizeof(struct cluster_stats));
	if(!ce->stats || !ce->snap) {
		log_err("malloc failure");
		cluster_env_delete(ce);
		env->modinfo[id] = NULL;
		return 0;
	}
	lock_basic_init(&ce->snap_lock);
	ce->snap_lock_inited = 1;
	lock_basic_init(&ce->eject_lock);
	ce->eject_lock_inited = 1;
	if(!cluster_apply_cfg(ce, env->cfg)) {
		log_err("cluster: could not apply configuration settings.");
		cluster_env_delete(ce);
		env->modinfo[id] = NULL;
		return 0;
	}
	/* The option from the peers, owner side.  The cache stage is not
	 * bypassed, so that the owner answers from its cache, and the
	 * mesh states are aggregated, see R2 in mesh_new_client. */
	if(!edns_register_option(LDNS_EDNS_UNBOUND_CLUSTER, 0, 0, env)) {
		log_err("cluster: could not register the EDNS option");
		cluster_env_delete(ce);
		env->modinfo[id] = NULL;
		return 0;
	}
	if(!inplace_cb_register((void*)cluster_inplace_reply,
		inplace_cb_reply, ce, env, id) ||
		!inplace_cb_register((void*)cluster_inplace_reply,
		inplace_cb_reply_cache, ce, env, id)) {
		log_err("cluster: could not register the reply callbacks");
		inplace_cb_delete(env, inplace_cb_reply, id);
		inplace_cb_delete(env, inplace_cb_reply_cache, id);
		cluster_env_delete(ce);
		env->modinfo[id] = NULL;
		return 0;
	}
	/* Running inside libunbound cannot be detected here: at init
	 * time env->send_query is not set yet, neither for the daemon
	 * (it is set on the per-thread worker env) nor for libunbound
	 * (set in libworker_setup, after the modules are initialised).
	 * It is detected at operate time, in cluster_operate. */
	verbose(VERB_OPS, "cluster: %u peers, self %s%s, local-ttl-max %d, "
		"timeout %d ms, %s", (unsigned)ce->num_peers,
		ce->self>=0?"is ":"unknown", ce->self>=0?ce->peers[ce->self].str:"",
		ce->local_ttl_max, ce->timeout_ms,
		ce->num_peers?"routing enabled when used as a daemon":
		"inert, no cluster-peer configured");
	if(ce->num_peers && ce->self < 0)
		log_warn("cluster: this node is not found in the peer list; "
			"queries for names that it owns itself are sent to "
			"its own address");
	return 1;
}

void
cluster_deinit(struct module_env* env, int id)
{
	struct cluster_env* ce;
	if(!env || !env->modinfo[id])
		return;
	ce = (struct cluster_env*)env->modinfo[id];
	inplace_cb_delete(env, inplace_cb_reply, id);
	inplace_cb_delete(env, inplace_cb_reply_cache, id);
	cluster_env_delete(ce);
	env->modinfo[id] = NULL;
}

/* ---- per query state ---- */

/** the steps of the lookup at the owner, see the two-step lookup in the
 * design */
enum cluster_step {
	/** step 1: the cache probe, CACHE_ONLY, with the deadline
	 * cluster-timeout; a miss is answered by REFUSED with the MISS flag */
	CLUSTER_STEP_PROBE,
	/** step 2: the owner is alive, it is asked to resolve the query,
	 * with the deadline from the client budget, see
	 * cluster_resolve_deadline_ms */
	CLUSTER_STEP_RESOLVE
};

/** per query state of the cluster module, when a peer is queried */
struct cluster_qstate {
	/** the query state, for the timer callback */
	struct module_qstate* qstate;
	/** the module id */
	int id;
	/** the outbound entries, at most one */
	struct outbound_list outlist;
	/** the deadline timer, or NULL */
	struct comm_timer* timer;
	/** time the query of the current step was first sent, for the round
	 * trip time sample of the cache probe */
	struct timeval step_start;
	/** this query holds the trial slot of the peer, the resolve
	 * request is the single trial after a resolve-ejection; released
	 * when the verdict is known or the state ends */
	int trial;
	/** the generation of the trial of the peer, see trial_gen */
	unsigned trial_gen;
	/** paired attribution: the owner failed step 2 and the local
	 * fallback is running; the verdict is made at moddone */
	int fb_pending;
	/** time the local fallback started, if fb_pending */
	struct timeval fb_start;
	/** the index of the peer that is queried */
	int peer;
	/** the current step */
	enum cluster_step step;
	/** the query to the peer is a probe of a down peer, it holds the
	 * probe slot of the peer until the end of step 1 */
	int probe;
	/** waiting for the peer, no result has been processed */
	int pending;
	/** the deadline timer fired */
	int timed_out;
	/** number of times the cache probe was sent again after a
	 * timeout of the outnet before the deadline */
	int resends;
	/** this module set no_cache_store of the query, for a stale answer
	 * of the owner; it is reset when the state is cleared, for a
	 * validator restart that resolves the query locally */
	int set_no_store;
};

/** return an error to the client */
static void
cluster_error_response(struct module_qstate* qstate, int id, int rcode)
{
	verbose(VERB_QUERY, "return error response %s",
		sldns_lookup_by_id(sldns_rcodes, rcode)?
		sldns_lookup_by_id(sldns_rcodes, rcode)->name:"??");
	qstate->return_rcode = rcode;
	qstate->return_msg = NULL;
	qstate->ext_state[id] = module_finished;
}

/**
 * Is the module running inside libunbound.  The cluster module needs
 * the network of a daemon worker, and refuses to act under libunbound.
 */
static int
cluster_in_libunbound(struct module_qstate* qstate)
{
	return qstate->env->send_query == &libworker_send_query;
}

/** stop the timer and the outbound entries of the query, no more events
 * for this query can arrive after this */
static void
cluster_stop_waiting(struct cluster_qstate* cq, struct outbound_entry* e)
{
	if(cq->timer) {
		comm_timer_delete(cq->timer);
		cq->timer = NULL;
	}
	if(e)
		outbound_list_remove(&cq->outlist, e);
	/* any other entries, there is at most one */
	outbound_list_clear(&cq->outlist);
}

void
cluster_clear(struct module_qstate* qstate, int id)
{
	struct cluster_qstate* cq;
	struct cluster_env* ce;
	if(!qstate)
		return;
	cq = (struct cluster_qstate*)qstate->minfo[id];
	ce = (struct cluster_env*)qstate->env->modinfo[id];
	if(cq) {
		cluster_stop_waiting(cq, NULL);
		if(cq->pending && ce && cq->peer >= 0)
			cluster_peer_abort(&ce->peers[cq->peer], cq->probe);
		/* the state ends before the local fallback is done, or the
		 * validator restarts: no verdict, no sample */
		if(cq->trial && ce && cq->peer >= 0)
			cluster_res_result(ce, &ce->peers[cq->peer],
				RES_NEUTRAL, 1, cq->trial_gen, qstate->env);
		cq->trial = 0;
		cq->fb_pending = 0;
		cq->pending = 0;
		if(cq->set_no_store) {
			qstate->no_cache_store = 0;
			cq->set_no_store = 0;
		}
	}
	qstate->minfo[id] = NULL;
}

void
cluster_timer_cb(void* arg)
{
	struct cluster_qstate* cq = (struct cluster_qstate*)arg;
	struct module_qstate* qstate = cq->qstate;
	verbose(VERB_ALGO, "cluster: timeout waiting for the owner");
	/* The timer is a one shot, it does not run again.  The state is
	 * woken like for a lost reply.  The outbound entry is removed by
	 * the operate routine, so that there is one place for that.
	 * This runs from the event loop and not from within mesh_run, so
	 * it is fine to start mesh_run here, like for a reply. */
	if(!cq->pending)
		return;
	cq->timed_out = 1;
	mesh_run(qstate->env->mesh, qstate->mesh_info, module_event_noreply,
		NULL);
}

/* ---- routing decisions ---- */

/**
 * See if one of the super states of the query state is a peer query.
 * Validator subqueries of a peer query have to stay local.
 * @return 0 if not, 1 for a peer query, 2 if one of them is a cache only
 * 	probe.
 */
static int
cluster_super_is_peer(struct mesh_state* ms, int depth)
{
	struct mesh_state_ref* ref;
	int r = 0, sub;
	if(depth <= 0)
		return 0;
	RBTREE_FOR(ref, struct mesh_state_ref*, &ms->super_set) {
		struct edns_option* o;
		uint8_t flags = 0;
		uint64_t nid;
		if(cluster_edns_peer_check(ref->s->s.edns_opts_front_in)
			== 1) {
			o = edns_opt_list_find(ref->s->s.edns_opts_front_in,
				LDNS_EDNS_UNBOUND_CLUSTER);
			if(o && cluster_opt_decode(o, &flags, &nid) &&
				(flags & CLUSTER_FLAG_CACHE_ONLY))
				return 2;
			r = 1;
		}
		sub = cluster_super_is_peer(ref->s, depth-1);
		if(sub == 2)
			return 2;
		if(sub)
			r = 1;
	}
	return r;
}

/**
 * Find the node to send the query to.
 * The scores of all peers are calculated once, then the best peer that is
 * not down is taken.
 * @param ce: cluster env.
 * @param qstate: the query.
 * @param probe: set to true if the query is a probe of a down peer.
 * @return peer index, or -1 if the owner is this node, or -2 if there is no
 *	peer that can be used.
 */
static int
cluster_pick_owner(struct cluster_env* ce, struct module_qstate* qstate,
	int* probe)
{
	size_t it, i, n = ce->num_peers;
	long long now_ms = cluster_now_ms(qstate->env);
	uint8_t lc[LDNS_MAX_DOMAINLEN + 1];
	size_t lclen;
	uint64_t* score = (uint64_t*)regional_alloc(qstate->env->scratch,
		n*sizeof(uint64_t));
	uint8_t* skip = (uint8_t*)regional_alloc_zero(qstate->env->scratch, n);
	if(!score || !skip)
		return -2;
	lclen = cluster_lowercase_name(lc, qstate->qinfo.qname,
		qstate->qinfo.qname_len);
	for(i=0; i<n; i++)
		score[i] = cluster_hrw_score_lc(ce->node_ids[i], lc, lclen);
	/* The highest scoring node that is not down.  A down node that may
	 * be probed is used for the probe. */
	for(it=0; it<n; it++) {
		int best = -1;
		for(i=0; i<n; i++) {
			/* strictly greater, a tie goes to the lowest index */
			if(!skip[i] && (best == -1 || score[i] > score[best]))
				best = (int)i;
		}
		if(best < 0)
			break;
		if(best == ce->self)
			return -1;
		if(cluster_peer_acquire(&ce->peers[best], now_ms, probe))
			return best;
		skip[best] = 1;
	}
	return -2;
}

/** is the query one that carries client subnet, or is subnetcache in use,
 * those queries have answers that depend on the client address */
static int
cluster_has_ecs_or_subnet(struct module_qstate* qstate)
{
#ifdef CLIENT_SUBNET
	if(modstack_find(&qstate->env->mesh->mods, "subnetcache") != -1)
		return 1;
	if(edns_opt_list_find(qstate->edns_opts_front_in,
		qstate->env->cfg->client_subnet_opcode))
		return 1;
#else
	(void)qstate;
#endif
	return 0;
}

/**
 * The deadline of step 2, the resolve request: the time left until the
 * client query is discarded (arrival plus discard-timeout), so the local
 * fallback has time left to answer it; at least CLUSTER_RESOLVE_MIN, at
 * most CLUSTER_RESOLVE_MAX.  The arrival time is the start_time of the
 * client reply (mesh_reply) in the reply_list of the mesh state, the
 * earliest one if several clients are aggregated.  A state without client
 * replies (prefetch, subquery), or discard-timeout 0, gets the cap.
 * @param qstate: the query.
 * @return msec.
 */
static int
cluster_resolve_deadline_ms(struct module_qstate* qstate)
{
	int dt = qstate->env->cfg->discard_timeout;
	struct mesh_reply* r;
	struct timeval* first = NULL;
	if(dt <= 0 || !qstate->mesh_info || !qstate->mesh_info->reply_list)
		return cluster_resolve_budget(0, 0);
	for(r = qstate->mesh_info->reply_list; r; r = r->next) {
		if(!first || r->start_time.tv_sec < first->tv_sec ||
			(r->start_time.tv_sec == first->tv_sec &&
			r->start_time.tv_usec < first->tv_usec))
			first = &r->start_time;
	}
	return cluster_resolve_budget(dt, (long long)cluster_tv_diff_us(first,
		qstate->env->now_tv)/1000);
}

/**
 * Send the query of a step to the peer.  The timer and the outbound entry
 * are set up.
 * @param qstate: the query.
 * @param ce: cluster env.
 * @param cq: the per query state, with the peer set.
 * @param step: the step to start.
 * @param resend: the probe is sent again after the timeout of the outnet;
 * 	the deadline timer of the step keeps running.  Never for step 2.
 * @return false on failure, nothing was sent.  Unless resend, nothing is
 * 	left to clean up.
 */
static int
cluster_send_step(struct module_qstate* qstate, struct cluster_env* ce,
	struct cluster_qstate* cq, enum cluster_step step, int resend)
{
	struct cluster_peer* peer = &ce->peers[cq->peer];
	struct outbound_entry* e;
	struct edns_option* saved = qstate->edns_opts_back_out;
	uint8_t optdata[CLUSTER_OPT_LEN];
	uint16_t flags = BIT_RD | (qstate->query_flags & BIT_CD);
	uint8_t optflags = CLUSTER_FLAG_PEER;
	/* the probe deadline is cluster-timeout, 0 for none */
	int deadline = (step == CLUSTER_STEP_PROBE)?ce->timeout_ms:
		cluster_resolve_deadline_ms(qstate);
	int was_ratelimited = 0, ratelimit_incremented = 0;

	/* Step 2 is a UDP query that is never sent again: the answer can
	 * take as long as the owner recurses, a resend would use a new source
	 * port and could be handed to another thread of the owner, that
	 * resolves the name a second time.  The timeout of the outnet is
	 * raised above the deadline below, so the module deadline governs. */
	log_assert(!(resend && step == CLUSTER_STEP_RESOLVE));
	if(step == CLUSTER_STEP_PROBE)
		optflags |= CLUSTER_FLAG_CACHE_ONLY;
	/* a resend keeps the running deadline timer of the step */
	if(deadline > 0 && !resend) {
		struct timeval tv;
		cq->timer = comm_timer_create(qstate->env->worker_base,
			cluster_timer_cb, cq);
		if(!cq->timer)
			return 0;
#ifndef S_SPLINT_S
		tv.tv_sec = deadline/1000;
		tv.tv_usec = (deadline%1000)*1000;
#endif
		comm_timer_set(cq->timer, &tv);
	}
	if(step == CLUSTER_STEP_RESOLVE) {
		/* the timeout of the UDP query follows the RTO of the infra
		 * cache; keep it at least the deadline, so that the outnet
		 * does not time out before the module deadline */
		(void)cluster_rto_floor(qstate->env->infra_cache, &peer->addr,
			peer->addrlen, *qstate->env->now, deadline);
	}
	/* The CLUSTER option goes out with this query only.  The outnet
	 * copies the option list when the query is made, so the list on the
	 * query state is put back after the send, and the option can not
	 * reach the queries of the iterator when it resolves locally. */
	qstate->edns_opts_back_out = NULL;
	cluster_opt_encode(optdata, optflags,
		ce->self>=0?ce->peers[ce->self].node_id:0);
	if(!edns_opt_list_append(&qstate->edns_opts_back_out,
		LDNS_EDNS_UNBOUND_CLUSTER, CLUSTER_OPT_LEN, optdata,
		qstate->region)) {
		qstate->edns_opts_back_out = saved;
		goto fail;
	}
	e = (*qstate->env->send_query)(&qstate->qinfo, flags, 1, 1, 1, 0,
		&peer->addr, peer->addrlen,
		(step == CLUSTER_STEP_PROBE)?cluster_zone:cluster_zone_resolve,
		(step == CLUSTER_STEP_PROBE)?sizeof(cluster_zone):
		sizeof(cluster_zone_resolve),
		0, 0, NULL, qstate, &was_ratelimited,
		&ratelimit_incremented);
	qstate->edns_opts_back_out = saved;
	if(!e)
		goto fail;
	outbound_list_insert(&cq->outlist, e);
	cq->step = step;
	cq->pending = 1;
	cq->timed_out = 0;
	if(!resend) {
		cq->resends = 0;
		cq->step_start = *qstate->env->now_tv;
	}
	return 1;
fail:
	if(cq->timer && !resend) {
		comm_timer_delete(cq->timer);
		cq->timer = NULL;
	}
	return 0;
}

/**
 * Start the lookup at the owner, with step 1.
 * @return false on failure, nothing was sent, and the peer is released.
 */
static int
cluster_send(struct module_qstate* qstate, struct cluster_env* ce, int id,
	int peeridx, int probe)
{
	struct cluster_peer* peer = &ce->peers[peeridx];
	struct cluster_qstate* cq;
	cq = (struct cluster_qstate*)regional_alloc_zero(qstate->region,
		sizeof(*cq));
	if(!cq) {
		cluster_peer_release(peer, probe);
		return 0;
	}
	cq->qstate = qstate;
	cq->id = id;
	cq->peer = peeridx;
	cq->probe = probe;
	outbound_list_init(&cq->outlist);
	if(!cluster_send_step(qstate, ce, cq, CLUSTER_STEP_PROBE, 0)) {
		cluster_peer_release(peer, probe);
		return 0;
	}
	qstate->minfo[id] = cq;
	return 1;
}

/** the TTLs of the rrsets and the message are lowered to the cap */
static void
cluster_cap_ttl(struct reply_info* rep, time_t cap)
{
	size_t i, j;
	if(rep->ttl > cap)
		rep->ttl = cap;
	rep->prefetch_ttl = PREFETCH_TTL_CALC(rep->ttl);
	rep->serve_expired_ttl = rep->ttl + SERVE_EXPIRED_TTL;
	for(i=0; i<rep->rrset_count; i++) {
		struct packed_rrset_data* d = (struct packed_rrset_data*)
			rep->rrsets[i]->entry.data;
		size_t total = d->count + d->rrsig_count;
		if(d->ttl > cap)
			d->ttl = cap;
		for(j=0; j<total; j++)
			if(d->rr_ttl[j] > cap)
				d->rr_ttl[j] = cap;
	}
}

/** result of looking at the reply of the owner */
enum cluster_reply_result {
	/** a good answer, in the result */
	CLUSTER_REPLY_OK,
	/** the cache probe missed, REFUSED with the MISS flag */
	CLUSTER_REPLY_MISS,
	/** the peer is alive, but the answer is not usable, like servfail,
	 * or a lame answer */
	CLUSTER_REPLY_REJECT,
	/** REFUSED without the cluster option: access-control denies this
	 * node, or the peer does not run the module; a health failure */
	CLUSTER_REPLY_REFUSED,
	/** the reply is bad, like a parse failure */
	CLUSTER_REPLY_BAD
};

/**
 * See if a good rcode answer from a recursive server is lame: a referral
 * or an empty message, NOERROR without answer and without SOA for the name,
 * or an NXDOMAIN without SOA in the authority section.
 * This is the part of the iterator response classification that applies
 * to answers for RD queries (response_type_from_server, REC_LAME and LAME),
 * that function needs a delegation point that we do not have.
 */
static int
cluster_reply_is_lame(struct dns_msg* msg, struct query_info* qinfo)
{
	struct reply_info* rep = msg->rep;
	size_t i;
	if(FLAGS_GET_RCODE(rep->flags) == LDNS_RCODE_NXDOMAIN) {
		/* a negative answer needs the SOA in the authority section,
		 * for the cache and the client; the zone of the SOA is not
		 * compared, a CNAME chain can end in another zone */
		for(i=rep->an_numrrsets;
			i<rep->an_numrrsets+rep->ns_numrrsets; i++) {
			if(ntohs(rep->rrsets[i]->rk.type) == LDNS_RR_TYPE_SOA)
				return 0;
		}
		return 1;
	}
	if(rep->an_numrrsets > 0)
		return 0;
	for(i=rep->an_numrrsets; i<rep->an_numrrsets+rep->ns_numrrsets; i++) {
		struct ub_packed_rrset_key* k = rep->rrsets[i];
		if(ntohs(k->rk.type) == LDNS_RR_TYPE_SOA &&
			dname_subdomain_c(qinfo->qname, k->rk.dname))
			return 0;
	}
	/* empty, or only a delegation in the authority section */
	return 1;
}

/**
 * Process the reply packet of the owner.
 * @param qstate: the query.
 * @param ce: cluster env.
 * @param result: the message is returned here, for an OK result.
 * @param cachehit: set to true if the owner says it came from its cache.
 * @param stale: set to true if the owner says the answer was expired.
 * @param opt_seen: set to true if the reply has the cluster option.
 * @return the result code.
 */
static enum cluster_reply_result
cluster_process_reply(struct module_qstate* qstate, struct cluster_env* ce,
	struct dns_msg** result, int* cachehit, int* stale, int* opt_seen)
{
	struct msg_parse* prs;
	struct edns_data edns;
	struct sldns_buffer* pkt;
	struct dns_msg* msg;
	struct query_info qinfo_out;
	struct edns_option* co;
	struct iter_env* ie;
	int iter_id, lame_empty = 0, lame_referral = 0, rcode, has_opt = 0;
	uint8_t cflags = 0;
	uint64_t cid;

	*result = NULL;
	*cachehit = 0;
	*stale = 0;
	*opt_seen = 0;
	if(!qstate->reply)
		return CLUSTER_REPLY_BAD;
	pkt = qstate->reply->c->buffer;
	prs = (struct msg_parse*)regional_alloc_zero(qstate->env->scratch,
		sizeof(struct msg_parse));
	if(!prs) {
		log_err("out of memory on incoming message");
		return CLUSTER_REPLY_BAD;
	}
	memset(&edns, 0, sizeof(edns));
	sldns_buffer_set_position(pkt, 0);
	if(parse_packet(pkt, prs, qstate->env->scratch) != LDNS_RCODE_NOERROR) {
		verbose(VERB_ALGO, "cluster: parse error on reply packet");
		return CLUSTER_REPLY_BAD;
	}
	if(parse_extract_edns_from_response_msg(prs, &edns,
		qstate->env->scratch) != LDNS_RCODE_NOERROR) {
		verbose(VERB_ALGO, "cluster: parse error on reply edns");
		return CLUSTER_REPLY_BAD;
	}
	/* the owner tells with flags about the cache, and expired data */
	co = edns_opt_list_find(edns.opt_list_in, LDNS_EDNS_UNBOUND_CLUSTER);
	if(co && cluster_opt_decode(co, &cflags, &cid))
		has_opt = 1;
	*opt_seen = has_opt;
	if(!(prs->flags & BIT_QR) || (prs->flags & BIT_TC)) {
		verbose(VERB_ALGO, "cluster: reply is not a response, or "
			"truncated");
		return CLUSTER_REPLY_BAD;
	}
	rcode = (int)FLAGS_GET_RCODE(prs->flags);
	if(rcode == LDNS_RCODE_REFUSED) {
		if(!has_opt)
			return CLUSTER_REPLY_REFUSED;
		if(cflags & CLUSTER_FLAG_MISS)
			return CLUSTER_REPLY_MISS;
		return CLUSTER_REPLY_REJECT;
	}
	if(rcode != LDNS_RCODE_NOERROR && rcode != LDNS_RCODE_NXDOMAIN) {
		verbose(VERB_ALGO, "cluster: reply from the owner has rcode %d",
			rcode);
		return CLUSTER_REPLY_REJECT;
	}
	if(has_opt && (cflags & CLUSTER_FLAG_MISS))
		return CLUSTER_REPLY_REJECT; /* a miss is not an answer */
	/* remove the CD bit we asked for, validation is done here */
	prs->flags &= ~BIT_CD;
	/* The scrubber of the iterator is used like for a forwarder with
	 * zone ".", with the RD bit set.  It cleans the message to the
	 * rrsets that belong in the answer for the query name. */
	iter_id = modstack_find(&qstate->env->mesh->mods, "iterator");
	if(iter_id < 0) {
		log_err("cluster: no iterator module");
		return CLUSTER_REPLY_BAD;
	}
	ie = (struct iter_env*)qstate->env->modinfo[iter_id];
	qinfo_out = qstate->qinfo;
	qinfo_out.local_alias = NULL;
	if(!scrub_message(pkt, prs, &qinfo_out, cluster_zone,
		qstate->env->scratch, qstate->env, qstate, ie, &lame_empty,
		&lame_referral, 1))
		return CLUSTER_REPLY_BAD;
	msg = dns_alloc_msg(pkt, prs, qstate->region);
	if(!msg)
		return CLUSTER_REPLY_BAD;
	/* it has to be the answer to the question */
	if(msg->qinfo.qtype != qstate->qinfo.qtype ||
		msg->qinfo.qclass != qstate->qinfo.qclass ||
		query_dname_compare(msg->qinfo.qname, qstate->qinfo.qname)
		!= 0) {
		verbose(VERB_ALGO, "cluster: reply for a different question");
		return CLUSTER_REPLY_BAD;
	}
	/* a referral or empty answer from a peer that is not able to
	 * resolve for us, like a lame server for the iterator */
	if(cluster_reply_is_lame(msg, &qstate->qinfo)) {
		verbose(VERB_ALGO, "cluster: lame reply from the owner, "
			"referral or empty without SOA");
		return CLUSTER_REPLY_REJECT;
	}
	if(verbosity >= VERB_ALGO)
		log_dns_msg("cluster: incoming scrubbed packet:", &msg->qinfo,
			msg->rep);
	if(qstate->env->cfg->aggressive_nsec)
		limit_nsec_ttl(msg);
	/* the names of this answer are not owned by this node, it is a
	 * copy that is allowed to be of limited lifetime */
	if(ce->local_ttl_max > 0)
		cluster_cap_ttl(msg->rep, (time_t)ce->local_ttl_max);
	msg->rep->flags |= BIT_RA;
	msg->rep->flags &= ~(BIT_AA | BIT_AD);
	if(has_opt) {
		*cachehit = (cflags & CLUSTER_FLAG_OWNER_CACHE_HIT)?1:0;
		*stale = (cflags & CLUSTER_FLAG_STALE)?1:0;
	}
	*result = msg;
	return CLUSTER_REPLY_OK;
}

/** a failure of the owner, resolve locally */
static void
cluster_fallback(struct module_qstate* qstate, struct cluster_env* ce, int id)
{
	cluster_mystats(ce, qstate->env)->fallback++;
	qstate->ext_state[id] = module_wait_module;
}

/**
 * The local fallback after a failure of step 2 of the owner is done
 * (module_event_moddone, the module below finished); paired attribution.
 * If it ended in an answer (NOERROR or NXDOMAIN) within
 * CLUSTER_FAST_FALLBACK msec, the failure is charged to the owner: a
 * local resolution can do what the owner could not.  A slow fallback or
 * a failure is no charge: the upstream is slow or broken for everyone.
 * It runs after the module below has finished, in the same event that
 * delivers the reply to the client, and costs a peer lock.
 */
static void
cluster_fallback_done(struct module_qstate* qstate, struct cluster_env* ce,
	struct cluster_qstate* cq)
{
	struct cluster_peer* peer = &ce->peers[cq->peer];
	int ok = 0;
	int32_t elapsed_us = cluster_tv_diff_us(&cq->fb_start,
		qstate->env->now_tv);
	cq->fb_pending = 0;
	if(qstate->return_rcode == LDNS_RCODE_NOERROR && qstate->return_msg &&
		qstate->return_msg->rep) {
		int rc = (int)FLAGS_GET_RCODE(qstate->return_msg->rep->flags);
		ok = (rc == LDNS_RCODE_NOERROR || rc == LDNS_RCODE_NXDOMAIN);
	}
	if(ok && elapsed_us <= CLUSTER_FAST_FALLBACK*1000) {
		cluster_mystats(ce, qstate->env)->charged++;
		cluster_res_result(ce, peer, RES_CHARGED, cq->trial,
			cq->trial_gen, qstate->env);
	} else {
		cluster_res_result(ce, peer, RES_NEUTRAL, cq->trial,
			cq->trial_gen, qstate->env);
	}
	cq->trial = 0;
}

/** the reply of the owner, or the failure of the query to the owner */
static void
cluster_handle_reply(struct module_qstate* qstate, struct cluster_env* ce,
	struct cluster_qstate* cq, enum module_ev event, int id,
	struct outbound_entry* outbound)
{
	struct cluster_stats* st = cluster_mystats(ce, qstate->env);
	struct cluster_peer* peer = &ce->peers[cq->peer];
	struct dns_msg* msg = NULL;
	enum cluster_reply_result res = CLUSTER_REPLY_BAD;
	enum cluster_step step = cq->step;
	int probe = cq->probe, cachehit = 0, stale = 0, has_opt = 0;

	/* The outnet gave up on the cache probe after the UDP timeout that
	 * infra learned from earlier replies of the peer (the RTO, at least
	 * 50 msec), that can be shorter than the deadline of the probe.  The
	 * wait is governed by the module deadline, so while that has not
	 * passed, the probe is sent again.  Step 2 is never sent again: its
	 * outnet timeout is at least the module deadline (cluster_rto_floor),
	 * and a resend would use another source port, and the owner could
	 * hand it to another thread that starts a second resolution while the
	 * first answer goes to a closed port.  A timeout or error of the
	 * outnet in step 2 (a lost packet) is a failure of step 2: local
	 * fallback, no health change. */
	if(event == module_event_noreply && step == CLUSTER_STEP_PROBE &&
		!cq->timed_out && cq->timer &&
		cq->resends < CLUSTER_PROBE_RESENDS) {
		verbose(VERB_ALGO, "cluster: outbound timeout before the "
			"deadline, sending the probe again");
		if(outbound)
			outbound_list_remove(&cq->outlist, outbound);
		outbound_list_clear(&cq->outlist);
		cq->pending = 0;
		if(cluster_send_step(qstate, ce, cq, step, 1)) {
			cq->resends++;
			qstate->ext_state[id] = module_wait_reply;
			return;
		}
		/* could not send, give up as for any other error; the
		 * entry was removed above */
		outbound = NULL;
	}
	if(event == module_event_reply)
		res = cluster_process_reply(qstate, ce, &msg, &cachehit,
			&stale, &has_opt);
	if(step == CLUSTER_STEP_PROBE) {
		/* the round trip time of the probe, shown in cluster_status:
		 * samples are the valid replies of queries that were not
		 * sent again (Karn) */
		if(event == module_event_reply && cq->resends == 0 &&
			(res == CLUSTER_REPLY_OK || res == CLUSTER_REPLY_MISS
			|| res == CLUSTER_REPLY_REJECT))
			cluster_peer_rtt_sample(peer, cluster_tv_diff_us(
				&cq->step_start, qstate->env->now_tv));
	}
	/* From here the query to the owner is over; the timer and the
	 * entry are removed, so that no late event can arrive. */
	cluster_stop_waiting(cq, outbound);
	cq->pending = 0;
	if(step == CLUSTER_STEP_PROBE)
		cq->probe = 0; /* the slot is released by the report below */
	if(res == CLUSTER_REPLY_OK) {
		if(step == CLUSTER_STEP_PROBE && !has_opt)
			cluster_note_noopt(peer);
		st->answered++;
		if(cachehit)
			st->answered_cachehit++;
		cluster_peer_report(ce, peer, PEER_ANSWERED, probe,
			step == CLUSTER_STEP_PROBE, qstate->env);
		if(step == CLUSTER_STEP_RESOLVE) {
			cluster_res_result(ce, peer, RES_SUCCESS, cq->trial,
				cq->trial_gen, qstate->env);
			cq->trial = 0;
		}
		if(stale) {
			/* An expired answer of the owner is used for this
			 * client but not stored, here and in the validator
			 * above, that looks at no_cache_store.  It is reset
			 * in clear, when the validator restarts the query. */
			if(!qstate->no_cache_store) {
				qstate->no_cache_store = 1;
				cq->set_no_store = 1;
			}
		}
		/* The message is stored here for the local cache, like the
		 * iterator does for its answers.  A validator before this
		 * module validates the message and stores it again with the
		 * security status.  For queries that the validator does not
		 * store (validation recursion) this is the only store. */
		if(!qstate->no_cache_store && (qstate->query_flags&BIT_RD)) {
			if(!dns_cache_store(qstate->env, &msg->qinfo, msg->rep,
				0, qstate->prefetch_leeway, 0, qstate->region,
				qstate->query_flags, qstate->qstarttime,
				qstate->is_valrec))
				log_err("out of memory storing cluster answer");
		}
		qstate->return_rcode = LDNS_RCODE_NOERROR;
		qstate->return_msg = msg;
		qstate->ext_state[id] = module_finished;
		return;
	}
	if(res == CLUSTER_REPLY_MISS && step == CLUSTER_STEP_PROBE) {
		/* the owner is alive and has nothing, ask it to resolve */
		st->probe_miss++;
		cluster_peer_report(ce, peer, PEER_MISS, probe, 1,
			qstate->env);
		/* a resolve-ejected owner is not asked to resolve, except
		 * for the trial request after the ejection time */
		if(!cluster_res_gate(ce, peer, cluster_now_ms(qstate->env),
			&cq->trial, &cq->trial_gen)) {
			verbose(VERB_ALGO, "cluster: owner cache miss, the "
				"owner is resolve-ejected, resolving locally");
			st->resolve_ejected++;
			cluster_fallback(qstate, ce, id);
			return;
		}
		verbose(VERB_ALGO, "cluster: owner cache miss, asking the "
			"owner to resolve%s", cq->trial?" (trial)":"");
		if(cluster_send_step(qstate, ce, cq, CLUSTER_STEP_RESOLVE, 0)) {
			qstate->ext_state[id] = module_wait_reply;
			return;
		}
		if(cq->trial) {
			cluster_res_result(ce, peer, RES_NEUTRAL, 1,
				cq->trial_gen, qstate->env);
			cq->trial = 0;
		}
		st->failed++;
		cluster_fallback(qstate, ce, id);
		return;
	}
	st->failed++;
	if(event != module_event_reply) {
		if(step == CLUSTER_STEP_RESOLVE) {
			/* the owner may be busy recursing, only the probe
			 * decides about the health of the peer */
			if(cq->timed_out)
				st->resolve_timeout++;
			cluster_peer_report(ce, peer, PEER_STEP2_FAILED, 0, 0,
				qstate->env);
		} else {
			if(cq->timed_out)
				st->timeout++;
			cluster_peer_report(ce, peer, PEER_FAILED, probe, 1,
				qstate->env);
		}
	} else if(res == CLUSTER_REPLY_REJECT || res == CLUSTER_REPLY_MISS) {
		/* a valid reply of the peer, it is alive */
		cluster_peer_report(ce, peer, PEER_REJECTED, probe,
			step == CLUSTER_STEP_PROBE, qstate->env);
	} else if(step == CLUSTER_STEP_RESOLVE) {
		cluster_peer_report(ce, peer, PEER_STEP2_FAILED, 0, 0,
			qstate->env);
	} else {
		if(res == CLUSTER_REPLY_REFUSED)
			cluster_note_refused(peer);
		cluster_peer_report(ce, peer, PEER_FAILED, probe, 1,
			qstate->env);
	}
	if(step == CLUSTER_STEP_RESOLVE) {
		/* The owner failed the resolve request.  Whether that is
		 * charged to the owner is decided when the local fallback
		 * is done, see cluster_fallback_done. */
		cq->fb_pending = 1;
		cq->fb_start = *qstate->env->now_tv;
	}
	cluster_fallback(qstate, ce, id);
}

/**
 * A cache only probe from a peer that missed in the cache of the worker:
 * answer REFUSED, the option with the MISS flag is added by the reply
 * callback.  The query never goes on to the iterator.
 */
static void
cluster_answer_miss(struct module_qstate* qstate, struct cluster_env* ce,
	int id)
{
	cluster_mystats(ce, qstate->env)->served_probe_miss++;
	verbose(VERB_ALGO, "cluster: cache only peer query, miss");
	qstate->return_rcode = LDNS_RCODE_REFUSED;
	qstate->return_msg = NULL;
	qstate->ext_state[id] = module_finished;
}

/** a new query or a pass: route it or pass it on */
static void
cluster_handle_query(struct module_qstate* qstate, struct cluster_env* ce,
	int id)
{
	struct cluster_stats* st;
	int owner, probe = 0, pc, sp = 0;
	if(cluster_in_libunbound(qstate)) {
		qstate->ext_state[id] = module_wait_module;
		return;
	}
	pc = cluster_edns_peer_check(qstate->edns_opts_front_in);
	if(pc != 1 && qstate->mesh_info->super_set.count != 0) {
		sp = cluster_super_is_peer(qstate->mesh_info,
			CLUSTER_SUPER_DEPTH);
		if(sp == 2 && !qstate->is_valrec) {
			/* A subquery of a cache only probe, like the A query
			 * of dns64 for the AAAA probe, is not resolved either.
			 * Validation lookups (is_valrec) of an answer that a
			 * module above found, like cachedb, may resolve. */
			cluster_answer_miss(qstate, ce, id);
			return;
		}
	}
	if(pc == 1) {
		/* A peer query.  A cache only probe has missed the cache of
		 * the worker (and the modules above), it is not resolved. */
		struct edns_option* o = edns_opt_list_find(
			qstate->edns_opts_front_in, LDNS_EDNS_UNBOUND_CLUSTER);
		uint8_t flags = 0;
		uint64_t nid;
		if(o && cluster_opt_decode(o, &flags, &nid) &&
			(flags & CLUSTER_FLAG_CACHE_ONLY)) {
			cluster_answer_miss(qstate, ce, id);
			return;
		}
	}
	if(ce->num_peers == 0) {
		qstate->ext_state[id] = module_wait_module;
		return;
	}
	st = cluster_mystats(ce, qstate->env);
	qstate->ext_state[id] = module_wait_module; /* the default */
	if(qstate->is_priming || !(qstate->query_flags&BIT_RD) ||
		qstate->qinfo.qclass != LDNS_RR_CLASS_IN) {
		st->excluded++;
		return;
	}
	if(pc == 1) {
		/* a peer query, resolved locally and never forwarded */
		st->served++;
		return;
	}
	if(pc == -1) {
		/* an option we do not understand, like a newer version,
		 * this is handled as a plain client query */
		st->version_mismatch++;
	}
	/* With a blacklist, the validator found the answer bogus and
	 * restarted the query, or the query is part of such a chain of
	 * trust fetch.  The answer of the owner is not used again, the
	 * query is resolved locally like the iterator skips its cache. */
	if(qstate->blacklist || sp ||
		cluster_has_ecs_or_subnet(qstate) ||
		cluster_is_excluded(ce, qstate->qinfo.qname)) {
		st->excluded++;
		return;
	}
	owner = cluster_pick_owner(ce, qstate, &probe);
	if(owner == -1) {
		st->self++;
		return;
	}
	if(owner < 0) {
		st->nolive++;
		return;
	}
	if(!cluster_send(qstate, ce, id, owner, probe)) {
		log_err("cluster: could not send the query to the owner");
		return;
	}
	st->routed++;
	verbose(VERB_ALGO, "cluster: sent query to the owner %s",
		ce->peers[owner].str);
	qstate->ext_state[id] = module_wait_reply;
}

void
cluster_operate(struct module_qstate* qstate, enum module_ev event, int id,
	struct outbound_entry* outbound)
{
	struct cluster_env* ce = (struct cluster_env*)qstate->env->modinfo[id];
	struct cluster_qstate* cq = (struct cluster_qstate*)qstate->minfo[id];
	verbose(VERB_QUERY, "cluster[module %d] operate: extstate:%s "
		"event:%s", id, strextstate(qstate->ext_state[id]),
		strmodulevent(event));

	if(event == module_event_new || event == module_event_pass) {
		if(cq && cq->pending) {
			/* still waiting for the owner */
			qstate->ext_state[id] = module_wait_reply;
			return;
		}
		if(cq && cq->fb_pending) {
			/* the query is passed to this module again before
			 * the fallback is done, no verdict */
			cq->fb_pending = 0;
			if(cq->trial)
				cluster_res_result(ce, &ce->peers[cq->peer],
					RES_NEUTRAL, 1, cq->trial_gen,
					qstate->env);
			cq->trial = 0;
		}
		cluster_handle_query(qstate, ce, id);
		return;
	}
	if(event == module_event_reply || event == module_event_noreply ||
		event == module_event_capsfail) {
		if(!cq || !cq->pending) {
			/* not waiting for a reply, nothing to do with it */
			log_err("cluster: unexpected reply event");
			if(cq)
				cluster_stop_waiting(cq, outbound);
			cluster_error_response(qstate, id, LDNS_RCODE_SERVFAIL);
			return;
		}
		cluster_handle_reply(qstate, ce, cq, event, id, outbound);
		return;
	}
	if(event == module_event_moddone) {
		/* the next module is done, we are done too.  This is also
		 * how the answer to a subquery of the iterator, that does not
		 * pass this module, is returned up. */
		if(cq && cq->fb_pending)
			cluster_fallback_done(qstate, ce, cq);
		qstate->ext_state[id] = module_finished;
		return;
	}
	if(event == module_event_error) {
		verbose(VERB_ALGO, "got called with event error, giving up");
		cluster_error_response(qstate, id, LDNS_RCODE_SERVFAIL);
		return;
	}
	log_err("bad event for cluster");
	cluster_error_response(qstate, id, LDNS_RCODE_SERVFAIL);
}

void
cluster_inform_super(struct module_qstate* ATTR_UNUSED(qstate),
	int ATTR_UNUSED(id), struct module_qstate* ATTR_UNUSED(super))
{
	/* cluster does not use subordinate requests at this time */
	verbose(VERB_ALGO, "cluster inform_super was called");
}

/* ---- owner side ---- */

int
cluster_inplace_reply(struct query_info* ATTR_UNUSED(qinfo),
	struct module_qstate* qstate, struct reply_info* rep, int rcode,
	struct edns_data* edns, struct edns_option** opt_list_out,
	struct comm_reply* repinfo, struct regional* region,
	struct timeval* start_time, int ATTR_UNUSED(id), void* callback)
{
	struct cluster_env* ce = (struct cluster_env*)callback;
	uint8_t optdata[CLUSTER_OPT_LEN];
	uint8_t qflags = 0, flags = CLUSTER_FLAG_PEER;
	uint64_t nid;
	struct edns_option* o;
	/* The cache reply has no query state, but has the query options in
	 * the edns data.  The other replies have the query state. */
	struct edns_option* in = qstate?qstate->edns_opts_front_in:
		edns->opt_list_in;
	/* the hot path for all replies: no options, no work */
	if(!in || !ce || !edns->edns_present)
		return 1;
	o = edns_opt_list_find(in, LDNS_EDNS_UNBOUND_CLUSTER);
	if(!o || !cluster_opt_decode(o, &qflags, &nid) ||
		!(qflags & CLUSTER_FLAG_PEER))
		return 1;
	/* only the peers get the echo, for the others the answer is that of
	 * a normal client query; the mesh removes the option of their
	 * queries in cluster_mesh_unique */
	if(repinfo && !cluster_addr_is_peer(ce, &repinfo->client_addr,
		repinfo->client_addrlen))
		return 1;
	if(!qstate) {
		/* from the msg cache of the worker.  start_time is the
		 * current time here, and the ttl of the entry is absolute. */
		flags |= CLUSTER_FLAG_OWNER_CACHE_HIT;
		if(rep && start_time && TTL_IS_EXPIRED(rep->ttl,
			start_time->tv_sec))
			flags |= CLUSTER_FLAG_STALE;
	} else if(rep) {
		/* The answer of the mesh state is the return_msg of the
		 * state.  The serve-expired reply is another message, from
		 * the cache with the expired data, for the waiting client. */
		if(!qstate->return_msg || qstate->return_msg->rep != rep)
			flags |= CLUSTER_FLAG_STALE;
	} else if(rcode == LDNS_RCODE_REFUSED &&
		(qflags & CLUSTER_FLAG_CACHE_ONLY)) {
		/* the cache only probe, answered by cluster_answer_miss */
		flags |= CLUSTER_FLAG_MISS;
	}
	cluster_opt_encode(optdata, flags,
		ce->self>=0?ce->peers[ce->self].node_id:0);
	/* if it fails there is no echo, that is tolerated */
	(void)edns_opt_list_append(opt_list_out, LDNS_EDNS_UNBOUND_CLUSTER,
		CLUSTER_OPT_LEN, optdata, region);
	return 1;
}

/** marker for the mesh states of recursive queries of peers, only the
 * address is used */
static char cluster_peer_sentinel;
/** marker for the mesh states of cache only queries of peers */
static char cluster_cacheonly_sentinel;

void*
cluster_peer_kind(struct edns_option* opt_list)
{
	struct edns_option* o;
	uint8_t flags;
	uint64_t nid;
	if(!opt_list)
		return NULL;
	o = edns_opt_list_find(opt_list, LDNS_EDNS_UNBOUND_CLUSTER);
	if(!o || !cluster_opt_decode(o, &flags, &nid) ||
		!(flags & CLUSTER_FLAG_PEER))
		return NULL;
	if(flags & CLUSTER_FLAG_CACHE_ONLY)
		return &cluster_cacheonly_sentinel;
	return &cluster_peer_sentinel;
}

void*
cluster_mesh_unique(struct mesh_area* mesh, struct edns_data* edns,
	struct comm_reply* rep)
{
	struct cluster_env* ce;
	if(!edns->opt_list_in || !edns_opt_list_find(edns->opt_list_in,
		LDNS_EDNS_UNBOUND_CLUSTER))
		return NULL; /* the normal client query, no work */
	ce = cluster_env_find(&mesh->mods, mesh->env);
	if(!ce)
		return NULL; /* no cluster module, an unknown option */
	if(!rep || !cluster_addr_is_peer(ce, &rep->client_addr,
		rep->client_addrlen)) {
		/* not from a peer, a normal client query; without the
		 * option it is not a peer query for the cluster module */
		(void)edns_opt_list_remove(&edns->opt_list_in,
			LDNS_EDNS_UNBOUND_CLUSTER);
		return NULL;
	}
	return cluster_peer_kind(edns->opt_list_in);
}

size_t
cluster_get_mem(struct module_env* env, int id)
{
	struct cluster_env* ce = (struct cluster_env*)env->modinfo[id];
	size_t s, i;
	struct cluster_exclude* e;
	if(!ce)
		return 0;
	s = sizeof(*ce) + ce->num_peers*(sizeof(struct cluster_peer) +
		sizeof(uint64_t)) + 2*(size_t)ce->num_stats*sizeof(*ce->stats);
	for(i=0; i<ce->num_peers; i++)
		s += ce->peers[i].str?strlen(ce->peers[i].str)+1:0;
	for(e = ce->excludes; e; e = e->next)
		s += sizeof(*e) + e->namelen;
	return s;
}

/**
 * The cluster function block
 */
static struct module_func_block cluster_block = {
	"cluster",
	NULL, NULL, &cluster_init, &cluster_deinit, &cluster_operate,
	&cluster_inform_super, &cluster_clear, &cluster_get_mem
};

struct module_func_block*
cluster_get_funcblock(void)
{
	return &cluster_block;
}
#endif /* USE_CLUSTER */
