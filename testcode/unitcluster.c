/*
 * testcode/unitcluster.c - unit test for the cluster module routing.
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
 *
 */
/**
 * \file
 * Unit tests for the cluster module: rendezvous hashing and the option.
 */

#include "config.h"
#ifdef USE_CLUSTER
#include "util/log.h"
#include "testcode/unitmain.h"
#include "cluster/cluster.h"
#include "util/net_help.h"
#include "util/data/msgparse.h"
#include "sldns/str2wire.h"
#include "sldns/rrdef.h"
#include "services/cache/infra.h"
#include "util/config_file.h"
#include "util/rtt.h"
#include "iterator/iterator.h"

/** number of nodes in the evenness test */
#define NUM_NODES 40
/** number of names in the evenness test */
#define NUM_NAMES 100000

/** make wireformat name for number */
static size_t
mkname(uint8_t* buf, size_t buflen, int i, int upper)
{
	char str[100];
	size_t len = buflen;
	uint8_t* w;
	snprintf(str, sizeof(str), upper?"Host%d.EXAMPLE.com.":"host%d.example.com.", i);
	w = sldns_str2wire_dname(str, &len);
	unit_assert(w);
	memcpy(buf, w, len);
	free(w);
	return len;
}

/** make a node id from a number */
static uint64_t
mknode(int i)
{
	struct sockaddr_storage addr;
	socklen_t addrlen;
	char str[64];
	snprintf(str, sizeof(str), "10.0.%d.%d", i/200, i%200+1);
	unit_assert(extstrtoaddr(str, &addr, &addrlen, 53));
	return cluster_node_id(&addr, addrlen);
}

/** test the node id */
static void
node_id_test(void)
{
	struct sockaddr_storage a, b, c;
	socklen_t al, bl, cl;
	unit_assert(extstrtoaddr("10.0.0.1", &a, &al, 53));
	unit_assert(extstrtoaddr("10.0.0.1@53", &b, &bl, 99));
	unit_assert(extstrtoaddr("10.0.0.1@54", &c, &cl, 53));
	/* independent of the spelling, depends on address and port */
	unit_assert(cluster_node_id(&a, al) == cluster_node_id(&b, bl));
	unit_assert(cluster_node_id(&a, al) != cluster_node_id(&c, cl));
	unit_assert(extstrtoaddr("2001:db8::1", &a, &al, 53));
	unit_assert(extstrtoaddr("2001:0db8:0:0:0:0:0:1@53", &b, &bl, 99));
	unit_assert(cluster_node_id(&a, al) == cluster_node_id(&b, bl));
}

/** stability and case insensitivity */
static void
stability_test(void)
{
	uint64_t ids[NUM_NODES];
	uint8_t n1[300], n2[300];
	int i, j;
	for(i=0; i<NUM_NODES; i++)
		ids[i] = mknode(i);
	for(i=0; i<1000; i++) {
		size_t l1 = mkname(n1, sizeof(n1), i, 0);
		size_t l2 = mkname(n2, sizeof(n2), i, 1);
		int o = cluster_hrw_select(ids, NUM_NODES, n1, l1, NULL);
		unit_assert(o >= 0 && o < NUM_NODES);
		for(j=0; j<3; j++)
			unit_assert(cluster_hrw_select(ids, NUM_NODES, n1, l1,
				NULL) == o);
		/* the same name in other case has the same owner */
		unit_assert(cluster_hrw_select(ids, NUM_NODES, n2, l2, NULL)
			== o);
	}
	/* the order of the nodes does not change the owner */
	{
		uint64_t rev[NUM_NODES];
		for(i=0; i<NUM_NODES; i++)
			rev[i] = ids[NUM_NODES-1-i];
		for(i=0; i<1000; i++) {
			size_t l1 = mkname(n1, sizeof(n1), i, 0);
			int o = cluster_hrw_select(ids, NUM_NODES, n1, l1,
				NULL);
			int r = cluster_hrw_select(rev, NUM_NODES, n1, l1,
				NULL);
			unit_assert(rev[r] == ids[o]);
		}
	}
	/* no nodes, no owner */
	unit_assert(cluster_hrw_select(ids, 0, n1, mkname(n1, sizeof(n1), 0,
		0), NULL) == -1);
}

/** the spread of the names over the nodes is even */
static void
evenness_test(void)
{
	uint64_t ids[NUM_NODES];
	int count[NUM_NODES];
	uint8_t nm[300];
	int i;
	int mean = NUM_NAMES/NUM_NODES;
	for(i=0; i<NUM_NODES; i++) {
		ids[i] = mknode(i);
		count[i] = 0;
	}
	for(i=0; i<NUM_NAMES; i++) {
		size_t l = mkname(nm, sizeof(nm), i, 0);
		count[cluster_hrw_select(ids, NUM_NODES, nm, l, NULL)]++;
	}
	for(i=0; i<NUM_NODES; i++) {
		/* within 15 percent of the mean */
		unit_assert(count[i] > mean - mean*15/100);
		unit_assert(count[i] < mean + mean*15/100);
	}
}

/** removal of a node moves only the names of that node */
static void
remap_test(void)
{
	uint64_t ids[NUM_NODES], less[NUM_NODES-1];
	uint8_t nm[300];
	int removed = 17, i, moved = 0, owned = 0;
	for(i=0; i<NUM_NODES; i++)
		ids[i] = mknode(i);
	for(i=0; i<NUM_NODES-1; i++)
		less[i] = ids[i<removed?i:i+1];
	for(i=0; i<NUM_NAMES; i++) {
		size_t l = mkname(nm, sizeof(nm), i, 0);
		int o = cluster_hrw_select(ids, NUM_NODES, nm, l, NULL);
		int n = cluster_hrw_select(less, NUM_NODES-1, nm, l, NULL);
		if(o == removed) {
			owned++;
			moved++;
			unit_assert(less[n] != ids[removed]);
		} else {
			/* the others stay where they are */
			unit_assert(less[n] == ids[o]);
		}
		/* skipping the node has the same effect as removing it */
		{
			uint8_t skip[NUM_NODES];
			int s;
			memset(skip, 0, sizeof(skip));
			skip[removed] = 1;
			s = cluster_hrw_select(ids, NUM_NODES, nm, l, skip);
			unit_assert(s != removed);
			unit_assert(ids[s] == less[n]);
		}
	}
	unit_assert(moved == owned);
	/* about one in 40 of the names moved, and only those */
	unit_assert(moved > NUM_NAMES/NUM_NODES*85/100);
	unit_assert(moved < NUM_NAMES/NUM_NODES*115/100);
}

/** ties go to the lowest index */
static void
tie_test(void)
{
	uint64_t ids[3];
	uint8_t nm[300];
	size_t l = mkname(nm, sizeof(nm), 1, 0);
	ids[0] = ids[1] = ids[2] = 12345;
	unit_assert(cluster_hrw_select(ids, 3, nm, l, NULL) == 0);
}

/** the option */
static void
option_test(void)
{
	uint8_t buf[CLUSTER_OPT_LEN];
	struct edns_option opt;
	uint8_t flags = 0;
	uint64_t id = 0;
	memset(&opt, 0, sizeof(opt));
	opt.opt_code = LDNS_EDNS_UNBOUND_CLUSTER;
	opt.opt_len = CLUSTER_OPT_LEN;
	opt.opt_data = buf;
	cluster_opt_encode(buf, CLUSTER_FLAG_PEER, 0x0102030405060708ULL);
	unit_assert(buf[0] == 1 && buf[1] == 1 && buf[2] == 1 && buf[9] == 8);
	unit_assert(cluster_opt_decode(&opt, &flags, &id));
	unit_assert(flags == CLUSTER_FLAG_PEER);
	unit_assert(id == 0x0102030405060708ULL);
	unit_assert(cluster_edns_peer_check(&opt) == 1);
	unit_assert(cluster_edns_peer_check(NULL) == 0);
	/* unknown version */
	buf[0] = 2;
	unit_assert(!cluster_opt_decode(&opt, &flags, &id));
	unit_assert(cluster_edns_peer_check(&opt) == -1);
	buf[0] = 1;
	/* wrong length */
	opt.opt_len = 4;
	unit_assert(!cluster_opt_decode(&opt, &flags, &id));
	unit_assert(cluster_edns_peer_check(&opt) == -1);
	opt.opt_len = CLUSTER_OPT_LEN;
	/* no peer flag */
	cluster_opt_encode(buf, CLUSTER_FLAG_OWNER_CACHE_HIT, 5);
	unit_assert(cluster_edns_peer_check(&opt) == -1);
	/* another option is not a cluster option */
	opt.opt_code = LDNS_EDNS_NSID;
	unit_assert(cluster_edns_peer_check(&opt) == 0);
}

/** the mesh marker for the kinds of peer queries */
static void
unique_test(void)
{
	uint8_t buf[CLUSTER_OPT_LEN];
	struct edns_option opt;
	void *peer, *probe;
	memset(&opt, 0, sizeof(opt));
	opt.opt_code = LDNS_EDNS_UNBOUND_CLUSTER;
	opt.opt_len = CLUSTER_OPT_LEN;
	opt.opt_data = buf;
	unit_assert(cluster_peer_kind(NULL) == NULL);
	cluster_opt_encode(buf, CLUSTER_FLAG_PEER, 1);
	peer = cluster_peer_kind(&opt);
	unit_assert(peer != NULL);
	cluster_opt_encode(buf, CLUSTER_FLAG_PEER|CLUSTER_FLAG_CACHE_ONLY, 1);
	probe = cluster_peer_kind(&opt);
	unit_assert(probe != NULL && probe != peer);
	/* the node id does not matter */
	cluster_opt_encode(buf, CLUSTER_FLAG_PEER|CLUSTER_FLAG_CACHE_ONLY, 7);
	unit_assert(cluster_peer_kind(&opt) == probe);
	/* a option that is not understood is a normal query */
	cluster_opt_encode(buf, CLUSTER_FLAG_CACHE_ONLY, 1);
	unit_assert(cluster_peer_kind(&opt) == NULL);
	cluster_opt_encode(buf, CLUSTER_FLAG_PEER, 1);
	buf[0] = 2;
	unit_assert(cluster_peer_kind(&opt) == NULL);
	/* all reply flags together */
	buf[0] = 1;
	cluster_opt_encode(buf, CLUSTER_FLAG_PEER|CLUSTER_FLAG_MISS|
		CLUSTER_FLAG_STALE|CLUSTER_FLAG_OWNER_CACHE_HIT, 1);
	unit_assert(buf[1] == 0x1d);
}

/** the check of the source address of peer queries */
static void
peer_addr_test(void)
{
	struct cluster_env ce;
	struct cluster_peer peers[2];
	struct sockaddr_storage a;
	socklen_t alen;
	memset(&ce, 0, sizeof(ce));
	memset(peers, 0, sizeof(peers));
	unit_assert(extstrtoaddr("10.0.0.1@53", &peers[0].addr,
		&peers[0].addrlen, 53));
	unit_assert(extstrtoaddr("fe80::1@5353", &peers[1].addr,
		&peers[1].addrlen, 53));
	ce.peers = peers;
	ce.num_peers = 2;
	/* the port does not matter, the queries come from a random port */
	unit_assert(extstrtoaddr("10.0.0.1@41234", &a, &alen, 53));
	unit_assert(cluster_addr_is_peer(&ce, &a, alen));
	unit_assert(extstrtoaddr("fe80::1", &a, &alen, 53));
	unit_assert(cluster_addr_is_peer(&ce, &a, alen));
	unit_assert(extstrtoaddr("10.0.0.2@53", &a, &alen, 53));
	unit_assert(!cluster_addr_is_peer(&ce, &a, alen));
	unit_assert(extstrtoaddr("fe80::2", &a, &alen, 53));
	unit_assert(!cluster_addr_is_peer(&ce, &a, alen));
	ce.num_peers = 0;
	unit_assert(extstrtoaddr("10.0.0.1", &a, &alen, 53));
	unit_assert(!cluster_addr_is_peer(&ce, &a, alen));
}

/** local address matching for the detection of the own position */
static void
local_match_test(void)
{
	struct cluster_peer peers[3];
	struct sockaddr_storage loc[3];
	socklen_t ll[3];
	int found = -1;
	memset(peers, 0, sizeof(peers));
	unit_assert(extstrtoaddr("10.0.0.1@53", &peers[0].addr,
		&peers[0].addrlen, 53));
	unit_assert(extstrtoaddr("10.0.0.2@53", &peers[1].addr,
		&peers[1].addrlen, 53));
	unit_assert(extstrtoaddr("2001:db8::3@53", &peers[2].addr,
		&peers[2].addrlen, 53));
	/* exactly one; the port of the local address is ignored */
	unit_assert(extstrtoaddr("10.0.0.2@9999", &loc[0], &ll[0], 53));
	unit_assert(extstrtoaddr("192.0.2.1", &loc[1], &ll[1], 53));
	unit_assert(cluster_match_local_addrs(peers, 3, loc, ll, 2, 53,
		&found) == 1 && found == 1);
	/* none */
	unit_assert(cluster_match_local_addrs(peers, 3, loc+1, ll+1, 1, 53,
		&found) == 0);
	unit_assert(cluster_match_local_addrs(peers, 3, loc, ll, 0, 53,
		&found) == 0);
	/* multiple */
	unit_assert(extstrtoaddr("10.0.0.1", &loc[1], &ll[1], 53));
	unit_assert(cluster_match_local_addrs(peers, 3, loc, ll, 2, 53,
		&found) == 2);
	/* a peer is counted once, also with two local matches */
	unit_assert(extstrtoaddr("10.0.0.1", &loc[2], &ll[2], 53));
	unit_assert(cluster_match_local_addrs(peers, 3, loc+1, ll+1, 2, 53,
		&found) == 1 && found == 0);
	/* port mismatch */
	unit_assert(cluster_match_local_addrs(peers, 3, loc, ll, 2, 5353,
		&found) == 0);
	/* v6, and v4 does not match v6 */
	unit_assert(extstrtoaddr("2001:db8::3", &loc[0], &ll[0], 53));
	unit_assert(cluster_match_local_addrs(peers, 3, loc, ll, 1, 53,
		&found) == 1 && found == 2);
	unit_assert(extstrtoaddr("2001:db8::4", &loc[0], &ll[0], 53));
	unit_assert(cluster_match_local_addrs(peers, 3, loc, ll, 1, 53,
		&found) == 0);
}

/** the ranking for the cluster_lookup command, and the stats snapshots */
static void
rank_test(void)
{
	struct cluster_env ce;
	uint64_t ids[NUM_NODES], scores[NUM_NODES];
	size_t order[NUM_NODES];
	uint8_t nm[LDNS_MAX_DOMAINLEN+1];
	size_t i, l;
	int n;
	memset(&ce, 0, sizeof(ce));
	for(i=0; i<NUM_NODES; i++)
		ids[i] = mknode((int)i);
	ce.node_ids = ids;
	ce.num_peers = NUM_NODES;
	for(n=0; n<100; n++) {
		l = mkname(nm, sizeof(nm), n, 0);
		cluster_rank(&ce, nm, l, order, scores);
		/* the first is the winner of the selection */
		unit_assert((int)order[0] == cluster_hrw_select(ids,
			NUM_NODES, nm, l, NULL));
		for(i=0; i+1<NUM_NODES; i++)
			unit_assert(scores[i] >= scores[i+1]);
		for(i=0; i<NUM_NODES; i++)
			unit_assert(scores[i] == cluster_hrw_score(
				ids[order[i]], nm, l));
	}
	/* the snapshot copies, the clear resets only the live counters */
	ce.num_stats = 2;
	ce.stats = (struct cluster_stats*)calloc(2, sizeof(*ce.stats));
	ce.snap = (struct cluster_stats*)calloc(2, sizeof(*ce.snap));
	unit_assert(ce.stats && ce.snap);
	lock_basic_init(&ce.snap_lock);
	ce.stats[0].routed = 3;
	ce.stats[1].routed = 4;
	ce.stats[1].served_probe_miss = 5;
	cluster_stats_snapshot(&ce, 0);
	cluster_stats_snapshot(&ce, 1);
	cluster_stats_clear_thread(&ce, 0);
	unit_assert(ce.stats[0].routed == 0 && ce.stats[1].routed == 4);
	{
		struct cluster_stats t;
		cluster_get_stats(&ce, &t);
		unit_assert(t.routed == 7 && t.served_probe_miss == 5);
	}
	lock_basic_destroy(&ce.snap_lock);
	free(ce.stats);
	free(ce.snap);
}

/** set up a cluster env with n peers for the health tests */
static void
health_setup(struct cluster_env* ce, struct cluster_peer* peers, size_t n,
	int cap)
{
	size_t i;
	memset(ce, 0, sizeof(*ce));
	memset(peers, 0, sizeof(*peers)*n);
	for(i=0; i<n; i++) {
		lock_basic_init(&peers[i].lock);
		peers[i].res_ewma = CLUSTER_FP_ONE;
		peers[i].probe_ewma = CLUSTER_FP_ONE;
		peers[i].str = (char*)"peer";
	}
	lock_basic_init(&ce->eject_lock);
	ce->eject_lock_inited = 1;
	ce->peers = peers;
	ce->num_peers = n;
	ce->res_eject_max = cap;
}

/** tear down */
static void
health_teardown(struct cluster_env* ce, struct cluster_peer* peers, size_t n)
{
	size_t i;
	for(i=0; i<n; i++)
		lock_basic_destroy(&peers[i].lock);
	lock_basic_destroy(&ce->eject_lock);
}

/** advance the clock of the test env */
static void
health_pass(struct timeval* tv, time_t* secs, int ms)
{
	tv->tv_sec += ms/1000;
	tv->tv_usec += (ms%1000)*1000;
	if(tv->tv_usec >= 1000000) {
		tv->tv_sec++;
		tv->tv_usec -= 1000000;
	}
	*secs = tv->tv_sec;
}

/** three charged failures eject the peer */
static void
health_eject(struct cluster_env* ce, struct cluster_peer* p,
	struct module_env* env)
{
	int i;
	for(i=0; i<CLUSTER_RES_EJECT_CONSEC; i++)
		cluster_res_result(ce, p, RES_CHARGED, 0, 0, env);
}

/** the slot of an ejected peer under the limit is released when the
 * ejection time is over, and taken again by a failed trial */
static void
slot_test(void)
{
	struct cluster_env ce;
	struct cluster_peer peers[2];
	struct module_env env;
	struct timeval tv;
	time_t secs;
	int trial = 0;
	unsigned gen = 0;
	memset(&env, 0, sizeof(env));
	memset(&tv, 0, sizeof(tv));
	tv.tv_sec = 1000;
	secs = tv.tv_sec;
	env.now_tv = &tv;
	env.now = &secs;
	health_setup(&ce, peers, 2, 1);
	health_eject(&ce, &peers[0], &env);
	unit_assert(peers[0].res_ejected && peers[0].eject_slot);
	unit_assert(ce.res_ejected_count == 1);
	/* the limit is reached: the other peer is not ejected */
	health_eject(&ce, &peers[1], &env);
	unit_assert(!peers[1].res_ejected && ce.res_ejected_count == 1);
	/* not before the time */
	unit_assert(!cluster_res_gate(&ce, &peers[0], 1000*1000+9000,
		&trial, &gen) && !trial);
	unit_assert(ce.res_ejected_count == 1);
	/* the time is over: the slot is free as soon as the gate sees it */
	health_pass(&tv, &secs, 10500);
	/* even for a charged failure of the other peer, without the gate:
	 * the sweep frees the slot, the other peer is ejected */
	cluster_res_result(&ce, &peers[1], RES_CHARGED, 0, 0, &env);
	unit_assert(peers[1].res_ejected && peers[1].eject_slot);
	unit_assert(ce.res_ejected_count == 1);
	unit_assert(peers[0].res_ejected && !peers[0].eject_slot);
	/* its trial: it is granted, no slot is held */
	unit_assert(cluster_res_gate(&ce, &peers[0], (long long)secs*1000,
		&trial, &gen) && trial);
	unit_assert(peers[0].trial_busy);
	/* the trial fails: no slot free, the peer is no longer ejected */
	cluster_res_result(&ce, &peers[0], RES_CHARGED, trial, gen, &env);
	unit_assert(!peers[0].res_ejected && !peers[0].trial_busy);
	unit_assert(ce.res_ejected_count == 1);
	/* the other peer recovers with its trial, the slot is free, and a
	 * failed trial of the first one is ejected again with a slot */
	health_pass(&tv, &secs, 10500);
	unit_assert(cluster_res_gate(&ce, &peers[1], (long long)secs*1000,
		&trial, &gen) && trial);
	cluster_res_result(&ce, &peers[1], RES_SUCCESS, trial, gen, &env);
	unit_assert(!peers[1].res_ejected && ce.res_ejected_count == 0);
	health_eject(&ce, &peers[0], &env);
	unit_assert(peers[0].res_ejected && peers[0].eject_slot &&
		ce.res_ejected_count == 1);
	health_pass(&tv, &secs, 20500);
	unit_assert(cluster_res_gate(&ce, &peers[0], (long long)secs*1000,
		&trial, &gen) && trial);
	unit_assert(ce.res_ejected_count == 0);
	cluster_res_result(&ce, &peers[0], RES_CHARGED, trial, gen, &env);
	unit_assert(peers[0].res_ejected && peers[0].eject_slot &&
		ce.res_ejected_count == 1);
	health_teardown(&ce, peers, 2);
}

/** a stale query that holds a trial of an earlier generation, from before
 * the peer went down, up and was ejected again, does not release or
 * decide the new trial */
static void
trial_gen_test(void)
{
	struct cluster_env ce;
	struct cluster_peer peers[1];
	struct module_env env;
	struct timeval tv;
	time_t secs;
	int trial = 0, trial2 = 0, i;
	unsigned gen = 0, gen2 = 0, g;
	memset(&env, 0, sizeof(env));
	memset(&tv, 0, sizeof(tv));
	tv.tv_sec = 1000;
	secs = tv.tv_sec;
	env.now_tv = &tv;
	env.now = &secs;
	health_setup(&ce, peers, 1, 1);
	health_eject(&ce, &peers[0], &env);
	health_pass(&tv, &secs, 10500);
	/* the old query gets the trial */
	unit_assert(cluster_res_gate(&ce, &peers[0], (long long)secs*1000,
		&trial, &gen) && trial);
	/* the peer goes down: silent for the alive window, three failed
	 * probes */
	health_pass(&tv, &secs, 1200);
	for(i=0; i<CLUSTER_HEALTH_FAIL_MAX; i++)
		cluster_peer_report(&ce, &peers[0], PEER_FAILED, 0, 1, &env);
	unit_assert(peers[0].down && !peers[0].trial_busy &&
		!peers[0].res_ejected && ce.res_ejected_count == 0);
	/* and up again, two successes of the probes */
	health_pass(&tv, &secs, 1200);
	cluster_peer_report(&ce, &peers[0], PEER_ANSWERED, 1, 1, &env);
	cluster_peer_report(&ce, &peers[0], PEER_ANSWERED, 1, 1, &env);
	unit_assert(!peers[0].down);
	/* ejected again, and the new trial */
	health_eject(&ce, &peers[0], &env);
	unit_assert(peers[0].res_ejected);
	health_pass(&tv, &secs, 10500);
	unit_assert(cluster_res_gate(&ce, &peers[0], (long long)secs*1000,
		&trial2, &gen2) && trial2);
	unit_assert(gen2 != gen);
	g = peers[0].trial_gen;
	/* the old query is done: neutral or success, it holds the slot of
	 * the earlier trial */
	cluster_res_result(&ce, &peers[0], RES_NEUTRAL, trial, gen, &env);
	unit_assert(peers[0].trial_busy && peers[0].res_ejected);
	cluster_res_result(&ce, &peers[0], RES_SUCCESS, trial, gen, &env);
	unit_assert(peers[0].trial_busy && peers[0].res_ejected);
	unit_assert(peers[0].trial_gen == g);
	/* no second trial */
	unit_assert(!cluster_res_gate(&ce, &peers[0], (long long)secs*1000,
		&trial, &gen) && !trial);
	/* the new trial decides */
	cluster_res_result(&ce, &peers[0], RES_SUCCESS, trial2, gen2, &env);
	unit_assert(!peers[0].trial_busy && !peers[0].res_ejected);
	health_teardown(&ce, peers, 1);
}

/** the retransmission timeout of the step 2 key is kept above the
 * deadline, so the outgoing UDP query does not time out first */
static void
rto_floor_test(void)
{
	struct config_file* cfg = config_create();
	struct infra_cache* infra;
	struct sockaddr_storage a;
	socklen_t alen;
	time_t now = 1000;
	int rto, i;
	uint8_t zone[] = "\017cluster-resolve";
	uint8_t root[1] = {0};
	uint8_t edns;
	int vs, to;
	unit_assert(cfg);
	config_auto_slab_values(cfg);
	infra = infra_create(cfg);
	unit_assert(infra);
	unit_assert(extstrtoaddr("10.0.0.3@53", &a, &alen, 53));
	/* no entry: the default is raised above the deadline */
	rto = cluster_rto_floor(infra, &a, alen, now, 3000);
	unit_assert(rto >= 3000);
	unit_assert(infra_host(infra, &a, alen, zone, sizeof(zone), now,
		&vs, &edns, &to));
	unit_assert(to >= 3000);
	/* the same call changes nothing */
	unit_assert(cluster_rto_floor(infra, &a, alen, now, 3000) == rto);
	/* samples of fast replies lower it, below the nicety limit even */
	for(i=0; i<200; i++)
		unit_assert(infra_rtt_update(infra, &a, alen, zone,
			sizeof(zone), LDNS_RR_TYPE_A, 1, to, now));
	unit_assert(infra_host(infra, &a, alen, zone, sizeof(zone), now,
		&vs, &edns, &to));
	unit_assert(to < UNKNOWN_SERVER_NICENESS);
	rto = cluster_rto_floor(infra, &a, alen, now, 1500);
	unit_assert(rto >= 1500);
	unit_assert(infra_host(infra, &a, alen, zone, sizeof(zone), now,
		&vs, &edns, &to));
	unit_assert(to >= 1500);
	/* a small deadline still gets the nicety limit */
	for(i=0; i<200; i++)
		unit_assert(infra_rtt_update(infra, &a, alen, zone,
			sizeof(zone), LDNS_RR_TYPE_A, 1, to, now));
	rto = cluster_rto_floor(infra, &a, alen, now, 300);
	unit_assert(rto >= UNKNOWN_SERVER_NICENESS);
	/* the entry of the probes (the root) is not touched */
	unit_assert(infra_host(infra, &a, alen, root, 1, now, &vs, &edns,
		&to));
	unit_assert(to == UNKNOWN_SERVER_NICENESS);
	/* an expired entry */
	now += cfg->host_ttl + 10;
	rto = cluster_rto_floor(infra, &a, alen, now, 3000);
	unit_assert(rto >= 3000);
	infra_delete(infra);
	config_delete(cfg);
}

/** the EWMA in fixed point */
static void
ewma_test(void)
{
	int32_t e = CLUSTER_FP_ONE;
	int i;
	unit_assert(cluster_ewma_update(CLUSTER_FP_ONE, 1, 10) ==
		CLUSTER_FP_ONE);
	/* one failure from 1.0 with weight 1/10: 0.9 */
	e = cluster_ewma_update(CLUSTER_FP_ONE, 0, 10);
	unit_assert(e == CLUSTER_FP_ONE - (CLUSTER_FP_ONE+9)/10);
	unit_assert(e > 58900 && e < 59100); /* 0.9 */
	/* the decay to zero reaches it, no stall near the end */
	e = CLUSTER_FP_ONE;
	for(i=0; i<500; i++)
		e = cluster_ewma_update(e, 0, 10);
	unit_assert(e == 0);
	/* the rise reaches 1.0 exactly */
	for(i=0; i<500; i++)
		e = cluster_ewma_update(e, 1, 20);
	unit_assert(e == CLUSTER_FP_ONE);
	/* 1/20 weight: after 20 failures it is below 0.5 (0.95^14 < 0.5) */
	e = CLUSTER_FP_ONE;
	for(i=0; i<14; i++)
		e = cluster_ewma_update(e, 0, CLUSTER_RES_EWMA_DIV);
	unit_assert(e < CLUSTER_RES_EJECT_EWMA);
	e = CLUSTER_FP_ONE;
	for(i=0; i<13; i++)
		e = cluster_ewma_update(e, 0, CLUSTER_RES_EWMA_DIV);
	unit_assert(e > CLUSTER_RES_EJECT_EWMA);
	/* never out of range */
	unit_assert(cluster_ewma_update(0, 0, 10) == 0);
	unit_assert(cluster_ewma_update(0, 1, 1) == CLUSTER_FP_ONE);
	unit_assert(cluster_ewma_update(CLUSTER_FP_ONE, 0, 1) == 0);
}

/** the RFC 6298 estimator of the probe round trip time */
static void
rtt_test(void)
{
	int32_t srtt = 0, var = 0;
	int n = 0, i;
	/* first sample: srtt = r, rttvar = r/2 */
	cluster_rtt_update(&srtt, &var, &n, 8000);
	unit_assert(srtt == 8000 && var == 4000 && n == 1);
	/* RFC 6298 second sample 16 ms: rttvar = 3/4*4000 + 1/4*8000 = 5000,
	 * srtt = 7/8*8000 + 1/8*16000 = 9000 */
	cluster_rtt_update(&srtt, &var, &n, 16000);
	unit_assert(var == 5000 && srtt == 9000 && n == 2);
	/* constant samples: the variation decays to a few us, the
	 * smoothed value converges to the sample */
	for(i=0; i<200; i++)
		cluster_rtt_update(&srtt, &var, &n, 2000);
	unit_assert(srtt >= 1990 && srtt <= 2010);
	unit_assert(var < 20);
	/* clamped input */
	cluster_rtt_update(&srtt, &var, &n, -5);
	unit_assert(srtt >= 0);
	cluster_rtt_update(&srtt, &var, &n, 2000000000);
	unit_assert(srtt <= 60000000);
	/* no overflow near the limit for many samples */
	for(i=0; i<100; i++)
		cluster_rtt_update(&srtt, &var, &n, 60000000);
	unit_assert(srtt > 0 && var >= 0);

}

/** the step 2 deadline from the client budget, and the ejection cap */
static void
budget_test(void)
{
	/* discard-timeout 1900, query arrived 0 or 100 msec ago */
	unit_assert(cluster_resolve_budget(1900, 0) == 1900);
	unit_assert(cluster_resolve_budget(1900, 100) == 1800);
	/* the floor, also when the budget is used up or negative */
	unit_assert(cluster_resolve_budget(1900, 1700) == CLUSTER_RESOLVE_MIN);
	unit_assert(cluster_resolve_budget(1900, 1899) == CLUSTER_RESOLVE_MIN);
	unit_assert(cluster_resolve_budget(1900, 5000) == CLUSTER_RESOLVE_MIN);
	/* the cap, also for a large discard-timeout; no discard-timeout */
	unit_assert(cluster_resolve_budget(10000, 0) == CLUSTER_RESOLVE_MAX);
	unit_assert(cluster_resolve_budget(0, 0) == CLUSTER_RESOLVE_MAX);
	unit_assert(cluster_resolve_budget(0, 4000) == CLUSTER_RESOLVE_MAX);
	/* at most 30% of the peers, rounded down */
	unit_assert(cluster_eject_cap(0) == 0);
	unit_assert(cluster_eject_cap(1) == 0);
	unit_assert(cluster_eject_cap(3) == 0);
	unit_assert(cluster_eject_cap(4) == 1);
	unit_assert(cluster_eject_cap(5) == 1);
	unit_assert(cluster_eject_cap(6) == 1);
	unit_assert(cluster_eject_cap(7) == 2);
	unit_assert(cluster_eject_cap(10) == 3);
	unit_assert(cluster_eject_cap(40) == 12);
}

void
cluster_test(void)
{
	unit_show_feature("cluster");
	node_id_test();
	stability_test();
	evenness_test();
	remap_test();
	tie_test();
	option_test();
	unique_test();
	peer_addr_test();
	local_match_test();
	rank_test();
	ewma_test();
	rtt_test();
	budget_test();
	slot_test();
	trial_gen_test();
	rto_floor_test();
}
#endif /* USE_CLUSTER */
