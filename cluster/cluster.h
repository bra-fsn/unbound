/*
 * cluster/cluster.h - cooperative cache sharing between unbound instances
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
 * instances act as one logical cache, by sending queries for names that
 * are owned by another instance of the cluster to that instance.
 *
 * The owner of a name is chosen with rendezvous hashing (highest random
 * weight) on the query name.  A cache miss for a name that is owned by
 * another node is sent to that node, as a query with the CLUSTER EDNS
 * option.  The owner treats such a query as a normal client query that is
 * resolved locally, it is never forwarded again.  When the owner does not
 * answer in time, the query is resolved locally.
 *
 * The CLUSTER EDNS option data is 10 bytes:
 *	byte 0: version (1)
 *	byte 1: flags, CLUSTER_FLAG_PEER, CLUSTER_FLAG_CACHE_ONLY (query),
 *		and in the reply CLUSTER_FLAG_OWNER_CACHE_HIT,
 *		CLUSTER_FLAG_MISS, CLUSTER_FLAG_STALE.
 *	byte 2-9: node id of the sender, big endian.
 */

#ifndef CLUSTER_CLUSTER_H
#define CLUSTER_CLUSTER_H
#include "util/module.h"
#include "util/netevent.h"
#include "util/locks.h"
struct config_file;
struct module_stack;
struct edns_option;
struct edns_data;
struct comm_reply;
struct mesh_area;
struct slabhash;

/** the version of the CLUSTER EDNS option */
#define CLUSTER_OPT_VERSION 1
/** length of the CLUSTER EDNS option data */
#define CLUSTER_OPT_LEN 10
/** flag: the query is a query from a cluster peer, resolve it locally */
#define CLUSTER_FLAG_PEER 0x01
/** flag in queries: step 1 cache probe, only answer from the cache; on a
 * miss the owner replies REFUSED with the CLUSTER_FLAG_MISS flag */
#define CLUSTER_FLAG_CACHE_ONLY 0x02
/** flag in replies: the owner answered from its message cache */
#define CLUSTER_FLAG_OWNER_CACHE_HIT 0x04
/** flag in replies: the cache probe missed, nothing was resolved */
#define CLUSTER_FLAG_MISS 0x08
/** flag in replies: the answer is an expired cache entry (serve-expired),
 * the requester must not store it */
#define CLUSTER_FLAG_STALE 0x10

/** step 2 (resolve request) deadline: at most this many msec.  The
 * deadline is the time left until the discard point of the client query
 * (arrival plus discard-timeout) so that the local fallback still has a
 * chance to answer; states without client reply or with discard-timeout 0
 * have this value.  Expiry is not a health failure of the peer, it only
 * starts the local fallback. */
#define CLUSTER_RESOLVE_MAX 3000
/** floor in msec of the step 2 deadline, also when the client budget is
 * used up */
#define CLUSTER_RESOLVE_MIN 300
/** maximum number of times the cache probe (UDP) is sent again after the
 * timeout of the outnet, within the probe deadline.  The resolve request
 * (step 2) is a UDP query too but is never sent again: a resend would take
 * a new source port and could be handled by another thread of the owner,
 * that then resolves the name a second time. */
#define CLUSTER_PROBE_RESENDS 4

/** a peer is only marked down when it has not sent a valid reply (probe
 * answer, probe miss or step 2 answer) for this long, in msec, besides
 * the consecutive probe failures */
#define CLUSTER_ALIVE_WINDOW 1000

/** consecutive failures after which a peer is marked down */
#define CLUSTER_HEALTH_FAIL_MAX 3
/** a down peer is marked up when this many of the last
 * CLUSTER_HEALTH_UP_OUT_OF half-open probes succeeded */
#define CLUSTER_HEALTH_UP_NEED 2
/** see CLUSTER_HEALTH_UP_NEED, at most 8 */
#define CLUSTER_HEALTH_UP_OUT_OF 3
/** Fixed point fractions (EWMA values) are in units of 1/65536, 65536 is
 * 1.0.  The probe success EWMA has weight 1/10 for a new sample, the
 * resolve success EWMA has weight 1/20. */
#define CLUSTER_FP_ONE 65536
/** weight divisor of the probe success EWMA, initial value 1.0, 0.5 after
 * a peer is marked up again */
#define CLUSTER_PROBE_EWMA_DIV 10
/** weight divisor of the resolve success EWMA, initial value 1.0 */
#define CLUSTER_RES_EWMA_DIV 20

/** paired attribution: the failure of step 2 of the owner is charged to
 * the owner when the local fallback that follows it succeeds within this
 * many msec; otherwise it is not charged (the upstream is slow or broken
 * for everyone) */
#define CLUSTER_FAST_FALLBACK 500
/** the owner is resolve-ejected after this many consecutive charged
 * failures, or when the resolve EWMA is below CLUSTER_RES_EJECT_EWMA with
 * at least CLUSTER_RES_EJECT_MIN_N samples */
#define CLUSTER_RES_EJECT_CONSEC 3
/** minimum number of samples for the EWMA ejection rule */
#define CLUSTER_RES_EJECT_MIN_N 20
/** EWMA ejection threshold, 0.5 */
#define CLUSTER_RES_EJECT_EWMA (CLUSTER_FP_ONE/2)
/** resolve EWMA after a successful trial request, 0.7 */
#define CLUSTER_RES_TRIAL_EWMA ((CLUSTER_FP_ONE*7)/10)
/** ejection time in msec, times the ejection count */
#define CLUSTER_EJECT_BASE_MS 10000
/** maximum ejection time in msec */
#define CLUSTER_EJECT_MAX_MS 120000
/** at most this percentage of the peers (rounded down) is resolve-ejected
 * at the same time */
#define CLUSTER_EJECT_MAX_PCT 30

/** first probe delay for a down peer, in msec */
#define CLUSTER_PROBE_BACKOFF_MIN 1000
/** maximum probe delay for a down peer, in msec */
#define CLUSTER_PROBE_BACKOFF_MAX 60000

/** a cluster peer, from the cluster-peer config */
struct cluster_peer {
	/** the address of the peer */
	struct sockaddr_storage addr;
	/** length of the address */
	socklen_t addrlen;
	/** the original config string, for logging, malloced */
	char* str;
	/** node id of the peer, derived from its address */
	uint64_t node_id;

	/** lock for the health state and counters below.  The peer table is
	 * shared by all threads, so that the threads share what they learn
	 * about the peer; it is taken briefly at selection and when a query
	 * to the peer ends, only on the cache miss path. */
	lock_basic_type lock;
	/** is the peer considered down, protected by lock */
	int down;
	/** consecutive failures, protected by lock */
	int consec_fail;
	/** results of the last half-open probes of a down peer, bit 0 is the
	 * last, 1 is success, protected by lock */
	unsigned half_hist;
	/** current probe backoff in msec, if down, protected by lock */
	int backoff_ms;
	/** time in msec (epoch) after which the next probe is allowed,
	 * if down, protected by lock */
	long long next_probe_ms;
	/** a probe query is outstanding, protected by lock */
	int probe_busy;
	/** the REFUSED without cluster option was logged, protected by lock */
	int refused_logged;
	/** an answer without the cluster option was logged, protected by
	 * lock */
	int noopt_logged;
	/** time in seconds of the last success, 0 if none, protected by lock */
	time_t last_success;
	/** time in msec (epoch) of the last valid reply from the peer, from
	 * any step, protected by lock */
	long long last_alive_ms;
	/** there has been a valid reply, last_alive_ms is set, protected by
	 * lock */
	int alive_seen;
	/** queries sent to this peer, protected by lock */
	uint64_t routed;
	/** answers accepted from this peer, protected by lock */
	uint64_t answered;
	/** queries to this peer that failed, protected by lock */
	uint64_t failed;

	/** probe success EWMA, units of 1/65536, initial 1.0, protected by
	 * lock.  Visibility only, step 1 results only. */
	int32_t probe_ewma;
	/** RFC 6298 smoothed round trip time of the probe in microseconds,
	 * valid if rtt_samples > 0, protected by lock.  Visibility only,
	 * the probe deadline is the fixed cluster-timeout. */
	int32_t srtt_us;
	/** RFC 6298 round trip time variation in microseconds, protected by
	 * lock */
	int32_t rttvar_us;
	/** number of probe RTT samples, saturates, protected by lock */
	int rtt_samples;

	/** resolve (step 2) success EWMA, units of 1/65536, initial 1.0,
	 * protected by lock */
	int32_t res_ewma;
	/** number of resolve samples, saturates, protected by lock */
	int res_n;
	/** consecutive charged resolve failures, protected by lock */
	int res_consec_charged;
	/** the peer is resolve-ejected: its cache hits are used, but a
	 * cache miss is resolved locally.  Protected by lock; counted in
	 * the cluster_env res_ejected_count. */
	int res_ejected;
	/** time in msec (epoch) when the ejection ends and one trial step 2
	 * request is allowed, if res_ejected, protected by lock */
	long long eject_until_ms;
	/** number of ejections in a row (decays after successful trials),
	 * protected by lock */
	int eject_count;
	/** the trial step 2 request is outstanding, protected by lock */
	int trial_busy;
	/** generation of the trial: increased when a trial is granted and
	 * when the peer is marked down, so a stale query that holds an
	 * older trial can not release or decide a newer one.  Protected by
	 * lock. */
	unsigned trial_gen;
	/** this peer holds a slot of the limit on the number of
	 * resolve-ejected peers (res_ejected_count).  It is released when
	 * the ejection time is over, before the trial, and taken again if
	 * the trial fails.  Protected by lock. */
	int eject_slot;
};

/** a zone that is always resolved locally, from cluster-exclude */
struct cluster_exclude {
	/** next in list */
	struct cluster_exclude* next;
	/** the zone name, uncompressed wireformat, malloced */
	uint8_t* name;
	/** length of the name */
	size_t namelen;
	/** number of labels in the name */
	int labs;
};

/**
 * Counters for the statistics, per thread.  Every thread only changes its
 * own struct (the live counters).  When statistics are asked for, every
 * thread copies its live counters to its snapshot slot, from
 * server_stats_compile(), in its own thread; the remote control thread
 * sums the snapshots when printing, after the thread has answered over
 * the tube.  The reset of stats follows the one of the other counters,
 * worker_stats_clear() clears the live counters.
 */
struct cluster_stats {
	/** queries sent to the owner */
	uint64_t routed;
	/** answers of the owner that were accepted */
	uint64_t answered;
	/** of the answered, the owner answered from its msg cache */
	uint64_t answered_cachehit;
	/** queries to the owner that failed: timeout, error or bad answer */
	uint64_t failed;
	/** of the failed, the cluster-timeout deadline of the cache probe
	 * passed */
	uint64_t timeout;
	/** of the failed, the deadline of the resolve request (step 2)
	 * passed; not a failure of the peer */
	uint64_t resolve_timeout;
	/** queries resolved locally after a failure of the owner */
	uint64_t fallback;
	/** misses for names that are owned by this node */
	uint64_t self;
	/** queries passed on without routing: exclude, ECS, RD=0, not IN,
	 * priming, or the query is part of a peer query */
	uint64_t excluded;
	/** failures of step 2 of the owner that were charged to the owner by
	 * the paired attribution: the local fallback succeeded fast */
	uint64_t charged;
	/** failures of step 2 of the owner that were a SERVFAIL answered from
	 * the cache of the owner, these are not charged */
	uint64_t owner_cached_servfail;
	/** answers of the owner that are a partial CNAME chain (the rest is
	 * cut off by the scrubber, or the chain ends in NODATA or NXDOMAIN),
	 * the chain is followed locally; these are counted in answered as
	 * well */
	uint64_t cname;
	/** misses that the owner, resolve-ejected, was not asked to resolve,
	 * these were resolved locally */
	uint64_t resolve_ejected;
	/** misses with no usable owner (all candidates down) */
	uint64_t nolive;
	/** peer queries received, that missed in the cache (owner side);
	 * the owner side cache hits are answered by the worker without a
	 * thread context for the callback and are not counted here, the
	 * requester counts them as answered_cachehit */
	uint64_t served;
	/** queries with a CLUSTER option with an unknown version */
	uint64_t version_mismatch;
	/** requester side: the cache probe of the owner was a miss, and
	 * the owner is asked to resolve (step 2) */
	uint64_t probe_miss;
	/** owner side: cache only probes of peers that missed the cache
	 * and were answered REFUSED with the MISS flag */
	uint64_t served_probe_miss;
};

/**
 * The global environment of the cluster module.
 * Shared between threads.  The configuration part is read-only after init,
 * the module reads only this copy of the configuration, never the
 * cluster-* settings in the config_file, since fast_reload can change
 * those without reinitialising the module.
 */
struct cluster_env {
	/** array of peers, malloced, includes this node if it is listed */
	struct cluster_peer* peers;
	/** number of peers */
	size_t num_peers;
	/** array of the node ids of the peers, for the hash selection,
	 * malloced */
	uint64_t* node_ids;
	/** index of this node in the peers array, or -1 if not known */
	int self;
	/** cap on the TTL of answers for names not owned by this node,
	 * in seconds, 0 is no cap */
	int local_ttl_max;
	/** time in msec to wait for the owner peer before falling back to
	 * local resolution */
	int timeout_ms;
	/** list of zones that are always resolved locally */
	struct cluster_exclude* excludes;
	/** lock for res_ejected_count.  It is a leaf lock, taken (inside a
	 * peer lock) only when a peer is resolve-ejected or recovers, rare
	 * events; the per peer lock cannot give the global limit. */
	lock_basic_type eject_lock;
	/** eject_lock is initialised */
	int eject_lock_inited;
	/** the number of peers that are resolve-ejected now, protected by
	 * eject_lock */
	int res_ejected_count;
	/** maximum number of peers that can be resolve-ejected at once,
	 * CLUSTER_EJECT_MAX_PCT percent of the peers, rounded down */
	int res_eject_max;

	/** per thread live statistics, array of num_stats.  Only changed by
	 * the thread itself, and read by it for the snapshot. */
	struct cluster_stats* stats;
	/** per thread snapshots of the statistics, array of num_stats,
	 * written by the thread itself in server_stats_compile, read by the
	 * remote control thread.  Protected by snap_lock. */
	struct cluster_stats* snap;
	/** lock for the snapshots */
	lock_basic_type snap_lock;
	/** snap_lock is initialised */
	int snap_lock_inited;
	/** number of entries in stats, the number of threads */
	int num_stats;
};

/** snapshot of the health state of a peer, for the status output */
struct cluster_peer_info {
	/** is the peer down */
	int down;
	/** consecutive failures */
	int consec_fail;
	/** current probe backoff in msec if down */
	int backoff_ms;
	/** time of the last success, 0 for none */
	time_t last_success;
	/** a probe query to the down peer is outstanding */
	int probe_busy;
	/** counters, queries to the peer */
	uint64_t routed, answered, failed;
	/** probe success EWMA, 1/65536 units */
	int32_t probe_ewma;
	/** smoothed probe RTT in microseconds, -1 if there are no samples */
	int32_t srtt_us;
	/** resolve success EWMA, 1/65536 units */
	int32_t res_ewma;
	/** the peer is resolve-ejected */
	int res_ejected;
	/** msec until the ejection ends, 0 if over (trial allowed or in
	 * progress) */
	long long eject_left_ms;
	/** the trial request is outstanding */
	int trial_busy;
};

/**
 * Get the cluster function block.
 * @return: the function block for the cluster module.
 */
struct module_func_block* cluster_get_funcblock(void);

/** cluster init */
int cluster_init(struct module_env* env, int id);

/** cluster deinit */
void cluster_deinit(struct module_env* env, int id);

/** cluster operate on a query */
void cluster_operate(struct module_qstate* qstate, enum module_ev event,
	int id, struct outbound_entry* outbound);

/** cluster inform_super, cluster does not use subordinate queries */
void cluster_inform_super(struct module_qstate* qstate, int id,
	struct module_qstate* super);

/** cluster cleanup, remove the per query state */
void cluster_clear(struct module_qstate* qstate, int id);

/** cluster, how much memory is in use */
size_t cluster_get_mem(struct module_env* env, int id);

/** the timer callback for the owner deadline, for the fptr whitelist */
void cluster_timer_cb(void* arg);

/**
 * Callback for the reply of the owner, in the fptr whitelist for the
 * inplace reply callbacks.  Adds the CLUSTER option to replies for peer
 * queries.
 */
int cluster_inplace_reply(struct query_info* qinfo,
	struct module_qstate* qstate, struct reply_info* rep, int rcode,
	struct edns_data* edns, struct edns_option** opt_list_out,
	struct comm_reply* repinfo, struct regional* region,
	struct timeval* start_time, int id, void* callback);

/**
 * Find the peers that have a local address, ignoring the ports of the
 * addresses, but a peer must have the given port.  Exported for unit tests.
 * @param peers: peer array.
 * @param num_peers: number of peers.
 * @param locals: local addresses (ports and scope ids are ignored).
 * @param lens: their lengths.
 * @param num_locals: number of local addresses.
 * @param port: the port a peer must have to match.
 * @param found: set to the index of the last matching peer.
 * @return the number of peers that match.
 */
size_t cluster_match_local_addrs(struct cluster_peer* peers,
	size_t num_peers, struct sockaddr_storage* locals, socklen_t* lens,
	size_t num_locals, int port, int* found);

/* ---- health arithmetic, fixed point, exported for the unit tests ---- */

/**
 * EWMA update in fixed point.
 * @param ewma: the value, 1/65536 units.
 * @param sample: 1 for success, 0 for failure.
 * @param div: weight of the sample is 1/div.
 * @return new value, between 0 and CLUSTER_FP_ONE.
 */
int32_t cluster_ewma_update(int32_t ewma, int sample, int div);

/**
 * RFC 6298 round trip time estimator, integer arithmetic, microseconds.
 * The first sample sets srtt = r and rttvar = r/2; later samples
 * rttvar = 3/4 rttvar + 1/4 |srtt - r|, srtt = 7/8 srtt + 1/8 r.
 * @param srtt_us: smoothed rtt, updated.
 * @param rttvar_us: variation, updated.
 * @param samples: number of samples so far, updated (saturates).
 * @param r_us: the new sample, clamped to 0 .. 60 seconds.
 */
void cluster_rtt_update(int32_t* srtt_us, int32_t* rttvar_us, int* samples,
	int32_t r_us);

/**
 * The step 2 deadline from the client budget.
 * @param discard_timeout_ms: the discard-timeout config, 0 if none.
 * @param used_ms: msec since the arrival of the (earliest) client query.
 * @return discard_timeout_ms - used_ms, at least CLUSTER_RESOLVE_MIN and
 * 	at most CLUSTER_RESOLVE_MAX; the cap if discard_timeout_ms is 0.
 */
int cluster_resolve_budget(int discard_timeout_ms, long long used_ms);

/**
 * The number of peers that may be resolve-ejected at once.
 * @param num_peers: number of peers.
 * @return floor(30% of num_peers).
 */
int cluster_eject_cap(size_t num_peers);

/* The health judgments of a peer.  Exported for the unit test. */
/** what the end of a step of a query says about the peer */
enum cluster_peer_result {
	/** an answer that is used: alive, counted as answered */
	PEER_ANSWERED,
	/** the cache probe missed: alive, no counter */
	PEER_MISS,
	/** a reply that is not usable (servfail, lame): alive, counted as
	 * failed */
	PEER_REJECTED,
	/** no usable reply to the cache probe: timeout, error, REFUSED
	 * without option.  The only result that is a health failure. */
	PEER_FAILED,
	/** the resolve request (step 2) ended without a valid reply: timeout
	 * of the deadline, error, bad reply.  Counted as failed, but not a
	 * health failure, and no sign of life either. */
	PEER_STEP2_FAILED
};

/** the outcome of the resolve request for the resolution health */
enum cluster_res_result {
	/** the owner answered the resolve request */
	RES_SUCCESS,
	/** the owner failed, and the local fallback succeeded fast: the
	 * failure is charged to the owner */
	RES_CHARGED,
	/** no verdict: the fallback was slow or failed, or the state ended
	 * without it; only releases the trial slot */
	RES_NEUTRAL
};

/**
 * Report the end of a step of a query to a peer, for its health.  With
 * three consecutive failures of the cache probe and no sign of life for
 * CLUSTER_ALIVE_WINDOW the peer goes down.
 * @param ce: cluster env.
 * @param peer: the peer.
 * @param res: what happened.
 * @param probe: the query was a probe of a down peer, this releases the
 *	slot.  Only for the cache probe step.
 * @param step1: the report is for the cache probe step.
 * @param env: for the time.
 */
void cluster_peer_report(struct cluster_env* ce, struct cluster_peer* peer,
	enum cluster_peer_result res, int probe, int step1,
	struct module_env* env);

/**
 * Step 2 gate at the cache probe miss, see the implementation.
 * @return false if the query must be resolved locally.
 */
int cluster_res_gate(struct cluster_env* ce, struct cluster_peer* peer,
	long long now_ms, int* trial, unsigned* gen);

/**
 * Report the outcome of the resolve request for the resolution health, see
 * the implementation.
 */
void cluster_res_result(struct cluster_env* ce, struct cluster_peer* peer,
	enum cluster_res_result res, int trial, unsigned gen,
	struct module_env* env);

struct infra_cache;
/**
 * Make sure the retransmission timeout that the infra cache holds for the
 * step 2 key (zone cluster-resolve.) of the peer is above min_rto.  The
 * outnet takes the timeout of a UDP query from that value (see
 * serviced_udp_send), and OUTBOUND_UDP_RETRY is 1, so a timeout that is
 * after the step 2 deadline means the outnet does not time out or send
 * the query again before the module deadline (strictly after, so the
 * module timer, set first, is not tied with the outnet timer).  The
 * samples of round trip times lower it, fast replies of an owner with a
 * warm cache for example, and a shorter UDP timeout would then cut the
 * owner short.  The timeout is backed off (doubled, as after lost
 * queries) until it is above min_rto.  It can not go over
 * infra-cache-max-rtt.
 * @param infra: the infra cache.
 * @param addr: address of the peer.
 * @param addrlen: length of addr.
 * @param now: time in seconds.
 * @param min_rto: minimum in msec, at least UNKNOWN_SERVER_NICENESS is
 * 	ensured as well.
 * @return the timeout in msec after the call.
 */
int cluster_rto_floor(struct infra_cache* infra,
	struct sockaddr_storage* addr, socklen_t addrlen, time_t now,
	int min_rto);

/* ---- routing primitives, exported for the unit tests ---- */

/**
 * Calculate the node id for a peer address.  It is the siphash of the
 * canonical text "ip@port" with the fixed cluster seed, so that all nodes
 * agree on it independent of how the address was written in the config.
 * @param addr: peer address.
 * @param addrlen: length of addr.
 * @return the node id.
 */
uint64_t cluster_node_id(struct sockaddr_storage* addr, socklen_t addrlen);

/**
 * Highest random weight score of a node for a name.
 * siphash 64 bit over node_id (8 bytes big endian) followed by the
 * lowercased wireformat qname, with the fixed cluster seed.
 * @param node_id: the node.
 * @param qname: uncompressed wireformat name.
 * @param qname_len: length of qname.
 * @return the score.
 */
uint64_t cluster_hrw_score(uint64_t node_id, uint8_t* qname,
	size_t qname_len);

/**
 * Select the node with the highest score.
 * @param node_ids: array of node ids.
 * @param n: number of nodes.
 * @param qname: uncompressed wireformat name.
 * @param qname_len: length of qname.
 * @param skip: NULL, or array of n bytes, nonzero entries are not
 * 	considered.
 * @return index of the best node, or -1 if none.  A tie is broken by the
 * 	lowest index.
 */
int cluster_hrw_select(const uint64_t* node_ids, size_t n, uint8_t* qname,
	size_t qname_len, const uint8_t* skip);

/**
 * Encode the CLUSTER option data.
 * @param buf: CLUSTER_OPT_LEN bytes.
 * @param flags: the CLUSTER_FLAG_ bits.
 * @param node_id: the node id of the sender.
 */
void cluster_opt_encode(uint8_t* buf, uint8_t flags, uint64_t node_id);

/**
 * Decode the CLUSTER option.
 * @param opt: the option.
 * @param flags: returns the flags.
 * @param node_id: returns the node id.
 * @return false if the length or the version is not understood.
 */
int cluster_opt_decode(struct edns_option* opt, uint8_t* flags,
	uint64_t* node_id);

/**
 * Check the option list for a peer query.
 * @param list: the edns option list of a query, can be NULL.
 * @return 1 if the list has a valid CLUSTER option with the PEER flag,
 * 	0 if there is no CLUSTER option, and -1 if there is a CLUSTER option
 * 	that is not understood (unknown version, bad length or no PEER flag).
 */
int cluster_edns_peer_check(struct edns_option* list);

/**
 * For the mesh: the value for the unique member of the mesh state of a
 * query, so that queries of cluster peers only merge with queries of the
 * same kind: recursive peer queries with each other, and cache only
 * probes with each other, never with normal queries.
 * A CLUSTER option in a query from an address that is not in the
 * cluster-peer list is removed from the options, the query is handled
 * like a normal client query.  This stops clients from using the cache
 * only probe to look into the cache without access-control allow_snoop.
 * @param mesh: the mesh, with the module stack and env.
 * @param edns: the edns data of the query, the option list can be changed.
 * @param rep: the reply information with the client address.
 * @return NULL for a normal query, or the shared marker for the kind.
 */
void* cluster_mesh_unique(struct mesh_area* mesh, struct edns_data* edns,
	struct comm_reply* rep);

/**
 * The kind of peer query in the options, the marker for the unique member
 * of the mesh state, see cluster_mesh_unique.  The source address is not
 * checked here.
 * @param opt_list: the edns options of the query, can be NULL.
 * @return NULL for a normal query, or the shared marker for the kind.
 */
void* cluster_peer_kind(struct edns_option* opt_list);

/**
 * See if the address is one of the cluster peers.  Only the IP address is
 * compared, not the port, since the queries of a peer come from a random
 * port.
 * @param ce: cluster env.
 * @param addr: the address.
 * @param addrlen: length of addr.
 * @return true if it is the address of a peer.
 */
int cluster_addr_is_peer(struct cluster_env* ce,
	struct sockaddr_storage* addr, socklen_t addrlen);

/* ---- accessors for the statistics and status output ---- */

/**
 * Find the cluster environment.
 * @param mods: the module stack.
 * @param env: the module env, with the modinfo array.
 * @return the cluster_env, or NULL if the cluster module is not in use.
 */
struct cluster_env* cluster_env_find(struct module_stack* mods,
	struct module_env* env);

/**
 * Sum the snapshots of the statistics of all threads, those taken by the
 * last statistics request.  Called from the remote control thread, after
 * the statistics of every thread have been obtained.
 * @param ce: cluster env.
 * @param total: the sum.
 */
void cluster_get_stats(struct cluster_env* ce, struct cluster_stats* total);

/**
 * Copy the live counters of a thread to its snapshot.  Called in that
 * thread, from server_stats_compile.  The reset of the live counters is
 * done by cluster_stats_clear_thread, called from worker_stats_clear.
 * @param ce: cluster env.
 * @param thread_num: the thread, the caller is this thread.
 */
void cluster_stats_snapshot(struct cluster_env* ce, int thread_num);

/**
 * Reset the live counters of a thread.  Called in that thread, from
 * worker_stats_clear (stats reset, flush_stats and the statistics
 * interval).
 * @param ce: cluster env.
 * @param thread_num: the thread, the caller is this thread.
 */
void cluster_stats_clear_thread(struct cluster_env* ce, int thread_num);

/**
 * Get the owner of a name and the full rank order of the peers.
 * @param ce: cluster env.
 * @param qname: uncompressed wireformat name.
 * @param qname_len: length of qname.
 * @param order: array of ce->num_peers, filled with the peer indexes in
 * 	order of decreasing score.
 * @param scores: array of ce->num_peers, the scores, in the rank order.
 */
void cluster_rank(struct cluster_env* ce, uint8_t* qname, size_t qname_len,
	size_t* order, uint64_t* scores);

/**
 * Callback to print a line of output, for the status output and
 * statistics.  The caller sets it up to print to the remote control
 * connection.
 * @param arg: user argument.
 * @param format: printf style format.
 * @return false if printing failed and the output must stop.
 */
typedef int (*cluster_print_cb)(void* arg, const char* format, ...);

/**
 * Print the cluster statistics lines, "cluster.name=value", for the
 * stats command.  Prints nothing if the cluster module is not in use.
 * The counters are the snapshots that were taken when the statistics were
 * compiled by every thread.  In multi-process (fork) operation the
 * counters of the other processes are not visible.
 * @param env: module env of the worker, with the module stack.
 * @param cb: print callback.
 * @param arg: argument for the callback.
 * @return false if the callback failed.
 */
int cluster_print_stats(struct module_env* env, cluster_print_cb cb,
	void* arg);

/**
 * The cluster_status remote control command.  Prints the self address,
 * the settings and the peer table.  Prints an error if the module is not
 * enabled.  Reads the shared peer table under the peer locks.
 * @param env: module env of the worker that handles the command.
 * @param cb: print callback.
 * @param arg: argument for the callback.
 * @param multiproc: true if running in several processes without thread
 * 	support, then a note is printed that only this process is shown.
 * @param scan: if true, also scan the message cache and print how many
 * 	entries are owned by this node.  The cost is proportional to the
 * 	size of the cache and it runs in the calling thread.
 */
void cluster_cmd_status(struct module_env* env, cluster_print_cb cb,
	void* arg, int multiproc, int scan);

/**
 * The cluster_lookup remote control command.  Prints the owner ranking
 * for the name and whether it is in the local message cache.  Prints an
 * error if the module is not enabled or the name does not parse.
 * @param env: module env of the worker that handles the command.
 * @param cb: print callback.
 * @param arg: argument for the callback.
 * @param name: the name, text format.
 */
void cluster_cmd_lookup(struct module_env* env, cluster_print_cb cb,
	void* arg, const char* name);

#endif /* CLUSTER_CLUSTER_H */
