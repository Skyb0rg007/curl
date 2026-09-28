#ifndef HEADER_CURL_DNSSEC_H
#define HEADER_CURL_DNSSEC_H
/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
 *
 * This software is licensed as described in the file COPYING, which
 * you should have received as part of this distribution. The terms
 * are also available at https://curl.se/docs/copyright.html.
 *
 * You may opt to use, copy, modify, merge, publish, distribute and/or sell
 * copies of the Software, and permit persons to whom the Software is
 * furnished to do so, under the terms of the COPYING file.
 *
 * This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
 * KIND, either express or implied.
 *
 * SPDX-License-Identifier: curl
 *
 ***************************************************************************/
#include "curl_setup.h"

#ifdef USE_DNSSEC

#if !defined(USE_ARES) || !defined(USE_OPENSSL)
#error "DNSSEC validation needs c-ares and OpenSSL"
#endif

/*
 * DNSSEC validation (RFC 4033, 4034, 4035, 5155, 6840 and friends).
 *
 * The validator itself does no I/O. It is fed complete DNS response
 * messages and tells its user which queries it needs answers for, so the
 * same code can be driven by c-ares (see dnssec-ares.c), by DoH or by a
 * test harness.
 *
 * All queries the validator asks for must be sent with the DO bit set (in
 * an EDNS0 OPT record) and the CD bit set (RFC 6840 section 5.9) to a
 * recursive resolver. The resolver is not trusted: everything it returns is
 * validated from the configured trust anchors (by default, the DNS root
 * KSKs) down.
 *
 * Usage:
 *
 *   Curl_dnssec_ctx_create(&ctx);
 *   Curl_dnssec_req_create(ctx, "_443._tcp.example.com", 52, &req);
 *   while(Curl_dnssec_req_run(req) == CURLE_AGAIN) {
 *     while(Curl_dnssec_ctx_next_query(ctx, name, sizeof(name), &qtype))
 *       ... send query, and when the response arrives:
 *       Curl_dnssec_ctx_add_response(ctx, name, qtype, msg, msglen);
 *       ... or if the query failed:
 *       Curl_dnssec_ctx_add_failure(ctx, name, qtype);
 *   }
 *   status = Curl_dnssec_req_status(req);
 *
 * A context holds trust anchors, all responses and cached zone keys. Many
 * requests can share one context and then also share the DNSKEY and DS
 * lookups. A context is meant to live for the duration of a name
 * resolve or a transfer, not forever: it has fixed upper limits on the
 * number of queries and the amount of cryptographic work it does, as
 * protection against resource exhaustion attacks (like CVE-2023-50387,
 * "KeyTrap").
 */

/* Resource record types used by the validator and its users */
#define CURL_DNSSEC_TYPE_A          1
#define CURL_DNSSEC_TYPE_NS         2
#define CURL_DNSSEC_TYPE_CNAME      5
#define CURL_DNSSEC_TYPE_SOA        6
#define CURL_DNSSEC_TYPE_AAAA       28
#define CURL_DNSSEC_TYPE_DNAME      39
#define CURL_DNSSEC_TYPE_DS         43
#define CURL_DNSSEC_TYPE_RRSIG      46
#define CURL_DNSSEC_TYPE_NSEC       47
#define CURL_DNSSEC_TYPE_DNSKEY     48
#define CURL_DNSSEC_TYPE_NSEC3      50
#define CURL_DNSSEC_TYPE_TLSA       52
#define CURL_DNSSEC_TYPE_SVCB       64
#define CURL_DNSSEC_TYPE_HTTPS      65

/* Maximum length of a domain name in presentation format, with all
   characters escaped as \DDD, plus a terminating zero */
#define CURL_DNSSEC_NAME_STRLEN     1010

/* The security status of a DNS answer, RFC 4033 section 5 and RFC 4035
   section 4.3 */
typedef enum {
  /* Validation did not complete: a lookup failed (timeout, SERVFAIL),
     there is no trust anchor covering the name, or a resource limit was
     hit. The answer is neither proven secure nor proven insecure, and
     security decisions MUST treat it like CURL_DNSSEC_BOGUS. */
  CURL_DNSSEC_INDETERMINATE = 0,
  /* A chain of trust from a trust anchor proves the answer (or its
     nonexistence) authentic. */
  CURL_DNSSEC_SECURE,
  /* A chain of trust from a trust anchor proves that the answer comes from
     an unsigned part of the DNS (or one only signed with algorithms we do
     not accept). */
  CURL_DNSSEC_INSECURE,
  /* The answer should be signed but validation failed: missing or bad
     signatures, broken chain of trust, invalid denial of existence. */
  CURL_DNSSEC_BOGUS
} Curl_dnssec_status;

/* Context flags */
/* Accept the SHA-1 based signature algorithms RSASHA1 (5) and
   RSASHA1-NSEC3-SHA1 (7). By default they are treated as unsupported,
   making zones signed only with them insecure, as RFC 9905 requires of
   validating resolver operators. */
#define CURL_DNSSEC_ALLOW_SHA1      (1 << 0)

struct Curl_dnssec_ctx;
struct Curl_dnssec_req;

/* Create a validation context, with the root zone trust anchors (the
   KSK-2017 and KSK-2024 key digests published by IANA) installed. */
CURLcode Curl_dnssec_ctx_create(struct Curl_dnssec_ctx **pctx);

/* Destroy the context. All requests created on it must be destroyed
   first. */
void Curl_dnssec_ctx_destroy(struct Curl_dnssec_ctx *ctx);

/* Remove all trust anchors, including the built-in ones. */
void Curl_dnssec_ctx_clear_anchors(struct Curl_dnssec_ctx *ctx);

/* Add a trust anchor, given as a DS or DNSKEY record in presentation
   (zone file) format. Set the trust anchors before creating requests:
   results are cached in the context. Like:
     ". IN DS 20326 8 2 E06D44B80B8F1D39A95C0B0D7C65D08458E880409B..."
   The TTL and class are optional, the owner name is required. A zone with
   trust anchors is trusted through them only, its parent is not asked. */
CURLcode Curl_dnssec_ctx_add_anchor(struct Curl_dnssec_ctx *ctx,
                                    const char *rr);

/* Set CURL_DNSSEC_* flags */
void Curl_dnssec_ctx_set_flags(struct Curl_dnssec_ctx *ctx,
                               unsigned int flags);

/* Validate signatures against this time (seconds since the epoch) instead
   of the current time. Zero means the current time. */
void Curl_dnssec_ctx_set_time(struct Curl_dnssec_ctx *ctx, time_t now);

/* Get the next query the validator wants answered. Copies the query name
   in presentation format (with a trailing dot) to 'name', which needs to
   be at least CURL_DNSSEC_NAME_STRLEN bytes, and sets 'qtype'. Each query
   is returned once. Returns FALSE when there are no more queries to send
   at this time. */
bool Curl_dnssec_ctx_next_query(struct Curl_dnssec_ctx *ctx,
                                char *name, size_t namelen,
                                uint16_t *qtype);

/* Add the response message for a query returned by
   Curl_dnssec_ctx_next_query(). The message is copied. The question in the
   message must match the query. A message that cannot be parsed is stored
   as a failed lookup and makes validation depending on it end as
   CURL_DNSSEC_INDETERMINATE (or bogus, where appropriate). Returns
   CURLE_OK when the response was stored. */
CURLcode Curl_dnssec_ctx_add_response(struct Curl_dnssec_ctx *ctx,
                                      const char *name, uint16_t qtype,
                                      const unsigned char *msg,
                                      size_t msglen);

/* Mark a query as failed, like for a timeout or a SERVFAIL response. */
CURLcode Curl_dnssec_ctx_add_failure(struct Curl_dnssec_ctx *ctx,
                                     const char *name, uint16_t qtype);

/* Number of queries asked for that have no response or failure yet. */
size_t Curl_dnssec_ctx_pending(struct Curl_dnssec_ctx *ctx);

/* Create a request to validate the answer for 'name' and 'qtype' (class
   IN). 'name' is in presentation format. */
CURLcode Curl_dnssec_req_create(struct Curl_dnssec_ctx *ctx,
                                const char *name, uint16_t qtype,
                                struct Curl_dnssec_req **preq);

void Curl_dnssec_req_destroy(struct Curl_dnssec_req *req);

/* Advance the validation with the responses available in the context.
   Returns CURLE_AGAIN when more responses are needed (fetch them with
   Curl_dnssec_ctx_next_query()), CURLE_OK when validation is complete (the
   result can be any of the status values) or an error code, like
   CURLE_OUT_OF_MEMORY, when validation cannot go on. */
CURLcode Curl_dnssec_req_run(struct Curl_dnssec_req *req);

/* The result of a completed request */
Curl_dnssec_status Curl_dnssec_req_status(const struct Curl_dnssec_req *req);

/* A human readable explanation of why the request did not end as
   CURL_DNSSEC_SECURE, or NULL. */
const char *Curl_dnssec_req_reason(const struct Curl_dnssec_req *req);

/* The DNS response code for the final name: 0 (NOERROR) or 3 (NXDOMAIN).
   When the zone uses compact denial of existence (RFC 9824), an
   authenticated NXNAME signal also results in 3. */
int Curl_dnssec_req_rcode(const struct Curl_dnssec_req *req);

/* The name the answer records are owned by after following CNAME and
   DNAME records, in presentation format. */
const char *Curl_dnssec_req_final_name(const struct Curl_dnssec_req *req);

/* The TTL the validated answer can be cached for: the minimum of the
   record TTLs, their signatures' original TTLs and the time left until
   the signatures expire. */
uint32_t Curl_dnssec_req_ttl(const struct Curl_dnssec_req *req);

/* The number of records of the requested type in the answer. */
size_t Curl_dnssec_req_count(const struct Curl_dnssec_req *req);

/* Get the RDATA of answer record 'idx' (0 <= idx < count), in canonical
   form (RFC 4034 section 6.2): domain names in it are not compressed, and
   in lowercase for the record types listed there. The pointer is valid
   until the request is destroyed. Returns FALSE for a bad index. */
bool Curl_dnssec_req_rdata(const struct Curl_dnssec_req *req, size_t idx,
                           const unsigned char **prdata, size_t *prdlen);

/* Return a text description of a status */
const char *Curl_dnssec_status_str(Curl_dnssec_status status);

/*
 * Driving validation with c-ares.
 *
 * Sends the queries a context needs on a c-ares channel, adds the
 * responses to the context and runs the requests. The owner of the channel
 * processes its events as usual (like with Curl_ares_perform()), the
 * callbacks happen from within that processing.
 */
#include <ares.h>

struct Curl_dnssec_ares;

/* Called when validation of a request is complete. The request is
   destroyed when the callback returns. */
typedef void Curl_dnssec_ares_cb(void *userp, struct Curl_dnssec_req *req);

/* Create a driver for 'ctx' sending queries on 'channel'. Neither is
   owned by the driver, but both must live longer than it. The channel must
   have the c-ares query cache disabled (ARES_OPT_QUERY_CACHE with a
   qcache_max_ttl of zero): it mixes up responses for different query
   types c-ares does not know, like DS and DNSKEY.
   Using TCP (ARES_FLAG_USEVC) is recommended: DNSSEC responses are large,
   and c-ares fails truncated UDP responses that end in the middle of a
   record (like systemd-resolved sends) instead of retrying over TCP. */
CURLcode Curl_dnssec_ares_create(struct Curl_dnssec_ares **pda,
                                 ares_channel_t *channel,
                                 struct Curl_dnssec_ctx *ctx);

/* Destroy the driver. Requests not completed are dropped without their
   callbacks being called. Queries still in flight are forgotten. */
void Curl_dnssec_ares_destroy(struct Curl_dnssec_ares *da);

/* Start validating the answer for 'name' and 'qtype'. 'cb' is called on
   completion, which may happen before this function returns. */
CURLcode Curl_dnssec_ares_validate(struct Curl_dnssec_ares *da,
                                   const char *name, uint16_t qtype,
                                   Curl_dnssec_ares_cb *cb, void *userp);

/* Number of requests not completed yet */
size_t Curl_dnssec_ares_active(struct Curl_dnssec_ares *da);

#endif /* USE_DNSSEC */
#endif /* HEADER_CURL_DNSSEC_H */
