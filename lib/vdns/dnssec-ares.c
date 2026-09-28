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

#include "vdns/dnssec.h"
#include <ares.h>

#if ARES_VERSION < 0x011c00
#error "c-ares 1.28.0 or greater required for DNSSEC"
#endif

/* The EDNS0 UDP payload size to announce, as recommended by the DNS flag
   day 2020. Larger responses come over TCP, c-ares handles that. */
#define DNSSEC_EDNS_SIZE 1232
/* the DO bit in the EDNS0 flags, RFC 3225 */
#define DNSSEC_EDNS_DO   0x8000

struct dnssec_ares_job {
  struct dnssec_ares_job *next;
  struct Curl_dnssec_req *req;
  Curl_dnssec_ares_cb *cb;
  void *userp;
};

/* one query in flight */
struct dnssec_ares_query {
  struct dnssec_ares_query *next;
  struct Curl_dnssec_ares *da; /* NULL when the driver is gone */
  uint16_t qtype;
  char name[CURL_DNSSEC_NAME_STRLEN];
};

struct Curl_dnssec_ares {
  ares_channel_t *channel;
  struct Curl_dnssec_ctx *ctx;
  struct dnssec_ares_job *jobs;
  struct dnssec_ares_query *queries;
  BIT(running);
  BIT(again);
  BIT(stopped); /* the channel is going away, send no more queries */
  BIT(destroy); /* destroyed from a callback, when done running */
};

static void dnssec_ares_progress(struct Curl_dnssec_ares *da);
static void dnssec_ares_free(struct Curl_dnssec_ares *da);

static void query_unlink(struct Curl_dnssec_ares *da,
                         struct dnssec_ares_query *q)
{
  struct dnssec_ares_query **pp;
  for(pp = &da->queries; *pp; pp = &(*pp)->next) {
    if(*pp == q) {
      *pp = q->next;
      break;
    }
  }
}

static void dnssec_ares_cb(void *arg, ares_status_t status, size_t timeouts,
                           const ares_dns_record_t *dnsrec)
{
  struct dnssec_ares_query *q = arg;
  struct Curl_dnssec_ares *da = q->da;
  (void)timeouts;

  if(da) {
    unsigned char *buf = NULL;
    size_t len = 0;
    CURLcode result = CURLE_OK;

    query_unlink(da, q);
    if((status == ARES_ECANCELLED) || (status == ARES_EDESTRUCTION))
      da->stopped = TRUE;
    /* c-ares has parsed the response. Records it knows are written back
       as they were, those it does not know (like all the DNSSEC ones) are
       kept as raw RDATA. */
    if((status == ARES_SUCCESS) && dnsrec &&
       (ares_dns_write(dnsrec, &buf, &len) == ARES_SUCCESS)) {
      result = Curl_dnssec_ctx_add_response(da->ctx, q->name, q->qtype,
                                            buf, len);
      ares_free_string(buf);
    }
    else
      result = Curl_dnssec_ctx_add_failure(da->ctx, q->name, q->qtype);
    (void)result;
    dnssec_ares_progress(da);
  }
  curlx_free(q);
}

static CURLcode dnssec_ares_send(struct Curl_dnssec_ares *da,
                                 const char *name, uint16_t qtype)
{
  ares_dns_record_t *rec = NULL;
  ares_dns_rr_t *opt = NULL;
  struct dnssec_ares_query *q;
  ares_status_t status;

  q = curlx_calloc(1, sizeof(*q));
  if(!q)
    return CURLE_OUT_OF_MEMORY;
  q->da = da;
  q->qtype = qtype;
  curl_msnprintf(q->name, sizeof(q->name), "%s", name);

  /* RD and CD set (RFC 6840 section 5.9), DO set in EDNS0 */
  status = ares_dns_record_create(&rec, 0,
                                  (unsigned short)(ARES_FLAG_RD |
                                                   ARES_FLAG_CD),
                                  ARES_OPCODE_QUERY, ARES_RCODE_NOERROR);
  if(status == ARES_SUCCESS)
    status = ares_dns_record_query_add(rec, name,
                                       (ares_dns_rec_type_t)qtype,
                                       ARES_CLASS_IN);
  if(status == ARES_SUCCESS)
    status = ares_dns_record_rr_add(&opt, rec, ARES_SECTION_ADDITIONAL, "",
                                    ARES_REC_TYPE_OPT, ARES_CLASS_IN, 0);
  if(status == ARES_SUCCESS)
    status = ares_dns_rr_set_u16(opt, ARES_RR_OPT_UDP_SIZE,
                                 DNSSEC_EDNS_SIZE);
  if(status == ARES_SUCCESS)
    status = ares_dns_rr_set_u8(opt, ARES_RR_OPT_VERSION, 0);
  if(status == ARES_SUCCESS)
    status = ares_dns_rr_set_u16(opt, ARES_RR_OPT_FLAGS, DNSSEC_EDNS_DO);
  if(status != ARES_SUCCESS) {
    ares_dns_record_destroy(rec);
    curlx_free(q);
    return (status == ARES_ENOMEM) ? CURLE_OUT_OF_MEMORY :
      CURLE_COULDNT_RESOLVE_HOST;
  }

  q->next = da->queries;
  da->queries = q;
  /* this may call the callback right away */
  status = ares_send_dnsrec(da->channel, rec, dnssec_ares_cb, q, NULL);
  ares_dns_record_destroy(rec);
  (void)status; /* failures are reported through the callback */
  return CURLE_OK;
}

static void dnssec_ares_progress(struct Curl_dnssec_ares *da)
{
  if(da->running) {
    /* called from a callback while sending, run again when done */
    da->again = TRUE;
    return;
  }
  da->running = TRUE;
  do {
    struct dnssec_ares_job **pp = &da->jobs;
    char name[CURL_DNSSEC_NAME_STRLEN];
    uint16_t qtype;

    da->again = FALSE;
    while(*pp && !da->destroy) {
      struct dnssec_ares_job *job = *pp;
      if(Curl_dnssec_req_run(job->req) == CURLE_AGAIN) {
        pp = &job->next;
        continue;
      }
      *pp = job->next;
      job->cb(job->userp, job->req);
      Curl_dnssec_req_destroy(job->req);
      curlx_free(job);
    }
    while(!da->destroy &&
          Curl_dnssec_ctx_next_query(da->ctx, name, sizeof(name), &qtype)) {
      if(da->stopped || dnssec_ares_send(da, name, qtype)) {
        (void)Curl_dnssec_ctx_add_failure(da->ctx, name, qtype);
        da->again = TRUE;
      }
    }
  } while(da->again && !da->destroy);
  da->running = FALSE;
  if(da->destroy)
    dnssec_ares_free(da);
}

/* The c-ares query cache keys responses by the query type's name, and
   every type c-ares does not know (like DS and DNSKEY) has the same one.
   With the cache on, a DNSKEY query can get a cached DS response. */
static bool dnssec_ares_qcache_off(ares_channel_t *channel)
{
  struct ares_options opts;
  int optmask = 0;
  bool off;
  memset(&opts, 0, sizeof(opts));
  if(ares_save_options(channel, &opts, &optmask) != ARES_SUCCESS)
    return FALSE;
  off = (optmask & ARES_OPT_QUERY_CACHE) && !opts.qcache_max_ttl;
  ares_destroy_options(&opts);
  return off;
}

CURLcode Curl_dnssec_ares_create(struct Curl_dnssec_ares **pda,
                                 ares_channel_t *channel,
                                 struct Curl_dnssec_ctx *ctx)
{
  struct Curl_dnssec_ares *da;
  *pda = NULL;
  if(!dnssec_ares_qcache_off(channel))
    return CURLE_BAD_FUNCTION_ARGUMENT;
  da = curlx_calloc(1, sizeof(*da));
  if(!da)
    return CURLE_OUT_OF_MEMORY;
  da->channel = channel;
  da->ctx = ctx;
  *pda = da;
  return CURLE_OK;
}

void Curl_dnssec_ares_destroy(struct Curl_dnssec_ares *da)
{
  if(!da)
    return;
  if(da->running) {
    /* called from a callback, free it when the callback returns */
    da->destroy = TRUE;
    return;
  }
  dnssec_ares_free(da);
}

static void dnssec_ares_free(struct Curl_dnssec_ares *da)
{
  while(da->jobs) {
    struct dnssec_ares_job *job = da->jobs;
    da->jobs = job->next;
    Curl_dnssec_req_destroy(job->req);
    curlx_free(job);
  }
  /* the query structs are freed by their callbacks, which c-ares calls
     at the latest when the channel is destroyed */
  while(da->queries) {
    struct dnssec_ares_query *q = da->queries;
    da->queries = q->next;
    q->da = NULL;
  }
  curlx_free(da);
}

CURLcode Curl_dnssec_ares_validate(struct Curl_dnssec_ares *da,
                                   const char *name, uint16_t qtype,
                                   Curl_dnssec_ares_cb *cb, void *userp)
{
  struct dnssec_ares_job *job;
  CURLcode result;

  job = curlx_calloc(1, sizeof(*job));
  if(!job)
    return CURLE_OUT_OF_MEMORY;
  result = Curl_dnssec_req_create(da->ctx, name, qtype, &job->req);
  if(result) {
    curlx_free(job);
    return result;
  }
  job->cb = cb;
  job->userp = userp;
  job->next = da->jobs;
  da->jobs = job;
  dnssec_ares_progress(da);
  return CURLE_OK;
}

size_t Curl_dnssec_ares_active(struct Curl_dnssec_ares *da)
{
  struct dnssec_ares_job *job;
  size_t n = 0;
  for(job = da->jobs; job; job = job->next)
    n++;
  return n;
}

#endif /* USE_DNSSEC */
