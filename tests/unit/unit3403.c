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
#include "unitcheck.h"

#ifdef USE_DNSSEC
#include "vdns/dnssec.h"
#include "curlx/base64.h"
#include "curlx/dynbuf.h"
#include "dnssec-vectors.h"

/* DNSSEC validation of recorded responses, see dnssec-vectors.py */

static const struct t3403_msg *t3403_find(const struct t3403_msg *table,
                                          const char *name, uint16_t qtype)
{
  if(table) {
    for(; table->name; table++) {
      if((table->type == qtype) && curl_strequal(table->name, name))
        return table;
    }
  }
  return NULL;
}

static CURLcode t3403_decode(const char *const *pieces, uint8_t **pmsg,
                             size_t *plen)
{
  struct dynbuf b64;
  CURLcode result = CURLE_OK;
  curlx_dyn_init(&b64, 1 << 20);
  for(; *pieces && !result; pieces++)
    result = curlx_dyn_add(&b64, *pieces);
  if(!result)
    result = curlx_base64_decode(curlx_dyn_ptr(&b64), pmsg, plen);
  curlx_dyn_free(&b64);
  return result;
}

/* answer the queries the validator asks for from the tables */
static CURLcode t3403_answer(struct Curl_dnssec_ctx *ctx,
                             const struct t3403_case *c)
{
  char name[CURL_DNSSEC_NAME_STRLEN];
  uint16_t qtype;
  CURLcode result = CURLE_OK;

  while(!result && Curl_dnssec_ctx_next_query(ctx, name, sizeof(name),
                                              &qtype)) {
    const struct t3403_msg *m = t3403_find(c->override, name, qtype);
    if(!m)
      m = t3403_find(c->table, name, qtype);
    if(m) {
      uint8_t *msg = NULL;
      size_t len = 0;
      result = t3403_decode(m->msg, &msg, &len);
      if(!result)
        result = Curl_dnssec_ctx_add_response(ctx, name, qtype, msg, len);
      curlx_free(msg);
    }
    else
      result = Curl_dnssec_ctx_add_failure(ctx, name, qtype);
  }
  return result;
}

static bool t3403_run(const struct t3403_case *c)
{
  struct Curl_dnssec_ctx *ctx = NULL;
  struct Curl_dnssec_req *req = NULL;
  Curl_dnssec_status status;
  const char *reason;
  int rounds = 0;
  bool ok = FALSE;
  CURLcode result;

  result = Curl_dnssec_ctx_create(&ctx);
  if(result)
    goto out;
  if(c->anchors) {
    const char *const *a;
    Curl_dnssec_ctx_clear_anchors(ctx);
    for(a = c->anchors; *a && !result; a++)
      result = Curl_dnssec_ctx_add_anchor(ctx, *a);
    if(result)
      goto out;
  }
  Curl_dnssec_ctx_set_time(ctx, (time_t)c->now);
  Curl_dnssec_ctx_set_flags(ctx, c->flags);
  result = Curl_dnssec_req_create(ctx, c->qname, (uint16_t)c->qtype, &req);
  if(result)
    goto out;

  for(;;) {
    result = Curl_dnssec_req_run(req);
    if(result != CURLE_AGAIN)
      break;
    if(++rounds > 100) {
      curl_mfprintf(stderr, "%s: does not finish\n", c->desc);
      goto out;
    }
    result = t3403_answer(ctx, c);
    if(result)
      goto out;
  }
  if(result)
    goto out;

  status = Curl_dnssec_req_status(req);
  reason = Curl_dnssec_req_reason(req);
  ok = (status == c->status) &&
       ((c->rcode < 0) || (Curl_dnssec_req_rcode(req) == c->rcode)) &&
       ((c->count < 0) ||
        (Curl_dnssec_req_count(req) == (size_t)c->count));
  if(ok && (status == CURL_DNSSEC_SECURE) && reason) {
    curl_mfprintf(stderr, "%s: secure with a reason\n", c->desc);
    ok = FALSE;
  }
  if(ok && (status != CURL_DNSSEC_SECURE) && !reason) {
    curl_mfprintf(stderr, "%s: no reason\n", c->desc);
    ok = FALSE;
  }
  if(ok && Curl_dnssec_req_count(req)) {
    const unsigned char *rdata;
    size_t rdlen;
    size_t count = Curl_dnssec_req_count(req);
    ok = Curl_dnssec_req_rdata(req, count - 1, &rdata, &rdlen) &&
         !Curl_dnssec_req_rdata(req, count, &rdata, &rdlen);
  }
  curl_mfprintf(stderr, "%s%s: %s %s rcode %d count %zu ttl %u%s%s\n",
                ok ? "" : "FAILED ", c->desc, c->qname,
                Curl_dnssec_status_str(status), Curl_dnssec_req_rcode(req),
                Curl_dnssec_req_count(req), Curl_dnssec_req_ttl(req),
                reason ? ": " : "", reason ? reason : "");
  if(!ok)
    curl_mfprintf(stderr, "  expected %s rcode %d count %d\n",
                  Curl_dnssec_status_str(c->status), c->rcode, c->count);

out:
  if(result)
    curl_mfprintf(stderr, "%s: error %d\n", c->desc, (int)result);
  Curl_dnssec_req_destroy(req);
  Curl_dnssec_ctx_destroy(ctx);
  return ok;
}

/* API corner cases */
static void t3403_api(void)
{
  struct Curl_dnssec_ctx *ctx = NULL;
  struct Curl_dnssec_req *req = NULL;
  const struct t3403_msg *m;
  char name[CURL_DNSSEC_NAME_STRLEN];
  uint16_t qtype;
  uint8_t *msg = NULL;
  size_t len = 0;

  abort_if(Curl_dnssec_ctx_create(&ctx), "create");
  fail_unless(Curl_dnssec_req_create(ctx, "example.com", 255, &req) ==
              CURLE_BAD_FUNCTION_ARGUMENT, "ANY is refused");
  fail_unless(Curl_dnssec_req_create(ctx, "a..b", 1, &req) ==
              CURLE_BAD_FUNCTION_ARGUMENT, "bad name is refused");
  fail_unless(Curl_dnssec_ctx_add_failure(ctx, "example.com.", 1) ==
              CURLE_BAD_FUNCTION_ARGUMENT, "not asked for");

  /* a response to another question is a failed lookup */
  abort_if(Curl_dnssec_req_create(ctx, "www.nsec.test.", 1, &req), "req");
  Curl_dnssec_ctx_clear_anchors(ctx);
  fail_unless(Curl_dnssec_req_run(req) == CURLE_AGAIN, "run");
  fail_unless(Curl_dnssec_ctx_pending(ctx) == 1, "one query");
  fail_unless(Curl_dnssec_ctx_next_query(ctx, name, sizeof(name), &qtype) &&
              !strcmp(name, "www.nsec.test.") && (qtype == 1), "query");
  fail_if(Curl_dnssec_ctx_next_query(ctx, name, sizeof(name), &qtype),
          "each query is returned once");
  m = t3403_find(t3403_bind, "www.nsec.test.", 16);
  abort_unless(m && !t3403_decode(m->msg, &msg, &len), "TXT response");
  fail_unless(!Curl_dnssec_ctx_add_response(ctx, "www.nsec.test.", 1, msg,
                                            len), "add");
  fail_unless(!Curl_dnssec_ctx_pending(ctx), "no queries");
  fail_unless(!Curl_dnssec_req_run(req), "done");
  fail_unless(Curl_dnssec_req_status(req) == CURL_DNSSEC_INDETERMINATE,
              "indeterminate");
  fail_unless(!Curl_dnssec_req_count(req), "no records");

unit_test_abort:
  curlx_free(msg);
  Curl_dnssec_req_destroy(req);
  Curl_dnssec_ctx_destroy(ctx);
}

static CURLcode test_unit3403(const char *arg)
{
  UNITTEST_BEGIN_SIMPLE

  size_t i;
  for(i = 0; i < CURL_ARRAYSIZE(t3403_cases); i++) {
    if(!t3403_run(&t3403_cases[i]))
      unitfail++;
  }
  t3403_api();

  UNITTEST_END_SIMPLE
}

#else /* !USE_DNSSEC */

static CURLcode test_unit3403(const char *arg)
{
  UNITTEST_BEGIN_SIMPLE
  UNITTEST_END_SIMPLE
}

#endif
