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
#include "vdns/dnssec-int.h"
#include "curlx/dynbuf.h"
#include "curlx/base64.h"

/*
 * The DNSSEC validator.
 *
 * Validation of an answer is a pure function of the responses collected in
 * the context. Curl_dnssec_req_run() evaluates it from the start every
 * time it is called. When a response it needs is missing, it asks for the
 * query (see query_get()) and the evaluation ends as pending. Once all
 * the responses it asked for are there, the next run gets further. The
 * results of expensive steps (validated zone keys, validated RRsets) are
 * cached, so repeating the evaluation is cheap.
 *
 * The chain of trust is built bottom-up from the signer names in RRSIG
 * records (RFC 4035 section 5): the keys of a signer zone are trusted if
 * the zone's DNSKEY RRset is signed by a key matching a trust anchor or a
 * validated DS RRset from the parent zone, whose keys are in turn trusted
 * the same way.
 *
 * Unsigned data is only accepted as insecure after a top-down walk from
 * the trust anchor has proven, with validated DS denials, that it is
 * below a delegation to an unsigned zone (see walk_down()). Anything else
 * is bogus.
 */

/* Upper limits, to bound the work an attacker can make us do */
#define DNSSEC_MAX_QUERIES      128 /* queries per context */
#define DNSSEC_MAX_VERIFY       128 /* signature verifications per context */
#define DNSSEC_MAX_KEY_TRIES    4   /* keys tried per RRSIG (same key tag) */
#define DNSSEC_MAX_SIGS         8   /* RRSIGs tried per RRset and signer */
#define DNSSEC_MAX_SIGNERS      3   /* signer zones tried per RRset */
#define DNSSEC_MAX_RRSET        256 /* records in an RRset */
#define DNSSEC_MAX_DENIAL       16  /* NSEC/NSEC3 records used in a proof */
#define DNSSEC_MAX_DS           16  /* DS records looked at */
#define DNSSEC_MAX_ZONEKEYS     32  /* DNSKEY records looked at */
#define DNSSEC_MAX_CHAIN        12  /* CNAME and DNAME links */
#define DNSSEC_MAX_DEPTH        300 /* recursion depth */
#define DNSSEC_MAX_ZONES        24  /* nested zones in a chain of trust */
#define DNSSEC_MAX_NSEC3_HASH   1024 /* NSEC3 hash calculations per context */
#define DNSSEC_MAX_BYTES        (4 * 1024 * 1024) /* response data kept */
/* NSEC3 records with more iterations are treated as insecure (RFC 9276
   section 3.2), like BIND, Knot and PowerDNS do */
#define DNSSEC_NSEC3_MAX_ITER   50

#define DNSSEC_NONE ((size_t)-1)

/* evaluation status */
typedef enum {
  VS_PENDING = 0,  /* waiting for responses */
  VS_SECURE,
  VS_INSECURE,
  VS_BOGUS,
  VS_INDETERMINATE
} vstat;

/* query states */
#define Q_WANTED  0
#define Q_SENT    1
#define Q_DONE    2

struct dnssec_query {
  struct dnssec_query *next;
  struct dnssec_msg *msg;         /* response, NULL if the query failed */
  uint8_t name[DNSSEC_NAME_MAX];  /* in lowercase */
  uint16_t qtype;
  uint8_t state;
  /* for a DS query: the proof walk_down() got from it */
  uint8_t wstat;
  uint8_t wfact;
  uint8_t wparent;  /* labels in the zone above, plus one */
};

struct dnssec_anchor {
  struct dnssec_anchor *next;
  uint8_t name[DNSSEC_NAME_MAX];
  uint8_t *rdata;
  uint16_t rdlen;
  uint16_t type;                  /* DS or DNSKEY */
};

/* the validated keys of a zone, or why there are none */
struct dnssec_zone {
  struct dnssec_zone *next;
  uint8_t name[DNSSEC_NAME_MAX];
  struct dnssec_msg *msg;         /* message with the DNSKEY RRset */
  size_t keys[DNSSEC_MAX_ZONEKEYS];
  size_t nkeys;
  char reason[160];
  vstat status;
};

struct Curl_dnssec_ctx {
  struct dnssec_anchor *anchors;
  struct dnssec_query *queries;
  struct dnssec_zone *zones;
  time_t fixed_now;
  unsigned int flags;
  unsigned int nqueries;
  unsigned int nverify;
  unsigned int nhash;
  size_t nbytes;
};

struct Curl_dnssec_req {
  struct Curl_dnssec_ctx *ctx;
  struct dnssec_msg *amsg;        /* message with the answer RRset */
  size_t afirst;                  /* the first answer record in 'amsg' */
  size_t acount;
  struct dynbuf rdata;            /* the answer RDATA, in canonical form */
  size_t *rdoffs;                 /* where each one starts, acount + 1 */
  uint32_t ttl;
  int rcode;
  Curl_dnssec_status status;
  uint16_t qtype;
  uint8_t qname[DNSSEC_NAME_MAX];
  char final_name[CURL_DNSSEC_NAME_STRLEN];
  char reason[256];
  BIT(done);
};

/* state of one evaluation run */
struct vctx {
  struct Curl_dnssec_ctx *ctx;
  struct Curl_dnssec_req *req;
  CURLcode error;                 /* fatal error, like out of memory */
  uint32_t now;
  unsigned int depth;
  unsigned int nactive;
  const uint8_t *active[DNSSEC_MAX_ZONES];  /* zone_keys() in progress */
  char reason[256];               /* the latest reason for a failure */
  /* for names in reasons, here to keep them off the recursive frames */
  char nb[3][CURL_DNSSEC_NAME_STRLEN];
};

/* validated NSEC or NSEC3 records from one zone in one response */
struct nsecs {
  struct dnssec_msg *m;
  size_t rr[DNSSEC_MAX_DENIAL];
  size_t n;
  uint8_t zone[DNSSEC_NAME_MAX];
  uint32_t ttl;
  bool nsec3;
  /* NSEC3 parameters, the same for all records used */
  const uint8_t *salt;
  uint8_t saltlen;
  uint16_t iterations;
};

/* A parsed RRSIG */
struct dnssec_sig {
  const uint8_t *rdata;
  const uint8_t *sig;
  size_t siglen;
  uint32_t ttl;
  uint32_t origttl;
  uint32_t expire;
  uint32_t incept;
  uint16_t covered;
  uint16_t keytag;
  uint8_t alg;
  uint8_t labels;
  uint8_t signer[DNSSEC_NAME_MAX];
};

/* facts a DS denial proves */
typedef enum {
  DS_UNSIGNED_CUT,   /* a delegation without DS records */
  DS_OPTOUT,         /* in an NSEC3 opt-out span, maybe a delegation */
  DS_NOT_CUT,        /* the name exists, but is no delegation */
  DS_NO_NAME         /* the name does not exist */
} dsfact;

static vstat zone_keys(struct vctx *v, const uint8_t *zone,
                       struct dnssec_zone **pz);
static vstat walk_down(struct vctx *v, const uint8_t *name, uint8_t *zone);
static vstat answer_rrset(struct vctx *v, struct dnssec_msg *m, size_t first,
                          uint32_t *pttl);

static uint16_t rd16(const uint8_t *p)
{
  return (uint16_t)((p[0] << 8) | p[1]);
}

static uint32_t rd32(const uint8_t *p)
{
  return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
         ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

static void why(struct vctx *v, const char *fmt, ...) CURL_PRINTF(2, 3);

static void why(struct vctx *v, const char *fmt, ...)
{
  va_list ap;
  va_start(ap, fmt);
  (void)curl_mvsnprintf(v->reason, sizeof(v->reason), fmt, ap);
  va_end(ap);
}

/* presentation format of a name, for reason texts */
#define NAMESTR(n, buf) (Curl_dnssec_name_str(n, buf, sizeof(buf)), buf)

static const char *typestr(uint16_t type, char *buf, size_t len)
{
  switch(type) {
  case CURL_DNSSEC_TYPE_A:
    return "A";
  case CURL_DNSSEC_TYPE_NS:
    return "NS";
  case CURL_DNSSEC_TYPE_CNAME:
    return "CNAME";
  case CURL_DNSSEC_TYPE_SOA:
    return "SOA";
  case CURL_DNSSEC_TYPE_AAAA:
    return "AAAA";
  case CURL_DNSSEC_TYPE_DNAME:
    return "DNAME";
  case CURL_DNSSEC_TYPE_DS:
    return "DS";
  case CURL_DNSSEC_TYPE_NSEC:
    return "NSEC";
  case CURL_DNSSEC_TYPE_DNSKEY:
    return "DNSKEY";
  case CURL_DNSSEC_TYPE_NSEC3:
    return "NSEC3";
  case CURL_DNSSEC_TYPE_TLSA:
    return "TLSA";
  case CURL_DNSSEC_TYPE_HTTPS:
    return "HTTPS";
  default:
    curl_msnprintf(buf, len, "TYPE%u", type);
    return buf;
  }
}

static vstat vs_oom(struct vctx *v)
{
  v->error = CURLE_OUT_OF_MEMORY;
  why(v, "out of memory");
  return VS_INDETERMINATE;
}

/* Is the signature algorithm acceptable? */
static bool alg_ok(struct Curl_dnssec_ctx *ctx, uint8_t alg)
{
  if(((alg == DNSSEC_ALG_RSASHA1) || (alg == DNSSEC_ALG_RSASHA1_NSEC3)) &&
     !(ctx->flags & CURL_DNSSEC_ALLOW_SHA1))
    return FALSE;
  return Curl_dnssec_alg_supported(alg);
}

/*
 * Queries
 */

static struct dnssec_query *query_find(struct Curl_dnssec_ctx *ctx,
                                       const uint8_t *name, uint16_t qtype)
{
  struct dnssec_query *q;
  for(q = ctx->queries; q; q = q->next) {
    if((q->qtype == qtype) && Curl_dnssec_name_eq(q->name, name))
      return q;
  }
  return NULL;
}

/* Get the response for a query. Returns VS_SECURE (meaning "here it is")
   with *pmsg set, VS_PENDING when the query is not answered yet (and asks
   for it if it was not asked for before) or VS_INDETERMINATE when the
   query failed. */
static vstat query_get(struct vctx *v, const uint8_t *name, uint16_t qtype,
                       struct dnssec_msg **pmsg)
{
  struct Curl_dnssec_ctx *ctx = v->ctx;
  struct dnssec_query *q = query_find(ctx, name, qtype);
  char tbuf[16];

  *pmsg = NULL;
  if(!q) {
    if(ctx->nqueries >= DNSSEC_MAX_QUERIES) {
      why(v, "too many queries");
      return VS_INDETERMINATE;
    }
    q = curlx_calloc(1, sizeof(*q));
    if(!q)
      return vs_oom(v);
    Curl_dnssec_name_lower(q->name, name);
    q->qtype = qtype;
    q->state = Q_WANTED;
    q->next = ctx->queries;
    ctx->queries = q;
    ctx->nqueries++;
    return VS_PENDING;
  }
  if(q->state != Q_DONE)
    return VS_PENDING;
  if(!q->msg) {
    why(v, "lookup of %s %s failed", NAMESTR(name, v->nb[0]),
        typestr(qtype, tbuf, sizeof(tbuf)));
    return VS_INDETERMINATE;
  }
  if((q->msg->rcode != DNSSEC_RCODE_NOERROR) &&
     (q->msg->rcode != DNSSEC_RCODE_NXDOMAIN)) {
    why(v, "lookup of %s %s: response code %u", NAMESTR(name, v->nb[0]),
        typestr(qtype, tbuf, sizeof(tbuf)), q->msg->rcode);
    return VS_INDETERMINATE;
  }
  *pmsg = q->msg;
  return VS_SECURE;
}

/*
 * RRsets
 */

static bool rr_same_set(const struct dnssec_msg *m,
                        const struct dnssec_rr *a,
                        const struct dnssec_rr *b)
{
  return (a->section == b->section) && (a->type == b->type) &&
         (a->rclass == b->rclass) &&
         Curl_dnssec_name_eq(DNSSEC_RR_OWNER(m, a), DNSSEC_RR_OWNER(m, b));
}

/* Find the first record of the RRset 'name'/'type' in 'section' */
static size_t rrset_find(const struct dnssec_msg *m, uint8_t section,
                         const uint8_t *name, uint16_t type)
{
  size_t i;
  for(i = 0; i < m->nrrs; i++) {
    const struct dnssec_rr *rr = &m->rrs[i];
    if((rr->section == section) && (rr->type == type) &&
       (rr->rclass == DNSSEC_CLASS_IN) &&
       Curl_dnssec_name_eq(DNSSEC_RR_OWNER(m, rr), name))
      return i;
  }
  return DNSSEC_NONE;
}

/* Is 'i' the first record of its RRset? */
static bool rrset_first(const struct dnssec_msg *m, size_t i)
{
  size_t j;
  for(j = 0; j < i; j++) {
    if(rr_same_set(m, &m->rrs[j], &m->rrs[i]))
      return FALSE;
  }
  return TRUE;
}

/* Does RRSIG 'rr' cover the RRset starting at 'set'? */
static bool rrsig_covers(const struct dnssec_msg *m,
                         const struct dnssec_rr *rr,
                         const struct dnssec_rr *set)
{
  return (rr->type == CURL_DNSSEC_TYPE_RRSIG) &&
         (rr->section == set->section) && (rr->rclass == set->rclass) &&
         (rr->rdlen >= 18) &&
         (rd16(DNSSEC_RR_RDATA(m, rr)) == set->type) &&
         Curl_dnssec_name_eq(DNSSEC_RR_OWNER(m, rr), DNSSEC_RR_OWNER(m, set));
}

static bool sig_parse(const struct dnssec_msg *m, const struct dnssec_rr *rr,
                      struct dnssec_sig *s)
{
  const uint8_t *d = DNSSEC_RR_RDATA(m, rr);
  size_t off = 18;
  if(rr->rdlen < 18)
    return FALSE;
  /* the signer name is never compressed, RFC 4034 section 3.1.7 */
  if(Curl_dnssec_read_name(d, rr->rdlen, &off, FALSE, s->signer) ||
     (off >= rr->rdlen))
    return FALSE;
  Curl_dnssec_name_lower(s->signer, s->signer);
  s->rdata = d;
  s->covered = rd16(d);
  s->alg = d[2];
  s->labels = d[3];
  s->origttl = rd32(&d[4]);
  s->expire = rd32(&d[8]);
  s->incept = rd32(&d[12]);
  s->keytag = rd16(&d[16]);
  s->sig = &d[off];
  s->siglen = rr->rdlen - off;
  s->ttl = rr->ttl;
  return TRUE;
}

/* a <= b in serial number arithmetic, RFC 1982 */
static bool serial_le(uint32_t a, uint32_t b)
{
  return (int32_t)(b - a) >= 0;
}

struct canon_rdata {
  const uint8_t *p;
  size_t len;
};

static int canon_rdata_cmp(const void *a, const void *b)
{
  const struct canon_rdata *x = a;
  const struct canon_rdata *y = b;
  size_t len = (x->len < y->len) ? x->len : y->len;
  int rc = len ? memcmp(x->p, y->p, len) : 0;
  if(rc)
    return rc;
  return (x->len < y->len) ? -1 : ((x->len > y->len) ? 1 : 0);
}

/* Build the data an RRSIG signs, RFC 4034 section 3.1.8.1 and RFC 4035
   section 5.3.2 */
static CURLcode sig_data(const struct dnssec_msg *m, size_t first,
                         const struct dnssec_sig *s, struct dynbuf *out)
{
  const struct dnssec_rr *set = &m->rrs[first];
  const uint8_t *owner = DNSSEC_RR_OWNER(m, set);
  uint8_t name[DNSSEC_NAME_MAX];
  size_t namelen;
  struct dynbuf rd;
  struct canon_rdata *list = NULL;
  size_t *offs = NULL;
  size_t n = 0;
  size_t i;
  uint8_t hdr[10];
  CURLcode result = CURLE_OK;

  /* the owner name, with the wildcard restored */
  if(s->labels < Curl_dnssec_name_sig_labels(owner)) {
    const uint8_t *suffix = Curl_dnssec_name_suffix(owner, s->labels);
    name[0] = 1;
    name[1] = '*';
    memcpy(&name[2], suffix, Curl_dnssec_name_len(suffix));
  }
  else
    memcpy(name, owner, Curl_dnssec_name_len(owner));
  Curl_dnssec_name_lower(name, name);
  namelen = Curl_dnssec_name_len(name);

  /* RRSIG RDATA without the signature, with the signer in canonical form */
  if(curlx_dyn_addn(out, s->rdata, 18) ||
     curlx_dyn_addn(out, s->signer, Curl_dnssec_name_len(s->signer)))
    return CURLE_OUT_OF_MEMORY;

  curlx_dyn_init(&rd, DNSSEC_MAX_RRSET * 65536);
  offs = curlx_malloc(sizeof(size_t) * (DNSSEC_MAX_RRSET + 1));
  list = curlx_malloc(sizeof(struct canon_rdata) * DNSSEC_MAX_RRSET);
  if(!offs || !list) {
    result = CURLE_OUT_OF_MEMORY;
    goto out;
  }
  for(i = first; i < m->nrrs; i++) {
    if(!rr_same_set(m, &m->rrs[i], set))
      continue;
    if(n >= DNSSEC_MAX_RRSET) {
      result = CURLE_TOO_LARGE;
      goto out;
    }
    offs[n++] = curlx_dyn_len(&rd);
    result = Curl_dnssec_rdata_canonical(m, &m->rrs[i], &rd);
    if(result)
      goto out;
  }
  offs[n] = curlx_dyn_len(&rd);
  for(i = 0; i < n; i++) {
    list[i].p = curlx_dyn_uptr(&rd) + offs[i];
    list[i].len = offs[i + 1] - offs[i];
    if(list[i].len > 0xffff) {
      result = CURLE_TOO_LARGE;
      goto out;
    }
  }
  qsort(list, n, sizeof(struct canon_rdata), canon_rdata_cmp);

  hdr[0] = (uint8_t)(set->type >> 8);
  hdr[1] = (uint8_t)set->type;
  hdr[2] = (uint8_t)(set->rclass >> 8);
  hdr[3] = (uint8_t)set->rclass;
  memcpy(&hdr[4], &s->rdata[4], 4); /* original TTL */
  for(i = 0; i < n; i++) {
    /* RFC 4034 section 6.3: duplicates are only included once */
    if(i && !canon_rdata_cmp(&list[i - 1], &list[i]))
      continue;
    hdr[8] = (uint8_t)(list[i].len >> 8);
    hdr[9] = (uint8_t)list[i].len;
    if(curlx_dyn_addn(out, name, namelen) ||
       curlx_dyn_addn(out, hdr, sizeof(hdr)) ||
       (list[i].len && curlx_dyn_addn(out, list[i].p, list[i].len))) {
      result = CURLE_OUT_OF_MEMORY;
      goto out;
    }
  }

out:
  curlx_free(offs);
  curlx_free(list);
  curlx_dyn_free(&rd);
  return result;
}

/* Verify the RRset starting at 'first' in 'm' with an RRSIG made by
   'signer' and one of the DNSKEY records 'keys' (indexes into 'km').
   RFC 4035 section 5.3. On success, sets the TTL the RRset may be used
   for and the RRSIG Labels value of the signature. */
static vstat rrset_verify(struct vctx *v, const struct dnssec_msg *m,
                          size_t first, const uint8_t *signer,
                          const struct dnssec_msg *km, const size_t *keys,
                          size_t nkeys, uint32_t *pttl,
                          unsigned int *plabels)
{
  const struct dnssec_rr *set = &m->rrs[first];
  const uint8_t *owner = DNSSEC_RR_OWNER(m, set);
  unsigned int olabels = Curl_dnssec_name_sig_labels(owner);
  unsigned int tries = 0;
  char tbuf[16];
  struct dynbuf data;
  size_t i;
  vstat result = VS_BOGUS;

  curlx_dyn_init(&data, DNSSEC_MAX_RRSET * 65536);
  why(v, "no valid signature for %s %s", NAMESTR(owner, v->nb[0]),
      typestr(set->type, tbuf, sizeof(tbuf)));

  for(i = 0; i < m->nrrs; i++) {
    const struct dnssec_rr *rr = &m->rrs[i];
    struct dnssec_sig s;
    unsigned int ktries = 0;
    size_t k;

    if(!rrsig_covers(m, rr, set) || !sig_parse(m, rr, &s) ||
       !Curl_dnssec_name_eq(s.signer, signer))
      continue;
    /* RFC 4035 section 5.3.1 */
    if(s.labels > olabels) {
      why(v, "RRSIG for %s %s has a bad label count", NAMESTR(owner, v->nb[0]),
          typestr(set->type, tbuf, sizeof(tbuf)));
      continue;
    }
    if(!alg_ok(v->ctx, s.alg)) {
      why(v, "RRSIG for %s %s uses unsupported algorithm %u",
          NAMESTR(owner, v->nb[0]), typestr(set->type, tbuf, sizeof(tbuf)),
          s.alg);
      continue;
    }
    if(!serial_le(s.incept, s.expire) || !serial_le(v->now, s.expire)) {
      why(v, "RRSIG for %s %s has expired", NAMESTR(owner, v->nb[0]),
          typestr(set->type, tbuf, sizeof(tbuf)));
      continue;
    }
    if(!serial_le(s.incept, v->now)) {
      why(v, "RRSIG for %s %s is not valid yet", NAMESTR(owner, v->nb[0]),
          typestr(set->type, tbuf, sizeof(tbuf)));
      continue;
    }
    /* only signatures that can be valid count, junk ones must not hide
       them (RFC 6840 5.4) */
    if(++tries > DNSSEC_MAX_SIGS)
      break;
    curlx_dyn_reset(&data);
    if(sig_data(m, first, &s, &data)) {
      why(v, "cannot build signed data for %s %s", NAMESTR(owner, v->nb[0]),
          typestr(set->type, tbuf, sizeof(tbuf)));
      continue;
    }

    for(k = 0; k < nkeys; k++) {
      const struct dnssec_rr *key = &km->rrs[keys[k]];
      const uint8_t *kd = DNSSEC_RR_RDATA(km, key);
      CURLcode rc;
      if((kd[3] != s.alg) || (Curl_dnssec_keytag(kd, key->rdlen) != s.keytag))
        continue;
      if(++ktries > DNSSEC_MAX_KEY_TRIES)
        break;
      if(v->ctx->nverify >= DNSSEC_MAX_VERIFY) {
        why(v, "too many signature verifications");
        result = VS_INDETERMINATE;
        goto out;
      }
      v->ctx->nverify++;
      rc = Curl_dnssec_verify(s.alg, kd + 4, key->rdlen - 4u,
                              curlx_dyn_uptr(&data), curlx_dyn_len(&data),
                              s.sig, s.siglen);
      if(!rc) {
        /* RFC 4035 section 5.3.3 */
        uint32_t ttl = s.ttl;
        size_t j;
        if(s.origttl < ttl)
          ttl = s.origttl;
        if(s.expire - v->now < ttl)
          ttl = s.expire - v->now;
        for(j = first; j < m->nrrs; j++) {
          if(rr_same_set(m, &m->rrs[j], set) && (m->rrs[j].ttl < ttl))
            ttl = m->rrs[j].ttl;
        }
        *pttl = ttl;
        *plabels = s.labels;
        result = VS_SECURE;
        goto out;
      }
      if(rc == CURLE_OUT_OF_MEMORY) {
        result = vs_oom(v);
        goto out;
      }
      why(v, "RRSIG for %s %s by key %u does not verify",
          NAMESTR(owner, v->nb[0]), typestr(set->type, tbuf, sizeof(tbuf)),
          s.keytag);
    }
  }
out:
  curlx_dyn_free(&data);
  return result;
}

static int rank(vstat r)
{
  /* the order of preference when there are several ways to validate */
  switch(r) {
  case VS_SECURE:
    return 4;
  case VS_INSECURE:
    return 3;
  case VS_INDETERMINATE:
    return 2;
  default:
    return 1;
  }
}


/* The closest trust anchor at or above 'name', or NULL */
static const uint8_t *deepest_anchor(struct Curl_dnssec_ctx *ctx,
                                     const uint8_t *name)
{
  struct dnssec_anchor *a;
  const uint8_t *ta = NULL;
  for(a = ctx->anchors; a; a = a->next) {
    if(Curl_dnssec_name_sub(name, a->name) &&
       (!ta || (Curl_dnssec_name_labels(a->name) >
                Curl_dnssec_name_labels(ta))))
      ta = a->name;
  }
  return ta;
}

/* The lowest TTL in the RRset starting at 'first', RFC 2181 5.2 */
static uint32_t rrset_ttl(const struct dnssec_msg *m, size_t first)
{
  uint32_t ttl = m->rrs[first].ttl;
  size_t i;
  for(i = first + 1; i < m->nrrs; i++) {
    if(rr_same_set(m, &m->rrs[i], &m->rrs[first]) && (m->rrs[i].ttl < ttl))
      ttl = m->rrs[i].ttl;
  }
  return ttl;
}

/* Is the record at 'first' the only one in its RRset? */
static bool rrset_single(const struct dnssec_msg *m, size_t first)
{
  size_t i;
  for(i = first + 1; i < m->nrrs; i++) {
    if(rr_same_set(m, &m->rrs[i], &m->rrs[first]))
      return FALSE;
  }
  return TRUE;
}

/* Does the RRset starting at 'first' have an RRSIG made by 'signer'? */
static bool rrset_signed_by(const struct dnssec_msg *m, size_t first,
                            const uint8_t *signer)
{
  size_t i;
  for(i = 0; i < m->nrrs; i++) {
    struct dnssec_sig s;
    if(rrsig_covers(m, &m->rrs[i], &m->rrs[first]) &&
       sig_parse(m, &m->rrs[i], &s) && Curl_dnssec_name_eq(s.signer, signer))
      return TRUE;
  }
  return FALSE;
}

/* Validate the RRset starting at 'first', with the keys of the zones that
   signed it. An unsigned RRset is insecure when walk_down() proves it is
   in an unsigned zone, and bogus otherwise. On success, sets the TTL the
   RRset may be used for, the RRSIG Labels value of the signature and the
   signer (a pointer into the owner name). */
static vstat rrset_validate(struct vctx *v, struct dnssec_msg *m,
                            size_t first, uint32_t *pttl,
                            unsigned int *plabels, const uint8_t **psigner)
{
  struct dnssec_rr *set = &m->rrs[first];
  const uint8_t *owner = DNSSEC_RR_OWNER(m, set);
  const uint8_t *ta = deepest_anchor(v->ctx, owner);
  unsigned int olabels = Curl_dnssec_name_labels(owner);
  unsigned int tlabels = ta ? Curl_dnssec_name_labels(ta) : 0;
  /* the signers seen, by their number of labels: they are all at or above
     the owner name */
  bool cand[DNSSEC_LABELS_MAX + 1];
  unsigned int ncand = 0;
  unsigned int tries = 0;
  unsigned int l;
  bool have_sig = FALSE;
  bool pending = FALSE;
  vstat best = VS_BOGUS;
  char tbuf[16];
  size_t i;

  *pttl = rrset_ttl(m, first);
  *plabels = Curl_dnssec_name_sig_labels(owner);
  *psigner = NULL;
  if(set->vstat) {
    *pttl = set->vttl;
    if(set->vstat == VS_SECURE) {
      *plabels = set->vlabels;
      *psigner = Curl_dnssec_name_suffix(owner, set->vsigner);
    }
    return (vstat)set->vstat;
  }

  memset(cand, 0, sizeof(cand));
  for(i = 0; i < m->nrrs; i++) {
    const struct dnssec_rr *rr = &m->rrs[i];
    struct dnssec_sig s;
    unsigned int sl;
    bool ok;
    if(!rrsig_covers(m, rr, set))
      continue;
    have_sig = TRUE;
    if(!sig_parse(m, rr, &s))
      continue;
    /* RFC 4035 5.3.1: the signer is the zone that contains the RRset. The
       DNSKEY RRset is at the zone apex, the DS RRset is in the parent. */
    sl = Curl_dnssec_name_labels(s.signer);
    if(set->type == CURL_DNSSEC_TYPE_DNSKEY)
      ok = (sl == olabels);
    else if(set->type == CURL_DNSSEC_TYPE_DS)
      ok = (sl < olabels);
    else
      ok = TRUE;
    /* Only zones at or below the closest trust anchor. Above it, an
       unsigned zone would make the data look insecure. */
    if(ok && ta && (sl >= tlabels) && Curl_dnssec_name_sub(owner, s.signer) &&
       !cand[sl]) {
      cand[sl] = TRUE;
      ncand++;
    }
  }

  if(!have_sig) {
    vstat r = walk_down(v, owner, NULL);
    if(r == VS_SECURE) {
      why(v, "%s %s is not signed", NAMESTR(owner, v->nb[0]),
          typestr(set->type, tbuf, sizeof(tbuf)));
      r = VS_BOGUS;
    }
    if((r != VS_PENDING) && !v->error) {
      set->vstat = (uint8_t)r;
      set->vttl = *pttl;
    }
    return r;
  }
  if(!ta) {
    why(v, "no trust anchor for %s", NAMESTR(owner, v->nb[0]));
    return VS_INDETERMINATE;
  }
  if(!ncand) {
    why(v, "RRSIG for %s %s has a bad signer name",
        NAMESTR(owner, v->nb[0]), typestr(set->type, tbuf, sizeof(tbuf)));
    set->vstat = VS_BOGUS;
    set->vttl = *pttl;
    return VS_BOGUS;
  }

  /* the closest zone first, it is the one that should have signed */
  for(l = olabels + 1; l-- > tlabels;) {
    const uint8_t *signer = Curl_dnssec_name_suffix(owner, l);
    struct dnssec_zone *z;
    vstat r;
    if(!cand[l])
      continue;
    if(++tries > DNSSEC_MAX_SIGNERS)
      break;
    r = zone_keys(v, signer, &z);
    if(r == VS_PENDING) {
      pending = TRUE;
      continue;
    }
    if(r == VS_SECURE) {
      r = rrset_verify(v, m, first, z->name, z->msg, z->keys, z->nkeys,
                       pttl, plabels);
      if(r == VS_SECURE) {
        set->vstat = VS_SECURE;
        set->vttl = *pttl;
        set->vlabels = (uint8_t)*plabels;
        set->vsigner = (uint8_t)l;
        *psigner = signer;
        return VS_SECURE;
      }
    }
    if(rank(r) > rank(best))
      best = r;
  }
  *pttl = rrset_ttl(m, first);
  *plabels = Curl_dnssec_name_sig_labels(owner);
  if(pending)
    return VS_PENDING;
  if(!v->error) {
    set->vstat = (uint8_t)best;
    set->vttl = *pttl;
  }
  return best;
}

/*
 * Zone keys and the chain of trust
 */

static struct dnssec_zone *zone_find(struct Curl_dnssec_ctx *ctx,
                                     const uint8_t *name)
{
  struct dnssec_zone *z;
  for(z = ctx->zones; z; z = z->next) {
    if(Curl_dnssec_name_eq(z->name, name))
      return z;
  }
  return NULL;
}

static bool anchored(struct Curl_dnssec_ctx *ctx, const uint8_t *zone)
{
  struct dnssec_anchor *a;
  for(a = ctx->anchors; a; a = a->next) {
    if(Curl_dnssec_name_eq(a->name, zone))
      return TRUE;
  }
  return FALSE;
}

/* Is there a trust anchor at or above 'name'? */
static bool covered(struct Curl_dnssec_ctx *ctx, const uint8_t *name)
{
  struct dnssec_anchor *a;
  for(a = ctx->anchors; a; a = a->next) {
    if(Curl_dnssec_name_sub(name, a->name))
      return TRUE;
  }
  return FALSE;
}

struct dsref {
  const uint8_t *rdata;
  size_t rdlen;
};

static void ds_add(struct Curl_dnssec_ctx *ctx, struct dsref *ds,
                   size_t *pnds, const uint8_t *rdata, size_t rdlen)
{
  /* RFC 4035 5.2 and RFC 6840 5.2: DS records for unsupported algorithms
     and digest types are disregarded */
  if((*pnds < DNSSEC_MAX_DS) && (rdlen > 4) && alg_ok(ctx, rdata[2]) &&
     Curl_dnssec_digest_supported(rdata[3])) {
    ds[*pnds].rdata = rdata;
    ds[*pnds].rdlen = rdlen;
    (*pnds)++;
  }
}

/* Validate the DNSKEY RRset of zone 'z' in 'km' with the trust anchors of
   the zone or the validated DS RRset starting at 'dfirst' in 'dm'. RFC
   4035 section 5.2. */
static vstat dnskey_validate(struct vctx *v, struct dnssec_zone *z,
                             struct dnssec_msg *km,
                             const struct dnssec_msg *dm, size_t dfirst,
                             bool by_anchor)
{
  struct Curl_dnssec_ctx *ctx = v->ctx;
  struct dsref ds[DNSSEC_MAX_DS];
  struct dsref tk[DNSSEC_MAX_DS];
  size_t sep[DNSSEC_MAX_ZONEKEYS];
  size_t nds = 0;
  size_t ntk = 0;
  size_t nsep = 0;
  size_t looked = 0;
  bool sha2 = FALSE;
  size_t kfirst;
  size_t olen;
  size_t i;
  uint32_t ttl;
  unsigned int labels;
  vstat r;

  kfirst = rrset_find(km, DNSSEC_SECT_ANSWER, z->name,
                      CURL_DNSSEC_TYPE_DNSKEY);
  if(kfirst == DNSSEC_NONE) {
    why(v, "no DNSKEY records for %s", NAMESTR(z->name, v->nb[0]));
    return VS_BOGUS;
  }

  if(by_anchor) {
    struct dnssec_anchor *a;
    for(a = ctx->anchors; a; a = a->next) {
      if(!Curl_dnssec_name_eq(a->name, z->name))
        continue;
      if(a->type == CURL_DNSSEC_TYPE_DS)
        ds_add(ctx, ds, &nds, a->rdata, a->rdlen);
      else if((ntk < DNSSEC_MAX_DS) && alg_ok(ctx, a->rdata[3])) {
        tk[ntk].rdata = a->rdata;
        tk[ntk].rdlen = a->rdlen;
        ntk++;
      }
    }
  }
  else {
    for(i = dfirst; i < dm->nrrs; i++) {
      if(rr_same_set(dm, &dm->rrs[i], &dm->rrs[dfirst]))
        ds_add(ctx, ds, &nds, DNSSEC_RR_RDATA(dm, &dm->rrs[i]),
               dm->rrs[i].rdlen);
    }
  }
  if(!nds && !ntk) {
    why(v, "no supported algorithms in the DS records of %s",
        NAMESTR(z->name, v->nb[0]));
    return VS_INSECURE;
  }
  /* RFC 4509 section 3: ignore SHA-1 DS records when there are SHA-2
     ones */
  for(i = 0; i < nds; i++) {
    if(ds[i].rdata[3] != DNSSEC_DIGEST_SHA1)
      sha2 = TRUE;
  }

  /* find the keys the DS records or trust anchors point to */
  olen = Curl_dnssec_name_len(z->name);
  for(i = kfirst; (i < km->nrrs) && (nsep < DNSSEC_MAX_ZONEKEYS); i++) {
    const struct dnssec_rr *rr = &km->rrs[i];
    const uint8_t *kd = DNSSEC_RR_RDATA(km, rr);
    uint16_t flags;
    uint16_t tag;
    bool match = FALSE;
    size_t j;
    if(!rr_same_set(km, rr, &km->rrs[kfirst]))
      continue;
    if(++looked > DNSSEC_MAX_ZONEKEYS * 2)
      break;
    if(rr->rdlen < 5)
      continue;
    flags = rd16(kd);
    if((kd[2] != 3) || !(flags & DNSSEC_DNSKEY_ZONE) ||
       (flags & DNSSEC_DNSKEY_REVOKE) || !alg_ok(ctx, kd[3]))
      continue;
    for(j = 0; (j < ntk) && !match; j++) {
      /* compare protocol, algorithm and key, not the flags */
      match = (tk[j].rdlen == rr->rdlen) &&
              !memcmp(tk[j].rdata + 2, kd + 2, rr->rdlen - 2u);
    }
    tag = Curl_dnssec_keytag(kd, rr->rdlen);
    for(j = 0; (j < nds) && !match; j++) {
      const uint8_t *d = ds[j].rdata;
      uint8_t digest[DNSSEC_DIGEST_MAX];
      size_t dlen;
      if((rd16(d) != tag) || (d[2] != kd[3]) ||
         (sha2 && (d[3] == DNSSEC_DIGEST_SHA1)))
        continue;
      /* digest = hash(owner name | DNSKEY RDATA), RFC 4034 section 5.1.4.
         z->name is in lowercase. */
      dlen = Curl_dnssec_digest(d[3], z->name, olen, kd, rr->rdlen, digest);
      match = dlen && (dlen == ds[j].rdlen - 4) &&
              !memcmp(digest, d + 4, dlen);
    }
    if(match)
      sep[nsep++] = i;
  }
  if(!nsep) {
    why(v, "no DNSKEY of %s matches its %s", NAMESTR(z->name, v->nb[0]),
        by_anchor ? "trust anchor" : "DS records");
    return VS_BOGUS;
  }

  r = rrset_verify(v, km, kfirst, z->name, km, sep, nsep, &ttl, &labels);
  if(r != VS_SECURE)
    return r;
  if(labels != Curl_dnssec_name_sig_labels(z->name)) {
    why(v, "DNSKEY RRSIG for %s has a bad label count",
        NAMESTR(z->name, v->nb[0]));
    return VS_BOGUS;
  }
  km->rrs[kfirst].vstat = VS_SECURE;
  km->rrs[kfirst].vttl = ttl;
  km->rrs[kfirst].vlabels = (uint8_t)labels;
  km->rrs[kfirst].vsigner = (uint8_t)Curl_dnssec_name_labels(z->name);

  /* Any key of the zone can sign data in it, RFC 6840 section 6.2 */
  z->msg = km;
  z->nkeys = 0;
  for(i = kfirst; (i < km->nrrs) && (z->nkeys < DNSSEC_MAX_ZONEKEYS); i++) {
    const struct dnssec_rr *rr = &km->rrs[i];
    const uint8_t *kd = DNSSEC_RR_RDATA(km, rr);
    if(!rr_same_set(km, rr, &km->rrs[kfirst]) || (rr->rdlen < 5))
      continue;
    if((kd[2] == 3) && (rd16(kd) & DNSSEC_DNSKEY_ZONE) &&
       !(rd16(kd) & DNSSEC_DNSKEY_REVOKE))
      z->keys[z->nkeys++] = i;
  }
  return VS_SECURE;
}

/*
 * Denial of existence
 */

static bool map_has(const uint8_t *map, size_t len, uint16_t type)
{
  bool bad;
  /* the maps are checked when collected */
  return Curl_dnssec_bitmap_has(map, len, type, &bad);
}

/* The next name and type bit map of NSEC record 'idx' */
static void nsec_fields(const struct nsecs *ns, size_t idx,
                        uint8_t next[DNSSEC_NAME_MAX],
                        const uint8_t **pmap, size_t *pmaplen)
{
  const struct dnssec_rr *rr = &ns->m->rrs[ns->rr[idx]];
  const uint8_t *d = DNSSEC_RR_RDATA(ns->m, rr);
  size_t off = 0;
  /* the record was checked when collected */
  (void)Curl_dnssec_read_name(d, rr->rdlen, &off, FALSE, next);
  *pmap = d + off;
  *pmaplen = rr->rdlen - off;
}

/* The next hash, flags and type bit map of NSEC3 record 'idx' */
static void n3_fields(const struct nsecs *ns, size_t idx,
                      const uint8_t **pnext, uint8_t *pflags,
                      const uint8_t **pmap, size_t *pmaplen)
{
  const struct dnssec_rr *rr = &ns->m->rrs[ns->rr[idx]];
  const uint8_t *d = DNSSEC_RR_RDATA(ns->m, rr);
  size_t off = 5 + (size_t)d[4] + 1;
  *pflags = d[1];
  *pnext = d + off;
  *pmap = d + off + DNSSEC_NSEC3_HASHLEN;
  *pmaplen = rr->rdlen - off - DNSSEC_NSEC3_HASHLEN;
}

/* Check the fields of an NSEC or NSEC3 record, and that it can be used
   together with the records already collected. */
static bool nsec_check(struct nsecs *ns, const struct dnssec_rr *rr)
{
  const struct dnssec_msg *m = ns->m;
  const uint8_t *d = DNSSEC_RR_RDATA(m, rr);
  const uint8_t *owner = DNSSEC_RR_OWNER(m, rr);
  uint8_t name[DNSSEC_NAME_MAX];
  uint8_t hash[DNSSEC_NSEC3_HASHLEN];
  size_t off = 0;
  bool bad;

  if(rr->type == CURL_DNSSEC_TYPE_NSEC) {
    if(Curl_dnssec_read_name(d, rr->rdlen, &off, FALSE, name))
      return FALSE;
  }
  else {
    size_t saltlen;
    /* RFC 5155 8.1 and 8.2: ignore unknown hash algorithms and flags */
    if((rr->rdlen < 6) || (d[0] != DNSSEC_NSEC3_SHA1) || (d[1] > 1))
      return FALSE;
    saltlen = d[4];
    off = 5 + saltlen + 1 + DNSSEC_NSEC3_HASHLEN;
    if((off > rr->rdlen) || (d[5 + saltlen] != DNSSEC_NSEC3_HASHLEN))
      return FALSE;
    /* the owner is the base32hex hash as a label below the zone */
    if((Curl_dnssec_name_labels(owner) !=
        Curl_dnssec_name_labels(ns->zone) + 1) || (owner[0] != 32) ||
       (Curl_dnssec_b32hex_decode(&owner[1], 32, hash, sizeof(hash)) !=
        DNSSEC_NSEC3_HASHLEN))
      return FALSE;
    /* RFC 5155 8.2: all records in a proof use the same parameters */
    if(ns->n && ((ns->iterations != rd16(&d[2])) ||
                 (ns->saltlen != saltlen) ||
                 (saltlen && memcmp(ns->salt, &d[5], saltlen))))
      return FALSE;
    if(!ns->n) {
      ns->iterations = rd16(&d[2]);
      ns->saltlen = (uint8_t)saltlen;
      ns->salt = &d[5];
    }
  }
  (void)Curl_dnssec_bitmap_has(d + off, rr->rdlen - off, 0, &bad);
  return !bad;
}

/* Collect and validate the NSEC or NSEC3 records in the authority section
   of 'm' that can prove something about 'sname'. They must all come from
   one zone: 'known' when the caller knows the zone that holds 'sname',
   otherwise the closest zone above 'sname' that signed any, or with
   'parent' set, the closest one strictly above it (for DS, which is in the
   parent zone). Without signed records, walk_down() decides if the
   response is insecure, unless 'known' is set. */
static vstat denial_collect(struct vctx *v, struct dnssec_msg *m,
                            const uint8_t *sname, bool parent,
                            const uint8_t *known, struct nsecs *ns)
{
  struct dnssec_zone *z;
  const uint8_t *ta = deepest_anchor(v->ctx, sname);
  unsigned int tlabels = 0;
  bool have_signer = FALSE;
  bool self = FALSE;
  size_t i;
  vstat r;

  memset(ns, 0, sizeof(*ns));
  ns->m = m;
  ns->ttl = 0xffffffff;
  if(ta)
    tlabels = Curl_dnssec_name_labels(ta);

  for(i = 0; i < m->nrrs; i++) {
    const struct dnssec_rr *rr = &m->rrs[i];
    uint16_t covered;
    struct dnssec_sig s;
    if((rr->section != DNSSEC_SECT_AUTHORITY) ||
       (rr->type != CURL_DNSSEC_TYPE_RRSIG) || (rr->rdlen < 18))
      continue;
    covered = rd16(DNSSEC_RR_RDATA(m, rr));
    /* only zones at or below the closest trust anchor, see
       rrset_validate() */
    if(((covered != CURL_DNSSEC_TYPE_NSEC) &&
        (covered != CURL_DNSSEC_TYPE_NSEC3)) || !sig_parse(m, rr, &s) ||
       !ta || !Curl_dnssec_name_sub(sname, s.signer) ||
       (Curl_dnssec_name_labels(s.signer) < tlabels))
      continue;
    if(parent && Curl_dnssec_name_eq(sname, s.signer)) {
      self = TRUE;
      continue;
    }
    if(!have_signer || (Curl_dnssec_name_labels(s.signer) >
                        Curl_dnssec_name_labels(ns->zone))) {
      memcpy(ns->zone, s.signer, DNSSEC_NAME_MAX);
      have_signer = TRUE;
    }
  }

  if(!have_signer) {
    if(self) {
      why(v, "DS for %s is denied by the zone itself instead of its parent",
          NAMESTR(sname, v->nb[0]));
      return VS_BOGUS;
    }
    r = known ? VS_SECURE : walk_down(v, sname, NULL);
    if(r == VS_SECURE) {
      why(v, "no signed NSEC or NSEC3 records for %s",
          NAMESTR(sname, v->nb[0]));
      r = VS_BOGUS;
    }
    return r;
  }
  if(known && !Curl_dnssec_name_eq(ns->zone, known)) {
    why(v, "denial of existence for %s is from %s instead of %s",
        NAMESTR(sname, v->nb[0]), NAMESTR(ns->zone, v->nb[1]),
        NAMESTR(known, v->nb[2]));
    return VS_BOGUS;
  }

  r = zone_keys(v, ns->zone, &z);
  if(r != VS_SECURE)
    return r;

  for(i = 0; (i < m->nrrs) && (ns->n < DNSSEC_MAX_DENIAL); i++) {
    const struct dnssec_rr *rr = &m->rrs[i];
    const uint8_t *signer;
    unsigned int labels;
    uint32_t ttl;
    size_t j;
    if((rr->section != DNSSEC_SECT_AUTHORITY) ||
       (rr->rclass != DNSSEC_CLASS_IN) ||
       ((rr->type != CURL_DNSSEC_TYPE_NSEC) &&
        (rr->type != CURL_DNSSEC_TYPE_NSEC3)) ||
       !rrset_first(m, i) ||
       !Curl_dnssec_name_sub(DNSSEC_RR_OWNER(m, rr), ns->zone) ||
       !rrset_signed_by(m, i, ns->zone))
      continue;
    /* one kind only */
    if(ns->n && ((rr->type == CURL_DNSSEC_TYPE_NSEC3) != ns->nsec3))
      continue;
    r = rrset_validate(v, m, i, &ttl, &labels, &signer);
    if(v->error)
      return r;
    if((r != VS_SECURE) || !Curl_dnssec_name_eq(signer, ns->zone) ||
       (labels != Curl_dnssec_name_sig_labels(DNSSEC_RR_OWNER(m, rr))))
      continue;
    for(j = i; (j < m->nrrs) && (ns->n < DNSSEC_MAX_DENIAL); j++) {
      if(!rr_same_set(m, &m->rrs[j], rr) || !nsec_check(ns, &m->rrs[j]))
        continue;
      ns->nsec3 = (rr->type == CURL_DNSSEC_TYPE_NSEC3);
      ns->rr[ns->n++] = j;
    }
    if(ttl < ns->ttl)
      ns->ttl = ttl;
  }
  if(!ns->n) {
    why(v, "no valid NSEC or NSEC3 records from %s",
        NAMESTR(ns->zone, v->nb[0]));
    return VS_BOGUS;
  }
  if(ns->nsec3 && (ns->iterations > DNSSEC_NSEC3_MAX_ITER)) {
    /* RFC 9276 3.2: too many iterations to check, the answer is insecure.
       Only if the records are from the zone that holds 'sname', which the
       proof would have shown. Otherwise the NSEC3 records of any zone
       above could make anything below it insecure. */
    if(!known) {
      uint8_t zone[DNSSEC_NAME_MAX];
      r = walk_down(v, sname, zone);
      if(r != VS_SECURE)
        return r;
      if(!Curl_dnssec_name_eq(zone, ns->zone)) {
        why(v, "NSEC3 records of %s cannot deny %s in %s",
            NAMESTR(ns->zone, v->nb[0]), NAMESTR(sname, v->nb[1]),
            NAMESTR(zone, v->nb[2]));
        return VS_BOGUS;
      }
    }
    why(v, "NSEC3 records of %s use %u iterations, more than %u",
        NAMESTR(ns->zone, v->nb[0]), (unsigned int)ns->iterations,
        (unsigned int)DNSSEC_NSEC3_MAX_ITER);
    return VS_INSECURE;
  }
  return VS_SECURE;
}

static size_t nsec_match(const struct nsecs *ns, const uint8_t *name)
{
  size_t i;
  for(i = 0; i < ns->n; i++) {
    const struct dnssec_rr *rr = &ns->m->rrs[ns->rr[i]];
    if(Curl_dnssec_name_eq(DNSSEC_RR_OWNER(ns->m, rr), name))
      return i;
  }
  return DNSSEC_NONE;
}

/* Find an NSEC that covers 'name', meaning 'name' is between its owner
   and next names. Sets 'next' to the next name. */
static size_t nsec_cover(const struct nsecs *ns, const uint8_t *name,
                         uint8_t next[DNSSEC_NAME_MAX])
{
  size_t i;
  if(!Curl_dnssec_name_sub(name, ns->zone))
    return DNSSEC_NONE;
  for(i = 0; i < ns->n; i++) {
    const uint8_t *owner = DNSSEC_RR_OWNER(ns->m, &ns->m->rrs[ns->rr[i]]);
    const uint8_t *map;
    size_t maplen;
    nsec_fields(ns, i, next, &map, &maplen);
    if(Curl_dnssec_name_cmp(owner, name) >= 0)
      continue;
    /* the last NSEC in a zone has the apex as next name */
    if((Curl_dnssec_name_cmp(owner, next) < 0) &&
       (Curl_dnssec_name_cmp(name, next) >= 0))
      continue;
    /* RFC 6840 4.1: an NSEC at a delegation or DNAME says nothing about
       the names below it */
    if(Curl_dnssec_name_sub(name, owner) &&
       ((map_has(map, maplen, CURL_DNSSEC_TYPE_NS) &&
         !map_has(map, maplen, CURL_DNSSEC_TYPE_SOA)) ||
        map_has(map, maplen, CURL_DNSSEC_TYPE_DNAME)))
      continue;
    return i;
  }
  return DNSSEC_NONE;
}

/* The number of labels of the closest encloser of 'name' that an NSEC
   covering it proves */
static unsigned int nsec_ce_labels(const uint8_t *name, const uint8_t *owner,
                                   const uint8_t *next)
{
  unsigned int a = Curl_dnssec_name_common(name, owner);
  unsigned int b = Curl_dnssec_name_common(name, next);
  return (a > b) ? a : b;
}

/* Make the wildcard name at the closest encloser of 'name' */
static bool wildcard_name(uint8_t out[DNSSEC_NAME_MAX], const uint8_t *name,
                          unsigned int ce_labels)
{
  const uint8_t *ce = Curl_dnssec_name_suffix(name, ce_labels);
  size_t len = Curl_dnssec_name_len(ce);
  if(len + 2 > DNSSEC_NAME_MAX)
    return FALSE;
  out[0] = 1;
  out[1] = '*';
  memcpy(&out[2], ce, len);
  return TRUE;
}

/* A type bit map in a matching record proves that 'qtype' does not exist
   at the name. RFC 4035 5.4, RFC 5155 8.5 and 8.6, RFC 6840 4.1 and
   4.3. */
static vstat map_nodata(struct vctx *v, const uint8_t *map, size_t maplen,
                        const uint8_t *sname, uint16_t qtype)
{
  char tbuf[16];
  bool ns = map_has(map, maplen, CURL_DNSSEC_TYPE_NS);
  bool soa = map_has(map, maplen, CURL_DNSSEC_TYPE_SOA);
  if(map_has(map, maplen, qtype) ||
     map_has(map, maplen, CURL_DNSSEC_TYPE_CNAME)) {
    why(v, "denial of existence for %s %s says it exists",
        NAMESTR(sname, v->nb[0]), typestr(qtype, tbuf, sizeof(tbuf)));
    return VS_BOGUS;
  }
  if(qtype == CURL_DNSSEC_TYPE_DS) {
    /* DS is in the parent zone, the child's apex record does not know */
    if(soa && sname[0]) {
      why(v, "denial of DS for %s is from the child zone",
          NAMESTR(sname, v->nb[0]));
      return VS_BOGUS;
    }
  }
  else if(ns && !soa) {
    /* the parent side of a delegation only knows about DS */
    why(v, "denial of existence for %s %s is from the parent zone",
        NAMESTR(sname, v->nb[0]), typestr(qtype, tbuf, sizeof(tbuf)));
    return VS_BOGUS;
  }
  return VS_SECURE;
}

static vstat nsec_nodata(struct vctx *v, const struct nsecs *ns,
                         const uint8_t *sname, uint16_t qtype, bool *pnx)
{
  uint8_t next[DNSSEC_NAME_MAX];
  uint8_t wc[DNSSEC_NAME_MAX];
  const uint8_t *map;
  size_t maplen;
  size_t i;

  i = nsec_match(ns, sname);
  if(i != DNSSEC_NONE) {
    nsec_fields(ns, i, next, &map, &maplen);
    /* compact denial of existence, RFC 9824 */
    if(map_has(map, maplen, DNSSEC_TYPE_NXNAME)) {
      *pnx = TRUE;
      return VS_SECURE;
    }
    return map_nodata(v, map, maplen, sname, qtype);
  }
  i = nsec_cover(ns, sname, next);
  if(i != DNSSEC_NONE) {
    const uint8_t *owner = DNSSEC_RR_OWNER(ns->m, &ns->m->rrs[ns->rr[i]]);
    unsigned int ce;
    /* an empty non-terminal: the next name is below sname */
    if(Curl_dnssec_name_sub(next, sname) &&
       !Curl_dnssec_name_eq(next, sname))
      return VS_SECURE;
    /* sname does not exist, a wildcard at the closest encloser without
       the type makes this NODATA, RFC 4035 3.1.3.4 */
    ce = nsec_ce_labels(sname, owner, next);
    if((ce >= Curl_dnssec_name_labels(ns->zone)) &&
       wildcard_name(wc, sname, ce)) {
      i = nsec_match(ns, wc);
      if(i != DNSSEC_NONE) {
        nsec_fields(ns, i, next, &map, &maplen);
        return map_nodata(v, map, maplen, sname, qtype);
      }
    }
  }
  why(v, "no NSEC proves NODATA for %s", NAMESTR(sname, v->nb[0]));
  return VS_BOGUS;
}

static vstat nsec_nxdomain(struct vctx *v, const struct nsecs *ns,
                           const uint8_t *sname)
{
  uint8_t next[DNSSEC_NAME_MAX];
  uint8_t wc[DNSSEC_NAME_MAX];
  const uint8_t *owner;
  const uint8_t *map;
  size_t maplen;
  unsigned int ce;
  size_t i;

  i = nsec_match(ns, sname);
  if(i != DNSSEC_NONE) {
    nsec_fields(ns, i, next, &map, &maplen);
    /* compact denial of existence with the NXDOMAIN rcode restored,
       RFC 9824 section 5.1 */
    if(map_has(map, maplen, DNSSEC_TYPE_NXNAME))
      return VS_SECURE;
    why(v, "NSEC says %s exists", NAMESTR(sname, v->nb[0]));
    return VS_BOGUS;
  }
  i = nsec_cover(ns, sname, next);
  if(i == DNSSEC_NONE) {
    why(v, "no NSEC proves %s does not exist", NAMESTR(sname, v->nb[0]));
    return VS_BOGUS;
  }
  if(Curl_dnssec_name_sub(next, sname)) {
    why(v, "NSEC says %s is an empty non-terminal", NAMESTR(sname, v->nb[0]));
    return VS_BOGUS;
  }
  owner = DNSSEC_RR_OWNER(ns->m, &ns->m->rrs[ns->rr[i]]);
  ce = nsec_ce_labels(sname, owner, next);
  if((ce < Curl_dnssec_name_labels(ns->zone)) ||
     !wildcard_name(wc, sname, ce) ||
     (nsec_cover(ns, wc, next) == DNSSEC_NONE)) {
    why(v, "no NSEC proves there is no wildcard for %s",
        NAMESTR(sname, v->nb[0]));
    return VS_BOGUS;
  }
  return VS_SECURE;
}

/* A wildcard answer, synthesized from the wildcard with 'labels' labels
   after the '*': sname must not exist, and the wildcard must be at its
   closest encloser. RFC 4035 5.3.4. */
static vstat nsec_wildcard(struct vctx *v, const struct nsecs *ns,
                           const uint8_t *sname, unsigned int labels)
{
  uint8_t next[DNSSEC_NAME_MAX];
  size_t i = nsec_cover(ns, sname, next);
  if((i == DNSSEC_NONE) || Curl_dnssec_name_sub(next, sname) ||
     (nsec_ce_labels(sname,
                     DNSSEC_RR_OWNER(ns->m, &ns->m->rrs[ns->rr[i]]),
                     next) != labels)) {
    why(v, "no NSEC proves the wildcard expansion of %s",
        NAMESTR(sname, v->nb[0]));
    return VS_BOGUS;
  }
  return VS_SECURE;
}

static vstat nsec_ds(struct vctx *v, const struct nsecs *ns,
                     const uint8_t *name, dsfact *fact)
{
  uint8_t next[DNSSEC_NAME_MAX];
  const uint8_t *map;
  size_t maplen;
  size_t i;

  i = nsec_match(ns, name);
  if(i != DNSSEC_NONE) {
    vstat r;
    nsec_fields(ns, i, next, &map, &maplen);
    if(map_has(map, maplen, DNSSEC_TYPE_NXNAME)) {
      *fact = DS_NO_NAME;
      return VS_SECURE;
    }
    r = map_nodata(v, map, maplen, name, CURL_DNSSEC_TYPE_DS);
    if(r == VS_SECURE)
      *fact = map_has(map, maplen, CURL_DNSSEC_TYPE_NS) ?
        DS_UNSIGNED_CUT : DS_NOT_CUT;
    return r;
  }
  i = nsec_cover(ns, name, next);
  if(i != DNSSEC_NONE) {
    /* an empty non-terminal, or no name at all */
    *fact = Curl_dnssec_name_sub(next, name) ? DS_NOT_CUT : DS_NO_NAME;
    return VS_SECURE;
  }
  why(v, "no NSEC proves the absence of DS for %s", NAMESTR(name, v->nb[0]));
  return VS_BOGUS;
}

/*
 * NSEC3, RFC 5155
 */

static vstat n3_hash(struct vctx *v, const struct nsecs *ns,
                     const uint8_t *name, uint8_t hash[DNSSEC_NSEC3_HASHLEN])
{
  uint8_t lower[DNSSEC_NAME_MAX];
  if(++v->ctx->nhash > DNSSEC_MAX_NSEC3_HASH) {
    why(v, "too many NSEC3 hash calculations");
    return VS_INDETERMINATE;
  }
  Curl_dnssec_name_lower(lower, name);
  if(Curl_dnssec_nsec3_hash(lower, Curl_dnssec_name_len(lower),
                            ns->salt, ns->saltlen, ns->iterations, hash)) {
    why(v, "NSEC3 hash calculation failed");
    return VS_INDETERMINATE;
  }
  return VS_SECURE;
}

static void n3_owner(const struct nsecs *ns, size_t idx,
                     uint8_t hash[DNSSEC_NSEC3_HASHLEN])
{
  const uint8_t *owner = DNSSEC_RR_OWNER(ns->m, &ns->m->rrs[ns->rr[idx]]);
  /* checked when collected */
  (void)Curl_dnssec_b32hex_decode(&owner[1], owner[0], hash,
                                  DNSSEC_NSEC3_HASHLEN);
}

static size_t n3_match(const struct nsecs *ns, const uint8_t *hash)
{
  size_t i;
  for(i = 0; i < ns->n; i++) {
    uint8_t oh[DNSSEC_NSEC3_HASHLEN];
    n3_owner(ns, i, oh);
    if(!memcmp(oh, hash, DNSSEC_NSEC3_HASHLEN))
      return i;
  }
  return DNSSEC_NONE;
}

static size_t n3_cover(const struct nsecs *ns, const uint8_t *hash)
{
  size_t i;
  for(i = 0; i < ns->n; i++) {
    uint8_t oh[DNSSEC_NSEC3_HASHLEN];
    const uint8_t *next;
    const uint8_t *map;
    size_t maplen;
    uint8_t flags;
    n3_owner(ns, i, oh);
    n3_fields(ns, i, &next, &flags, &map, &maplen);
    if(memcmp(oh, next, DNSSEC_NSEC3_HASHLEN) < 0) {
      if((memcmp(oh, hash, DNSSEC_NSEC3_HASHLEN) < 0) &&
         (memcmp(hash, next, DNSSEC_NSEC3_HASHLEN) < 0))
        return i;
    }
    /* the last one in the hash order wraps around */
    else if((memcmp(hash, oh, DNSSEC_NSEC3_HASHLEN) > 0) ||
            (memcmp(hash, next, DNSSEC_NSEC3_HASHLEN) < 0))
      return i;
  }
  return DNSSEC_NONE;
}

/* The closest encloser proof, RFC 5155 section 8.3. When there is an NSEC3
   matching sname itself, sets *pmatch to it and returns. Otherwise sets
   the label count of the closest encloser and if the NSEC3 covering the
   next closer name has the opt-out flag. */
static vstat n3_closest_encloser(struct vctx *v, const struct nsecs *ns,
                                 const uint8_t *sname, size_t *pmatch,
                                 unsigned int *pce, bool *poptout)
{
  uint8_t hash[DNSSEC_NSEC3_HASHLEN];
  uint8_t prev[DNSSEC_NSEC3_HASHLEN];
  unsigned int zl = Curl_dnssec_name_labels(ns->zone);
  unsigned int sl = Curl_dnssec_name_labels(sname);
  unsigned int l;

  *pmatch = DNSSEC_NONE;
  if(!Curl_dnssec_name_sub(sname, ns->zone)) {
    why(v, "NSEC3 records are not from a zone above %s",
        NAMESTR(sname, v->nb[0]));
    return VS_BOGUS;
  }
  for(l = sl; l >= zl; l--) {
    const uint8_t *map;
    const uint8_t *next;
    size_t maplen;
    uint8_t flags;
    size_t i;
    vstat r = n3_hash(v, ns, Curl_dnssec_name_suffix(sname, l), hash);
    if(r != VS_SECURE)
      return r;
    i = n3_match(ns, hash);
    if(i != DNSSEC_NONE) {
      if(l == sl) {
        *pmatch = i;
        return VS_SECURE;
      }
      n3_fields(ns, i, &next, &flags, &map, &maplen);
      if(map_has(map, maplen, CURL_DNSSEC_TYPE_DNAME) ||
         (map_has(map, maplen, CURL_DNSSEC_TYPE_NS) &&
          !map_has(map, maplen, CURL_DNSSEC_TYPE_SOA))) {
        why(v, "NSEC3 closest encloser of %s is a delegation or DNAME",
            NAMESTR(sname, v->nb[0]));
        return VS_BOGUS;
      }
      i = n3_cover(ns, prev);
      if(i == DNSSEC_NONE) {
        why(v, "no NSEC3 covers the next closer name of %s",
            NAMESTR(sname, v->nb[0]));
        return VS_BOGUS;
      }
      n3_fields(ns, i, &next, &flags, &map, &maplen);
      *pce = l;
      *poptout = !!(flags & DNSSEC_NSEC3_OPTOUT);
      return VS_SECURE;
    }
    memcpy(prev, hash, sizeof(prev));
    if(!l)
      break;
  }
  why(v, "no NSEC3 closest encloser proof for %s", NAMESTR(sname, v->nb[0]));
  return VS_BOGUS;
}

/* Is the wildcard at the closest encloser covered (nonexistent) or
   matched? Returns the record index or DNSSEC_NONE. */
static vstat n3_wildcard_find(struct vctx *v, const struct nsecs *ns,
                              const uint8_t *sname, unsigned int ce,
                              bool cover, size_t *pidx)
{
  uint8_t wc[DNSSEC_NAME_MAX];
  uint8_t hash[DNSSEC_NSEC3_HASHLEN];
  vstat r;
  *pidx = DNSSEC_NONE;
  if(!wildcard_name(wc, sname, ce))
    return VS_SECURE;
  r = n3_hash(v, ns, wc, hash);
  if(r == VS_SECURE)
    *pidx = cover ? n3_cover(ns, hash) : n3_match(ns, hash);
  return r;
}

/* RFC 5155 8.4 */
static vstat n3_nxdomain(struct vctx *v, const struct nsecs *ns,
                         const uint8_t *sname)
{
  unsigned int ce = 0;
  bool optout = FALSE;
  size_t i;
  vstat r = n3_closest_encloser(v, ns, sname, &i, &ce, &optout);
  if(r != VS_SECURE)
    return r;
  if(i != DNSSEC_NONE) {
    const uint8_t *next;
    const uint8_t *map;
    size_t maplen;
    uint8_t flags;
    n3_fields(ns, i, &next, &flags, &map, &maplen);
    /* compact denial of existence, RFC 9824 section 5.1 */
    if(map_has(map, maplen, DNSSEC_TYPE_NXNAME))
      return VS_SECURE;
    why(v, "NSEC3 says %s exists", NAMESTR(sname, v->nb[0]));
    return VS_BOGUS;
  }
  r = n3_wildcard_find(v, ns, sname, ce, TRUE, &i);
  if(r != VS_SECURE)
    return r;
  if(i == DNSSEC_NONE) {
    why(v, "no NSEC3 proves there is no wildcard for %s",
        NAMESTR(sname, v->nb[0]));
    return VS_BOGUS;
  }
  if(optout) {
    /* RFC 5155 12.2: names in an opt-out span may be unsigned
       delegations */
    why(v, "%s is in an NSEC3 opt-out span", NAMESTR(sname, v->nb[0]));
    return VS_INSECURE;
  }
  return VS_SECURE;
}

/* RFC 5155 8.5, 8.6 and 8.7 */
static vstat n3_nodata(struct vctx *v, const struct nsecs *ns,
                       const uint8_t *sname, uint16_t qtype, bool *pnx)
{
  const uint8_t *next;
  const uint8_t *map;
  size_t maplen;
  uint8_t flags;
  unsigned int ce = 0;
  bool optout = FALSE;
  size_t i;
  vstat r = n3_closest_encloser(v, ns, sname, &i, &ce, &optout);
  if(r != VS_SECURE)
    return r;
  if(i != DNSSEC_NONE) {
    n3_fields(ns, i, &next, &flags, &map, &maplen);
    if(map_has(map, maplen, DNSSEC_TYPE_NXNAME)) {
      *pnx = TRUE;
      return VS_SECURE;
    }
    return map_nodata(v, map, maplen, sname, qtype);
  }
  /* a wildcard NODATA response */
  r = n3_wildcard_find(v, ns, sname, ce, FALSE, &i);
  if(r != VS_SECURE)
    return r;
  if(i != DNSSEC_NONE) {
    n3_fields(ns, i, &next, &flags, &map, &maplen);
    r = map_nodata(v, map, maplen, sname, qtype);
    if((r == VS_SECURE) && optout) {
      why(v, "%s is in an NSEC3 opt-out span", NAMESTR(sname, v->nb[0]));
      r = VS_INSECURE;
    }
    return r;
  }
  if(optout) {
    /* an unsigned delegation (or no name) in an opt-out span */
    why(v, "%s is in an NSEC3 opt-out span", NAMESTR(sname, v->nb[0]));
    return VS_INSECURE;
  }
  why(v, "no NSEC3 proves NODATA for %s", NAMESTR(sname, v->nb[0]));
  return VS_BOGUS;
}

/* RFC 5155 8.8 */
static vstat n3_wildcard(struct vctx *v, const struct nsecs *ns,
                         const uint8_t *sname, unsigned int labels)
{
  uint8_t hash[DNSSEC_NSEC3_HASHLEN];
  const uint8_t *next;
  const uint8_t *map;
  size_t maplen;
  uint8_t flags;
  size_t i;
  vstat r;

  if((labels < Curl_dnssec_name_labels(ns->zone)) ||
     (labels >= Curl_dnssec_name_labels(sname))) {
    why(v, "bad wildcard expansion of %s", NAMESTR(sname, v->nb[0]));
    return VS_BOGUS;
  }
  r = n3_hash(v, ns, Curl_dnssec_name_suffix(sname, labels + 1), hash);
  if(r != VS_SECURE)
    return r;
  i = n3_cover(ns, hash);
  if(i == DNSSEC_NONE) {
    why(v, "no NSEC3 proves the wildcard expansion of %s",
        NAMESTR(sname, v->nb[0]));
    return VS_BOGUS;
  }
  n3_fields(ns, i, &next, &flags, &map, &maplen);
  if(flags & DNSSEC_NSEC3_OPTOUT) {
    why(v, "%s is in an NSEC3 opt-out span", NAMESTR(sname, v->nb[0]));
    return VS_INSECURE;
  }
  return VS_SECURE;
}

static vstat n3_ds(struct vctx *v, const struct nsecs *ns,
                   const uint8_t *name, dsfact *fact)
{
  const uint8_t *next;
  const uint8_t *map;
  size_t maplen;
  uint8_t flags;
  unsigned int ce = 0;
  bool optout = FALSE;
  size_t i;
  vstat r = n3_closest_encloser(v, ns, name, &i, &ce, &optout);
  if(r != VS_SECURE)
    return r;
  if(i != DNSSEC_NONE) {
    n3_fields(ns, i, &next, &flags, &map, &maplen);
    if(map_has(map, maplen, DNSSEC_TYPE_NXNAME)) {
      *fact = DS_NO_NAME;
      return VS_SECURE;
    }
    r = map_nodata(v, map, maplen, name, CURL_DNSSEC_TYPE_DS);
    if(r == VS_SECURE)
      *fact = map_has(map, maplen, CURL_DNSSEC_TYPE_NS) ?
        DS_UNSIGNED_CUT : DS_NOT_CUT;
    return r;
  }
  /* RFC 5155 8.6: without a matching NSEC3, only an opt-out span can hold
     an unsigned delegation */
  *fact = optout ? DS_OPTOUT : DS_NO_NAME;
  return VS_SECURE;
}

/* What does the response 'm' to a DS query for 'name' prove, when it has
   no DS records? The proof must come from 'parent', the zone above
   'name'. */
static vstat ds_denial(struct vctx *v, struct dnssec_msg *m,
                       const uint8_t *name, const uint8_t *parent,
                       dsfact *fact)
{
  struct nsecs ns;
  vstat r = denial_collect(v, m, name, TRUE, parent, &ns);
  if(r != VS_SECURE)
    return r;
  return ns.nsec3 ? n3_ds(v, &ns, name, fact) : nsec_ds(v, &ns, name, fact);
}

/* Find the validated DS RRset of 'zone', RFC 4035 section 5.2 */
static vstat ds_lookup(struct vctx *v, const uint8_t *zone,
                       struct dnssec_msg **pdm, size_t *pfirst)
{
  struct dnssec_msg *m;
  const uint8_t *signer;
  unsigned int labels;
  uint32_t ttl;
  size_t first;
  vstat r = query_get(v, zone, CURL_DNSSEC_TYPE_DS, &m);
  if(r != VS_SECURE)
    return r;

  first = rrset_find(m, DNSSEC_SECT_ANSWER, zone, CURL_DNSSEC_TYPE_DS);
  if(first != DNSSEC_NONE) {
    r = rrset_validate(v, m, first, &ttl, &labels, &signer);
    if((r == VS_SECURE) && (labels != Curl_dnssec_name_sig_labels(zone))) {
      why(v, "DS RRSIG for %s has a bad label count",
          NAMESTR(zone, v->nb[0]));
      r = VS_BOGUS;
    }
    *pdm = m;
    *pfirst = first;
    return r;
  }

  /* No DS records: 'zone' must be proven an unsigned delegation, by its
     parent zone. Which zone that is only a walk from the top shows. */
  r = walk_down(v, zone, NULL);
  if(r == VS_SECURE) {
    /* an RRSIG claims 'zone' is a zone, but its parent says it is not */
    why(v, "%s signs records but is no delegation", NAMESTR(zone, v->nb[0]));
    r = VS_BOGUS;
  }
  return r;
}

/* Get the validated keys of 'zone' */
static vstat zone_keys(struct vctx *v, const uint8_t *zone,
                       struct dnssec_zone **pz)
{
  struct Curl_dnssec_ctx *ctx = v->ctx;
  struct dnssec_zone *z = zone_find(ctx, zone);
  struct dnssec_msg *km = NULL;
  struct dnssec_msg *dm = NULL;
  size_t dfirst = DNSSEC_NONE;
  bool by_anchor;
  unsigned int i;
  vstat rk;
  vstat r;

  *pz = z;
  if(z) {
    if(z->status != VS_SECURE)
      why(v, "%s", z->reason);
    return z->status;
  }
  for(i = 0; i < v->nactive; i++) {
    if(Curl_dnssec_name_eq(v->active[i], zone)) {
      /* the keys of 'zone' depend on themselves */
      why(v, "loop in the chain of trust at %s", NAMESTR(zone, v->nb[0]));
      return VS_BOGUS;
    }
  }
  if((v->depth >= DNSSEC_MAX_DEPTH) ||
     (v->nactive >= CURL_ARRAYSIZE(v->active))) {
    why(v, "chain of trust too long");
    return VS_INDETERMINATE;
  }
  v->depth++;
  v->active[v->nactive++] = zone;

  by_anchor = anchored(ctx, zone);
  if(!by_anchor && !covered(ctx, zone)) {
    /* RFC 4035 section 4.3: without a trust anchor, nothing is known */
    why(v, "no trust anchor for %s", NAMESTR(zone, v->nb[0]));
    r = VS_INDETERMINATE;
    goto done;
  }
  /* ask for the DNSKEY and DS records at the same time */
  rk = query_get(v, zone, CURL_DNSSEC_TYPE_DNSKEY, &km);
  if(!by_anchor) {
    r = ds_lookup(v, zone, &dm, &dfirst);
    if(r != VS_SECURE)
      goto done;
  }
  r = rk;
  if(r != VS_SECURE)
    goto done;

  z = curlx_calloc(1, sizeof(*z));
  if(!z) {
    r = vs_oom(v);
    goto done;
  }
  Curl_dnssec_name_lower(z->name, zone);
  r = dnskey_validate(v, z, km, dm, dfirst, by_anchor);

done:
  v->depth--;
  v->nactive--;
  if((r == VS_PENDING) || v->error) {
    curlx_free(z);
    return r;
  }
  if(!z) {
    z = curlx_calloc(1, sizeof(*z));
    if(!z)
      return vs_oom(v);
    Curl_dnssec_name_lower(z->name, zone);
  }
  z->status = r;
  if(r != VS_SECURE)
    curl_msnprintf(z->reason, sizeof(z->reason), "%s", v->reason);
  z->next = ctx->zones;
  ctx->zones = z;
  *pz = z;
  return r;
}

/* Find the security status of the zone 'name' is in, starting at the
   closest trust anchor and walking down one label at a time, asking for
   the DS records at each name (RFC 4035 section 5.2, RFC 6840 section 4.4).
   Returns VS_INSECURE when there is a proven unsigned delegation above
   'name', and VS_SECURE when 'name' is in a secure zone, where all data
   must be signed. That zone is then copied to 'zone', if not NULL. */
static vstat walk_down(struct vctx *v, const uint8_t *name, uint8_t *zone)
{
  struct Curl_dnssec_ctx *ctx = v->ctx;
  const uint8_t *ta = deepest_anchor(ctx, name);
  uint8_t cur[DNSSEC_NAME_MAX];
  struct dnssec_zone *z;
  unsigned int nl = Curl_dnssec_name_labels(name);
  unsigned int l;
  vstat r;

  if(!ta) {
    why(v, "no trust anchor for %s", NAMESTR(name, v->nb[0]));
    return VS_INDETERMINATE;
  }
  memcpy(cur, ta, Curl_dnssec_name_len(ta));
  r = zone_keys(v, cur, &z);
  if(r != VS_SECURE)
    return r;

  /* ask for all the DS records at once */
  for(l = Curl_dnssec_name_labels(cur) + 1; l <= nl; l++) {
    struct dnssec_msg *m;
    (void)query_get(v, Curl_dnssec_name_suffix(name, l),
                    CURL_DNSSEC_TYPE_DS, &m);
    if(v->error)
      return VS_INDETERMINATE;
  }

  for(l = Curl_dnssec_name_labels(cur) + 1; l <= nl; l++) {
    const uint8_t *n = Curl_dnssec_name_suffix(name, l);
    struct dnssec_query *q;
    struct dnssec_msg *m;
    const uint8_t *signer;
    unsigned int labels;
    uint32_t ttl;
    size_t first;
    uint8_t parent;
    dsfact fact = DS_NO_NAME;

    r = query_get(v, n, CURL_DNSSEC_TYPE_DS, &m);
    if(r != VS_SECURE)
      return r;

    first = rrset_find(m, DNSSEC_SECT_ANSWER, n, CURL_DNSSEC_TYPE_DS);
    if(first == DNSSEC_NONE)
      first = rrset_find(m, DNSSEC_SECT_ANSWER, n, CURL_DNSSEC_TYPE_CNAME);
    if(first != DNSSEC_NONE) {
      /* A delegation with DS records, or an alias. Either way the records
         belong to the zone we are in. */
      if(!rrset_signed_by(m, first, cur)) {
        why(v, "%s %s is not signed by %s", NAMESTR(n, v->nb[0]),
            (m->rrs[first].type == CURL_DNSSEC_TYPE_DS) ? "DS" : "CNAME",
            NAMESTR(cur, v->nb[2]));
        return VS_BOGUS;
      }
      if(m->rrs[first].type == CURL_DNSSEC_TYPE_CNAME) {
        /* with the proof, when it is a wildcard expansion */
        ttl = 0xffffffff;
        r = answer_rrset(v, m, first, &ttl);
        if(r != VS_SECURE)
          return r;
        continue;
      }
      r = rrset_validate(v, m, first, &ttl, &labels, &signer);
      if(r != VS_SECURE)
        return r;
      r = zone_keys(v, n, &z);
      if(r != VS_SECURE)
        return r;
      memcpy(cur, n, Curl_dnssec_name_len(n));
      continue;
    }

    /* The proof is the same every run, remember it. It depends on the
       zone above, so remember that too. */
    q = query_find(ctx, n, CURL_DNSSEC_TYPE_DS);
    parent = (uint8_t)(Curl_dnssec_name_labels(cur) + 1);
    if(q && (q->wstat == VS_SECURE) && (q->wparent == parent))
      fact = (dsfact)q->wfact;
    else {
      r = ds_denial(v, m, n, cur, &fact);
      if(r != VS_SECURE)
        return r;
      if(q) {
        q->wstat = VS_SECURE;
        q->wfact = (uint8_t)fact;
        q->wparent = parent;
      }
    }
    switch(fact) {
    case DS_UNSIGNED_CUT:
      why(v, "%s is an unsigned delegation", NAMESTR(n, v->nb[0]));
      return VS_INSECURE;
    case DS_OPTOUT:
      why(v, "%s is in an NSEC3 opt-out span", NAMESTR(n, v->nb[0]));
      return VS_INSECURE;
    case DS_NO_NAME:
      /* nothing below exists, it is all in the secure zone 'cur' */
      l = nl;
      break;
    default:
      break;
    }
  }
  if(zone)
    memcpy(zone, cur, Curl_dnssec_name_len(cur));
  return VS_SECURE;
}

/*
 * Answers
 */

/* Validate an answer RRset and, for a wildcard expansion, the proof that
   the wildcard applies */
static vstat answer_rrset(struct vctx *v, struct dnssec_msg *m, size_t first,
                          uint32_t *pttl)
{
  const uint8_t *owner = DNSSEC_RR_OWNER(m, &m->rrs[first]);
  const uint8_t *signer;
  unsigned int labels;
  uint32_t ttl;
  vstat r = rrset_validate(v, m, first, &ttl, &labels, &signer);

  if((r == VS_SECURE) && (labels < Curl_dnssec_name_sig_labels(owner))) {
    /* expanded from a wildcard, RFC 4035 5.3.4 and RFC 5155 8.8 */
    struct nsecs ns;
    r = denial_collect(v, m, owner, FALSE, NULL, &ns);
    if(r == VS_SECURE) {
      if(!Curl_dnssec_name_eq(ns.zone, signer)) {
        why(v, "the wildcard proof for %s is from another zone",
            NAMESTR(owner, v->nb[0]));
        r = VS_BOGUS;
      }
      else if(ns.nsec3)
        r = n3_wildcard(v, &ns, owner, labels);
      else
        r = nsec_wildcard(v, &ns, owner, labels);
      if(ns.ttl < ttl)
        ttl = ns.ttl;
    }
  }
  if(ttl < *pttl)
    *pttl = ttl;
  return r;
}

/* The negative caching TTL of a response, RFC 2308 section 5 */
static uint32_t negative_ttl(const struct dnssec_msg *m)
{
  size_t i;
  for(i = 0; i < m->nrrs; i++) {
    const struct dnssec_rr *rr = &m->rrs[i];
    uint8_t name[DNSSEC_NAME_MAX];
    size_t off = rr->rdata;
    uint32_t minimum;
    if((rr->section != DNSSEC_SECT_AUTHORITY) ||
       (rr->type != CURL_DNSSEC_TYPE_SOA))
      continue;
    /* MNAME, RNAME, then serial, refresh, retry, expire and minimum */
    if(Curl_dnssec_read_name(m->buf, m->len, &off, TRUE, name) ||
       Curl_dnssec_read_name(m->buf, m->len, &off, TRUE, name) ||
       (off + 20 != (size_t)rr->rdata + rr->rdlen))
      return 0;
    minimum = rd32(&m->buf[off + 16]);
    return (minimum < rr->ttl) ? minimum : rr->ttl;
  }
  return 0;
}

/* Validate the response to a query for a name that has no records of the
   type: NXDOMAIN or NODATA */
static vstat answer_negative(struct vctx *v, struct dnssec_msg *m,
                             const uint8_t *sname, uint16_t qtype,
                             uint32_t *pttl)
{
  struct Curl_dnssec_req *req = v->req;
  struct nsecs ns;
  bool nx = (m->rcode == DNSSEC_RCODE_NXDOMAIN);
  vstat r = denial_collect(v, m, sname, (qtype == CURL_DNSSEC_TYPE_DS),
                           NULL, &ns);
  uint32_t ttl = negative_ttl(m);

  req->rcode = m->rcode;
  if(ttl < *pttl)
    *pttl = ttl;
  if(r != VS_SECURE)
    return r;
  if(nx)
    r = ns.nsec3 ? n3_nxdomain(v, &ns, sname) :
      nsec_nxdomain(v, &ns, sname);
  else
    r = ns.nsec3 ? n3_nodata(v, &ns, sname, qtype, &nx) :
      nsec_nodata(v, &ns, sname, qtype, &nx);
  if(nx)
    req->rcode = DNSSEC_RCODE_NXDOMAIN;
  if(ns.ttl < *pttl)
    *pttl = ns.ttl;
  return r;
}

static vstat vs_combine(vstat a, vstat b)
{
  if((a == VS_BOGUS) || (b == VS_BOGUS))
    return VS_BOGUS;
  if((a == VS_INDETERMINATE) || (b == VS_INDETERMINATE))
    return VS_INDETERMINATE;
  if((a == VS_INSECURE) || (b == VS_INSECURE))
    return VS_INSECURE;
  return VS_SECURE;
}

static bool authority_has_denial(const struct dnssec_msg *m)
{
  size_t i;
  for(i = 0; i < m->nrrs; i++) {
    const struct dnssec_rr *rr = &m->rrs[i];
    if((rr->section == DNSSEC_SECT_AUTHORITY) &&
       ((rr->type == CURL_DNSSEC_TYPE_SOA) ||
        (rr->type == CURL_DNSSEC_TYPE_NSEC) ||
        (rr->type == CURL_DNSSEC_TYPE_NSEC3)))
      return TRUE;
  }
  return FALSE;
}

/* Find the DNAME RRset in the answer section that applies to 'sname', the
   one closest to the root: there are no names below a DNAME */
static size_t find_dname(const struct dnssec_msg *m, const uint8_t *sname)
{
  size_t found = DNSSEC_NONE;
  size_t i;
  for(i = 0; i < m->nrrs; i++) {
    const struct dnssec_rr *rr = &m->rrs[i];
    const uint8_t *owner = DNSSEC_RR_OWNER(m, rr);
    if((rr->section == DNSSEC_SECT_ANSWER) &&
       (rr->type == CURL_DNSSEC_TYPE_DNAME) &&
       (rr->rclass == DNSSEC_CLASS_IN) &&
       Curl_dnssec_name_sub(sname, owner) &&
       !Curl_dnssec_name_eq(sname, owner) &&
       ((found == DNSSEC_NONE) ||
        (Curl_dnssec_name_labels(owner) <
         Curl_dnssec_name_labels(DNSSEC_RR_OWNER(m, &m->rrs[found])))))
      found = i;
  }
  return found;
}

/* The name 'sname' becomes with the DNAME record 'rr' (RFC 6672 section
   2.2), in 'out'. FALSE if the record is bad or the name too long. */
static bool dname_subst(const struct dnssec_msg *m,
                        const struct dnssec_rr *rr, const uint8_t *sname,
                        uint8_t out[DNSSEC_NAME_MAX])
{
  uint8_t target[DNSSEC_NAME_MAX];
  const uint8_t *owner = DNSSEC_RR_OWNER(m, rr);
  unsigned int prefix = Curl_dnssec_name_labels(sname) -
    Curl_dnssec_name_labels(owner);
  size_t plen = 0;
  size_t off = 0;
  /* the DNAME target is never compressed, RFC 6672 section 2.5 */
  if(Curl_dnssec_read_name(DNSSEC_RR_RDATA(m, rr), rr->rdlen, &off, FALSE,
                           target) || (off != rr->rdlen))
    return FALSE;
  while(prefix--)
    plen += 1 + (size_t)sname[plen];
  if(plen + Curl_dnssec_name_len(target) > DNSSEC_NAME_MAX)
    return FALSE;
  memmove(out, sname, plen);
  memcpy(&out[plen], target, Curl_dnssec_name_len(target));
  return TRUE;
}

/* Read the target of the CNAME record 'rr' */
static bool cname_target(const struct dnssec_msg *m,
                         const struct dnssec_rr *rr,
                         uint8_t out[DNSSEC_NAME_MAX])
{
  size_t off = rr->rdata;
  return !Curl_dnssec_read_name(m->buf, m->len, &off, TRUE, out) &&
         (off == (size_t)rr->rdata + rr->rdlen);
}

/* Validate the answer to the request's question, following CNAME and
   DNAME records (RFC 6672) */
static vstat req_eval(struct vctx *v)
{
  struct Curl_dnssec_req *req = v->req;
  uint8_t sname[DNSSEC_NAME_MAX];
  uint8_t next[DNSSEC_NAME_MAX];
  struct dnssec_msg *m;
  vstat total = VS_SECURE;
  uint32_t ttl = 0xffffffff;
  unsigned int hops = 0;
  vstat r;

  memcpy(sname, req->qname, DNSSEC_NAME_MAX);
  req->amsg = NULL;
  r = query_get(v, sname, req->qtype, &m);
  if(r != VS_SECURE)
    return r;
  req->rcode = m->rcode;

  for(;;) {
    size_t first = find_dname(m, sname);

    if(first != DNSSEC_NONE) {
      /* A DNAME above sname applies. The CNAME record synthesized from it
         is not signed, the substitution is done here instead. */
      if(!dname_subst(m, &m->rrs[first], sname, next)) {
        why(v, "bad DNAME substitution for %s", NAMESTR(sname, v->nb[0]));
        total = VS_BOGUS;
        break;
      }
      r = answer_rrset(v, m, first, &ttl);
      if(r == VS_PENDING)
        return r;
      total = vs_combine(total, r);
      if((total == VS_BOGUS) || (total == VS_INDETERMINATE))
        break;
      if(req->qtype == CURL_DNSSEC_TYPE_CNAME) {
        /* the answer is the synthesized CNAME, which must match */
        uint8_t target[DNSSEC_NAME_MAX];
        first = rrset_find(m, DNSSEC_SECT_ANSWER, sname,
                           CURL_DNSSEC_TYPE_CNAME);
        if((first == DNSSEC_NONE) ||
           !cname_target(m, &m->rrs[first], target) ||
           !Curl_dnssec_name_eq(target, next) ||
           !rrset_single(m, first)) {
          why(v, "CNAME for %s does not match the DNAME",
              NAMESTR(sname, v->nb[0]));
          total = VS_BOGUS;
          break;
        }
        req->amsg = m;
        req->afirst = first;
        req->rcode = DNSSEC_RCODE_NOERROR;
        break;
      }
      memcpy(sname, next, DNSSEC_NAME_MAX);
    }
    else {
      first = rrset_find(m, DNSSEC_SECT_ANSWER, sname, req->qtype);
      if(first != DNSSEC_NONE) {
        r = answer_rrset(v, m, first, &ttl);
        if(r == VS_PENDING)
          return r;
        total = vs_combine(total, r);
        req->amsg = m;
        req->afirst = first;
        req->rcode = DNSSEC_RCODE_NOERROR;
        break;
      }
      if(req->qtype == CURL_DNSSEC_TYPE_CNAME)
        goto negative;
      first = rrset_find(m, DNSSEC_SECT_ANSWER, sname,
                         CURL_DNSSEC_TYPE_CNAME);
      if(first == DNSSEC_NONE)
        goto negative;
      if(!cname_target(m, &m->rrs[first], next)) {
        why(v, "bad CNAME record for %s", NAMESTR(sname, v->nb[0]));
        return VS_BOGUS;
      }
      r = answer_rrset(v, m, first, &ttl);
      if(r == VS_PENDING)
        return r;
      total = vs_combine(total, r);
      if((total == VS_BOGUS) || (total == VS_INDETERMINATE))
        break;
      memcpy(sname, next, DNSSEC_NAME_MAX);
    }

    if(++hops > DNSSEC_MAX_CHAIN) {
      why(v, "too many CNAME and DNAME records");
      return VS_INDETERMINATE;
    }
    continue;

negative:
    /* A response for a CNAME chain can end before the last name (like
       when it is in another zone), then ask for the rest. */
    if(hops && !Curl_dnssec_name_eq(m->qname, sname) &&
       !authority_has_denial(m)) {
      r = query_get(v, sname, req->qtype, &m);
      if(r == VS_PENDING)
        return r;
      if(r == VS_SECURE)
        continue;
      total = vs_combine(total, r);
      break;
    }
    r = answer_negative(v, m, sname, req->qtype, &ttl);
    if(r == VS_PENDING)
      return r;
    total = vs_combine(total, r);
    break;
  }

  Curl_dnssec_name_str(sname, req->final_name, sizeof(req->final_name));
  req->ttl = (ttl == 0xffffffff) ? 0 : ttl;
  return total;
}

/*
 * API
 */

static CURLcode anchor_add(struct Curl_dnssec_ctx *ctx, const uint8_t *name,
                           uint16_t type, const uint8_t *rdata, size_t rdlen)
{
  struct dnssec_anchor *a = curlx_calloc(1, sizeof(*a) + rdlen);
  if(!a)
    return CURLE_OUT_OF_MEMORY;
  Curl_dnssec_name_lower(a->name, name);
  a->type = type;
  a->rdata = (uint8_t *)a + sizeof(*a);
  memcpy(a->rdata, rdata, rdlen);
  a->rdlen = (uint16_t)rdlen;
  a->next = ctx->anchors;
  ctx->anchors = a;
  return CURLE_OK;
}

/* Parse a decimal number from the token */
static bool token_num(const char *tok, size_t len, unsigned long max,
                      unsigned long *pnum)
{
  unsigned long num = 0;
  size_t i;
  if(!len)
    return FALSE;
  for(i = 0; i < len; i++) {
    unsigned long digit;
    if(!ISDIGIT(tok[i]))
      return FALSE;
    digit = (unsigned long)(tok[i] - '0');
    if(num > (max - digit) / 10)
      return FALSE;
    num = num * 10 + digit;
  }
  *pnum = num;
  return TRUE;
}

static int hexval(char c)
{
  if((c >= '0') && (c <= '9'))
    return c - '0';
  if((c >= 'a') && (c <= 'f'))
    return c - 'a' + 10;
  if((c >= 'A') && (c <= 'F'))
    return c - 'A' + 10;
  return -1;
}

#define ANCHOR_MAX_TOKENS 64

CURLcode Curl_dnssec_ctx_add_anchor(struct Curl_dnssec_ctx *ctx,
                                    const char *rr)
{
  const char *tok[ANCHOR_MAX_TOKENS];
  size_t toklen[ANCHOR_MAX_TOKENS];
  size_t ntok = 0;
  size_t t;
  uint8_t name[DNSSEC_NAME_MAX];
  uint8_t rdata[1024];
  size_t rdlen = 0;
  unsigned long num;
  uint16_t type;
  struct dynbuf data;
  CURLcode result = CURLE_BAD_FUNCTION_ARGUMENT;

  /* split into tokens, skipping parentheses and comments */
  while(*rr && (*rr != ';')) {
    const char *start;
    if(ISSPACE(*rr) || (*rr == '(') || (*rr == ')')) {
      rr++;
      continue;
    }
    start = rr;
    while(*rr && !ISSPACE(*rr) && (*rr != '(') && (*rr != ')') &&
          (*rr != ';'))
      rr++;
    if(ntok >= ANCHOR_MAX_TOKENS)
      return CURLE_BAD_FUNCTION_ARGUMENT;
    tok[ntok] = start;
    toklen[ntok] = (size_t)(rr - start);
    ntok++;
  }
  if(ntok < 2)
    return CURLE_BAD_FUNCTION_ARGUMENT;
  if(Curl_dnssec_name_parse(tok[0], toklen[0], name))
    return CURLE_BAD_FUNCTION_ARGUMENT;
  t = 1;
  /* optional TTL and class */
  if((t < ntok) && token_num(tok[t], toklen[t], 0xffffffffUL, &num))
    t++;
  if((t < ntok) && (toklen[t] == 2) && curl_strnequal(tok[t], "IN", 2))
    t++;
  if(t >= ntok)
    return CURLE_BAD_FUNCTION_ARGUMENT;
  if((toklen[t] == 2) && curl_strnequal(tok[t], "DS", 2))
    type = CURL_DNSSEC_TYPE_DS;
  else if((toklen[t] == 6) && curl_strnequal(tok[t], "DNSKEY", 6))
    type = CURL_DNSSEC_TYPE_DNSKEY;
  else
    return CURLE_BAD_FUNCTION_ARGUMENT;
  t++;
  if(ntok - t < 4)
    return CURLE_BAD_FUNCTION_ARGUMENT;

  if(type == CURL_DNSSEC_TYPE_DS) {
    /* key tag, algorithm, digest type, digest in hex */
    if(!token_num(tok[t], toklen[t], 0xffff, &num))
      return CURLE_BAD_FUNCTION_ARGUMENT;
    rdata[0] = (uint8_t)(num >> 8);
    rdata[1] = (uint8_t)num;
    if(!token_num(tok[t + 1], toklen[t + 1], 0xff, &num))
      return CURLE_BAD_FUNCTION_ARGUMENT;
    rdata[2] = (uint8_t)num;
    if(!token_num(tok[t + 2], toklen[t + 2], 0xff, &num))
      return CURLE_BAD_FUNCTION_ARGUMENT;
    rdata[3] = (uint8_t)num;
    rdlen = 4;
    for(t += 3; t < ntok; t++) {
      size_t i;
      if(toklen[t] & 1)
        return CURLE_BAD_FUNCTION_ARGUMENT;
      for(i = 0; i < toklen[t]; i += 2) {
        int hi = hexval(tok[t][i]);
        int lo = hexval(tok[t][i + 1]);
        if((hi < 0) || (lo < 0) || (rdlen >= sizeof(rdata)))
          return CURLE_BAD_FUNCTION_ARGUMENT;
        rdata[rdlen++] = (uint8_t)((hi << 4) | lo);
      }
    }
    if(rdlen < 5)
      return CURLE_BAD_FUNCTION_ARGUMENT;
    return anchor_add(ctx, name, type, rdata, rdlen);
  }

  /* DNSKEY: flags, protocol, algorithm, public key in base64 */
  if(!token_num(tok[t], toklen[t], 0xffff, &num))
    return CURLE_BAD_FUNCTION_ARGUMENT;
  rdata[0] = (uint8_t)(num >> 8);
  rdata[1] = (uint8_t)num;
  if(!token_num(tok[t + 1], toklen[t + 1], 0xff, &num) || (num != 3))
    return CURLE_BAD_FUNCTION_ARGUMENT;
  rdata[2] = (uint8_t)num;
  if(!token_num(tok[t + 2], toklen[t + 2], 0xff, &num))
    return CURLE_BAD_FUNCTION_ARGUMENT;
  rdata[3] = (uint8_t)num;
  rdlen = 4;
  curlx_dyn_init(&data, 8192);
  for(t += 3; t < ntok; t++) {
    if(curlx_dyn_addn(&data, tok[t], toklen[t])) {
      result = CURLE_OUT_OF_MEMORY;
      goto out;
    }
  }
  {
    uint8_t *key = NULL;
    size_t keylen = 0;
    result = curlx_base64_decode(curlx_dyn_ptr(&data), &key, &keylen);
    if(!result) {
      if(!keylen || (keylen > sizeof(rdata) - 4))
        result = CURLE_BAD_FUNCTION_ARGUMENT;
      else {
        memcpy(&rdata[4], key, keylen);
        rdlen += keylen;
      }
      curlx_free(key);
    }
    else if(result != CURLE_OUT_OF_MEMORY)
      result = CURLE_BAD_FUNCTION_ARGUMENT;
  }
  if(!result)
    result = anchor_add(ctx, name, type, rdata, rdlen);
out:
  curlx_dyn_free(&data);
  return result;
}

void Curl_dnssec_ctx_clear_anchors(struct Curl_dnssec_ctx *ctx)
{
  while(ctx->anchors) {
    struct dnssec_anchor *a = ctx->anchors;
    ctx->anchors = a->next;
    curlx_free(a);
  }
}

/* The root zone trust anchors, https://data.iana.org/root-anchors/ */
static const char *const root_anchors[] = {
  /* KSK-2017 */
  ". IN DS 20326 8 2 "
  "E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D",
  /* KSK-2024 */
  ". IN DS 38696 8 2 "
  "683D2D0ACB8C9B712A1948B27F741219298D0A450D612C483AF444A4C0FB2B16"
};

CURLcode Curl_dnssec_ctx_create(struct Curl_dnssec_ctx **pctx)
{
  struct Curl_dnssec_ctx *ctx = curlx_calloc(1, sizeof(*ctx));
  size_t i;
  *pctx = NULL;
  if(!ctx)
    return CURLE_OUT_OF_MEMORY;
  for(i = 0; i < CURL_ARRAYSIZE(root_anchors); i++) {
    CURLcode result = Curl_dnssec_ctx_add_anchor(ctx, root_anchors[i]);
    if(result) {
      Curl_dnssec_ctx_destroy(ctx);
      return result;
    }
  }
  *pctx = ctx;
  return CURLE_OK;
}

void Curl_dnssec_ctx_destroy(struct Curl_dnssec_ctx *ctx)
{
  if(!ctx)
    return;
  Curl_dnssec_ctx_clear_anchors(ctx);
  while(ctx->queries) {
    struct dnssec_query *q = ctx->queries;
    ctx->queries = q->next;
    Curl_dnssec_msg_free(q->msg);
    curlx_free(q);
  }
  while(ctx->zones) {
    struct dnssec_zone *z = ctx->zones;
    ctx->zones = z->next;
    curlx_free(z);
  }
  curlx_free(ctx);
}

void Curl_dnssec_ctx_set_flags(struct Curl_dnssec_ctx *ctx,
                               unsigned int flags)
{
  ctx->flags = flags;
}

void Curl_dnssec_ctx_set_time(struct Curl_dnssec_ctx *ctx, time_t now)
{
  ctx->fixed_now = now;
}

bool Curl_dnssec_ctx_next_query(struct Curl_dnssec_ctx *ctx,
                                char *name, size_t namelen,
                                uint16_t *qtype)
{
  struct dnssec_query *q;
  struct dnssec_query *oldest = NULL;
  /* the list has the newest first, send the oldest first */
  for(q = ctx->queries; q; q = q->next) {
    if(q->state == Q_WANTED)
      oldest = q;
  }
  if(!oldest)
    return FALSE;
  oldest->state = Q_SENT;
  Curl_dnssec_name_str(oldest->name, name, namelen);
  *qtype = oldest->qtype;
  return TRUE;
}

static struct dnssec_query *query_by_str(struct Curl_dnssec_ctx *ctx,
                                         const char *name, uint16_t qtype)
{
  uint8_t wire[DNSSEC_NAME_MAX];
  if(Curl_dnssec_name_parse(name, strlen(name), wire))
    return NULL;
  return query_find(ctx, wire, qtype);
}

CURLcode Curl_dnssec_ctx_add_response(struct Curl_dnssec_ctx *ctx,
                                      const char *name, uint16_t qtype,
                                      const unsigned char *msg,
                                      size_t msglen)
{
  struct dnssec_query *q = query_by_str(ctx, name, qtype);
  struct dnssec_msg *m = NULL;
  CURLcode result;

  if(!q)
    return CURLE_BAD_FUNCTION_ARGUMENT;
  if(q->state == Q_DONE)
    return CURLE_OK;
  /* without a usable response, the query failed */
  q->state = Q_DONE;
  result = Curl_dnssec_msg_parse(msg, msglen, &m);
  if(result == CURLE_OUT_OF_MEMORY)
    return result;
  if(m && ((m->qtype != qtype) || (m->qclass != DNSSEC_CLASS_IN) ||
           !Curl_dnssec_name_eq(m->qname, q->name) ||
           (ctx->nbytes + m->size > DNSSEC_MAX_BYTES))) {
    /* not the response to this query, or too much data */
    Curl_dnssec_msg_free(m);
    m = NULL;
  }
  if(m)
    ctx->nbytes += m->size;
  q->msg = m;
  return CURLE_OK;
}

CURLcode Curl_dnssec_ctx_add_failure(struct Curl_dnssec_ctx *ctx,
                                     const char *name, uint16_t qtype)
{
  struct dnssec_query *q = query_by_str(ctx, name, qtype);
  if(!q)
    return CURLE_BAD_FUNCTION_ARGUMENT;
  q->state = Q_DONE;
  return CURLE_OK;
}

size_t Curl_dnssec_ctx_pending(struct Curl_dnssec_ctx *ctx)
{
  struct dnssec_query *q;
  size_t n = 0;
  for(q = ctx->queries; q; q = q->next) {
    if(q->state != Q_DONE)
      n++;
  }
  return n;
}

CURLcode Curl_dnssec_req_create(struct Curl_dnssec_ctx *ctx,
                                const char *name, uint16_t qtype,
                                struct Curl_dnssec_req **preq)
{
  struct Curl_dnssec_req *req;
  uint8_t wire[DNSSEC_NAME_MAX];

  *preq = NULL;
  /* meta types and types that are not validated as answers */
  if(!qtype || (qtype == DNSSEC_TYPE_OPT) ||
     (qtype == CURL_DNSSEC_TYPE_RRSIG) || (qtype == DNSSEC_TYPE_NXNAME) ||
     ((qtype >= 249) && (qtype <= 255)))
    return CURLE_BAD_FUNCTION_ARGUMENT;
  if(Curl_dnssec_name_parse(name, strlen(name), wire))
    return CURLE_BAD_FUNCTION_ARGUMENT;
  req = curlx_calloc(1, sizeof(*req));
  if(!req)
    return CURLE_OUT_OF_MEMORY;
  req->ctx = ctx;
  curlx_dyn_init(&req->rdata, DNSSEC_MAX_RRSET * 65536);
  Curl_dnssec_name_lower(req->qname, wire);
  req->qtype = qtype;
  req->status = CURL_DNSSEC_INDETERMINATE;
  *preq = req;
  return CURLE_OK;
}

void Curl_dnssec_req_destroy(struct Curl_dnssec_req *req)
{
  if(req) {
    curlx_dyn_free(&req->rdata);
    curlx_free(req->rdoffs);
    curlx_free(req);
  }
}

CURLcode Curl_dnssec_req_run(struct Curl_dnssec_req *req)
{
  struct Curl_dnssec_ctx *ctx = req->ctx;
  struct vctx v;
  time_t now;
  vstat r;

  if(req->done)
    return CURLE_OK;
  memset(&v, 0, sizeof(v));
  v.ctx = ctx;
  v.req = req;
  now = ctx->fixed_now ? ctx->fixed_now : time(NULL);
  v.now = (uint32_t)now; /* seconds modulo 2^32, RFC 4034 3.1.5 */

  r = req_eval(&v);
  if(v.error)
    return v.error;
  if(r == VS_PENDING) {
    if(Curl_dnssec_ctx_pending(ctx))
      return CURLE_AGAIN;
    /* cannot happen, but never wait for nothing */
    why(&v, "validation stalled");
    r = VS_INDETERMINATE;
  }

  switch(r) {
  case VS_SECURE:
    req->status = CURL_DNSSEC_SECURE;
    break;
  case VS_INSECURE:
    req->status = CURL_DNSSEC_INSECURE;
    break;
  case VS_BOGUS:
    req->status = CURL_DNSSEC_BOGUS;
    break;
  default:
    req->status = CURL_DNSSEC_INDETERMINATE;
    break;
  }
  if(req->status != CURL_DNSSEC_SECURE)
    curl_msnprintf(req->reason, sizeof(req->reason), "%s", v.reason);

  /* only hand out records that are secure or proven insecure */
  req->acount = 0;
  req->done = TRUE;
  if(req->amsg && ((req->status == CURL_DNSSEC_SECURE) ||
                   (req->status == CURL_DNSSEC_INSECURE))) {
    const struct dnssec_msg *m = req->amsg;
    size_t n = 0;
    size_t i;
    for(i = req->afirst; i < m->nrrs; i++) {
      if(rr_same_set(m, &m->rrs[i], &m->rrs[req->afirst]))
        n++;
    }
    req->rdoffs = curlx_malloc((n + 1) * sizeof(size_t));
    if(!req->rdoffs)
      return CURLE_OUT_OF_MEMORY;
    for(i = req->afirst; i < m->nrrs; i++) {
      if(!rr_same_set(m, &m->rrs[i], &m->rrs[req->afirst]))
        continue;
      req->rdoffs[req->acount++] = curlx_dyn_len(&req->rdata);
      if(Curl_dnssec_rdata_canonical(m, &m->rrs[i], &req->rdata)) {
        /* validated records are well-formed, unless out of memory */
        req->acount = 0;
        return CURLE_OUT_OF_MEMORY;
      }
    }
    req->rdoffs[req->acount] = curlx_dyn_len(&req->rdata);
  }
  return CURLE_OK;
}

Curl_dnssec_status Curl_dnssec_req_status(const struct Curl_dnssec_req *req)
{
  return req->done ? req->status : CURL_DNSSEC_INDETERMINATE;
}

const char *Curl_dnssec_req_reason(const struct Curl_dnssec_req *req)
{
  return (req->done && req->reason[0]) ? req->reason : NULL;
}

int Curl_dnssec_req_rcode(const struct Curl_dnssec_req *req)
{
  return req->rcode;
}

const char *Curl_dnssec_req_final_name(const struct Curl_dnssec_req *req)
{
  return req->final_name;
}

uint32_t Curl_dnssec_req_ttl(const struct Curl_dnssec_req *req)
{
  return req->ttl;
}

size_t Curl_dnssec_req_count(const struct Curl_dnssec_req *req)
{
  return req->acount;
}

bool Curl_dnssec_req_rdata(const struct Curl_dnssec_req *req, size_t idx,
                           const unsigned char **prdata, size_t *prdlen)
{
  if(idx >= req->acount)
    return FALSE;
  *prdata = curlx_dyn_uptr(&req->rdata) + req->rdoffs[idx];
  *prdlen = req->rdoffs[idx + 1] - req->rdoffs[idx];
  return TRUE;
}

const char *Curl_dnssec_status_str(Curl_dnssec_status status)
{
  switch(status) {
  case CURL_DNSSEC_SECURE:
    return "secure";
  case CURL_DNSSEC_INSECURE:
    return "insecure";
  case CURL_DNSSEC_BOGUS:
    return "bogus";
  default:
    return "indeterminate";
  }
}

#endif /* USE_DNSSEC */
