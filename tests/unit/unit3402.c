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
#include "vdns/dnssec-int.h"
#include "curlx/base64.h"
#include "curlx/dynbuf.h"
#include "dnssec-vectors.h"

/* DNSSEC validator building blocks: names, messages, canonical form,
   key tags, digests, signatures and NSEC3 hashes */

static bool t3402_name(const char *str, uint8_t *wire)
{
  return !Curl_dnssec_name_parse(str, strlen(str), wire);
}

static void t3402_names(void)
{
  uint8_t a[DNSSEC_NAME_MAX];
  uint8_t b[DNSSEC_NAME_MAX];
  char str[CURL_DNSSEC_NAME_STRLEN];
  char label63[70];
  char longname[300];
  size_t i;
  /* RFC 4034 section 6.1, in canonical order */
  static const char *const order[] = {
    "example.", "a.example.", "yljkjljk.a.example.", "Z.a.example.",
    "zABC.a.EXAMPLE.", "z.example.", "\\001.z.example.", "*.z.example.",
    "\\200.z.example."
  };
  static const char *const bad[] = {
    "", "..", "a..b.", ".a.", "a.b..", "\\256.", "\\25", "a\\"
  };

  fail_unless(t3402_name("www.Example.COM", a), "parse");
  fail_unless(Curl_dnssec_name_len(a) == 17, "length");
  fail_unless(Curl_dnssec_name_labels(a) == 3, "labels");
  Curl_dnssec_name_str(a, str, sizeof(str));
  fail_unless(!strcmp(str, "www.Example.COM."), str);
  fail_unless(t3402_name("www.example.com.", b), "parse");
  fail_unless(Curl_dnssec_name_eq(a, b), "case insensitive");
  fail_unless(!Curl_dnssec_name_cmp(a, b), "case insensitive order");

  fail_unless(t3402_name(".", a) && !a[0], "root");
  Curl_dnssec_name_str(a, str, sizeof(str));
  fail_unless(!strcmp(str, "."), str);

  /* escapes */
  fail_unless(t3402_name("a\\.b.\\065\\\\c.", a), "escapes");
  fail_unless((a[0] == 3) && !memcmp(&a[1], "a.b", 3), "escaped dot");
  fail_unless((a[4] == 3) && !memcmp(&a[5], "A\\c", 3), "escaped digits");
  Curl_dnssec_name_str(a, str, sizeof(str));
  fail_unless(!strcmp(str, "a\\046b.A\\092c."), str);

  for(i = 0; i < CURL_ARRAYSIZE(bad); i++) {
    if(t3402_name(bad[i], a)) {
      curl_mfprintf(stderr, "bad name accepted: '%s'\n", bad[i]);
      unitfail++;
    }
  }
  memset(label63, 'a', 63);
  label63[63] = 0;
  fail_unless(t3402_name(label63, a), "63 octet label");
  label63[63] = 'a';
  label63[64] = 0;
  fail_if(t3402_name(label63, a), "64 octet label");
  /* 127 labels of one octet is 255 octets with the root */
  for(i = 0; i < 127; i++)
    memcpy(&longname[i * 2], "a.", 2);
  longname[254] = 0;
  fail_unless(t3402_name(longname, a), "255 octet name");
  fail_unless(Curl_dnssec_name_labels(a) == 127, "127 labels");
  memcpy(&longname[254], "a.", 3);
  fail_if(t3402_name(longname, a), "257 octet name");

  for(i = 1; i < CURL_ARRAYSIZE(order); i++) {
    fail_unless(t3402_name(order[i - 1], a) && t3402_name(order[i], b),
                "parse");
    if((Curl_dnssec_name_cmp(a, b) >= 0) ||
       (Curl_dnssec_name_cmp(b, a) <= 0)) {
      curl_mfprintf(stderr, "%s should be before %s\n", order[i - 1],
                    order[i]);
      unitfail++;
    }
  }

  fail_unless(t3402_name("x.y.Example.", a) &&
              t3402_name("example.", b), "parse");
  fail_unless(Curl_dnssec_name_sub(a, b), "subdomain");
  fail_unless(Curl_dnssec_name_sub(a, a), "subdomain of itself");
  fail_if(Curl_dnssec_name_sub(b, a), "not a subdomain");
  fail_unless(Curl_dnssec_name_common(a, b) == 1, "common labels");
  fail_unless(Curl_dnssec_name_eq(Curl_dnssec_name_suffix(a, 1), b),
              "suffix");
  fail_unless(t3402_name("*.a.example.", a), "parse");
  fail_unless(Curl_dnssec_name_sig_labels(a) == 2, "wildcard labels");
  fail_unless(t3402_name("xexample.", a), "parse");
  fail_if(Curl_dnssec_name_sub(a, b), "not a label boundary");
}

/* a response with compressed names: example.com. IN MX, one MX record
   "10 MAIL.example.com." with the RDATA name compressed */
static const unsigned char t3402_mx[] = {
  0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00,
  /* question at 12: example.com. MX IN */
  0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0x03, 'c', 'o', 'm', 0x00,
  0x00, 0x0f, 0x00, 0x01,
  /* answer: EXAMPLE.com (pointer to "com" at 20) MX IN TTL 3600 */
  0x07, 'E', 'X', 'A', 'M', 'P', 'L', 'E', 0xc0, 0x14,
  0x00, 0x0f, 0x00, 0x01, 0x00, 0x00, 0x0e, 0x10, 0x00, 0x09,
  0x00, 0x0a, 0x04, 'M', 'A', 'I', 'L', 0xc0, 0x0c,
  /* answer: pointer to the question name, NSEC to "A.example.com." */
  0xc0, 0x0c, 0x00, 0x2f, 0x00, 0x01, 0x00, 0x00, 0x0e, 0x10, 0x00, 0x12,
  0x01, 'A', 0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0x03, 'c', 'o', 'm',
  0x00, 0x00, 0x01, 0x40
};

static void t3402_messages(void)
{
  struct dnssec_msg *m = NULL;
  uint8_t name[DNSSEC_NAME_MAX];
  struct dynbuf out;
  unsigned char bad[sizeof(t3402_mx)];
  bool badmap;
  CURLcode result;

  result = Curl_dnssec_msg_parse(t3402_mx, sizeof(t3402_mx), &m);
  abort_if(result || !m, "parse");
  fail_unless(m->nrrs == 2, "records");
  fail_unless(m->qtype == 15, "question type");
  fail_unless(t3402_name("example.com.", name), "parse");
  fail_unless(Curl_dnssec_name_eq(DNSSEC_RR_OWNER(m, &m->rrs[0]), name),
              "compressed owner");
  fail_unless(Curl_dnssec_name_eq(DNSSEC_RR_OWNER(m, &m->rrs[1]), name),
              "pointer owner");

  /* MX: the name is expanded and lowercased */
  curlx_dyn_init(&out, 1024);
  fail_unless(!Curl_dnssec_rdata_canonical(m, &m->rrs[0], &out), "mx");
  fail_unless((curlx_dyn_len(&out) == 20) &&
              !memcmp(curlx_dyn_ptr(&out),
                      "\x00\x0a\x04mail\x07" "example\x03" "com", 20),
              "mx canonical");
  /* NSEC: the next name keeps its case (RFC 6840 5.1) */
  curlx_dyn_reset(&out);
  fail_unless(!Curl_dnssec_rdata_canonical(m, &m->rrs[1], &out), "nsec");
  fail_unless((curlx_dyn_len(&out) == 18) &&
              !memcmp(curlx_dyn_ptr(&out), "\x01" "A", 2), "nsec canonical");
  fail_unless(Curl_dnssec_bitmap_has(DNSSEC_RR_RDATA(m, &m->rrs[1]) + 15, 3,
                                     CURL_DNSSEC_TYPE_A, &badmap) &&
              !badmap, "bitmap");
  curlx_dyn_free(&out);
  Curl_dnssec_msg_free(m);
  m = NULL;

  /* a compression pointer pointing forward */
  memcpy(bad, t3402_mx, sizeof(bad));
  bad[38] = 0x30;
  fail_unless(Curl_dnssec_msg_parse(bad, sizeof(bad), &m) && !m,
              "forward pointer");
  /* a pointer to itself */
  memcpy(bad, t3402_mx, sizeof(bad));
  bad[59] = 0x3a;
  fail_unless(Curl_dnssec_msg_parse(bad, sizeof(bad), &m) && !m,
              "pointer loop");
  /* truncated (TC) */
  memcpy(bad, t3402_mx, sizeof(bad));
  bad[2] |= 0x02;
  fail_unless(Curl_dnssec_msg_parse(bad, sizeof(bad), &m) && !m,
              "truncated");
  /* a query, not a response */
  memcpy(bad, t3402_mx, sizeof(bad));
  bad[2] &= 0x7f;
  fail_unless(Curl_dnssec_msg_parse(bad, sizeof(bad), &m) && !m, "query");
  /* cut short */
  fail_unless(Curl_dnssec_msg_parse(t3402_mx, sizeof(t3402_mx) - 1, &m) &&
              !m, "short");
  /* more records than can fit */
  memcpy(bad, t3402_mx, sizeof(bad));
  bad[7] = 0xff;
  fail_unless(Curl_dnssec_msg_parse(bad, sizeof(bad), &m) && !m,
              "record count");

unit_test_abort:
  Curl_dnssec_msg_free(m);
}

static void t3402_bitmaps(void)
{
  /* RFC 4034 section 4.3: A MX RRSIG NSEC TYPE1234 */
  static const uint8_t map[] = {
    0x00, 0x06, 0x40, 0x01, 0x00, 0x00, 0x00, 0x03,
    0x04, 0x1b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x20
  };
  static const uint8_t unordered[] = { 0x01, 0x01, 0x80, 0x00, 0x01, 0x40 };
  static const uint8_t empty[] = { 0x00, 0x00 };
  static const uint8_t toolong[] = { 0x00, 0x05, 0x40 };
  bool bad;

  fail_unless(Curl_dnssec_bitmap_has(map, sizeof(map), 1, &bad) && !bad,
              "A");
  fail_unless(Curl_dnssec_bitmap_has(map, sizeof(map), 15, &bad), "MX");
  fail_unless(Curl_dnssec_bitmap_has(map, sizeof(map), 46, &bad), "RRSIG");
  fail_unless(Curl_dnssec_bitmap_has(map, sizeof(map), 47, &bad), "NSEC");
  fail_unless(Curl_dnssec_bitmap_has(map, sizeof(map), 1234, &bad),
              "TYPE1234");
  fail_if(Curl_dnssec_bitmap_has(map, sizeof(map), 2, &bad), "NS");
  fail_if(Curl_dnssec_bitmap_has(map, sizeof(map), 1235, &bad), "TYPE1235");
  fail_if(Curl_dnssec_bitmap_has(map, sizeof(map), 65535, &bad), "65535");
  fail_if(Curl_dnssec_bitmap_has(map, 0, 1, &bad) || bad, "no map");
  (void)Curl_dnssec_bitmap_has(unordered, sizeof(unordered), 1, &bad);
  fail_unless(bad, "window order");
  (void)Curl_dnssec_bitmap_has(empty, sizeof(empty), 1, &bad);
  fail_unless(bad, "empty window");
  (void)Curl_dnssec_bitmap_has(toolong, sizeof(toolong), 1, &bad);
  fail_unless(bad, "window past the end");
}

static uint8_t *t3402_b64(const char *str, size_t *plen)
{
  uint8_t *out = NULL;
  if(curlx_base64_decode(str, &out, plen))
    return NULL;
  return out;
}

static void t3402_digests(void)
{
  size_t i;
  for(i = 0; i < CURL_ARRAYSIZE(t3402_ds); i++) {
    const struct t3402_ds *t = &t3402_ds[i];
    uint8_t owner[DNSSEC_NAME_MAX];
    uint8_t digest[DNSSEC_DIGEST_MAX];
    char hex[2 * DNSSEC_DIGEST_MAX + 1];
    size_t keylen = 0;
    size_t dlen;
    size_t j;
    uint8_t *key = t3402_b64(t->dnskey, &keylen);
    if(!key || !t3402_name(t->owner, owner)) {
      fail("decode");
      curlx_free(key);
      continue;
    }
    if(Curl_dnssec_keytag(key, keylen) != t->keytag) {
      curl_mfprintf(stderr, "%s: key tag %u, expected %d\n", t->owner,
                    Curl_dnssec_keytag(key, keylen), t->keytag);
      unitfail++;
    }
    dlen = Curl_dnssec_digest((uint8_t)t->dtype, owner,
                              Curl_dnssec_name_len(owner), key, keylen,
                              digest);
    for(j = 0; j < dlen; j++)
      curl_msnprintf(&hex[j * 2], 3, "%02x", digest[j]);
    hex[dlen * 2] = 0;
    if(strcmp(hex, t->digest)) {
      curl_mfprintf(stderr, "%s: DS digest type %d\n%s, expected\n%s\n",
                    t->owner, t->dtype, hex, t->digest);
      unitfail++;
    }
    curlx_free(key);
  }
}

static void t3402_signatures(void)
{
  size_t i;
  for(i = 0; i < CURL_ARRAYSIZE(t3402_sig); i++) {
    const struct t3402_sig *t = &t3402_sig[i];
    size_t keylen = 0;
    size_t datalen = 0;
    size_t siglen = 0;
    uint8_t *key = t3402_b64(t->key, &keylen);
    uint8_t *data = t3402_b64(t->data, &datalen);
    uint8_t *sig = t3402_b64(t->sig, &siglen);
    CURLcode expect = t->expect;
    CURLcode result;

    if(!key || !data || !sig) {
      fail("decode");
      goto next;
    }
    if(!Curl_dnssec_alg_supported((uint8_t)t->alg)) {
      /* like ED448 with BoringSSL */
      curl_mfprintf(stderr, "%s: algorithm not supported\n", t->desc);
      goto next;
    }
    result = Curl_dnssec_verify((uint8_t)t->alg, key, keylen, data, datalen,
                                sig, siglen);
    if(result != expect) {
      curl_mfprintf(stderr, "%s: result %d, expected %d\n", t->desc,
                    (int)result, (int)expect);
      unitfail++;
    }
    if(expect == CURLE_OK) {
      /* a changed signature, and a signature of the wrong length */
      sig[siglen / 2] ^= 0x01;
      result = Curl_dnssec_verify((uint8_t)t->alg, key, keylen, data,
                                  datalen, sig, siglen);
      if(result != CURLE_PEER_FAILED_VERIFICATION) {
        curl_mfprintf(stderr, "%s: changed signature: %d\n", t->desc,
                      (int)result);
        unitfail++;
      }
      result = Curl_dnssec_verify((uint8_t)t->alg, key, keylen, data,
                                  datalen, sig, siglen - 1);
      if(!result) {
        curl_mfprintf(stderr, "%s: short signature verified\n", t->desc);
        unitfail++;
      }
      /* a key of the wrong length */
      result = Curl_dnssec_verify((uint8_t)t->alg, key, keylen - 1, data,
                                  datalen, sig, siglen);
      if(!result) {
        curl_mfprintf(stderr, "%s: short key verified\n", t->desc);
        unitfail++;
      }
    }
next:
    curlx_free(key);
    curlx_free(data);
    curlx_free(sig);
  }
  fail_unless(Curl_dnssec_verify(1, (const uint8_t *)"x", 1,
                                 (const uint8_t *)"x", 1,
                                 (const uint8_t *)"x", 1) ==
              CURLE_NOT_BUILT_IN, "RSAMD5 is not supported");
  fail_if(Curl_dnssec_alg_supported(3), "DSA is not supported");
  fail_if(Curl_dnssec_alg_supported(12), "GOST is not supported");
  fail_if(Curl_dnssec_digest_supported(3), "GOST digest is not supported");
}

static void t3402_nsec3_hashes(void)
{
  static const uint8_t salt[] = { 0xaa, 0xbb, 0xcc, 0xdd };
  uint8_t hash[DNSSEC_NSEC3_HASHLEN];
  uint8_t expect[DNSSEC_NSEC3_HASHLEN + 1];
  uint8_t name[DNSSEC_NAME_MAX];
  size_t i;

  for(i = 0; i < CURL_ARRAYSIZE(t3402_nsec3); i++) {
    const struct t3402_nsec3 *t = &t3402_nsec3[i];
    if(!t3402_name(t->name, name) ||
       (Curl_dnssec_b32hex_decode((const uint8_t *)t->hash, strlen(t->hash),
                                  expect, sizeof(expect)) !=
        DNSSEC_NSEC3_HASHLEN)) {
      fail("decode");
      continue;
    }
    Curl_dnssec_name_lower(name, name);
    if(Curl_dnssec_nsec3_hash(name, Curl_dnssec_name_len(name), salt,
                              sizeof(salt), 12, hash) ||
       memcmp(hash, expect, sizeof(hash))) {
      curl_mfprintf(stderr, "NSEC3 hash of %s is wrong\n", t->name);
      unitfail++;
    }
  }
  fail_unless(!Curl_dnssec_b32hex_decode((const uint8_t *)"0w", 2, expect,
                                         sizeof(expect)), "bad base32hex");
  fail_unless(!Curl_dnssec_b32hex_decode((const uint8_t *)"01", 2, expect,
                                         sizeof(expect)), "bad padding");
}

static void t3402_anchors(void)
{
  struct Curl_dnssec_ctx *ctx = NULL;
  size_t i;
  static const char *const good[] = {
    ". IN DS 20326 8 2 E06D44B80B8F1D39A95C0B0D7C65D084"
    "58E880409BBC683457104237C7F8EC8D",
    "example.com. 3600 IN DS 60485 5 1 ( 2BB183AF5F22588179A53B0A\n"
    "  98631FAD1A292118); comment",
    "example.com. DNSKEY 257 3 15 l02Woi0iS8Aa25FQkUd9RMzZHJpBoRQwAQEX1SxZ"
    "JA4=",
    "example.com DNSKEY 257 3 15 ( l02Woi0iS8Aa25FQkUd9RMzZ\n"
    "  HJpBoRQwAQEX1SxZJA4=)"
  };
  static const char *const bad[] = {
    "", ".", ". IN DS", ". IN DS 20326 8 2", ". IN DS 20326 8 2 E0F",
    ". IN DS 20326 8 2 XY", ". IN DS 70000 8 2 E0", ". IN A 192.0.2.1",
    "example.com. DNSKEY 257 2 15 l02Woi0iS8Aa25FQkUd9RMzZHJpBoRQwAQE=",
    "example.com. DNSKEY 257 3 15 !!!", "..example. DS 1 8 2 E0"
  };

  abort_if(Curl_dnssec_ctx_create(&ctx), "create");
  for(i = 0; i < CURL_ARRAYSIZE(good); i++) {
    if(Curl_dnssec_ctx_add_anchor(ctx, good[i])) {
      curl_mfprintf(stderr, "anchor not accepted: %s\n", good[i]);
      unitfail++;
    }
  }
  for(i = 0; i < CURL_ARRAYSIZE(bad); i++) {
    if(!Curl_dnssec_ctx_add_anchor(ctx, bad[i])) {
      curl_mfprintf(stderr, "bad anchor accepted: %s\n", bad[i]);
      unitfail++;
    }
  }
unit_test_abort:
  Curl_dnssec_ctx_destroy(ctx);
}

static CURLcode test_unit3402(const char *arg)
{
  UNITTEST_BEGIN_SIMPLE

  t3402_names();
  t3402_messages();
  t3402_bitmaps();
  t3402_digests();
  t3402_signatures();
  t3402_nsec3_hashes();
  t3402_anchors();

  UNITTEST_END_SIMPLE
}

#else /* !USE_DNSSEC */

static CURLcode test_unit3402(const char *arg)
{
  UNITTEST_BEGIN_SIMPLE
  UNITTEST_END_SIMPLE
}

#endif
