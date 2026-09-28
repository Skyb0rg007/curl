#ifndef HEADER_CURL_DNSSEC_INT_H
#define HEADER_CURL_DNSSEC_INT_H
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

/* Internals shared by the dnssec*.c files. Everything here works on DNS
   wire format. Domain names are kept uncompressed in wire format ("\3www\7
   example\3com\0"), at most DNSSEC_NAME_MAX bytes. */

struct dynbuf;

#define DNSSEC_NAME_MAX   255
#define DNSSEC_LABELS_MAX 127

#define DNSSEC_CLASS_IN   1

/* more RR types, beyond the ones in dnssec.h */
#define DNSSEC_TYPE_MD      3
#define DNSSEC_TYPE_MF      4
#define DNSSEC_TYPE_MB      7
#define DNSSEC_TYPE_MG      8
#define DNSSEC_TYPE_MR      9
#define DNSSEC_TYPE_PTR     12
#define DNSSEC_TYPE_MINFO   14
#define DNSSEC_TYPE_MX      15
#define DNSSEC_TYPE_RP      17
#define DNSSEC_TYPE_AFSDB   18
#define DNSSEC_TYPE_RT      21
#define DNSSEC_TYPE_SIG     24
#define DNSSEC_TYPE_PX      26
#define DNSSEC_TYPE_NXT     30
#define DNSSEC_TYPE_SRV     33
#define DNSSEC_TYPE_NAPTR   35
#define DNSSEC_TYPE_KX      36
#define DNSSEC_TYPE_A6      38
#define DNSSEC_TYPE_OPT     41
#define DNSSEC_TYPE_NXNAME  128 /* RFC 9824 */

/* DNSKEY flags, RFC 4034 section 2.1.1 and RFC 5011 section 3 */
#define DNSSEC_DNSKEY_ZONE    0x0100
#define DNSSEC_DNSKEY_REVOKE  0x0080
#define DNSSEC_DNSKEY_SEP     0x0001

/* NSEC3 */
#define DNSSEC_NSEC3_SHA1     1
#define DNSSEC_NSEC3_OPTOUT   0x01
#define DNSSEC_NSEC3_HASHLEN  20

/* Algorithm numbers, RFC 8624 / RFC 9904 */
#define DNSSEC_ALG_RSASHA1          5
#define DNSSEC_ALG_RSASHA1_NSEC3    7
#define DNSSEC_ALG_RSASHA256        8
#define DNSSEC_ALG_RSASHA512        10
#define DNSSEC_ALG_ECDSAP256SHA256  13
#define DNSSEC_ALG_ECDSAP384SHA384  14
#define DNSSEC_ALG_ED25519          15
#define DNSSEC_ALG_ED448            16

/* DS digest types */
#define DNSSEC_DIGEST_SHA1    1
#define DNSSEC_DIGEST_SHA256  2
#define DNSSEC_DIGEST_SHA384  4
#define DNSSEC_DIGEST_MAX     48

/* Message sections */
#define DNSSEC_SECT_ANSWER     1
#define DNSSEC_SECT_AUTHORITY  2

/* rcodes */
#define DNSSEC_RCODE_NOERROR   0
#define DNSSEC_RCODE_NXDOMAIN  3

/* One resource record in a parsed message */
struct dnssec_rr {
  size_t owner;       /* offset of the uncompressed owner in msg->names */
  size_t rdata;       /* offset of the RDATA in msg->buf */
  uint32_t ttl;
  uint16_t type;
  uint16_t rclass;
  uint16_t rdlen;
  uint8_t section;
  /* cached validation result of the RRset this record starts */
  uint8_t vstat;      /* status, 0 when not known */
  uint8_t vlabels;    /* RRSIG Labels value of the validating signature */
  uint8_t vsigner;    /* number of labels in the signer name */
  uint32_t vttl;      /* TTL the RRset can be used for */
};

/* A parsed DNS response. Only the question, answer and authority sections
   are parsed, the validator has no use for the additional section. */
struct dnssec_msg {
  unsigned char *buf;
  size_t len;
  unsigned char *names;         /* owner names, uncompressed */
  struct dnssec_rr *rrs;
  size_t nrrs;
  uint8_t qname[DNSSEC_NAME_MAX];
  uint16_t qtype;
  uint16_t qclass;
  size_t size;                  /* memory used, roughly */
  uint16_t flags;
  uint8_t rcode;
};

/* Parse a response message */
CURLcode Curl_dnssec_msg_parse(const unsigned char *buf, size_t len,
                               struct dnssec_msg **pmsg);
void Curl_dnssec_msg_free(struct dnssec_msg *msg);

#define DNSSEC_RR_OWNER(m, rr) ((m)->names + (rr)->owner)
#define DNSSEC_RR_RDATA(m, rr) ((m)->buf + (rr)->rdata)

/* Read a domain name at '*offset' in 'buf' (a DNS message, or RDATA when
   'compress' is FALSE) into 'out', following compression pointers if
   'compress' is TRUE. Advances '*offset' past the name as stored. */
CURLcode Curl_dnssec_read_name(const unsigned char *buf, size_t len,
                               size_t *offset, bool compress,
                               uint8_t out[DNSSEC_NAME_MAX]);

/* Name utilities */
size_t Curl_dnssec_name_len(const uint8_t *name);
unsigned int Curl_dnssec_name_labels(const uint8_t *name);
/* label count as in the RRSIG Labels field: without a leading '*' */
unsigned int Curl_dnssec_name_sig_labels(const uint8_t *name);
bool Curl_dnssec_name_eq(const uint8_t *a, const uint8_t *b);
/* TRUE if 'name' is 'parent' or below it */
bool Curl_dnssec_name_sub(const uint8_t *name, const uint8_t *parent);
/* the last 'labels' labels of 'name' */
const uint8_t *Curl_dnssec_name_suffix(const uint8_t *name,
                                       unsigned int labels);
/* number of rightmost labels 'a' and 'b' have in common */
unsigned int Curl_dnssec_name_common(const uint8_t *a, const uint8_t *b);
/* canonical DNS name order, RFC 4034 section 6.1. <0, 0 or >0 */
int Curl_dnssec_name_cmp(const uint8_t *a, const uint8_t *b);
void Curl_dnssec_name_lower(uint8_t *dest, const uint8_t *name);
/* presentation format, with trailing dot */
void Curl_dnssec_name_str(const uint8_t *name, char *out, size_t outlen);
/* parse presentation format */
CURLcode Curl_dnssec_name_parse(const char *str, size_t len,
                                uint8_t out[DNSSEC_NAME_MAX]);

/* Append the canonical form (RFC 4034 section 6.2, RFC 6840 section 5.1)
   of the RDATA of 'rr' to 'out'. */
CURLcode Curl_dnssec_rdata_canonical(const struct dnssec_msg *m,
                                     const struct dnssec_rr *rr,
                                     struct dynbuf *out);

/* TRUE if 'type' is set in an NSEC/NSEC3 type bit map. A malformed bit
   map makes *pbad TRUE. */
bool Curl_dnssec_bitmap_has(const uint8_t *map, size_t len, uint16_t type,
                            bool *pbad);

/* Key tag, RFC 4034 appendix B */
uint16_t Curl_dnssec_keytag(const uint8_t *rdata, size_t rdlen);

/* Decode a base32hex (RFC 4648 section 7) NSEC3 hash label. Returns the
   number of bytes written, 0 on error. */
size_t Curl_dnssec_b32hex_decode(const uint8_t *in, size_t inlen,
                                 uint8_t *out, size_t outlen);

/*
 * Crypto, implemented in dnssec-crypto.c
 */

/* TRUE if the crypto library supports the signature algorithm. */
bool Curl_dnssec_alg_supported(uint8_t alg);

/* TRUE if the crypto library supports the DS digest type. */
bool Curl_dnssec_digest_supported(uint8_t dtype);

/* Verify signature 'sig' over 'data' with DNSKEY public key 'key'.
   Returns CURLE_OK if the signature is valid,
   CURLE_PEER_FAILED_VERIFICATION if it is not, CURLE_NOT_BUILT_IN for an
   unsupported algorithm and CURLE_BAD_FUNCTION_ARGUMENT for a malformed or
   unacceptable key or signature. */
CURLcode Curl_dnssec_verify(uint8_t alg,
                            const uint8_t *key, size_t keylen,
                            const uint8_t *data, size_t datalen,
                            const uint8_t *sig, size_t siglen);

/* Hash the concatenation of two buffers with DS digest type 'dtype'.
   Returns the digest length, 0 on error or unsupported type. */
size_t Curl_dnssec_digest(uint8_t dtype,
                          const uint8_t *d1, size_t l1,
                          const uint8_t *d2, size_t l2,
                          uint8_t out[DNSSEC_DIGEST_MAX]);

/* NSEC3 hash, RFC 5155 section 5 (SHA-1 only) */
CURLcode Curl_dnssec_nsec3_hash(const uint8_t *name, size_t namelen,
                                const uint8_t *salt, size_t saltlen,
                                uint16_t iterations,
                                uint8_t out[DNSSEC_NSEC3_HASHLEN]);

#endif /* USE_DNSSEC */
#endif /* HEADER_CURL_DNSSEC_INT_H */
