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

/* DNS wire format handling for the DNSSEC validator: names, messages and
   the canonical form of records (RFC 1035, RFC 3597, RFC 4034) */

#define DNSSEC_MSG_MAX 65535
/* Most records in the answer and authority sections of a message. Real
   responses have far fewer, this bounds the work a large one causes. */
#define DNSSEC_MSG_MAX_RRS 512
/* Most compression pointers followed in one name */
#define DNSSEC_MAX_POINTERS 128

static uint16_t wire16(const unsigned char *p)
{
  return (uint16_t)((p[0] << 8) | p[1]);
}

static uint32_t wire32(const unsigned char *p)
{
  return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
         ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

static uint8_t lowc(uint8_t c)
{
  return ((c >= 'A') && (c <= 'Z')) ? (uint8_t)(c + ('a' - 'A')) : c;
}

CURLcode Curl_dnssec_read_name(const unsigned char *buf, size_t len,
                               size_t *offset, bool compress,
                               uint8_t out[DNSSEC_NAME_MAX])
{
  size_t pos = *offset;
  size_t limit = pos; /* compression pointers must point before this */
  size_t end = 0;
  size_t olen = 0;
  unsigned int pointers = 0;
  bool jumped = FALSE;

  for(;;) {
    uint8_t c;
    if(pos >= len)
      return CURLE_WEIRD_SERVER_REPLY;
    c = buf[pos];
    if((c & 0xc0) == 0xc0) {
      size_t ptr;
      if(!compress || (pos + 1 >= len) ||
         (++pointers > DNSSEC_MAX_POINTERS))
        return CURLE_WEIRD_SERVER_REPLY;
      ptr = ((size_t)(c & 0x3f) << 8) | buf[pos + 1];
      if(!jumped) {
        end = pos + 2;
        jumped = TRUE;
      }
      /* Only allow pointers going strictly backwards from the previous
         jump target. That guarantees termination. */
      if(ptr >= limit)
        return CURLE_WEIRD_SERVER_REPLY;
      limit = ptr;
      pos = ptr;
      continue;
    }
    if(c & 0xc0) /* extended label types are not supported */
      return CURLE_WEIRD_SERVER_REPLY;
    if((pos + 1 + c > len) || (olen + 1 + c > DNSSEC_NAME_MAX))
      return CURLE_WEIRD_SERVER_REPLY;
    memcpy(&out[olen], &buf[pos], 1 + (size_t)c);
    olen += 1 + (size_t)c;
    pos += 1 + (size_t)c;
    if(!c)
      break;
  }
  *offset = jumped ? end : pos;
  return CURLE_OK;
}

size_t Curl_dnssec_name_len(const uint8_t *name)
{
  size_t len = 0;
  while(name[len])
    len += 1 + (size_t)name[len];
  return len + 1;
}

unsigned int Curl_dnssec_name_labels(const uint8_t *name)
{
  unsigned int labels = 0;
  while(*name) {
    labels++;
    name += 1 + *name;
  }
  return labels;
}

unsigned int Curl_dnssec_name_sig_labels(const uint8_t *name)
{
  unsigned int labels = Curl_dnssec_name_labels(name);
  if((name[0] == 1) && (name[1] == '*'))
    labels--;
  return labels;
}

bool Curl_dnssec_name_eq(const uint8_t *a, const uint8_t *b)
{
  for(;;) {
    uint8_t len = *a;
    uint8_t i;
    if(len != *b)
      return FALSE;
    if(!len)
      return TRUE;
    for(i = 1; i <= len; i++) {
      if(lowc(a[i]) != lowc(b[i]))
        return FALSE;
    }
    a += 1 + len;
    b += 1 + len;
  }
}

const uint8_t *Curl_dnssec_name_suffix(const uint8_t *name,
                                       unsigned int labels)
{
  unsigned int have = Curl_dnssec_name_labels(name);
  while(have > labels) {
    name += 1 + *name;
    have--;
  }
  return name;
}

bool Curl_dnssec_name_sub(const uint8_t *name, const uint8_t *parent)
{
  unsigned int ln = Curl_dnssec_name_labels(name);
  unsigned int lp = Curl_dnssec_name_labels(parent);
  if(ln < lp)
    return FALSE;
  return Curl_dnssec_name_eq(Curl_dnssec_name_suffix(name, lp), parent);
}

/* store the offsets of the labels of 'name', return the number of them */
static unsigned int name_offsets(const uint8_t *name,
                                 uint8_t offs[DNSSEC_LABELS_MAX + 1])
{
  unsigned int n = 0;
  size_t pos = 0;
  while(name[pos] && (n <= DNSSEC_LABELS_MAX)) {
    offs[n++] = (uint8_t)pos;
    pos += 1 + (size_t)name[pos];
  }
  return n;
}

static int label_cmp(const uint8_t *a, const uint8_t *b)
{
  uint8_t la = a[0];
  uint8_t lb = b[0];
  uint8_t i;
  for(i = 1; (i <= la) && (i <= lb); i++) {
    uint8_t ca = lowc(a[i]);
    uint8_t cb = lowc(b[i]);
    if(ca != cb)
      return (int)ca - (int)cb;
  }
  return (int)la - (int)lb;
}

unsigned int Curl_dnssec_name_common(const uint8_t *a, const uint8_t *b)
{
  uint8_t oa[DNSSEC_LABELS_MAX + 1];
  uint8_t ob[DNSSEC_LABELS_MAX + 1];
  unsigned int na = name_offsets(a, oa);
  unsigned int nb = name_offsets(b, ob);
  unsigned int common = 0;
  while((common < na) && (common < nb) &&
        !label_cmp(&a[oa[na - common - 1]], &b[ob[nb - common - 1]]))
    common++;
  return common;
}

int Curl_dnssec_name_cmp(const uint8_t *a, const uint8_t *b)
{
  uint8_t oa[DNSSEC_LABELS_MAX + 1];
  uint8_t ob[DNSSEC_LABELS_MAX + 1];
  unsigned int na = name_offsets(a, oa);
  unsigned int nb = name_offsets(b, ob);
  unsigned int i;
  for(i = 1; (i <= na) && (i <= nb); i++) {
    int rc = label_cmp(&a[oa[na - i]], &b[ob[nb - i]]);
    if(rc)
      return rc;
  }
  return (int)na - (int)nb;
}

void Curl_dnssec_name_lower(uint8_t *dest, const uint8_t *name)
{
  size_t len = Curl_dnssec_name_len(name);
  size_t i;
  for(i = 0; i < len; i++)
    dest[i] = lowc(name[i]);
  /* the length octets are all < 64 and not affected by lowc() */
}

void Curl_dnssec_name_str(const uint8_t *name, char *out, size_t outlen)
{
  size_t o = 0;
  if(!outlen)
    return;
  if(!*name) {
    if(outlen > 1)
      out[o++] = '.';
    out[o] = 0;
    return;
  }
  while(*name) {
    uint8_t len = *name++;
    uint8_t i;
    for(i = 0; i < len; i++) {
      uint8_t c = name[i];
      if((c <= 0x20) || (c >= 0x7f) || (c == '.') || (c == '\\') ||
         (c == '"') || (c == '(') || (c == ')') || (c == ';') ||
         (c == '@') || (c == '$')) {
        if(o + 4 >= outlen)
          goto out;
        out[o++] = '\\';
        out[o++] = (char)('0' + c / 100);
        out[o++] = (char)('0' + (c / 10) % 10);
        out[o++] = (char)('0' + c % 10);
      }
      else {
        if(o + 1 >= outlen)
          goto out;
        out[o++] = (char)c;
      }
    }
    if(o + 1 >= outlen)
      goto out;
    out[o++] = '.';
    name += len;
  }
out:
  out[o] = 0;
}

CURLcode Curl_dnssec_name_parse(const char *str, size_t len,
                                uint8_t out[DNSSEC_NAME_MAX])
{
  size_t o = 0; /* where the current label's length octet is */
  size_t i = 0;
  uint8_t llen = 0;

  if((len == 1) && (str[0] == '.')) {
    out[0] = 0;
    return CURLE_OK;
  }
  if(!len)
    return CURLE_BAD_FUNCTION_ARGUMENT;

  while(i < len) {
    unsigned int c = (unsigned char)str[i++];
    if(c == '.') {
      if(!llen) /* empty label */
        return CURLE_BAD_FUNCTION_ARGUMENT;
      out[o] = llen;
      o += 1 + (size_t)llen;
      llen = 0;
      continue;
    }
    if(c == '\\') {
      if(i >= len)
        return CURLE_BAD_FUNCTION_ARGUMENT;
      if(ISDIGIT(str[i])) {
        if((i + 3 > len) || !ISDIGIT(str[i + 1]) || !ISDIGIT(str[i + 2]))
          return CURLE_BAD_FUNCTION_ARGUMENT;
        c = (unsigned int)((str[i] - '0') * 100 + (str[i + 1] - '0') * 10 +
                           (str[i + 2] - '0'));
        if(c > 255)
          return CURLE_BAD_FUNCTION_ARGUMENT;
        i += 3;
      }
      else
        c = (unsigned char)str[i++];
    }
    /* room for this octet, the label length and the root label */
    if((llen >= 63) || (o + 1 + llen + 1 >= DNSSEC_NAME_MAX))
      return CURLE_BAD_FUNCTION_ARGUMENT;
    out[o + 1 + llen] = (uint8_t)c;
    llen++;
  }
  if(llen) {
    out[o] = llen;
    o += 1 + (size_t)llen;
  }
  out[o] = 0;
  return CURLE_OK;
}

void Curl_dnssec_msg_free(struct dnssec_msg *msg)
{
  if(msg) {
    curlx_free(msg->buf);
    curlx_free(msg->names);
    curlx_free(msg->rrs);
    curlx_free(msg);
  }
}

CURLcode Curl_dnssec_msg_parse(const unsigned char *buf, size_t len,
                               struct dnssec_msg **pmsg)
{
  struct dnssec_msg *m = NULL;
  struct dynbuf names;
  uint8_t name[DNSSEC_NAME_MAX];
  size_t pos = 12;
  size_t nrrs;
  size_t an;
  size_t namelen;
  size_t i;
  CURLcode result = CURLE_WEIRD_SERVER_REPLY;

  *pmsg = NULL;
  curlx_dyn_init(&names, DNSSEC_MSG_MAX_RRS * DNSSEC_NAME_MAX);

  if((len < 12) || (len > DNSSEC_MSG_MAX))
    goto out;
  /* must be a response (QR), a standard query and not truncated (TC) */
  if(!(buf[2] & 0x80) || (buf[2] & 0x78) || (buf[2] & 0x02))
    goto out;
  if(wire16(&buf[4]) != 1)
    goto out;
  an = wire16(&buf[6]);
  nrrs = an + wire16(&buf[8]);

  m = curlx_calloc(1, sizeof(*m));
  if(!m) {
    result = CURLE_OUT_OF_MEMORY;
    goto out;
  }
  m->flags = wire16(&buf[2]);
  m->rcode = (uint8_t)(buf[3] & 0x0f);

  if(Curl_dnssec_read_name(buf, len, &pos, TRUE, m->qname) ||
     (pos + 4 > len))
    goto out;
  m->qtype = wire16(&buf[pos]);
  m->qclass = wire16(&buf[pos + 2]);
  pos += 4;

  /* every record is at least 11 bytes */
  if((nrrs > (len - pos) / 11) || (nrrs > DNSSEC_MSG_MAX_RRS))
    goto out;
  if(nrrs) {
    m->rrs = curlx_calloc(nrrs, sizeof(struct dnssec_rr));
    if(!m->rrs) {
      result = CURLE_OUT_OF_MEMORY;
      goto out;
    }
  }

  for(i = 0; i < nrrs; i++) {
    struct dnssec_rr *rr = &m->rrs[i];
    uint32_t ttl;
    if(Curl_dnssec_read_name(buf, len, &pos, TRUE, name) || (pos + 10 > len))
      goto out;
    rr->owner = curlx_dyn_len(&names);
    result = curlx_dyn_addn(&names, name, Curl_dnssec_name_len(name));
    if(result) {
      if(result != CURLE_OUT_OF_MEMORY)
        result = CURLE_WEIRD_SERVER_REPLY;
      goto out;
    }
    result = CURLE_WEIRD_SERVER_REPLY;
    rr->type = wire16(&buf[pos]);
    rr->rclass = wire16(&buf[pos + 2]);
    ttl = wire32(&buf[pos + 4]);
    /* RFC 2181 section 8: treat TTLs with the top bit set as zero */
    rr->ttl = (ttl & 0x80000000) ? 0 : ttl;
    rr->rdlen = wire16(&buf[pos + 8]);
    pos += 10;
    if(pos + rr->rdlen > len)
      goto out;
    rr->rdata = pos;
    rr->section = (uint8_t)((i < an) ? DNSSEC_SECT_ANSWER :
                            DNSSEC_SECT_AUTHORITY);
    pos += rr->rdlen;
  }
  m->nrrs = nrrs;

  m->buf = curlx_malloc(len);
  if(!m->buf) {
    result = CURLE_OUT_OF_MEMORY;
    goto out;
  }
  memcpy(m->buf, buf, len);
  m->len = len;
  m->names = (unsigned char *)curlx_dyn_take(&names, &namelen);
  if(!m->names && nrrs) {
    result = CURLE_OUT_OF_MEMORY;
    goto out;
  }
  m->size = sizeof(*m) + len + namelen + nrrs * sizeof(struct dnssec_rr);
  *pmsg = m;
  m = NULL;
  result = CURLE_OK;

out:
  curlx_dyn_free(&names);
  Curl_dnssec_msg_free(m);
  return result;
}

/*
 * Canonical RDATA.
 *
 * The RDATA layout of the types that contain domain names, as a string of
 * field codes:
 *   'N'  domain name, may be compressed, converted to lowercase
 *   'n'  domain name, not compressed, case kept (NSEC, RFC 6840 5.1)
 *   '2'  two octets, '4' four octets, '6' six octets, 'H' 18 octets
 *   'S'  character-string
 *   '*'  everything up to the end of the RDATA
 * Types not listed here have no names in their RDATA, or names that are
 * neither compressed nor lowercased, and are used as they are.
 */
static const char *rdata_layout(uint16_t type)
{
  switch(type) {
  case CURL_DNSSEC_TYPE_NS:
  case DNSSEC_TYPE_MD:
  case DNSSEC_TYPE_MF:
  case CURL_DNSSEC_TYPE_CNAME:
  case DNSSEC_TYPE_MB:
  case DNSSEC_TYPE_MG:
  case DNSSEC_TYPE_MR:
  case DNSSEC_TYPE_PTR:
  case CURL_DNSSEC_TYPE_DNAME:
    return "N";
  case CURL_DNSSEC_TYPE_SOA:
    return "NN*";
  case DNSSEC_TYPE_MINFO:
  case DNSSEC_TYPE_RP:
    return "NN";
  case DNSSEC_TYPE_MX:
  case DNSSEC_TYPE_AFSDB:
  case DNSSEC_TYPE_RT:
  case DNSSEC_TYPE_KX:
    return "2N";
  case DNSSEC_TYPE_PX:
    return "2NN";
  case DNSSEC_TYPE_SRV:
    return "6N";
  case DNSSEC_TYPE_NAPTR:
    return "22SSSN";
  case DNSSEC_TYPE_SIG:
  case CURL_DNSSEC_TYPE_RRSIG:
    return "HN*";
  case DNSSEC_TYPE_NXT:
    return "N*";
  case CURL_DNSSEC_TYPE_NSEC:
    return "n*";
  default:
    return NULL;
  }
}

/* A6, RFC 2874: prefix length, address suffix, prefix name */
static CURLcode rdata_a6(const struct dnssec_msg *m, size_t pos, size_t end,
                         struct dynbuf *out)
{
  uint8_t name[DNSSEC_NAME_MAX];
  size_t suffix;
  uint8_t plen;
  if(pos >= end)
    return CURLE_WEIRD_SERVER_REPLY;
  plen = m->buf[pos];
  if(plen > 128)
    return CURLE_WEIRD_SERVER_REPLY;
  suffix = (size_t)(128 - plen + 7) / 8;
  if(pos + 1 + suffix > end)
    return CURLE_WEIRD_SERVER_REPLY;
  if(curlx_dyn_addn(out, &m->buf[pos], 1 + suffix))
    return CURLE_OUT_OF_MEMORY;
  pos += 1 + suffix;
  if(!plen)
    return (pos == end) ? CURLE_OK : CURLE_WEIRD_SERVER_REPLY;
  if(Curl_dnssec_read_name(m->buf, end, &pos, FALSE, name) || (pos != end))
    return CURLE_WEIRD_SERVER_REPLY;
  Curl_dnssec_name_lower(name, name);
  return curlx_dyn_addn(out, name, Curl_dnssec_name_len(name));
}

CURLcode Curl_dnssec_rdata_canonical(const struct dnssec_msg *m,
                                     const struct dnssec_rr *rr,
                                     struct dynbuf *out)
{
  const char *layout = rdata_layout(rr->type);
  size_t pos = rr->rdata;
  size_t end = rr->rdata + rr->rdlen;

  if(rr->type == DNSSEC_TYPE_A6)
    return rdata_a6(m, pos, end, out);
  if(!layout)
    return curlx_dyn_addn(out, &m->buf[pos], rr->rdlen);

  for(; *layout; layout++) {
    uint8_t name[DNSSEC_NAME_MAX];
    size_t fixed = 0;
    switch(*layout) {
    case 'N':
    case 'n':
      /* Compression pointers can point anywhere before them in the
         message, but the name must start and end inside this RDATA. */
      if(pos >= end)
        return CURLE_WEIRD_SERVER_REPLY;
      if(Curl_dnssec_read_name(m->buf, m->len, &pos, (*layout == 'N'),
                               name) || (pos > end))
        return CURLE_WEIRD_SERVER_REPLY;
      if(*layout == 'N')
        Curl_dnssec_name_lower(name, name);
      if(curlx_dyn_addn(out, name, Curl_dnssec_name_len(name)))
        return CURLE_OUT_OF_MEMORY;
      continue;
    case 'S':
      if(pos >= end)
        return CURLE_WEIRD_SERVER_REPLY;
      fixed = 1 + (size_t)m->buf[pos];
      break;
    case '*':
      fixed = end - pos;
      break;
    case 'H':
      fixed = 18;
      break;
    default:
      fixed = (size_t)(*layout - '0');
      break;
    }
    if(pos + fixed > end)
      return CURLE_WEIRD_SERVER_REPLY;
    if(fixed && curlx_dyn_addn(out, &m->buf[pos], fixed))
      return CURLE_OUT_OF_MEMORY;
    pos += fixed;
  }
  return (pos == end) ? CURLE_OK : CURLE_WEIRD_SERVER_REPLY;
}

bool Curl_dnssec_bitmap_has(const uint8_t *map, size_t len, uint16_t type,
                            bool *pbad)
{
  size_t i = 0;
  int last = -1;
  bool found = FALSE;

  *pbad = FALSE;
  while(i < len) {
    uint8_t window;
    uint8_t blen;
    if(i + 2 > len) {
      *pbad = TRUE;
      return FALSE;
    }
    window = map[i];
    blen = map[i + 1];
    /* windows appear in increasing order, bitmaps are 1-32 octets */
    if(((int)window <= last) || !blen || (blen > 32) ||
       (i + 2 + blen > len)) {
      *pbad = TRUE;
      return FALSE;
    }
    last = window;
    if(window == (type >> 8)) {
      size_t octet = (size_t)((type & 0xff) >> 3);
      if(octet < blen)
        found = !!(map[i + 2 + octet] & (0x80 >> (type & 7)));
    }
    i += 2 + (size_t)blen;
  }
  return found;
}

uint16_t Curl_dnssec_keytag(const uint8_t *rdata, size_t rdlen)
{
  uint32_t ac = 0;
  size_t i;
  if(rdlen < 4)
    return 0;
  if(rdata[3] == 1) {
    /* RSA/MD5, RFC 4034 appendix B.1 as corrected by RFC 6840 5.5 */
    if(rdlen < 7)
      return 0;
    return (uint16_t)((rdata[rdlen - 3] << 8) | rdata[rdlen - 2]);
  }
  for(i = 0; i < rdlen; i++)
    ac += (i & 1) ? rdata[i] : ((uint32_t)rdata[i] << 8);
  ac += (ac >> 16) & 0xffff;
  return (uint16_t)(ac & 0xffff);
}

size_t Curl_dnssec_b32hex_decode(const uint8_t *in, size_t inlen,
                                 uint8_t *out, size_t outlen)
{
  uint32_t acc = 0;
  unsigned int bits = 0;
  size_t o = 0;
  size_t i;
  for(i = 0; i < inlen; i++) {
    uint8_t c = lowc(in[i]);
    unsigned int v;
    if((c >= '0') && (c <= '9'))
      v = (unsigned int)(c - '0');
    else if((c >= 'a') && (c <= 'v'))
      v = (unsigned int)(c - 'a' + 10);
    else
      return 0;
    acc = (acc << 5) | v;
    bits += 5;
    if(bits >= 8) {
      bits -= 8;
      if(o >= outlen)
        return 0;
      out[o++] = (uint8_t)(acc >> bits);
      acc &= (1U << bits) - 1;
    }
  }
  /* leftover bits must be zero padding */
  if(acc)
    return 0;
  return o;
}

#endif /* USE_DNSSEC */
