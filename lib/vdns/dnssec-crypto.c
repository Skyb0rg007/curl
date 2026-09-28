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

#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/err.h>

/*
 * Cryptographic operations for the DNSSEC validator, using OpenSSL (or a
 * library with a compatible libcrypto API).
 *
 * DNSSEC public keys and signatures are converted to the DER formats
 * OpenSSL takes (SubjectPublicKeyInfo and ECDSA-Sig-Value), which works
 * the same across OpenSSL, LibreSSL, BoringSSL and AWS-LC.
 *
 * Supported signature algorithms (RFC 8624, RFC 9904):
 *   5  RSASHA1             RFC 3110
 *   7  RSASHA1-NSEC3-SHA1  RFC 5155
 *   8  RSASHA256           RFC 5702
 *   10 RSASHA512           RFC 5702
 *   13 ECDSAP256SHA256     RFC 6605
 *   14 ECDSAP384SHA384     RFC 6605
 *   15 ED25519             RFC 8080
 *   16 ED448               RFC 8080 (not in BoringSSL, AWS-LC, LibreSSL)
 * Supported DS digest types: 1 SHA-1, 2 SHA-256, 4 SHA-384.
 */

#if defined(EVP_PKEY_ED25519) && \
  (!defined(LIBRESSL_VERSION_NUMBER) || \
   (LIBRESSL_VERSION_NUMBER >= 0x3070000fL))
#define DNSSEC_HAVE_ED25519
#endif
#if defined(EVP_PKEY_ED448) && !defined(LIBRESSL_VERSION_NUMBER) && \
  !defined(OPENSSL_IS_BORINGSSL) && !defined(OPENSSL_IS_AWSLC)
#define DNSSEC_HAVE_ED448
#endif
#ifndef OPENSSL_NO_EC
#define DNSSEC_HAVE_ECDSA
#endif

/* RSA modulus size limits in bits: RFC 3110 and RFC 5702 section 2.1
   allow 512 to 4096 bits for RSASHA1 and RSASHA256, RFC 5702 section 2.2
   1024 to 4096 bits for RSASHA512 */
#define DNSSEC_RSA_MIN_BITS     512
#define DNSSEC_RSA512_MIN_BITS  1024
#define DNSSEC_RSA_MAX_BITS     4096
/* Most octets in an RSA public exponent */
#define DNSSEC_RSA_MAX_EXPLEN   8

/* DER prefixes of SubjectPublicKeyInfo structures for fixed size keys */
static const uint8_t spki_p256[] = {
  0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02,
  0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03,
  0x42, 0x00, 0x04
};
static const uint8_t spki_p384[] = {
  0x30, 0x76, 0x30, 0x10, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02,
  0x01, 0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22, 0x03, 0x62, 0x00, 0x04
};
static const uint8_t spki_ed25519[] = {
  0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00
};
static const uint8_t spki_ed448[] = {
  0x30, 0x43, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x71, 0x03, 0x3a, 0x00
};
/* AlgorithmIdentifier for rsaEncryption, with NULL parameters */
static const uint8_t algid_rsa[] = {
  0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01,
  0x01, 0x05, 0x00
};

bool Curl_dnssec_alg_supported(uint8_t alg)
{
  switch(alg) {
  case DNSSEC_ALG_RSASHA1:
  case DNSSEC_ALG_RSASHA1_NSEC3:
  case DNSSEC_ALG_RSASHA256:
  case DNSSEC_ALG_RSASHA512:
    return TRUE;
#ifdef DNSSEC_HAVE_ECDSA
  case DNSSEC_ALG_ECDSAP256SHA256:
  case DNSSEC_ALG_ECDSAP384SHA384:
    return TRUE;
#endif
#ifdef DNSSEC_HAVE_ED25519
  case DNSSEC_ALG_ED25519:
    return TRUE;
#endif
#ifdef DNSSEC_HAVE_ED448
  case DNSSEC_ALG_ED448:
    return TRUE;
#endif
  default:
    return FALSE;
  }
}

bool Curl_dnssec_digest_supported(uint8_t dtype)
{
  return (dtype == DNSSEC_DIGEST_SHA1) || (dtype == DNSSEC_DIGEST_SHA256) ||
         (dtype == DNSSEC_DIGEST_SHA384);
}

/* The number of octets of a DER length */
static size_t der_lensize(size_t len)
{
  return (len < 0x80) ? 1 : ((len < 0x100) ? 2 : 3);
}

/* Write a DER length, return the number of octets */
static size_t der_putlen(uint8_t *p, size_t len)
{
  if(len < 0x80) {
    p[0] = (uint8_t)len;
    return 1;
  }
  if(len < 0x100) {
    p[0] = 0x81;
    p[1] = (uint8_t)len;
    return 2;
  }
  p[0] = 0x82;
  p[1] = (uint8_t)(len >> 8);
  p[2] = (uint8_t)len;
  return 3;
}

/* Skip the leading zero octets of an unsigned big-endian number, but not
   the last one. Returns the number of octets left, sets *pad when the
   INTEGER needs a zero octet to stay positive. */
static size_t der_trim(const uint8_t **num, size_t len, size_t *pad)
{
  while((len > 1) && !(*num)[0]) {
    (*num)++;
    len--;
  }
  *pad = (len && ((*num)[0] & 0x80)) ? 1 : 0;
  return len;
}

/* The number of octets of a DER INTEGER with the value 'num' */
static size_t der_uintsize(const uint8_t *num, size_t len)
{
  size_t pad;
  len = der_trim(&num, len, &pad);
  return 1 + der_lensize(len + pad) + len + pad;
}

/* Write a DER INTEGER with the unsigned big-endian value 'num', return the
   number of octets */
static size_t der_putuint(uint8_t *p, const uint8_t *num, size_t len)
{
  size_t pad;
  size_t n;
  len = der_trim(&num, len, &pad);
  p[0] = 0x02;
  n = 1 + der_putlen(&p[1], len + pad);
  if(pad)
    p[n++] = 0;
  memcpy(&p[n], num, len);
  return n + len;
}

/* Build the SubjectPublicKeyInfo for a DNSSEC RSA public key, RFC 3110
   section 2. Returns a DER buffer in *pder, to be freed. */
static CURLcode rsa_spki(const uint8_t *key, size_t keylen, size_t minbits,
                         uint8_t **pder, size_t *pderlen)
{
  const uint8_t *exp;
  const uint8_t *mod;
  size_t explen;
  size_t modlen;
  size_t bits;
  size_t seqlen;
  size_t bitslen;
  size_t spkilen;
  size_t total;
  uint8_t *der;
  uint8_t *p;

  if(keylen < 1)
    return CURLE_BAD_FUNCTION_ARGUMENT;
  if(key[0]) {
    explen = key[0];
    exp = &key[1];
  }
  else {
    if(keylen < 3)
      return CURLE_BAD_FUNCTION_ARGUMENT;
    explen = ((size_t)key[1] << 8) | key[2];
    exp = &key[3];
  }
  if(!explen || ((size_t)(exp - key) + explen >= keylen))
    return CURLE_BAD_FUNCTION_ARGUMENT;
  mod = exp + explen;
  modlen = keylen - (size_t)(mod - key);
  /* the modulus has no leading zero octets */
  if(!mod[0])
    return CURLE_BAD_FUNCTION_ARGUMENT;
  bits = modlen * 8;
  {
    uint8_t top = mod[0];
    while(!(top & 0x80)) {
      bits--;
      top = (uint8_t)(top << 1);
    }
  }
  /* RFC 3110 allows exponents up to 4096 bits, but a large exponent makes
     verifying as slow as signing. Real keys use 3 or 65537. */
  if((bits < minbits) || (bits > DNSSEC_RSA_MAX_BITS) ||
     (explen > DNSSEC_RSA_MAX_EXPLEN))
    return CURLE_BAD_FUNCTION_ARGUMENT;

  /* RSAPublicKey ::= SEQUENCE { modulus INTEGER, publicExponent INTEGER } */
  seqlen = der_uintsize(mod, modlen) +
           der_uintsize(exp, explen);
  /* BIT STRING: a zero octet for unused bits, then the RSAPublicKey */
  bitslen = 1 + (1 + der_lensize(seqlen) + seqlen);
  spkilen = sizeof(algid_rsa) + 1 + der_lensize(bitslen) + bitslen;
  total = 1 + der_lensize(spkilen) + spkilen;

  der = curlx_malloc(total);
  if(!der)
    return CURLE_OUT_OF_MEMORY;
  p = der;
  *p++ = 0x30;
  p += der_putlen(p, spkilen);
  memcpy(p, algid_rsa, sizeof(algid_rsa));
  p += sizeof(algid_rsa);
  *p++ = 0x03;
  p += der_putlen(p, bitslen);
  *p++ = 0x00;
  *p++ = 0x30;
  p += der_putlen(p, seqlen);
  p += der_putuint(p, mod, modlen);
  p += der_putuint(p, exp, explen);
  DEBUGASSERT((size_t)(p - der) == total);
  *pder = der;
  *pderlen = total;
  return CURLE_OK;
}

/* Prepend a fixed DER prefix to a raw public key */
static CURLcode fixed_spki(const uint8_t *prefix, size_t prefixlen,
                           const uint8_t *key, size_t keylen,
                           uint8_t **pder, size_t *pderlen)
{
  uint8_t *der = curlx_malloc(prefixlen + keylen);
  if(!der)
    return CURLE_OUT_OF_MEMORY;
  memcpy(der, prefix, prefixlen);
  memcpy(der + prefixlen, key, keylen);
  *pder = der;
  *pderlen = prefixlen + keylen;
  return CURLE_OK;
}

/* Convert an ECDSA signature from the DNSSEC r|s format (RFC 6605 section
   4) to DER ECDSA-Sig-Value */
static CURLcode ecdsa_sig_der(const uint8_t *sig, size_t siglen,
                              uint8_t *out, size_t outsize, size_t *poutlen)
{
  size_t half = siglen / 2;
  size_t rlen = der_uintsize(sig, half);
  size_t slen = der_uintsize(sig + half, half);
  size_t seqlen = rlen + slen;
  size_t total = 1 + der_lensize(seqlen) + seqlen;
  uint8_t *p = out;
  if(total > outsize)
    return CURLE_BAD_FUNCTION_ARGUMENT;
  *p++ = 0x30;
  p += der_putlen(p, seqlen);
  p += der_putuint(p, sig, half);
  p += der_putuint(p, sig + half, half);
  *poutlen = (size_t)(p - out);
  return CURLE_OK;
}

CURLcode Curl_dnssec_verify(uint8_t alg,
                            const uint8_t *key, size_t keylen,
                            const uint8_t *data, size_t datalen,
                            const uint8_t *sig, size_t siglen)
{
  const EVP_MD *md = NULL;
  uint8_t *der = NULL;
  size_t derlen = 0;
  uint8_t ecsig[2 * (48 + 3) + 4];
  const unsigned char *p;
  EVP_PKEY *pkey = NULL;
  EVP_MD_CTX *mdctx = NULL;
  bool oneshot = FALSE;
  CURLcode result;
  int rc;

  switch(alg) {
  case DNSSEC_ALG_RSASHA1:
  case DNSSEC_ALG_RSASHA1_NSEC3:
    md = EVP_sha1();
    result = rsa_spki(key, keylen, DNSSEC_RSA_MIN_BITS, &der, &derlen);
    break;
  case DNSSEC_ALG_RSASHA256:
    md = EVP_sha256();
    result = rsa_spki(key, keylen, DNSSEC_RSA_MIN_BITS, &der, &derlen);
    break;
  case DNSSEC_ALG_RSASHA512:
    md = EVP_sha512();
    result = rsa_spki(key, keylen, DNSSEC_RSA512_MIN_BITS, &der, &derlen);
    break;
#ifdef DNSSEC_HAVE_ECDSA
  case DNSSEC_ALG_ECDSAP256SHA256:
    md = EVP_sha256();
    if((keylen != 64) || (siglen != 64))
      return CURLE_BAD_FUNCTION_ARGUMENT;
    result = fixed_spki(spki_p256, sizeof(spki_p256), key, keylen,
                        &der, &derlen);
    if(!result)
      result = ecdsa_sig_der(sig, siglen, ecsig, sizeof(ecsig), &siglen);
    sig = ecsig;
    break;
  case DNSSEC_ALG_ECDSAP384SHA384:
    md = EVP_sha384();
    if((keylen != 96) || (siglen != 96))
      return CURLE_BAD_FUNCTION_ARGUMENT;
    result = fixed_spki(spki_p384, sizeof(spki_p384), key, keylen,
                        &der, &derlen);
    if(!result)
      result = ecdsa_sig_der(sig, siglen, ecsig, sizeof(ecsig), &siglen);
    sig = ecsig;
    break;
#endif
#ifdef DNSSEC_HAVE_ED25519
  case DNSSEC_ALG_ED25519:
    if((keylen != 32) || (siglen != 64))
      return CURLE_BAD_FUNCTION_ARGUMENT;
    result = fixed_spki(spki_ed25519, sizeof(spki_ed25519), key, keylen,
                        &der, &derlen);
    oneshot = TRUE;
    break;
#endif
#ifdef DNSSEC_HAVE_ED448
  case DNSSEC_ALG_ED448:
    if((keylen != 57) || (siglen != 114))
      return CURLE_BAD_FUNCTION_ARGUMENT;
    result = fixed_spki(spki_ed448, sizeof(spki_ed448), key, keylen,
                        &der, &derlen);
    oneshot = TRUE;
    break;
#endif
  default:
    return CURLE_NOT_BUILT_IN;
  }
  if(result)
    goto out;

  result = CURLE_BAD_FUNCTION_ARGUMENT;
  p = der;
  pkey = d2i_PUBKEY(NULL, &p, (long)derlen);
  if(!pkey || (p != der + derlen))
    goto out;

  result = CURLE_OUT_OF_MEMORY;
  mdctx = EVP_MD_CTX_new();
  if(!mdctx)
    goto out;

  result = CURLE_PEER_FAILED_VERIFICATION;
  if(EVP_DigestVerifyInit(mdctx, NULL, md, NULL, pkey) != 1)
    goto out;
  if(oneshot) {
#if defined(DNSSEC_HAVE_ED25519) || defined(DNSSEC_HAVE_ED448)
    rc = EVP_DigestVerify(mdctx, sig, siglen, data, datalen);
#else
    rc = 0;
#endif
  }
  else {
    if(EVP_DigestVerifyUpdate(mdctx, data, datalen) != 1)
      goto out;
    rc = EVP_DigestVerifyFinal(mdctx, sig, siglen);
  }
  if(rc == 1)
    result = CURLE_OK;

out:
  EVP_MD_CTX_free(mdctx);
  EVP_PKEY_free(pkey);
  curlx_free(der);
  /* do not leave errors in the queue for the TLS code to trip on */
  ERR_clear_error();
  return result;
}

static const EVP_MD *digest_md(uint8_t dtype)
{
  switch(dtype) {
  case DNSSEC_DIGEST_SHA1:
    return EVP_sha1();
  case DNSSEC_DIGEST_SHA256:
    return EVP_sha256();
  case DNSSEC_DIGEST_SHA384:
    return EVP_sha384();
  default:
    return NULL;
  }
}

size_t Curl_dnssec_digest(uint8_t dtype,
                          const uint8_t *d1, size_t l1,
                          const uint8_t *d2, size_t l2,
                          uint8_t out[DNSSEC_DIGEST_MAX])
{
  const EVP_MD *md = digest_md(dtype);
  EVP_MD_CTX *mdctx;
  unsigned int olen = 0;
  size_t result = 0;

  if(!md || ((size_t)EVP_MD_size(md) > DNSSEC_DIGEST_MAX))
    return 0;
  mdctx = EVP_MD_CTX_new();
  if(!mdctx)
    return 0;
  if((EVP_DigestInit_ex(mdctx, md, NULL) == 1) &&
     (EVP_DigestUpdate(mdctx, d1, l1) == 1) &&
     (!l2 || (EVP_DigestUpdate(mdctx, d2, l2) == 1)) &&
     (EVP_DigestFinal_ex(mdctx, out, &olen) == 1))
    result = olen;
  EVP_MD_CTX_free(mdctx);
  ERR_clear_error();
  return result;
}

CURLcode Curl_dnssec_nsec3_hash(const uint8_t *name, size_t namelen,
                                const uint8_t *salt, size_t saltlen,
                                uint16_t iterations,
                                uint8_t out[DNSSEC_NSEC3_HASHLEN])
{
  uint8_t digest[DNSSEC_DIGEST_MAX];
  unsigned int i;

  /* IH(salt, x, 0) = H(x || salt)
     IH(salt, x, k) = H(IH(salt, x, k-1) || salt), if k > 0 */
  if(Curl_dnssec_digest(DNSSEC_DIGEST_SHA1, name, namelen, salt, saltlen,
                        digest) != DNSSEC_NSEC3_HASHLEN)
    return CURLE_FAILED_INIT;
  for(i = 0; i < iterations; i++) {
    if(Curl_dnssec_digest(DNSSEC_DIGEST_SHA1, digest, DNSSEC_NSEC3_HASHLEN,
                          salt, saltlen, digest) != DNSSEC_NSEC3_HASHLEN)
      return CURLE_FAILED_INIT;
  }
  memcpy(out, digest, DNSSEC_NSEC3_HASHLEN);
  return CURLE_OK;
}

#endif /* USE_DNSSEC */
