<!--
Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.

SPDX-License-Identifier: curl
-->

# DNSSEC validation

libcurl can be built with a DNSSEC validator (RFC 4033, 4034, 4035). It is
**experimental** and a building block for DANE (RFC 6698, RFC 7671): DANE
needs to know if the TLSA records of a server, and the addresses it connects
to, are authentic. The validator does not trust the AD bit of the DNS server
it asks, it validates everything itself from the DNS root trust anchors, like
a validating stub resolver.

Nothing in libcurl uses the validator yet.

## Build

The validator needs c-ares 1.28.0 or later and OpenSSL 3, or a library with
a compatible libcrypto API (LibreSSL, BoringSSL, AWS-LC).

    ./configure --enable-ares --with-openssl --enable-dnssec

    cmake -DENABLE_ARES=ON -DCURL_USE_OPENSSL=ON -DUSE_DNSSEC=ON

This defines `USE_DNSSEC`.

## Design

The code is in `lib/vdns/`:

- `dnssec.h` - the API
- `dnssec.c` - the validator
- `dnssec-wire.c` - DNS messages, names and the canonical form of records
- `dnssec-crypto.c` - signatures and digests, with OpenSSL
- `dnssec-ares.c` - sending the queries with c-ares

The validator does no I/O. It is given complete DNS response messages and
tells the caller which queries it needs answered next. The same code can
validate responses that arrive with c-ares, DoH or from a test.

A *context* (`struct Curl_dnssec_ctx`) holds the trust anchors, all the
responses and the zone keys validated so far. A *request*
(`struct Curl_dnssec_req`) validates the answer to one question. Requests
sharing a context share the DNSKEY and DS lookups. A context is meant to
live for the duration of a resolve or a transfer: it has fixed limits on the
number of queries and the amount of work it does.

~~~c
  struct Curl_dnssec_ctx *ctx;
  struct Curl_dnssec_req *req;
  char name[CURL_DNSSEC_NAME_STRLEN];
  uint16_t qtype;

  Curl_dnssec_ctx_create(&ctx);
  Curl_dnssec_req_create(ctx, "_443._tcp.example.com", CURL_DNSSEC_TYPE_TLSA,
                         &req);
  while(Curl_dnssec_req_run(req) == CURLE_AGAIN) {
    while(Curl_dnssec_ctx_next_query(ctx, name, sizeof(name), &qtype)) {
      /* send a query for name/qtype with the DO and CD bits set, then */
      Curl_dnssec_ctx_add_response(ctx, name, qtype, msg, msglen);
      /* or, if it failed */
      Curl_dnssec_ctx_add_failure(ctx, name, qtype);
    }
  }
  switch(Curl_dnssec_req_status(req)) {
    ...
  }
~~~

`Curl_dnssec_req_run()` evaluates the request from the start each time it
is called, until it needs a response that is not there. Validated zone keys
and RRsets are cached in the context, so repeating the evaluation is cheap.
When there is more than one query to make, like the DNSKEY and DS records of
a zone, it asks for all of them at once.

With c-ares, `Curl_dnssec_ares_validate()` does the query sending and
response feeding on a given channel and calls a callback when a request is
done. The owner of the channel processes its events as usual.

### Queries

All queries have the RD and CD bits set (RFC 6840 section 5.9) and an EDNS0
OPT record with the DO bit set (RFC 3225) and a UDP payload size of 1232.
c-ares retries truncated responses over TCP.

c-ares parses responses and the driver writes them back into DNS wire format
for the validator. Records c-ares knows, like A, CNAME and TLSA, are written
back with the same RDATA, and it keeps the RDATA of those it does not know,
like DNSKEY, RRSIG and NSEC. The validator decompresses and lowercases the
names in RDATA for the canonical form anyway.

The c-ares query cache has to be disabled on the channel the validator uses:
its cache key uses the name of the query type, and all types c-ares does not
know (DS, DNSKEY, ...) have the same name there. A cached DS response can
then be returned for a DNSKEY query. `Curl_dnssec_ares_create()` fails for a
channel with the query cache enabled.

The channel should also use TCP (`ARES_FLAG_USEVC`). DNSSEC responses are
often larger than 1232 bytes. Some DNS servers, like the systemd-resolved
stub, truncate UDP responses in the middle of a record, and c-ares then
fails the query as malformed instead of retrying it over TCP.

The validator needs a DNS server that passes on DNSSEC records. When it does
not, like a server that fails DS and DNSKEY queries, validation ends as
indeterminate.

### Results

The result of a request is one of (RFC 4035 section 4.3):

- `CURL_DNSSEC_SECURE`: a chain of trust from a trust anchor proves the
  answer, or its nonexistence, authentic.
- `CURL_DNSSEC_INSECURE`: a chain of trust proves that the answer comes from
  an unsigned part of the DNS, or one only signed with algorithms that are
  not supported.
- `CURL_DNSSEC_BOGUS`: the answer should be signed, but validation failed.
- `CURL_DNSSEC_INDETERMINATE`: validation did not complete. A lookup failed,
  no trust anchor covers the name or a limit was hit. This is neither secure
  nor proven insecure. Security decisions must treat it like bogus.

`Curl_dnssec_req_reason()` explains why a result is not secure. A request
also gives the response code of the final name (NOERROR or NXDOMAIN), the
name the answer is for after CNAME and DNAME records, the TTL and the RDATA
of the answer records, in canonical form (names uncompressed). The records
are only given out for secure and insecure results.

## Validation

### The chain of trust

The chain of trust is built bottom-up from the signer names in the RRSIG
records (RFC 4035 section 5). The keys of a zone are trusted when the DNSKEY
RRset of the zone is signed by a key that matches a trust anchor, or a
validated DS record from the parent zone. The DS RRset is validated with the
keys of the zone that signed it, which must be above the child zone, and so
on up to a trust anchor.

The signer names come from the response, so the validator only uses signers
at or below the closest trust anchor above the data, trying the closest
signer first. A signer above a trust anchor could otherwise be an unsigned
zone and make the data look insecure.

For each RRset, the RRSIG checks of RFC 4035 section 5.3.1 apply: the signer
is the zone that contains the RRset (for DS: a zone above it, for DNSKEY:
the zone itself), the labels count is not larger than the owner name's and
the signature is inside its validity period, compared with serial number
arithmetic (RFC 1982). The key must have the zone flag and protocol 3 and
must not be revoked (RFC 5011). Any valid signature is enough (RFC 6840
section 5.4). Signatures by keys that do not exist are ignored (RFC 6840
section 5.12).

The signed data is rebuilt in canonical form (RFC 4034 section 6): owner
names in lowercase, wildcard owners restored from the labels count, the
original TTL, names in the RDATA of the types listed in RFC 4034 6.2
decompressed and in lowercase, except in NSEC records (RFC 6840 section
5.1), and the records sorted with duplicates removed.

DS records with unsupported algorithms or digest types are disregarded. When
none are left, the zone is insecure (RFC 4035 5.2, RFC 6840 5.2). SHA-1 DS
records are ignored when there are SHA-256 or SHA-384 ones (RFC 4509 section
3).

### Proving data insecure

Unsigned data is only insecure when a validated DS denial shows it is below
a delegation to an unsigned zone. To find out, the validator walks down from
the closest trust anchor above the name, one label at a time, and asks for
the DS records of each name. A signed DS RRset makes the name a secure zone
cut, a validated NSEC or NSEC3 record with the NS bit set and no DS or SOA
bits an unsigned delegation (RFC 6840 section 4.4), as does an NSEC3 opt-out
span covering the name. Unsigned data in a secure zone is bogus.

The walk knows the zone above each name, so it can require the DS denial to
come from exactly that zone. Denials of DS records found on the way up the
chain of trust are always checked with this walk.

### Denial of existence

NXDOMAIN and NODATA responses are proven with NSEC (RFC 4035 section 5.4) or
NSEC3 (RFC 5155 section 8) records, all from the closest zone above the name
that signed any.

- NXDOMAIN: an NSEC covering the name and one covering the wildcard at the
  closest encloser, or an NSEC3 closest encloser proof and an NSEC3 covering
  the wildcard.
- NODATA: a matching NSEC or NSEC3 without the type and without CNAME (RFC
  6840 section 4.3), an NSEC showing an empty non-terminal, or a matching
  wildcard without the type.
- Wildcard answers: the RRSIG labels count shows the expansion. An NSEC must
  cover the name and prove the wildcard is at the closest encloser, or an
  NSEC3 must cover the next closer name.
- NSEC and NSEC3 records at a delegation, from the parent side, or with the
  DNAME bit, do not deny anything below them, nor any type other than DS at
  their name (RFC 6840 section 4.1). A DS denial must come from the parent
  zone.
- Compact denial of existence (RFC 9824): a matching NSEC or NSEC3 with the
  NXNAME type proves that the name does not exist. The request then has the
  NXDOMAIN response code.

### CNAME and DNAME

CNAME and DNAME (RFC 6672) records in the answer are followed and validated.
The CNAME records synthesized from a DNAME are not used, the validator
substitutes the name itself. When the response does not have the whole
chain, the validator asks for the rest. The result is the least secure one
of the chain.

## Policy

- Signature algorithms: RSASHA256 (8), RSASHA512 (10), ECDSAP256SHA256 (13),
  ECDSAP384SHA384 (14), ED25519 (15) and ED448 (16, not with BoringSSL,
  AWS-LC or LibreSSL). RSASHA1 (5) and RSASHA1-NSEC3-SHA1 (7) are
  implemented but treated as unsupported unless the context has the
  `CURL_DNSSEC_ALLOW_SHA1` flag, as RFC 9905 requires of validating resolver
  operators. Zones signed only with them are insecure.
- DS digests: SHA-1 (1), SHA-256 (2) and SHA-384 (4).
- RSA keys: 512 to 4096 bits, 1024 to 4096 bits for RSASHA512 (RFC 3110,
  RFC 5702).
- NSEC3 proofs are checked up to 150 iterations, the limit Unbound uses.
  NSEC3 records with more iterations are bogus (RFC 9276 section 3.2).
  Iterations never make an answer insecure: RFC 9276 section 4 explains that
  this leaves such zones open to forged answers.
- A closest encloser proof where the NSEC3 covering the next closer name has
  the opt-out flag is insecure (RFC 5155 section 9.2).
- Trust anchors: the root zone KSK-2017 and KSK-2024 DS records published by
  IANA. Other anchors can be set, as DS or DNSKEY records. A zone with an
  anchor is only trusted through its anchors, never through its parent, and
  data below it only through the closest anchor (the "closest encloser"
  policy of RFC 6840 appendix C.1). There is no RFC 5011 anchor updating.
- Signer names: any zone at or above the owner name, up to the closest
  trust anchor, is accepted. RFC 4035 section 5.3.1 wants the zone that
  contains the RRset. A parent zone's signed data for a name it has since
  delegated can then be used as long as its signatures are valid.
- Time: signatures must be valid at the time of validation, there is no
  allowance for clock skew. The context time can be set, for tests.

## Limits

Against resource exhaustion attacks like KeyTrap (CVE-2023-50387) and
NSEC3 hashing (CVE-2023-50868), a context has upper limits:

- 128 queries and 4 MB of response data
- 128 signature verifications
- 8 RRSIGs tried per RRset and signer, 4 keys tried per RRSIG and 3 signer
  zones per RRset
- 100000 SHA-1 calculations for NSEC3 hashes
- 24 nested zones in a chain of trust, and a recursion depth of 48
- 12 CNAME and DNAME records in a chain
- 512 records in a response, 256 records in an RRset, 16 NSEC or NSEC3
  records in a proof
- RSA public exponents of at most 8 octets

Going over a limit ends validation as indeterminate.

## Not supported

- Queries of type ANY and other meta types
- Private algorithms (253, 254): treated as unsupported
- GOST and SM2 algorithms and digests
- Aggressive use of NSEC records (RFC 8198) and caching between contexts

## Tests

Test 3402 checks the building blocks with the examples of RFC 4034, 4509,
5155, 5702, 6605 and 8080. Test 3403 validates recorded responses:

- the example zones and responses in RFC 4035 and RFC 5155
- a test DNS tree signed by BIND and ldns, served by BIND, with all the
  algorithms, NSEC and NSEC3 with and without opt-out, wildcards, empty
  non-terminals, CNAME, DNAME and unsigned delegations
- attacks made from those responses: removed and changed signatures, a
  CNAME turned into NODATA, NXDOMAIN from the parent side NSEC of a
  delegation, a wildcard used at the wrong closest encloser, forged DS
  denials and KeyTrap-like key and signature sets
- responses from the real DNS, validated from the root trust anchors

The responses are in `tests/unit/dnssec-vectors.h`, made by
`tests/unit/dnssec-vectors.py`. It needs dnspython, BIND and ldns, and
network access for the real DNS responses:

    tests/unit/dnssec-vectors.py > tests/unit/dnssec-vectors.h

The tests use the time the responses were made at.
