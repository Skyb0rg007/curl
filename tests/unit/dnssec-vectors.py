#!/usr/bin/env python3
# ***************************************************************************
#                                  _   _ ____  _
#  Project                     ___| | | |  _ \| |
#                             / __| | | | |_) | |
#                            | (__| |_| |  _ <| |___
#                             \___|\___/|_| \_\_____|
#
# Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
#
# This software is licensed as described in the file COPYING, which
# you should have received as part of this distribution. The terms
# are also available at https://curl.se/docs/copyright.html.
#
# You may opt to use, copy, modify, merge, publish, distribute and/or sell
# copies of the Software, and permit persons to whom the Software is
# furnished to do so, under the terms of the COPYING file.
#
# This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
# KIND, either express or implied.
#
# SPDX-License-Identifier: curl
#
###########################################################################
"""
Generate the DNSSEC validator test vectors in dnssec-vectors.h.

The vectors come from sources independent of curl's validator:

 - the examples in RFC 4034, 4509, 5155, 5702, 6605 and 8080,
 - the signed example zone and responses of RFC 4035 appendix A and B
   (NSEC) and RFC 5155 appendix A and B (NSEC3),
 - a test DNS tree signed by BIND's dnssec-signzone and served by named,
   plus attacks made from those responses,
 - responses from the real DNS, validated from the real root trust anchor.

Usage: dnssec-vectors.py [--rfcdir DIR] [--resolver IP] > dnssec-vectors.h

Needs dnspython 2.4 or later, BIND 9 (named, dnssec-keygen,
dnssec-signzone, dnssec-dsfromkey) and ldns (ldns-keygen, ldns-key2ds,
ldns-signzone) in PATH. The RFC texts are fetched
from rfc-editor.org unless --rfcdir has them.
"""

import argparse
import base64
import os
import random
import re
import shutil
import signal
import socket
import struct
import subprocess
import sys
import tempfile
import time
import urllib.request

import dns.dnssec
import dns.flags
import dns.message
import dns.name
import dns.rdata
import dns.rdataclass
import dns.rdatatype
import dns.rrset
import dns.zone

# status values, as in lib/vdns/dnssec.h
INDETERMINATE = 'CURL_DNSSEC_INDETERMINATE'
SECURE = 'CURL_DNSSEC_SECURE'
INSECURE = 'CURL_DNSSEC_INSECURE'
BOGUS = 'CURL_DNSSEC_BOGUS'


def rtype(t):
    return dns.rdatatype.from_text(t) if isinstance(t, str) else t


def n(text):
    return dns.name.from_text(text)


def c_str(b64, indent='    '):
    """Return a base64 string as a C string literal, split in lines."""
    # C90 compilers need not support string literals over 509 characters
    assert len(b64) <= 509
    lines = [b64[i:i + 64] for i in range(0, len(b64), 64)] or ['']
    return '\n'.join(indent + '"' + x + '"' for x in lines)


def c_text(text, indent='    '):
    """Return a string as a C string literal, split in lines."""
    lines = [text[i:i + 60] for i in range(0, len(text), 60)] or ['']
    return '\n'.join(indent + '"' + x + '"' for x in lines)


def c_pieces(cname, b64):
    """Return a long base64 string as an array of string literals."""
    out = [f'static const char *const {cname}[] = {{']
    out.extend(c_str(b64[i:i + 448], '  ') + ','
               for i in range(0, len(b64), 448))
    out.append('  NULL\n};')
    return '\n'.join(out)


def b64(data):
    return base64.b64encode(data).decode()


# ---------------------------------------------------------------------------
# RFC text handling

def rfc_text(num, rfcdir):
    if rfcdir:
        path = os.path.join(rfcdir, f'rfc{num:d}.txt')
        if os.path.exists(path):
            with open(path) as f:
                return f.read()
    url = f'https://www.rfc-editor.org/rfc/rfc{num:d}.txt'
    with urllib.request.urlopen(url) as r:
        return r.read().decode()


def rfc_clean(text):
    """Remove page breaks, headers and footers."""
    out = []
    for line in text.split('\n'):
        line = line.replace('\f', '')
        if re.match(r'^\S.*\[Page \d+\]$', line):
            continue
        if re.match(r'^RFC \d+ ', line):
            continue
        out.append(line)
    return '\n'.join(out)


def rfc_section(text, start, end):
    i = text.index(start)
    j = text.index(end, i + len(start))
    return text[i + len(start):j]


def parse_rrs(text, default_ttl=3600):
    """
    Parse zone file style records into a list of dns.rrset.RRset.

    The owner can be omitted, TTL and class are optional, parentheses
    span lines. The record order is kept.
    """
    # join parenthesized lines and remove comments
    lines = []
    buf = ''
    depth = 0
    for line in text.split('\n'):
        line = re.sub(r';.*$', '', line)
        if depth:
            buf += ' ' + line.strip()
        else:
            buf = line.rstrip()
        depth += line.count('(') - line.count(')')
        if depth < 0:
            # a ')' without '(', like in RFC 5155 B.6: the lines since the
            # last one with an owner name belong to the same record
            while lines and lines[-1][0].isspace() and len(lines) > 1:
                cont = lines.pop()
                lines[-1] += ' ' + cont.strip()
            lines[-1] += ' ' + buf.strip().replace(')', ' ')
            depth = 0
            buf = ''
        elif depth == 0:
            if buf.strip():
                lines.append(buf.replace('(', ' ').replace(')', ' '))
            buf = ''
    rrsets = []
    owner = None
    for line in lines:
        if line[0].isspace():
            toks = line.split()
        else:
            toks = line.split()
            owner = n(toks[0])
            toks = toks[1:]
        ttl = default_ttl
        if toks[0].isdigit():
            ttl = int(toks[0])
            toks = toks[1:]
        if toks[0] == 'IN':
            toks = toks[1:]
        t = dns.rdatatype.from_text(toks[0])
        rd = dns.rdata.from_text(dns.rdataclass.IN, t, ' '.join(toks[1:]))
        covers = rd.covers() if t == dns.rdatatype.RRSIG else \
            dns.rdatatype.NONE
        for rs in rrsets:
            if rs.name == owner and rs.rdtype == t and rs.covers == covers:
                rs.add(rd, ttl)
                break
        else:
            rs = dns.rrset.RRset(owner, dns.rdataclass.IN, t, covers)
            rs.add(rd, ttl)
            rrsets.append(rs)
    return rrsets


def make_msg(qname, qtype, rcode, answer, authority, flags=None):
    m = dns.message.Message(id=0)
    m.flags = dns.flags.QR | dns.flags.RD | dns.flags.RA | dns.flags.CD \
        if flags is None else flags
    m.set_rcode(rcode)
    m.question = [dns.rrset.RRset(n(qname) if isinstance(qname, str)
                                  else qname,
                                  dns.rdataclass.IN, rtype(qtype))]
    m.answer = list(answer)
    m.authority = list(authority)
    m.use_edns(0, dns.flags.DO, 1232)
    return m.to_wire()


def rfc_records(text):
    """
    Return the records in a piece of RFC text.

    Remove the 3 column indent and stop at the prose after them.
    """
    out = []
    for line in text.split('\n'):
        line = line[3:] if line.startswith('   ') else line.lstrip()
        if re.match(r'^(The|Note|This) ', line):
            break
        out.append(line)
    return '\n'.join(out)


def rfc_responses(text):
    """Parse the example responses of RFC 4035/5155 appendix B."""
    out = {}
    for sec in re.split(r'\n(?=B\.\d+(?:\.\d+)?\.  )', text):
        m = re.match(r'B\.(\d+(?:\.\d+)?)\.  ', sec)
        if not m or ';; Question' not in sec:
            continue
        num = m.group(1)
        rcode = int(re.search(r'RCODE=(\d+)', sec).group(1))
        q = re.search(r';; Question\s*\n\s*(\S+)\s+IN\s+(\S+)', sec)
        # split at the section headers, other ';;' lines are comments
        parts = {}
        cur = None
        lines = {}
        for line in sec.split('\n'):
            mm = re.match(r'\s*;; (Question|Answer|Authority|Additional)\s*$',
                          line)
            if mm:
                cur = mm.group(1)
                lines[cur] = []
            elif cur and not line.strip().startswith(';;'):
                lines[cur].append(line)
        for name in ('Answer', 'Authority'):
            body = rfc_records('\n'.join(lines.get(name, [])))
            parts[name] = parse_rrs(body) if body.strip() else []
        out[num] = (q.group(1), q.group(2), rcode, parts['Answer'],
                    parts['Authority'])
    return out


# ---------------------------------------------------------------------------
# Low level vectors

def sig_vector(dnskey_text, rrset_text, rrsig_text, origin):
    """Return the signed data for an RRSIG, made by dnspython."""
    key = dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.DNSKEY,
                              dnskey_text)
    rrset = parse_rrs(rrset_text)[0]
    rrsig = dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.RRSIG,
                                rrsig_text)
    data = dns.dnssec._make_rrsig_signature_data(rrset, rrsig, n(origin))
    return key, data, rrsig


def low_level(rfcdir):
    out = []
    # key tags and DS digests: owner, DNSKEY, tag, digest type, digest
    ds = [
        # RFC 4034 section 5.4
        ('dskey.example.com.',
         ('256 3 5 AQOeiiR0GOMYkDshWoSKz9XzfwJr1AYtsmx3'
          'TGkJaNXVbfi/2pHm822aJ5iI9BMzNXxeYCmZDRD99WYwYqUSdjMmmAphXdvxegXd/M5'
          '+X7OrzKBaMbCVdFLUUh6DhweJBjEVv5f2wwjM9XzcnOf+EPbtG9DMBmADjFDc2w/rl'
          'jwvFw=='), 60485, 1, '2BB183AF5F22588179A53B0A98631FAD1A292118'),
        # RFC 4509 section 2.3
        ('dskey.example.com.',
         ('256 3 5 AQOeiiR0GOMYkDshWoSKz9XzfwJr1AYtsmx3'
          'TGkJaNXVbfi/2pHm822aJ5iI9BMzNXxeYCmZDRD99WYwYqUSdjMmmAphXdvxegXd/M5'
          '+X7OrzKBaMbCVdFLUUh6DhweJBjEVv5f2wwjM9XzcnOf+EPbtG9DMBmADjFDc2w/rl'
          'jwvFw=='), 60485, 2,
         'D4B7D520E7BB5F0F67674A0CCEB1E3E0614B93C4F9E99B8383F6A1E4469DA50A'),
        # RFC 6605 section 6.1 and 6.2
        ('example.net.',
         ('257 3 13 GojIhhXUN/u4v54ZQqGSnyhWJwaubCvTmeexv7bR6e'
          'dbkrSqQpF64cYbcB7wNcP+e+MAnLr+Wi9xMWyQLc8NAA=='), 55648, 2,
         'b4c8c1fe2e7477127b27115656ad6256f424625bf5c1e2770ce6d6e37df61d17'),
        ('example.net.',
         ('257 3 14 xKYaNhWdGOfJ+nPrL8/arkwf2EY3MDJ+SErKivBVS'
          'um1w/egsXvSADtNJhyem5RCOpgQ6K8X1DRSEkrbYQ+OB+v8/uX45NBwY8rp65F6Glur'
          '8I/mlVNgF6W/qTI37m40'), 10771, 4,
         ('72d7b62976ce06438e9c0bf319013cf801f09ecc84b8d7e9495f27e305c6a9b0'
          '563a9b5f4d288405c3008a946df983d6')),
        # RFC 8080 section 6
        ('example.com.',
         ('257 3 15 l02Woi0iS8Aa25FQkUd9RMzZHJpBoRQwAQEX1SxZ'
          'JA4='), 3613, 2,
         '3aa5ab37efce57f737fc1627013fee07bdf241bd10f3b1964ab55c78e79a304b'),
        ('example.com.',
         ('257 3 16 3kgROaDjrh0H2iuixWBrc8g2EpBBLCdGzHmn+G2M'
          'pTPhpj/OiBVHHSfPodx1FYYUcJKm1MDpJtIA'), 9713, 2,
         '6ccf18d5bc5d7fc2fceb1d59d17321402f2aa8d368048db93dd811f5cb2b19c7'),
    ]
    out.extend([
        '/* key tags and DS digests from RFC 4034, 4509, 6605, 8080 */',
        'static const struct t3402_ds t3402_ds[] = {'])
    for owner, key, tag, dtype, digest in ds:
        k = dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.DNSKEY, key)
        assert dns.dnssec.key_id(k) == tag
        mine = dns.dnssec.make_ds(n(owner), k, dtype,
                                 policy=dns.dnssec.allow_all_policy)\
            .digest.hex()
        assert mine.lower() == digest.lower(), owner
        out.append(f'  {{ "{owner}", {tag:d}, {dtype:d},\n'
                   f'{c_str(b64(k.to_wire()))},\n'
                   f'{c_text(digest.lower())} }},')
    out.append('};\n')

    # signatures: algorithm, key, signed data, signature, expected result
    sigs = []
    # RFC 5702 6.1, a 512 bit key, the smallest allowed
    k, d, s = sig_vector(
        '256 3 8 AwEAAcFcGsaxxdgiuuGmCkVImy4h99CqT7jwY3pexPGcnUFtR2Fh36Bponc'
        'wtkZ4cAgtvd4Qs8PkxUdp6p/DlUmObdk=',
        'www.example.net. 3600 IN A 192.0.2.91',
        'A 8 3 3600 20300101000000 20000101000000 9033 example.net. kRCOH6u'
        '7l0QGy9qpC9l1sLncJcOKFLJ7GhiUOibu4teYp5VE9RncriShZNz85mwlMgNEacFYK/'
        'lPtPiVYP4bwg==', 'example.net.')
    sigs.extend([
        ('RFC 5702 RSASHA256 512 bit', k, d, s, 'CURLE_OK'),
        # the same key is too small for RSASHA512
        ('512 bit RSASHA512 key', k.replace(algorithm=10), d,
         s.replace(algorithm=10), 'CURLE_BAD_FUNCTION_ARGUMENT')])
    k, d, s = sig_vector(
        '256 3 10 AwEAAdHoNTOW+et86KuJOWRDp1pndvwb6Y83nSVXXyLA3DLroROUkN6X0'
        'O6pnWnjJQujX/AyhqFDxj13tOnD9u/1kTg7cV6rklMrZDtJCQ5PCl/D7QNPsgVsMu1J'
        '2Q8gpMpztNFLpPBz1bWXjDtaR7ZQBlZ3PFY12ZTSncorffcGmhOL',
        'www.example.net. 3600 IN A 192.0.2.91',
        'A 10 3 3600 20300101000000 20000101000000 3740 example.net. tsb4wn'
        'jRUDnB1BUi+t6TMTXThjVnG+eCkWqjvvjhzQL1d0YRoOe0CbxrVDYd0xDtsuJRaeUw1'
        'ep94PzEWzr0iGYgZBWm/zpq+9fOuagYJRfDqfReKBzMweOLDiNa8iP5g9vMhpuv6OPl'
        'vpXwm9Sa9ZXIbNl1MBGk0fthPgxdDLw=', 'example.net.')
    sigs.append(('RFC 5702 RSASHA512', k, d, s, 'CURLE_OK'))
    k, d, s = sig_vector(
        '257 3 13 GojIhhXUN/u4v54ZQqGSnyhWJwaubCvTmeexv7bR6edbkrSqQpF64cYbc'
        'B7wNcP+e+MAnLr+Wi9xMWyQLc8NAA==',
        'www.example.net. 3600 IN A 192.0.2.1',
        'A 13 3 3600 20100909100439 20100812100439 55648 example.net. qx6wL'
        'Yqmh+l9oCKTN6qIc+bw6ya+KJ8oMz0YP107epXAyGmt+3SNruPFKG7tZoLBLlUzGGus'
        '7ZwmwWep666VCw==', 'example.net.')
    sigs.append(('RFC 6605 ECDSAP256SHA256', k, d, s, 'CURLE_OK'))
    k, d, s = sig_vector(
        '257 3 14 xKYaNhWdGOfJ+nPrL8/arkwf2EY3MDJ+SErKivBVSum1w/egsXvSADtNJ'
        'hyem5RCOpgQ6K8X1DRSEkrbYQ+OB+v8/uX45NBwY8rp65F6Glur8I/mlVNgF6W/qTI3'
        '7m40',
        'www.example.net. 3600 IN A 192.0.2.1',
        'A 14 3 3600 20100909102025 20100812102025 10771 example.net. /L5hD'
        'KIvGDyI1fcARX3z65qrmPsVz73QD1Mr5CEqOiLP95hxQouuroGCeZOvzFaxsT8Glr74'
        'hbavRKayJNuydCuzWTSSPdz7wnqXL5bdcJzusdnI0RSMROxxwGipWcJm',
        'example.net.')
    sigs.append(('RFC 6605 ECDSAP384SHA384', k, d, s, 'CURLE_OK'))
    # RFC 8080 section 6: the example signatures do not verify (the RRSIG
    # texts there also lack fields), so sign the example RRset with the
    # example private keys. EdDSA signatures are deterministic.
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric import ed448, ed25519
    for alg, priv, key in [
            (15, 'ODIyNjAzODQ2MjgwODAxMjI2NDUxOTAyMDQxNDIyNjI=',
             'l02Woi0iS8Aa25FQkUd9RMzZHJpBoRQwAQEX1SxZJA4='),
            (15, 'DSSF3o0s0f+ElWzj9E/Osxw8hLpk55chkmx0LYN5WiY=',
             'zPnZ/QwEe7S8C5SPz2OfS5RR40ATk2/rYnE9xHIEijs='),
            (16,
             ('xZ+5Cgm463xugtkY5B0Jx6erFTXp13rYegst0qRtNsOYnaVpMx0Z/c5EiA9x'
              '8wWbDDct/U3FhYWA'),
             ('3kgROaDjrh0H2iuixWBrc8g2EpBBLCdGzHmn+G2MpTPhpj/OiBVHHSfPodx1'
              'FYYUcJKm1MDpJtIA')),
            (16,
             ('WEykD3ht3MHkU8iH4uVOLz8JLwtRBSqiBoM6fF72+Mrp/u5gjxuB1DV6NnPO'
              '2BlZdz4hdSTkOdOA'),
             ('kkreGWoccSDmUBGAe7+zsbG6ZAFQp+syPmYUurBRQc3tDjeMCJcVMRDmgcNL'
              'p5HlHAMy12VoISsA'))]:
        cls = ed25519.Ed25519PrivateKey if alg == 15 else \
            ed448.Ed448PrivateKey
        pk = cls.from_private_bytes(base64.b64decode(priv))
        k = dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.DNSKEY,
                                f'257 3 {alg:d} {key}')
        rrset = parse_rrs('example.com. 3600 IN MX 10 mail.example.com.')[0]
        s = dns.dnssec.sign(rrset, pk, n('example.com.'), k,
                            inception=1438207200, expiration=1440021600)
        d = dns.dnssec._make_rrsig_signature_data(rrset, s, n('example.com.'))
        aname = 'ED25519' if alg == 15 else 'ED448'
        # the same with a changed signed data
        bad = bytearray(d)
        bad[-1] ^= 1
        sigs.extend([
            (f'RFC 8080 {aname} key {dns.dnssec.key_id(k):d}',
             k, d, s, 'CURLE_OK'),
            (f'RFC 8080 {aname} changed data', k, bytes(bad), s,
             'CURLE_PEER_FAILED_VERIFICATION')])
    out.extend(['/* signature examples from RFC 5702, 6605 and 8080 */',
                'static const struct t3402_sig t3402_sig[] = {'])
    for desc, k, d, s, expect in sigs:
        if expect == 'CURLE_OK':
            # check the vector with dnspython too
            rrsig_ok = True
            try:
                dns.dnssec._validate_signature(s.signature, d, k)
            except (InvalidSignature, dns.dnssec.ValidationFailure,
                    dns.dnssec.UnsupportedAlgorithm):
                rrsig_ok = False
            assert rrsig_ok, desc
        out.append(f'  {{ "{desc}", {k.algorithm:d}, {expect},\n'
                   f'{c_str(b64(k.key))},\n'
                   f'{c_str(b64(d))},\n'
                   f'{c_str(b64(s.signature))} }},')
    out.append('};\n')

    # NSEC3 hashes, RFC 5155 appendix A: salt aabbccdd, 12 iterations
    text = rfc_clean(rfc_text(5155, rfcdir))
    out.extend(['/* NSEC3 hashes from RFC 5155 appendix A */',
                'static const struct t3402_nsec3 t3402_nsec3[] = {'])
    for name, h in re.findall(r'; H\(([^)]+)\)\s*\n?\s*;?\s*=\s*(\w+)', text):
        mine = dns.dnssec.nsec3_hash(name, 'aabbccdd', 12, 1).lower()
        assert mine == h, name
        out.append(f'  {{ "{name}",\n    "{h}" }},')
    out.append('};\n')
    return '\n'.join(out)


# ---------------------------------------------------------------------------
# Response tables and test cases

class Table:
    """A set of responses to queries, by name and type."""

    def __init__(self, cname):
        self.cname = cname
        self.msgs = {}

    def add(self, qname, qtype, wire):
        key = (str(n(qname) if isinstance(qname, str) else qname).lower(),
               dns.rdatatype.to_text(rtype(qtype)))
        self.msgs[key] = wire

    def get(self, qname, qtype):
        return self.msgs.get((str(qname).lower(),
                              dns.rdatatype.to_text(rtype(qtype))))

    def emit(self):
        out = []
        entries = []
        for i, ((name, t), wire) in enumerate(sorted(self.msgs.items())):
            piece = f'{self.cname}_{i:d}'
            out.append(c_pieces(piece, b64(wire)))
            entries.append(f'  {{ "{name}", '
                           f'{dns.rdatatype.from_text(t):d}, {piece} }},')
        out.append(f'static const struct t3403_msg {self.cname}[] = {{')
        out += entries
        out.append('  { NULL, 0, NULL }')
        out.append('};\n')
        return '\n'.join(out)


class Case:
    def __init__(self, desc, table, qname, qtype, status, rcode=None,
                 count=None, now=0, anchors=None, flags='0', override=None):
        self.desc = desc
        self.table = table
        self.qname = qname
        self.qtype = rtype(qtype)
        self.status = status
        self.rcode = -1 if rcode is None else rcode
        self.count = -1 if count is None else count
        self.now = now
        self.anchors = anchors
        self.flags = flags
        self.override = override


def emit_cases(cases):
    out = []
    anchor_sets = {}
    for c in cases:
        if c.anchors and tuple(c.anchors) not in anchor_sets:
            name = f't3403_anchors{len(anchor_sets):d}'
            anchor_sets[tuple(c.anchors)] = name
            out.append(f'static const char *const {name}[] = {{')
            out.extend(c_text(a, '  ') + ',' for a in c.anchors)
            out.append('  NULL\n};\n')

    def entry(c):
        override = c.override.cname if c.override else 'NULL'
        anchors = anchor_sets[tuple(c.anchors)] if c.anchors else 'NULL'
        return (f'  {{ "{c.desc}",\n'
                f'    {c.table.cname}, {override}, {anchors},\n'
                f'    {c.now:d}L, {c.flags},\n'
                f'{c_text(c.qname)}, {c.qtype:d},\n'
                f'    {c.status}, {c.rcode:d}, {c.count:d} }},')
    out.append('static const struct t3403_case t3403_cases[] = {')
    out.extend(entry(c) for c in cases)
    out.append('};\n')
    return '\n'.join(out)


def ts(text):
    return int(time.mktime(time.strptime(text + 'UTC', '%Y%m%d%H%M%S%Z'))) \
        - time.timezone


def rfc_cases(rfcdir):
    """Make the cases from the RFC 4035 and RFC 5155 examples."""
    tables = []
    cases = []
    for num, secA, secB, secBend, now in [
            (4035, 'Appendix A.  Signed Zone Example',
             'Appendix B.  Example Responses',
             'Appendix C.  Authentication Examples', ts('20040420000000')),
            (5155, 'Appendix A.  Example Zone',
             'Appendix B.  Example Responses',
             'Appendix C.  Special Considerations', ts('20100101000000'))]:
        text = rfc_clean(rfc_text(num, rfcdir))
        # the second occurrences, after the table of contents
        body = text[text.rindex(secA):]
        zone_text = body[len(secA):body.index(secB)]
        zone_text = zone_text[zone_text.index('example.'):]
        zone = parse_rrs(rfc_records(zone_text))
        resp_text = body[body.index(secB):body.index(secBend)]
        responses = rfc_responses(resp_text)

        t = Table(f't3403_rfc{num:d}')
        tables.append(t)
        keys = [rs for rs in zone if rs.rdtype == dns.rdatatype.DNSKEY]
        ksigs = [rs for rs in zone if rs.rdtype == dns.rdatatype.RRSIG and
                 rs.covers == dns.rdatatype.DNSKEY]
        t.add('example.', 'DNSKEY', make_msg('example.', 'DNSKEY', 0,
                                             keys + ksigs, []))
        ksk = next(k for k in keys[0] if k.flags == 257)
        anchor = (f'example. IN DNSKEY 257 3 {ksk.algorithm:d} '
                  f'{base64.b64encode(ksk.key).decode()}')
        flags = 'CURL_DNSSEC_ALLOW_SHA1'
        tag = f'RFC {num:d} B.'

        # the DS records for the delegations are in the zone
        def ds_msg(owner, zone=zone):
            return [rs for rs in zone if rs.name == n(owner) and
                    (rs.rdtype == dns.rdatatype.DS or
                     (rs.rdtype == dns.rdatatype.RRSIG and
                      rs.covers == dns.rdatatype.DS))]

        for _, (qn, qt, rcode, ans, auth) in sorted(responses.items()):
            t.add(qn, qt, make_msg(qn, qt, rcode, ans, auth))
        if num == 4035:
            expect = {
                '1': (SECURE, 0, 1),     # answer
                '2': (SECURE, 3, 0),     # name error
                '3': (SECURE, 0, 0),     # no data
                '6': (SECURE, 0, 1),     # wildcard expansion
                '7': (SECURE, 0, 0),     # wildcard no data
                # the DS denial is from the child zone itself
                '8': (BOGUS, None, 0),
            }
            # B.5, a referral to an unsigned zone: its DS denial proves
            # the unsigned child insecure
            b5 = responses['5']
            nsec = [rs for rs in b5[4] if rs.rdtype == dns.rdatatype.NSEC or
                    rs.covers == dns.rdatatype.NSEC]
            soa = [rs for rs in zone if rs.name == n('example.') and
                   (rs.rdtype == dns.rdatatype.SOA or
                    rs.covers == dns.rdatatype.SOA)]
            t.add('b.example.', 'DS', make_msg('b.example.', 'DS', 0, [],
                                               soa + nsec))
            mx = parse_rrs('mc.b.example. 3600 IN MX 1 mx.b.example.')
            t.add('mc.b.example.', 'MX', make_msg('mc.b.example.', 'MX', 0,
                                                  mx, []))
            cases.append(Case(tag + '5 unsigned child', t, 'mc.b.example.',
                              'MX', INSECURE, 0, 1, now, [anchor], flags))
            # B.4, a signed child zone. Its keys are not in the RFC.
            t.add('a.example.', 'DS', make_msg('a.example.', 'DS', 0,
                                               ds_msg('a.example.'), []))
            cases.extend([
                # SHA-1 signatures are not accepted without the flag
                Case(tag + '1 without SHA-1', t, 'x.w.example.', 'MX',
                     INSECURE, 0, 1, now, [anchor], '0'),
                # validated signatures have expired later
                Case(tag + '1 expired', t, 'x.w.example.', 'MX', BOGUS,
                     None, 0, ts('20040510000000'), [anchor], flags),
                Case(tag + '1 not yet valid', t, 'x.w.example.', 'MX',
                     BOGUS, None, 0, ts('20040401000000'), [anchor],
                     flags)])
        else:
            # All NSEC3 records in the example zone have the opt-out flag.
            # RFC 5155 9.2: a closest encloser proof with an opt-out NSEC3
            # covering the next closer name does not make a secure answer
            expect = {
                '1': (INSECURE, 3, 0),   # name error
                '2': (SECURE, 0, 0),     # no data
                '2.1': (SECURE, 0, 0),   # no data, empty non-terminal
                '4': (INSECURE, 0, 1),   # wildcard expansion
                '5': (INSECURE, 0, 0),   # wildcard no data
                '6': (BOGUS, None, 0),   # DS denial from the child zone
            }
            # B.3, a referral to an opt-out unsigned zone
            b3 = responses['3']
            nsec3 = [rs for rs in b3[4] if rs.rdtype == dns.rdatatype.NSEC3 or
                     rs.covers == dns.rdatatype.NSEC3]
            soa = [rs for rs in zone if rs.name == n('example.') and
                   (rs.rdtype == dns.rdatatype.SOA or
                    rs.covers == dns.rdatatype.SOA)]
            t.add('c.example.', 'DS', make_msg('c.example.', 'DS', 0, [],
                                               soa + nsec3))
            mx = parse_rrs('mc.c.example. 3600 IN MX 1 mx.c.example.')
            t.add('mc.c.example.', 'MX', make_msg('mc.c.example.', 'MX', 0,
                                                  mx, []))
            cases.append(Case(tag + '3 opt-out unsigned child', t,
                              'mc.c.example.', 'MX', INSECURE, 0, 1, now,
                              [anchor], flags))
        for num_b, (status, rcode, count) in sorted(expect.items()):
            qn, qt = responses[num_b][0], responses[num_b][1]
            cases.append(Case(tag + num_b, t, qn, qt, status, rcode, count,
                              now, [anchor], flags))
        # from the root, without responses for the root zone
        qn, qt = responses[min(expect)][0:2]
        cases.extend([
            Case(tag + ' from the root', t, qn, qt, INDETERMINATE, None, 0,
                 now, None, flags),
            # without a trust anchor for it, nothing can be said about it
            Case(tag + ' no trust anchor', t, qn, qt, INDETERMINATE, None,
                 0, now, ['elsewhere. IN DS 1 13 2 ' + '00' * 32], flags)])
    return tables, cases


# ---------------------------------------------------------------------------
# Talking DNS

def query_raw(server, port, qname, qtype, cd=True):
    q = dns.message.make_query(qname, rtype(qtype), want_dnssec=True,
                               payload=1232)
    if cd:
        q.flags |= dns.flags.CD
    wire = q.to_wire()
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.settimeout(5)
        for _ in range(3):
            s.sendto(wire, (server, port))
            try:
                data = s.recv(65535)
                break
            except socket.timeout:
                continue
        else:
            raise RuntimeError(f'no response for {qname!s} {qtype!s}')
    if data[2] & 0x02:  # TC, retry over TCP
        with socket.create_connection((server, port), timeout=10) as s:
            s.sendall(struct.pack('!H', len(wire)) + wire)
            ln = b''
            while len(ln) < 2:
                ln += s.recv(2 - len(ln))
            want = struct.unpack('!H', ln)[0]
            data = b''
            while len(data) < want:
                data += s.recv(want - len(data))
    # a zero id makes the vectors stable
    return b'\0\0' + data[2:]


def collect(table, server, port, questions):
    """
    Query the questions and what validating them needs.

    That is the DNSKEY and DS records of the signer zones up to the root,
    the DS records at every name above unsigned records (to prove them
    insecure), and the rest of incomplete CNAME chains.
    """
    # the questions also get the DS records at every name above them: the
    # validator walks down to them to prove denials with too many NSEC3
    # iterations, and to find out about unsigned records in the attacks
    todo = []
    for qname, qtype in questions:
        todo.append((qname, qtype))
        name = n(qname) if isinstance(qname, str) else qname
        while name != dns.name.root:
            todo.append((name, 'DS'))
            name = name.parent()
    done = set()

    def add(name, qtype):
        todo.append((name, qtype))

    def walk(name):
        while name != dns.name.root:
            add(name, 'DS')
            name = name.parent()

    while todo:
        qname, qtype = todo.pop(0)
        qname = n(qname) if isinstance(qname, str) else qname
        key = (str(qname).lower(), rtype(qtype))
        if key in done:
            continue
        done.add(key)
        wire = query_raw(server, port, qname, qtype)
        table.add(qname, qtype, wire)
        m = dns.message.from_wire(wire)
        signed = set()
        for rs in m.answer + m.authority:
            if rs.rdtype == dns.rdatatype.RRSIG:
                for rd in rs:
                    signed.add((rs.name, rd.type_covered))
                    add(rd.signer, 'DNSKEY')
                    if rd.signer != dns.name.root:
                        add(rd.signer, 'DS')
        # unsigned data needs the DS records above it
        for rs in m.answer:
            if rs.rdtype != dns.rdatatype.RRSIG and \
               (rs.name, rs.rdtype) not in signed:
                walk(rs.name)
        if not m.answer and not any(
                rs.rdtype == dns.rdatatype.RRSIG for rs in m.authority):
            walk(qname)
        # follow the CNAME and DNAME chain
        name = qname
        for _ in range(12):
            nxt = None
            for rs in m.answer:
                if rs.rdtype == dns.rdatatype.CNAME and rs.name == name:
                    nxt = next(iter(rs)).target
                elif rs.rdtype == dns.rdatatype.DNAME and \
                        name.is_subdomain(rs.name) and name != rs.name:
                    nxt = name.relativize(rs.name).concatenate(
                        next(iter(rs)).target)
            if nxt is None:
                break
            name = nxt
        if name != qname and not m.get_rrset(m.answer, name,
                                             dns.rdataclass.IN,
                                             rtype(qtype)) and \
           not any(rs.rdtype in (dns.rdatatype.SOA, dns.rdatatype.NSEC,
                                 dns.rdatatype.NSEC3)
                   for rs in m.authority):
            add(name, qtype)


# ---------------------------------------------------------------------------
# BIND signed test zones

ALGS = {8: 'RSASHA256', 10: 'RSASHA512', 13: 'ECDSAP256SHA256',
        14: 'ECDSAP384SHA384', 15: 'ED25519', 16: 'ED448', 5: 'RSASHA1'}

TLSA_DATA = 'a' * 64

ZONES = [
    # name, algorithm, NSEC mode, records, delegations: (child, signed)
    ('.', 13, 'nsec', '', [('test.', True)]),
    ('test.', 13, 'nsec', '', [
        ('nsec.test.', True), ('nsec3.test.', True), ('optout.test.', True),
        ('ed448.test.', True), ('rsa512.test.', True), ('sha1.test.', True),
        ('iter.test.', True), ('iter50.test.', True),
        ('badds.test.', 'bad'),
        ('unsigned.test.', False)]),
    ('nsec.test.', 8, 'nsec', '''
www A 192.0.2.1
www AAAA 2001:db8::1
UPPER A 192.0.2.9
alias CNAME www
ext CNAME www.nsec3.test.
dn DNAME nsec3.test.
*.wild A 192.0.2.2
*.wild TXT "wildcard"
b.wild A 192.0.2.4
a.b.ent A 192.0.2.3
mx MX 10 www
_443._tcp.www TLSA 3 1 1 ''' + TLSA_DATA + '''
''', [('sub.nsec.test.', True), ('insec.nsec.test.', False)]),
    ('sub.nsec.test.', 15, 'nsec3', 'www A 192.0.2.5\n', []),
    ('insec.nsec.test.', None, None, 'www A 192.0.2.6\n', []),
    ('nsec3.test.', 13, 'nsec3', '''
www A 192.0.2.7
*.wild A 192.0.2.8
a.b.ent A 192.0.2.3
''', [('insec.nsec3.test.', False)]),
    ('insec.nsec3.test.', None, None, 'www A 192.0.2.10\n', []),
    ('optout.test.', 14, 'optout', 'www A 192.0.2.11\n',
     [('u1.optout.test.', False)]),
    ('u1.optout.test.', None, None, 'www A 192.0.2.12\n', []),
    ('ed448.test.', 16, 'nsec', 'www A 192.0.2.13\n', []),
    ('rsa512.test.', 10, 'nsec', 'www A 192.0.2.14\n', []),
    ('sha1.test.', 5, 'nsec', 'www A 192.0.2.15\n', []),
    # BIND does not sign with more than 50 NSEC3 iterations, ldns does
    ('iter.test.', 13, 'ldns-iter', 'www A 192.0.2.16\n',
     [('low.iter.test.', True)]),
    ('low.iter.test.', 13, 'nsec3', 'www A 192.0.2.20\n',
     [('sub.low.iter.test.', True)]),
    ('sub.low.iter.test.', 13, 'nsec', 'www A 192.0.2.22\n', []),
    ('iter50.test.', 13, 'iter', 'www A 192.0.2.19\n', []),
    ('badds.test.', 13, 'nsec', 'www A 192.0.2.17\n', []),
    ('unsigned.test.', None, None, 'www A 192.0.2.18\n',
     [('island.unsigned.test.', False)]),
    # a signed zone below an unsigned one, with its own trust anchor
    ('island.unsigned.test.', 13, 'nsec', 'www A 192.0.2.21\n', []),
]


def run(cmd, cwd):
    r = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True,
                       check=False)
    if r.returncode:
        sys.stderr.write(' '.join(cmd) + '\n' + r.stdout + r.stderr)
        raise RuntimeError('command failed')
    return r.stdout


def zfile(zone):
    return 'root' if zone == '.' else zone.rstrip('.')


def sign_zones(tmp, now):
    """Make, sign and return the zones, children first."""
    ds = {}
    anchor = None
    for zone, alg, mode, records, children in reversed(ZONES):
        base = zfile(zone)
        text = f'$TTL 3600\n$ORIGIN {zone}\n'
        text += '@ SOA ns.test. hostmaster.test. 1 3600 600 86400 300\n'
        text += '@ NS ns.test.\n'
        if zone == 'test.':
            text += 'ns A 192.0.2.53\n'
        text += records
        for child, signed in children:
            text += f'{child} NS ns.test.\n'
            if signed is True:
                text += ds[child]
            elif signed == 'bad':
                # DS for a key the child does not have
                text += f'{child} DS 12345 13 2 ' + '00' * 32 + '\n'
        with open(os.path.join(tmp, base + '.zone'), 'w') as f:
            f.write(text)
        if alg is None:
            continue
        if mode == 'ldns-iter':
            key = run(['ldns-keygen', '-a', ALGS[alg], '-k', zone],
                      tmp).strip()
            ds[zone] = run(['ldns-key2ds', '-n', '-2', key + '.key'], tmp)
            run(['ldns-signzone', '-n', '-t', '100', '-s', 'abcd',
                 '-i', str(now - 3600), '-e', str(now + 30 * 86400),
                 '-f', base + '.zone.signed', '-o', zone, base + '.zone',
                 key], tmp)
            continue
        name = ALGS[alg]
        bits = ['-b', '1024'] if alg in (5, 8, 10) else []
        split = zone in ('.', 'nsec.test.')
        keys = [run(['dnssec-keygen', '-q', '-K', tmp, '-a', name]
                    + bits + kf + ['-n', 'ZONE', zone], tmp).strip()
                for kf in ((['-f', 'KSK'], []) if split else
                           (['-f', 'KSK'],))]
        ds[zone] = run(['dnssec-dsfromkey', '-2', keys[0] + '.key'], tmp)
        if zone == '.':
            with open(os.path.join(tmp, keys[0] + '.key')) as f:
                for line in f:
                    if not line.startswith(';'):
                        anchor = line.strip()
        args = ['dnssec-signzone', '-q', '-K', tmp, '-o', zone,
                '-s', str(now - 3600), '-e', str(now + 30 * 86400),
                '-f', base + '.zone.signed']
        if mode == 'nsec3':
            args += ['-3', '-', '-H', '0']
        elif mode == 'optout':
            args += ['-3', '-', '-H', '0', '-A']
        elif mode == 'iter':
            args += ['-3', 'abcd', '-H', '50']
        if not split:
            args += ['-z']  # one key signs everything
        with open(os.path.join(tmp, base + '.zone'), 'a') as f:
            f.writelines(f'$INCLUDE {k}.key\n' for k in keys)
        args += [base + '.zone']
        run(args, tmp)
    return anchor, ds


def start_named(tmp, port):
    conf = [(f'options {{ directory "{tmp}"; '
             f'listen-on port {port:d} {{ 127.0.0.1; }};'
             ' listen-on-v6 { none; }; recursion no;'
             ' dnssec-validation no; pid-file "named.pid"; };'),
            'controls { };']
    for zone, alg, _, _, _ in ZONES:
        f = zfile(zone) + ('.zone.signed' if alg else '.zone')
        conf.append(f'zone "{zone}" {{ type primary; file "{f}"; }};')
    with open(os.path.join(tmp, 'named.conf'), 'w') as f:
        f.write('\n'.join(conf) + '\n')
    # named keeps its own copy of the log file descriptor
    with open(os.path.join(tmp, 'named.log'), 'w') as log:
        p = subprocess.Popen(['named', '-g', '-c',
                              os.path.join(tmp, 'named.conf')],
                             stdout=log, stderr=log)
    for _ in range(100):
        try:
            query_raw('127.0.0.1', port, '.', 'SOA')
            return p
        except (OSError, RuntimeError):
            # socket errors and timeouts (OSError), or no response
            time.sleep(0.1)
    p.kill()
    with open(os.path.join(tmp, 'named.log')) as f:
        raise RuntimeError('named did not start: ' + f.read())


def signed_zone(tmp, zone):
    with open(os.path.join(tmp, zfile(zone) + '.zone.signed')) as f:
        return dns.zone.from_text(f.read(), origin=zone, relativize=False,
                                  check_origin=False)


def zone_rrsets(z, name, rdtype):
    """Return the RRset and its RRSIGs from a zone."""
    node = z.get_node(n(name))
    out = []
    for rds in node.rdatasets:
        if rds.rdtype == rtype(rdtype) or \
           (rds.rdtype == dns.rdatatype.RRSIG and
                rds.covers == rtype(rdtype)):
            rs = dns.rrset.RRset(n(name), rds.rdclass, rds.rdtype,
                                 rds.covers)
            rs.update(rds)
            out.append(rs)
    return out


def edit(wire, fn):
    m = dns.message.from_wire(wire)
    fn(m)
    return b'\0\0' + m.to_wire()[2:]


def bind_cases(tmp):
    now = int(time.time())
    anchor, ds = sign_zones(tmp, now)
    island = ds['island.unsigned.test.'].strip()
    port = random.randint(20000, 30000)
    named = start_named(tmp, port)
    t = Table('t3403_bind')
    cases = []

    def case(desc, qname, qtype, status, rcode=None, count=None,
             flags='0', override=None, at=None, anchors=None):
        cases.append(Case('BIND ' + desc, t, qname, qtype, status, rcode,
                          count, now if at is None else at,
                          anchors or [anchor], flags, override))

    try:
        questions = [
            ('www.nsec.test.', 'A', 'answer', SECURE, 0, 1),
            ('www.nsec.test.', 'TXT', 'NODATA', SECURE, 0, 0),
            ('nx.nsec.test.', 'A', 'NXDOMAIN', SECURE, 3, 0),
            ('upper.nsec.test.', 'A', 'uppercase owner', SECURE, 0, 1),
            ('alias.nsec.test.', 'A', 'CNAME', SECURE, 0, 1),
            ('ext.nsec.test.', 'A', 'CNAME to another zone', SECURE, 0, 1),
            ('www.dn.nsec.test.', 'A', 'DNAME', SECURE, 0, 1),
            ('x.wild.nsec.test.', 'A', 'wildcard', SECURE, 0, 1),
            ('x.wild.nsec.test.', 'MX', 'wildcard NODATA', SECURE, 0, 0),
            ('a.b.wild.nsec.test.', 'A', 'below a name under a wildcard',
             SECURE, 3, 0),
            ('b.ent.nsec.test.', 'A', 'empty non-terminal', SECURE, 0, 0),
            ('_443._tcp.www.nsec.test.', 'TLSA', 'TLSA', SECURE, 0, 1),
            ('mx.nsec.test.', 'MX', 'MX', SECURE, 0, 1),
            ('www.insec.nsec.test.', 'A', 'unsigned child (NSEC)', INSECURE,
             0, 1),
            ('www.sub.nsec.test.', 'A', 'signed child', SECURE, 0, 1),
            ('nx.sub.nsec.test.', 'A', 'NSEC3 NXDOMAIN', SECURE, 3, 0),
            ('www.nsec3.test.', 'A', 'NSEC3 zone', SECURE, 0, 1),
            ('www.nsec3.test.', 'TXT', 'NSEC3 NODATA', SECURE, 0, 0),
            ('nx.nsec3.test.', 'A', 'NSEC3 NXDOMAIN', SECURE, 3, 0),
            ('x.wild.nsec3.test.', 'A', 'NSEC3 wildcard', SECURE, 0, 1),
            ('x.wild.nsec3.test.', 'MX', 'NSEC3 wildcard NODATA', SECURE, 0,
             0),
            ('b.ent.nsec3.test.', 'A', 'NSEC3 empty non-terminal', SECURE,
             0, 0),
            ('www.insec.nsec3.test.', 'A', 'unsigned child (NSEC3)',
             INSECURE, 0, 1),
            ('www.optout.test.', 'A', 'opt-out zone', SECURE, 0, 1),
            ('www.u1.optout.test.', 'A', 'opt-out unsigned child',
             INSECURE, 0, 1),
            ('nx.optout.test.', 'A', 'NXDOMAIN in an opt-out span',
             INSECURE, 3, 0),
            ('www.ed448.test.', 'A', 'ED448', SECURE, 0, 1),
            ('www.rsa512.test.', 'A', 'RSASHA512', SECURE, 0, 1),
            ('www.sha1.test.', 'A', 'RSASHA1 not accepted', INSECURE, 0, 1),
            ('nx.iter.test.', 'A', 'NSEC3 with 100 iterations', INSECURE,
             3, 0),
            ('www.iter.test.', 'A', 'answer from zone with 100 iterations',
             SECURE, 0, 1),
            ('nx.iter50.test.', 'A', 'NSEC3 with 50 iterations', SECURE, 3,
             0),
            ('www.low.iter.test.', 'A', 'zone below 100 iterations', SECURE,
             0, 1),
            ('nx.low.iter.test.', 'A', 'NXDOMAIN below 100 iterations',
             SECURE, 3, 0),
            ('www.sub.low.iter.test.', 'A', 'two zones below 100 iterations',
             SECURE, 0, 1),
            ('www.island.unsigned.test.', 'A', 'signed below unsigned',
             INSECURE, 0, 1),
            ('nx.island.unsigned.test.', 'A',
             'signed below unsigned NXDOMAIN', INSECURE, 3, 0),
            ('www.dn.nsec.test.', 'CNAME', 'CNAME below a DNAME', SECURE, 0,
             1),
            ('www.badds.test.', 'A', 'DS for a missing key', BOGUS, None,
             0),
            ('www.unsigned.test.', 'A', 'unsigned zone', INSECURE, 0, 1),
            ('nx.unsigned.test.', 'A', 'unsigned zone NXDOMAIN', INSECURE,
             3, 0),
            ('test.', 'DNSKEY', 'DNSKEY', SECURE, 0, None),
            ('nsec.test.', 'DS', 'DS', SECURE, 0, 1),
            ('insec.nsec.test.', 'DS', 'no DS', SECURE, 0, 0),
        ]
        collect(t, '127.0.0.1', port, [(q[0], q[1]) for q in questions] +
                # asked for when the island has a trust anchor
                [('nx.island.unsigned.test.', 'DS'),
                 ('www.island.unsigned.test.', 'DS')])
        for qname, qtype, desc, status, rcode, count in questions:
            case(desc, qname, qtype, status, rcode, count)
        case('RSASHA1 accepted', 'www.sha1.test.', 'A', SECURE, 0, 1,
             'CURL_DNSSEC_ALLOW_SHA1')
        case('island trust anchor', 'www.island.unsigned.test.', 'A', SECURE,
             0, 1, anchors=[anchor, island])
        case('island trust anchor NXDOMAIN', 'nx.island.unsigned.test.', 'A',
             SECURE, 3, 0, anchors=[anchor, island])
        case('expired', 'www.nsec.test.', 'A', BOGUS, None, 0,
             at=now + 31 * 86400)
        case('not yet valid', 'www.nsec.test.', 'A', BOGUS, None, 0,
             at=now - 7200)

        nsec = signed_zone(tmp, 'nsec.test.')

        def attack(desc, qname, qtype, status, wire, rcode=None, count=None,
                   extra=None):
            o = Table(f't3403_attack{len(attacks):d}')
            o.add(qname, qtype, wire)
            for q2, t2, w2 in extra or []:
                o.add(q2, t2, w2)
            attacks.append(o)
            case('attack: ' + desc, qname, qtype, status, rcode, count,
                 override=o)

        attacks = []
        www = t.get('www.nsec.test.', 'A')

        def strip_sigs(m):
            m.answer = [rs for rs in m.answer
                        if rs.rdtype != dns.rdatatype.RRSIG]
        attack('RRSIG removed', 'www.nsec.test.', 'A', BOGUS,
               edit(www, strip_sigs))

        def change_a(m):
            rs = m.find_rrset(m.answer, n('www.nsec.test.'),
                              dns.rdataclass.IN, dns.rdatatype.A)
            rs.clear()
            rs.add(dns.rdata.from_text('IN', 'A', '192.0.2.66'))
        attack('changed address', 'www.nsec.test.', 'A', BOGUS,
               edit(www, change_a))

        def flip_sig(m):
            for rs in m.answer:
                if rs.rdtype == dns.rdatatype.RRSIG:
                    rd = next(iter(rs))
                    sig = bytearray(rd.signature)
                    sig[10] ^= 1
                    rs.clear()
                    rs.add(rd.replace(signature=bytes(sig)))
        attack('corrupted signature', 'www.nsec.test.', 'A', BOGUS,
               edit(www, flip_sig))

        def dup_and_case(m):
            rs = m.find_rrset(m.answer, n('www.nsec.test.'),
                              dns.rdataclass.IN, dns.rdatatype.A)
            new = []
            for r in m.answer:
                r2 = dns.rrset.RRset(n('WwW.NsEc.TeSt.'), r.rdclass,
                                     r.rdtype, r.covers)
                r2.update(r)
                new.append(r2)
            m.answer = new
            del rs
        attack('mixed case owner', 'www.nsec.test.', 'A', SECURE,
               edit(www, dup_and_case), 0, 1)

        # RFC 6840 4.3: a CNAME turned into NODATA
        alias_nsec = zone_rrsets(nsec, 'alias.nsec.test.', 'NSEC')
        soa = zone_rrsets(nsec, 'nsec.test.', 'SOA')
        attack('CNAME removed, NODATA', 'alias.nsec.test.', 'A', BOGUS,
               make_msg('alias.nsec.test.', 'A', 0, [], soa + alias_nsec))

        # RFC 6840 4.1: the parent side NSEC of a delegation denies names
        # in the child
        sub_nsec = zone_rrsets(nsec, 'sub.nsec.test.', 'NSEC')
        attack('NXDOMAIN from parent side NSEC', 'www.sub.nsec.test.', 'A',
               BOGUS, make_msg('www.sub.nsec.test.', 'A', 3, [],
                               soa + sub_nsec))

        # a wildcard expansion for a name with a closer encloser
        wild = dns.message.from_wire(t.get('x.wild.nsec.test.', 'A'))
        nx = dns.message.from_wire(t.get('a.b.wild.nsec.test.', 'A'))
        forged = []
        for rs in wild.answer:
            r2 = dns.rrset.RRset(n('a.b.wild.nsec.test.'), rs.rdclass,
                                 rs.rdtype, rs.covers)
            r2.update(rs)
            forged.append(r2)
        attack('wildcard at the wrong closest encloser',
               'a.b.wild.nsec.test.', 'A', BOGUS,
               make_msg('a.b.wild.nsec.test.', 'A', 0, forged,
                        nx.authority))

        # claim a signed child is unsigned: strip the signatures, and deny
        # the DS with an unrelated NSEC
        sub = t.get('www.sub.nsec.test.', 'A')
        www_nsec = zone_rrsets(nsec, 'www.nsec.test.', 'NSEC')
        attack('unsigned answer, forged DS denial', 'www.sub.nsec.test.',
               'A', BOGUS, edit(sub, strip_sigs),
               extra=[('sub.nsec.test.', 'DS',
                       make_msg('sub.nsec.test.', 'DS', 0, [],
                                soa + www_nsec))])

        # DS denied by the child zone instead of the parent
        child = dns.message.from_wire(t.get('www.sub.nsec.test.', 'A'))
        sub_z = signed_zone(tmp, 'sub.nsec.test.')
        apex3 = []
        for name in sub_z.nodes:
            for rds in sub_z.nodes[name].rdatasets:
                if rds.rdtype == dns.rdatatype.NSEC3 or \
                   rds.covers == dns.rdatatype.NSEC3:
                    rs = dns.rrset.RRset(name, rds.rdclass, rds.rdtype,
                                         rds.covers)
                    rs.update(rds)
                    apex3.append(rs)
        sub_soa = zone_rrsets(sub_z, 'sub.nsec.test.', 'SOA')
        del child
        attack('DS denied by the child', 'www.sub.nsec.test.', 'A', BOGUS,
               edit(sub, strip_sigs),
               extra=[('sub.nsec.test.', 'DS',
                       make_msg('sub.nsec.test.', 'DS', 0, [],
                                sub_soa + apex3))])

        # NSEC3 records with too many iterations from a zone above the one
        # that holds the name prove nothing
        it = signed_zone(tmp, 'iter.test.')
        it_soa = zone_rrsets(it, 'iter.test.', 'SOA')
        it_n3 = []
        for name in it.nodes:
            for rds in it.nodes[name].rdatasets:
                if rds.rdtype == dns.rdatatype.NSEC3 or \
                   rds.covers == dns.rdatatype.NSEC3:
                    rs = dns.rrset.RRset(name, rds.rdclass, rds.rdtype,
                                         rds.covers)
                    rs.update(rds)
                    it_n3.append(rs)
        sub2 = t.get('www.sub.low.iter.test.', 'A')
        attack('DS denied by a zone above the parent',
               'www.sub.low.iter.test.', 'A', BOGUS, edit(sub2, flip_sig),
               extra=[('sub.low.iter.test.', 'DS',
                       make_msg('sub.low.iter.test.', 'DS', 0, [],
                                it_soa + it_n3))])
        attack('NXDOMAIN from a zone above', 'nx.low.iter.test.', 'A', BOGUS,
               make_msg('nx.low.iter.test.', 'A', 3, [], it_soa + it_n3))

        # RRSIGs claiming a signer above the trust anchor of the island,
        # an unsigned zone
        def signer_unsigned(m):
            for rs in m.answer + m.authority:
                if rs.rdtype == dns.rdatatype.RRSIG:
                    rds = list(rs)
                    rs.clear()
                    for rd in rds:
                        rs.add(rd.replace(signer=n('unsigned.test.')))
        o = Table(f't3403_attack{len(attacks):d}')
        o.add('www.island.unsigned.test.', 'A',
              edit(t.get('www.island.unsigned.test.', 'A'),
                   signer_unsigned))
        attacks.append(o)
        case('attack: signer above the trust anchor',
             'www.island.unsigned.test.', 'A', BOGUS, override=o,
             anchors=[anchor, island])
        o = Table(f't3403_attack{len(attacks):d}')
        o.add('nx.island.unsigned.test.', 'A',
              edit(t.get('nx.island.unsigned.test.', 'A'), signer_unsigned))
        attacks.append(o)
        case('attack: NSEC signer above the trust anchor',
             'nx.island.unsigned.test.', 'A', BOGUS, override=o,
             anchors=[anchor, island])

        # signatures claiming other signers do not hide the right one
        def junk_signers(m):
            for rs in m.answer:
                if rs.rdtype == dns.rdatatype.RRSIG:
                    rd = next(iter(rs))
                    rs.clear()
                    for sg in ('.', 'test.', '.', 'test.'):
                        sig = bytearray(rd.signature)
                        sig[3] ^= 0x10
                        rs.add(rd.replace(signer=n(sg),
                                          signature=bytes(sig)))
                    rs.add(rd)
        attack('junk signers', 'www.nsec.test.', 'A', SECURE,
               edit(www, junk_signers), 0, 1)

        # KeyTrap: many keys with the key tag of the ZSK, and many
        # signatures with that tag
        keys = dns.message.from_wire(t.get('nsec.test.', 'DNSKEY'))
        krs = next(rs for rs in keys.answer
                   if rs.rdtype == dns.rdatatype.DNSKEY)
        zsk = next(k for k in krs if k.flags == 256)
        tag = dns.dnssec.key_id(zsk)
        extra_keys = []
        while len(extra_keys) < 20:
            # random key material, with the last two octets chosen to give
            # the key tag (RFC 4034 appendix B)
            key = bytearray(zsk.key)
            key[-8:] = os.urandom(8)
            rd = bytearray(struct.pack('!HBB', zsk.flags, zsk.protocol,
                                       zsk.algorithm)) + key
            ln = len(rd)
            base = sum(b if i & 1 else b << 8
                       for i, b in enumerate(rd[:-2]))
            for v in range(65536):
                hi, lo = v >> 8, v & 0xff
                ac = base + (hi if (ln - 2) & 1 else hi << 8) + \
                    (lo if (ln - 1) & 1 else lo << 8)
                ac += (ac >> 16) & 0xffff
                if ac & 0xffff == tag:
                    key[-2:] = bytes([hi, lo])
                    k = zsk.replace(key=bytes(key))
                    assert dns.dnssec.key_id(k) == tag
                    extra_keys.append(k)
                    break

        def keytrap_keys(m):
            rs = m.find_rrset(m.answer, n('nsec.test.'), dns.rdataclass.IN,
                              dns.rdatatype.DNSKEY)
            for k in extra_keys:
                rs.add(k)

        def keytrap_sigs(m):
            for rs in m.answer:
                if rs.rdtype == dns.rdatatype.RRSIG:
                    rd = next(iter(rs))
                    rs.clear()
                    for i in range(20):
                        sig = bytearray(rd.signature)
                        sig[i] ^= 0x55
                        rs.add(rd.replace(signature=bytes(sig)))
                    rs.add(rd)
        # the DNSKEY RRset signatures are made with the KSK and stay valid
        # when keys are added to the answer, as long as they are
        # verified against the original RRset: they are not, so this is
        # bogus, but must not take long
        attack('KeyTrap', 'www.nsec.test.', 'A', BOGUS,
               edit(www, keytrap_sigs), extra=[
                   ('nsec.test.', 'DNSKEY', edit(t.get('nsec.test.',
                                                       'DNSKEY'),
                                                 keytrap_keys))])
    finally:
        named.send_signal(signal.SIGTERM)
        named.wait()
    return [t] + attacks, cases


# ---------------------------------------------------------------------------
# The real DNS

REAL = [
    ('.', 'DNSKEY', 'root DNSKEY', SECURE, 0, None),
    ('isc.org.', 'A', 'isc.org', SECURE, 0, None),
    ('nonexistent-curl-test.isc.org.', 'A', 'NXDOMAIN', SECURE, 3, 0),
    ('isc.org.', 'TLSA', 'NODATA', SECURE, 0, 0),
    ('_25._tcp.mail.ietf.org.', 'TLSA', 'TLSA', SECURE, 0, None),
    ('github.com.', 'AAAA', 'unsigned, in .com opt-out', INSECURE, None,
     None),
    ('nonexistent-curl-test.cloudflare.com.', 'A',
     'compact denial of existence', SECURE, 3, 0),
    ('www.huque.com.', 'AAAA', 'CNAME', SECURE, 0, None),
    ('dnssec-failed.org.', 'A', 'broken DS', BOGUS, None, 0),
]


def real_cases(resolver):
    t = Table('t3403_real')
    now = int(time.time())
    collect(t, resolver, 53, [(q[0], q[1]) for q in REAL])
    cases = []
    for qname, qtype, desc, status, rcode, count in REAL:
        cases.append(Case('real ' + desc, t, qname, qtype, status, rcode,
                          count, now))
    cases.append(Case('real expired', t, 'isc.org.', 'A', BOGUS, None, 0,
                      now + 60 * 86400))
    return [t], cases, now


PREAMBLE = """#ifndef HEADER_CURL_DNSSEC_VECTORS_H
#define HEADER_CURL_DNSSEC_VECTORS_H
/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \\| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \\___|\\___/|_| \\_\\_____|
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

/* Generated by dnssec-vectors.py, do not edit. */

/* DS digest: owner, key tag, digest type, DNSKEY RDATA, digest in hex */
struct t3402_ds {
  const char *owner;
  int keytag;
  int dtype;
  const char *dnskey;
  const char *digest;
};

/* signature: algorithm, expected result, public key, signed data and
   signature */
struct t3402_sig {
  const char *desc;
  int alg;
  CURLcode expect;
  const char *key;
  const char *data;
  const char *sig;
};

/* NSEC3 hash with salt aabbccdd and 12 iterations */
struct t3402_nsec3 {
  const char *name;
  const char *hash;
};

/* the response to a query, in base64 pieces */
struct t3403_msg {
  const char *name;
  int type;
  const char *const *msg;
};

/* a validation: responses (entries in 'override' are used first), trust
   anchors (NULL for the built-in ones), time and flags, question and the
   expected status, rcode and number of answer records (-1: any) */
struct t3403_case {
  const char *desc;
  const struct t3403_msg *table;
  const struct t3403_msg *override;
  const char *const *anchors;
  long now;
  unsigned int flags;
  const char *qname;
  int qtype;
  Curl_dnssec_status status;
  int rcode;
  int count;
};
"""


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--rfcdir')
    ap.add_argument('--resolver', default='1.1.1.1')
    args = ap.parse_args()

    out = [PREAMBLE, low_level(args.rfcdir)]
    tables, cases = rfc_cases(args.rfcdir)
    tmp = tempfile.mkdtemp()
    try:
        t2, c2 = bind_cases(tmp)
    finally:
        shutil.rmtree(tmp)
    t3, c3, real_now = real_cases(args.resolver)
    out.extend(t.emit() for t in tables + t2 + t3)
    stamp = time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime(real_now))
    out.extend([f'/* the real DNS responses are from {stamp} */',
                emit_cases(cases + c2 + c3),
                '#endif /* HEADER_CURL_DNSSEC_VECTORS_H */'])
    print('\n'.join(out))


if __name__ == '__main__':
    main()
