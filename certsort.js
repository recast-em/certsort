// certsort.js v0.1-----------------------------------------------------------------
// This script bundles the domain certificate and the CABundle (both in PEM format) 
// into a single PEM file. It also (re)arranges the certificates within the entire 
// certificate chain, ensuring the correct order for usage with nginx etc..
// Warning: This script does NOT validate the certificates; it simply orders them.
// ---------------------------------------------------------------------------------
// Copyright 2023 Alexander Jost (info@alexanderjost.com). Licensed under MPL 2.0.
// Source code is heavily based on the work of AJ ONeal, see below:
// https://git.coolaj86.com/coolaj86/asn1-parser.js/raw/branch/master/asn1-parser.js
// Copyright 2018 AJ ONeal. All rights reserved
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */
'use strict';
const fs = require('fs');
const bufToHex = u8 => {
  const hex = [], len = u8.byteLength || u8.length;
  for (let i = 0; i < len; i++) {
    let h = u8[i].toString(16);
    hex.push((h.length % 2) ? '0' + h : h);
  }
  return hex.join('').toLowerCase();
};
const exitWithUsage = () => {
  process.stderr.write('USAGE: node(.exe) certsort.js domain.crt cabundle.crt > certchain.crt\n');
  process.exit(1);
};
const ELOOPN = 102; // but each domain list could have up to 100
const ELOOP = "Iterated over " + ELOOPN + "+ elements (probably a malformed file)";
const EDEEPN = 60; // I've seen https certificates go 29 deep
const EDEEP = "Element nested " + EDEEPN + "+ layers deep (probably a malformed file)";
// Container Types are Sequence 0x30, Container Array? (0xA0, 0xA1)
// Value Types are Boolean 0x01, Integer 0x02, Null 0x05, Object ID 0x06, String 0x0C, 0x16, 0x13, 0x1e Value Array? (0x82)
// Bit String (0x03) and Octet String (0x04) may be values or containers
// Sometimes Bit String is used as a container (RSA Pub Spki)
const CTYPES = [ 0x30, 0x31, 0xa0, 0xa1 ];
const VTYPES = [ 0x01, 0x02, 0x05, 0x06, 0x0c, 0x82 ];
const parseAsn1 = buf => {
  function parse(buf, depth, eager) {
    if (depth.length >= EDEEPN) { throw new Error(EDEEP); }
    var index = 2; // we know, at minimum, data starts after type (0) and lengthSize (1)
    var asn1 = { type: buf[0], lengthSize: 0, length: buf[1] };
    var child;
    var iters = 0;
    var adjust = 0;
    var adjustedLen;
    // Determine how many bytes the length uses, and what it is
    if (0x80 & asn1.length) {
      asn1.lengthSize = 0x7f & asn1.length;
      // I think that buf->hex->int solves the problem of Endianness... not sure
      asn1.length = parseInt(bufToHex(buf.slice(index, index + asn1.lengthSize)), 16);
      index += asn1.lengthSize;
    }
    // High-order bit Integers have a leading 0x00 to signify that they are positive.
    // Bit Streams use the first byte to signify padding, which x.509 doesn't use.
    if (0x00 === buf[index] && (0x02 === asn1.type || 0x03 === asn1.type)) { // However, 0x00 on its own is a valid number      
      if (asn1.length > 1) {
        index += 1;
        adjust = -1;
      }
    }
    adjustedLen = asn1.length + adjust;
    function parseChildren(eager) {
      asn1.children = [];
      while (iters < ELOOPN && index < (2 + asn1.length + asn1.lengthSize)) {
        iters += 1;
        depth.length += 1;
        child = parse(buf.slice(index, index + adjustedLen), depth, eager);
        depth.length -= 1;
        index += (2 + child.lengthSize + child.length);
        if (index > (2 + asn1.lengthSize + asn1.length)) {
          throw new Error("Parse error: child value length (" + child.length
            + ") is greater than remaining parent length (" + (asn1.length - index)
            + " = " + asn1.length + " - " + index + ")");
        }
        asn1.children.push(child);
      }
      if (index !== (2 + asn1.lengthSize + asn1.length)) {
        throw new Error("premature end-of-file");
      }
      if (iters >= ELOOPN) { throw new Error(ELOOP); }
      delete asn1.value;
      return asn1;
    }
    // Recurse into types that are _always_ containers
    if (-1 !== CTYPES.indexOf(asn1.type)) { return parseChildren(eager); }
    // Return types that are _always_ values
    asn1.value = Object.values(buf.slice(index, index + adjustedLen)).map(v => String.fromCharCode(v)).join('');
    if (-1 !== VTYPES.indexOf(asn1.type)) { return asn1; }
    // For ambigious / unknown types, recurse and return on failure (and return child array size to zero)
    try { return parseChildren(true); }
    catch(e) { asn1.children.length = 0; return asn1; }
  }
  var asn1 = parse(buf, []);
  var len = buf.byteLength || buf.length;
  if (len !== 2 + asn1.lengthSize + asn1.length) {
    throw new Error("Length of buffer does not match length of ASN.1 sequence.");
  }
  return asn1;
};
const derEntryFromRawText = rawText => {
  const lines = rawText.trim().split(/[\r\n]+/);
  if(lines.length < 3 || !/BEGIN CERTIFICATE-----/.test(lines[0]) || !/-----END CERTIFICATE/.test(lines[lines.length - 1])) {
    throw new Error('PEM format error');
  }
  const base64Lines = lines.slice(1, lines.length - 1);
  return {
    index: -1,
    commonNames: [], 
    lines: base64Lines,
    der: Uint8Array.from(atob(base64Lines.join('')), c => c.charCodeAt(0))
  };
};
if(process.argv.length !== 4) { exitWithUsage(); }
let certDomainTxt, certBundleTxt;
try {
  certDomainTxt = fs.readFileSync(process.argv[2], 'latin1');
  certBundleTxt = fs.readFileSync(process.argv[3], 'latin1');
} catch(e) {
  throw new Error('Error reading input files');
}
if(/-----[\s]+-----/.test(certDomainTxt)) { exitWithUsage(); } // mix up of domain and cabundle?
const certChain = [
  derEntryFromRawText(certDomainTxt), 
  ...certBundleTxt.split(/-----[\s]+-----/).map(certRawText => derEntryFromRawText(certRawText))
];
for(let i = 0; i < certChain.length; i++) {
  const entry = certChain[i];
  const crawl = v => {
    if(v.children) {
      for(let i = 0; i < v.children.length; i++) {
        let e = v.children[i];
        if(e.type == 6 && e.value == "U\u0004\u0003") { // "CN" :commonName
          entry.commonNames.push(v.children[i + 1].value);
          if(entry.commonNames.length > 2) {
            throw new Error('Invalid or unknown cert format (too many common names)');
          }
        }
        crawl(e);
      }
    }
  };
  crawl(parseAsn1(entry.der));
  if(entry.commonNames.length < 2) {
    throw new Error('Invalid or unknown cert format (too few common names)');
  }
}
const result = [];
let incIndex = 0;
let searchFor = certChain[0].commonNames[1]; // first subject is the domain name itself
if(!/^((((?!-))(xn--|_)?[a-z0-9-]{0,61}[a-z0-9]{1,1}|\*)\.)*(xn--)?([a-z0-9][a-z0-9\-]{0,60}|[a-z0-9-]{1,30}\.[a-z]{2,})$/.test(
  searchFor // check, if first cert is really for the domain name ...
)) {
  console.log(searchFor);
  throw new Error('Subject of domain cert is not a valid domain name');
}
for(let i = 0; i < certChain.length; i++) {
  const entry = certChain[i];
  if(entry.index === -1 && searchFor === entry.commonNames[1]) {
    entry.index = incIndex++;
    searchFor = certChain[i].commonNames[0];
    if(entry.commonNames[0] !== entry.commonNames[1]) { // do not append self-signed certs
      result.push(entry);
    }
    i = 0; continue; // skip the first, since we already know, it comes first
  }
}
for(let i = 0; i < certChain.length; i++) {
  if(certChain[i].index === -1) {
    throw new Error('Chain entries ambiguous or incomplete');
  }
}
for(let i = 0; i < certChain.length; i++) {
  const entry = certChain[i];
  process.stderr.write('Issuer: ' + entry.commonNames[0] + 
    '; Subject: ' + entry.commonNames[1] + 
    ((entry.commonNames[0] !== entry.commonNames[1]) ? '' : '; (self-signed)') +
    '; ==> ORDER: ' + (entry.index + 1) + '\n');
}
process.stderr.write('\nIn REARRANGED(?) order (without trusted(?) self-signed root cert):\n');
for(let i = 0; i < result.length; i++) {
  process.stderr.write('\t' + result[i].commonNames[1] + '\n');
}
process.stderr.write('\n');
for(let i = 0; i < result.length; i++) {
  process.stdout.write('-----BEGIN CERTIFICATE-----\n');
  process.stdout.write(result[i].lines.map(l => l.trim()).join('\n'));
  process.stdout.write('\n-----END CERTIFICATE-----\n');
}
