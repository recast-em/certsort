certsort.js v0.1
-----------------------------------------------------------------

This script bundles the domain certificate and the CABundle (both in PEM format) 
into a single PEM file. It also (re)arranges the certificates within the entire 
certificate chain, ensuring the correct order for usage with nginx etc..
*Warning:* This script does NOT validate the certificates; it simply orders them.

### LICENSE
Copyright 2023 Alexander Jost (info@alexanderjost.com). Licensed under MPL 2.0.
Source code is heavily based on the work of AJ ONeal, see below:
https://git.coolaj86.com/coolaj86/asn1-parser.js/raw/branch/master/asn1-parser.js
Copyright 2018 AJ ONeal. All rights reserved
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */