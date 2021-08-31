# Change Log

All notable changes to this project will be documented in this file.

## v1.0.1 - 2019-07-17

### Misc

- Minor update in lodash to mitigate a snyk reported vulnerability
- Fixes bug in tests
- Minor updates in README

## v1.0.0 - 2018-10-30

### Adds

- Adds option for the samesite cookie flag
- Adds autoRenew option

### Changes

- Updates cryptographic algorithms. It's now using AES 256 in GCM mode

### Removes

- Removes the following exported functions:
  - readSession
  - readCookies
  - checkLength
  - headersToArray
  - hmac_signature

### Misc

- Code refactor
