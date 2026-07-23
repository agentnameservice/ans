# Changelog

## [0.2.0](https://github.com/agentnameservice/ans/compare/v0.1.6...v0.2.0) (2026-07-23)


### ⚠ BREAKING CHANGES

* **module:** importers must switch from github.com/godaddy/ans to github.com/agentnameservice/ans; the old import path no longer resolves against this repository.

### Features

* **finder:** make the publisher host free-text searchable ([#94](https://github.com/agentnameservice/ans/issues/94)) ([d8ed4bb](https://github.com/agentnameservice/ans/commit/d8ed4bb6b105863710a07dfce9ceb1c3145de486))
* **ra:** AI Catalog generation, FQDN exclusivity, and seal-before-success activation ([#47](https://github.com/agentnameservice/ans/issues/47)) ([daf5ba1](https://github.com/agentnameservice/ans/commit/daf5ba12d0f5e49a130d193e842d1ee4aa906892))
* **ra:** default discovery profiles to ANS_DNSAID; real-DNS demo tooling ([#89](https://github.com/agentnameservice/ans/issues/89)) ([79fb0b9](https://github.com/agentnameservice/ans/commit/79fb0b960c218622853c7c5e288a47d5dcf1ea11))
* **ra:** Implement ARD-compliant discovery service and event feed ([#46](https://github.com/agentnameservice/ans/issues/46)) ([9dbc5c1](https://github.com/agentnameservice/ans/commit/9dbc5c17185baed158f286ff0584c59807104da4))


### Bug Fixes

* **module:** move module path to github.com/agentnameservice/ans ([#93](https://github.com/agentnameservice/ans/issues/93)) ([93e5bf9](https://github.com/agentnameservice/ans/commit/93e5bf91ec3bbe643ed380ad3bb3376466bdbbe6))
* **ra:** emit v-prefixed ANSName version segment in TXT version= values ([#71](https://github.com/agentnameservice/ans/issues/71)) ([facb1ba](https://github.com/agentnameservice/ans/commit/facb1ba0894339e3889790ef51fff254048a3878)), closes [#69](https://github.com/agentnameservice/ans/issues/69)
* **ra:** seal the gate-verified ACME method into domainValidation ([#75](https://github.com/agentnameservice/ans/issues/75)) ([99152ec](https://github.com/agentnameservice/ans/commit/99152ecaef64d18c09a3cbe42391f342e35d8812)), closes [#61](https://github.com/agentnameservice/ans/issues/61)
* **release:** let GoReleaser infer the GitHub owner/name ([#67](https://github.com/agentnameservice/ans/issues/67)) ([e51993f](https://github.com/agentnameservice/ans/commit/e51993f781067202db7334fa4fb55e8b35e4e235))
* **tl:** generate logId as UUIDv7 as documented ([#72](https://github.com/agentnameservice/ans/issues/72)) ([996586d](https://github.com/agentnameservice/ans/commit/996586df8af6dbafe9b90b8f873e488002cbe9c1))
* **tl:** read V1 cert-attestation arrays in status-token builder ([#54](https://github.com/agentnameservice/ans/issues/54)) ([974ca94](https://github.com/agentnameservice/ans/commit/974ca9470dcf6e239250ea6c43cd44970c03c53d))


### Documentation

* adopt DCO and AI-disclosure contribution policy ([#84](https://github.com/agentnameservice/ans/issues/84)) ([f1daf35](https://github.com/agentnameservice/ans/commit/f1daf35473141cd328891167609d396ef869368a))
* fix stale comments ([#87](https://github.com/agentnameservice/ans/issues/87)) ([9383881](https://github.com/agentnameservice/ans/commit/938388112a4e35007d9b5612f364258587dc8bd3))

## [0.1.6](https://github.com/agentnameservice/ans/compare/v0.1.5...v0.1.6) (2026-06-26)


### Features

* **ra:** Adapter Style DNS Discovery Profiles ([6f26917](https://github.com/agentnameservice/ans/commit/6f2691755e045ee907e0530e42c42245912cb29d))
* **ra:** pluggable server-cert issuance via certificate-order lifecycle ([#45](https://github.com/agentnameservice/ans/issues/45)) ([1025db5](https://github.com/agentnameservice/ans/commit/1025db5cf569757577098e168896608851b0e509))
* verified identities — the who behind agents (did:web + did:key) ([#41](https://github.com/agentnameservice/ans/issues/41)) ([41d763e](https://github.com/agentnameservice/ans/commit/41d763e5983e6b88a0c9f78bb9e4339f897eab85))
* **verify:** add provider enumeration mode to ans-verify ([#32](https://github.com/agentnameservice/ans/issues/32)) ([0d80e66](https://github.com/agentnameservice/ans/commit/0d80e66419770ea9195fda48191b9465efab1600))


### Bug Fixes

* **tl:** emit DER C2SP checkpoint signatures ([#38](https://github.com/agentnameservice/ans/issues/38)) ([d94d531](https://github.com/agentnameservice/ans/commit/d94d531fed392594c0e9246d8a1e5fc8567496df))

## [0.1.5](https://github.com/godaddy/ans/compare/v0.1.4...v0.1.5) (2026-06-03)


### Features

* **ra:** make identityCsrPEM optional on agent registration ([#33](https://github.com/godaddy/ans/issues/33)) ([f4e0619](https://github.com/godaddy/ans/commit/f4e0619782ac145ea4feae123b7fd5490f3fc09a))

## [0.1.4](https://github.com/godaddy/ans/compare/v0.1.3...v0.1.4) (2026-05-28)


### Bug Fixes

* **domain:** point _ans-badge DNS record URL at transparency log ([#23](https://github.com/godaddy/ans/issues/23)) ([31adf40](https://github.com/godaddy/ans/commit/31adf40f28200beb65661c06c7507be36703b5ed))

## [0.1.3](https://github.com/godaddy/ans/compare/v0.1.2...v0.1.3) (2026-05-08)


### Bug Fixes

* **release:** trigger v0.1.3 release for windows-drop fix ([#8](https://github.com/godaddy/ans/issues/8)) ([bbb6193](https://github.com/godaddy/ans/commit/bbb619388e8d1671f3cfdd9a0eae96b2ef85636e))

## [0.1.2](https://github.com/godaddy/ans/compare/v0.1.1...v0.1.2) (2026-05-08)


### Code Refactoring

* **store:** replace mattn/go-sqlite3 with modernc.org/sqlite ([#5](https://github.com/godaddy/ans/issues/5)) ([61fd2b6](https://github.com/godaddy/ans/commit/61fd2b6292b00b86dac857725a6c86629d00091d))

## [0.1.1](https://github.com/godaddy/ans/compare/v0.1.0...v0.1.1) (2026-05-07)


### Features

* add release workflow with goreleaser and release-please ([a681d85](https://github.com/godaddy/ans/commit/a681d85f33420cbdc4331648541e78f796638d11))
