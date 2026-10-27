# CT data — provenance and distribution status

`data/log_list.json` is the unchanged historical Google Chrome CT snapshot used
by the 90/114-observation studies. Its schema, checksums and EDA are recorded in
`reports/ct_snapshot_validation.json`, `reports/ct_dataset_profile.json` and
`reports/research_sources/20261010/`. It has no original detached publisher
signature. Do not replace it with a current list to reproduce historical results.

Source policy: https://github.com/GoogleChrome/CertificateTransparency/blob/main/log_lists.md
(reviewed 2026-10-18). Google permits investigation of CT/WebPKI and restricts CT
enforcement in other TLS clients without written permission. This is a research
prototype. Public availability does not establish an unrestricted redistribution
license. Specific permission to redistribute the snapshot remains **UNCONFIRMED**.
The snapshot is retained in this research handoff to preserve exact inputs; this
archive must not be represented as a dataset cleared for unrestricted public
redistribution. Obtain confirmation before public release. This requirement is
still open, not marked PASS. No license from the background paper applies to it.

`config/ct_log_list_pubkey.pem` is a public verification key required by the
optional live CT registry, not a secret. The advanced registry authenticates a
separately downloaded current list/signature with this pinned publisher key;
that does not retroactively authenticate the historical snapshot.

Research evidence contains public certificate chains, public CT responses and
synthetic public certificates. Test private keys are generated at runtime;
temporary test folders and browser profiles are excluded from the submission.
