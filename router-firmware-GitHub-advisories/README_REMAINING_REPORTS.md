# Remaining Router Firmware Advisories -- Submission and Upload Guide

Prepared: 2026-10-21, from the two researcher-supplied firmware evidence archives.

## What is in this package?

Six complete English Markdown research advisories and six paste-ready VulDB field/description notes. The four earlier primary advisories (mini_httpd, upgrade_flash.cgi, authentication.cgi, HNAP SOAPAction) are intentionally not duplicated.

| File | Category | Assessment |
| --- | --- | --- |
| advisories/TRENDnet-TEW-657BRM-svn-entries.md | Independent candidate | Potential new-CVE candidate after duplicate and vendor-contact confirmation |
| advisories/TRENDnet-TEW-657BRM-restore_config-cgi.md | Low-priority candidate | HOLD until externally meaningful availability effect is validated |
| related-findings/D-Link-DIR-600L-gena-cgi-command-injection-affected-model.md | Known-family issue, additional affected model | Report affected model; ask CNA about CVE treatment |
| related-findings/D-Link-DIR-600L-hedwig-path-traversal-affected-model.md | Known-family issue, additional affected model | Recommend updating/associating with CVE-2024-0769 |
| related-findings/D-Link-DIR-600L-hedwig-xmldb-runtime-write.md | Supplemental technical finding | Do not claim independent new CVE without review |
| related-findings/D-Link-DIR-600L-gena-cgi-stack-overflow-review.md | Investigation only | HOLD; overlap likely with CVE-2023-33626 |

## For your existing GitHub repository

Your existing repository is:
https://github.com/ruanyi101/router-firmware-security-advisories

The repository already has a top-level `router-firmware-GitHub-advisories/` folder. The ZIP intentionally contains this SAME folder name, with additive files inside `advisories/`, `related-findings/`, and `vuldb-submissions/`. When uploading through GitHub's root Upload files page, drag in the extracted `router-firmware-GitHub-advisories` directory and preview the staged paths to confirm that the new files are inside that folder rather than duplicated at a second nesting level. Do not delete or overwrite the older four advisories.

**Disclosure caution:** The GitHub repository is public. Uploading these reports publishes them immediately. Confirm vendor contact and any embargo or coordinated disclosure plan before upload; if needed, stage in a private repository instead.

No exploit payloads, raw SVN metadata, captured Wi-Fi configuration, device credentials, or raw internal hostnames are included in this package. Do not copy unsanitized research artifacts into a public repository.

## VulDB usage

1. Open https://vuldb.com/vuln/add and complete vendor, product, version, vulnerability type.
2. Copy the `Description:` part from the matching file in `vuldb-submissions/` into the plain-text Description field.
3. After the matching GitHub report is ACTUALLY uploaded and publicly accessible, use that report's real URL as Advisory / Exploit. Do not enter an unverified or private URL as public evidence.
4. Check the vendor contact status, duplicate CVE status, and other-CNA submissions. The original researcher archives record suggested contact dates but not independently verified receipts. Only request a new CVE when all relevant conditions are met.
5. Preserve VulDB submission IDs and the corresponding vendor disclosures for future follow-up.

Note: A completed advisory draft is not proof of discovery novelty and is not proof of successful submission to VulDB.

## Main related public CVE references

- CVE-2019-17621: GENA command injection on related D-Link devices: https://nvd.nist.gov/vuln/detail/CVE-2019-17621
- CVE-2024-0769: hedwig.cgi path traversal on DIR-859: https://nvd.nist.gov/vuln/detail/CVE-2024-0769
- CVE-2023-33626: gena.cgi overflow on DIR-600 B5: https://nvd.nist.gov/vuln/detail/CVE-2023-33626
- VulDB submission policy: https://vuldb.com/kb/submission

## Evidence sources in original ZIP files (not bundled here)

- TRENDnet SVN: `TEW-657BRM-cves/CVE-TBD-svn-entries-information-disclosure/README.md` + `vuldb/FORM_FIND-0001.md`.
- TRENDnet restore: `TEW-657BRM-cves/CVE-TBD-restore_config-cgi-oob-read-dos/README.md` + `vuldb/FORM_FIND-0005.md`.
- D-Link GENA injection: `findings/FIND-0006/finding.md` and `evidence/gena_rce_transcript.txt`.
- D-Link traversal: `findings/FIND-0005/finding.md`, `novelty.md` and `evidence/wifi_config_disclosure.xml`.
- D-Link runtime write: `findings/FIND-0004/finding.md`, `novelty.md` and `evidence/hedwig_poc_transcript.txt`.
- D-Link GENA overflow: `findings/FIND-0006/finding.md`, `evidence/qemu_fatal.log` and `evidence/strace_gena_overflow.log`.

Both original ZIPs include overlapping DIR-600L files; duplicated source findings were processed only once.
