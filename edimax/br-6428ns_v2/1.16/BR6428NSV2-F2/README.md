# [CVE-TBD] Unauthenticated Configuration Restore via /goform/formUploadConfig in Edimax BR-6428nS V2

## VulDB Submission Fields

- Vendor: Edimax
- Product: BR-6428nS V2
- Version or Commit: 1.16
- Vulnerability: Missing Authentication (CWE-306)
- Advisory / Exploit URL: replace this with the URL of this directory after copying it to your public repository
- Description:

```
A missing authentication vulnerability was discovered in Edimax BR-6428nS V2 firmware v1.16. The /goform/formUploadConfig endpoint restores a configuration archive whose validation consists only of a 2-byte area tag and a rebalanceable byte checksum (wire format: plain 6-byte header 6V03 plus length, data obfuscated as 0xC7 minus plaintext, decoded 8-bit sum must be zero); no session or credential check is performed in the factory-default state. The archive is written directly into the configuration flash area. Reproduction: an unauthenticated multipart POST of the device's own exported configuration (round-trip) is accepted with HTTP 200, executing the full parse and flash write path; a crafted archive with one value changed is likewise accepted and the change persists after restart (confirmed in an isolated rehosting environment). The administrator username and password are stored in clear text inside the archive, so an adjacent attacker can set a known password, enable remote management, or plant values that boot scripts later source as shell code, yielding full device takeover. Proposed CVSS:3.1/AV:A/AC:L/PR:N/ UI:N/S:U/C:H/I:H/A:H (8.8).
```

---

## Technical Disclosure

# CVE-TBD: Unauthenticated Configuration Restore via /goform/formUploadConfig in Edimax BR-6428nS V2

## Summary

A missing-authentication vulnerability was discovered in the Edimax BR-6428nS
V2 router firmware v1.16. The `/goform/formUploadConfig` endpoint of
`/bin/webs` restores a configuration archive whose entire "validation"
consists of a 2-byte area tag and a rebalanceable byte checksum — with no
session or credential check in the factory-default state. An adjacent attacker
can therefore replace the device configuration wholesale: overwrite the
administrator password (stored in **clear text** in the configuration),
enable remote WAN management, or plant values that are later executed by
shell scripts at boot.

## Affected Product

- Vendor: **Edimax**
- Product: **BR-6428nS V2** (Realtek RTL8196C, MIPS32 BE)
- Firmware: **v1.16** (`BR6428NSv2_v1.16.bin`, SHA-256
 `93bcbbd9ea689ccbd3e69a835617eddba15dd7cba4233769e30dce2aae69b6c1`),
 latest and final release (verified 2026-10).

## Vulnerability Details

- Type: Missing Authentication for Critical Function (**CWE-306**)
- Component: `/bin/webs`, handler `formUploadConfig` (@ `0x004376d4`),
 helper `apmib_updateFlash` (@ `0x004643f8`)

### Wire format (fully reverse-engineered, cross-verified against the
device's own export function `formSaveConfig`)

```
[0:6] plain header: "6V03" + BE16(data_len)
[6:] data: every byte obfuscated as enc = 0xC7 - plain
 (encoded NUL = 0xC7; verified byte-for-byte against the device's
 own download: encode("edimax.setup") = "bc^ZfO.TbSRW")
check: 8-bit sum of the decoded data must equal 0
```

The handler matches the leading tag (`6v`/`CF`/`CU`/`6V`) to select the flash
area, de-obfuscates in place, checks the checksum, and passes the blob to
`apmib_updateFlash`, which writes it straight into the current-setting flash
region. Every element of this "validation" is trivially forgeable by the
attacker (the format was reconstructed entirely from the binary and confirmed
against the device's own export).

### Authentication context

Factory-default state: **no authentication** (setup-wizard mode).
Configured state: Basic auth, but the 401 realm discloses
`Default Name:admin Password:1234`.

### Sensitive content reachable in the archive

The configuration stores the administrator credentials in clear text
(blob offsets observed: user `admin` @ +0x443, password `1234` @ +0x462), so
restoring a crafted archive directly sets a known password. Other values of
interest: remote-management enable/host/port, SSID strings, WAN accounts.

## Proof of Concept (non-destructive)

Isolated rehosted environment.

**Non-destructive round-trip** (proves the unauthenticated write path without
changing a single setting): download the running configuration with the
device's own export, then upload it back, unauthenticated:

```bash
# 1. export current config (factory-default state: no credentials needed)
curl -X POST http://<device>/goform/formSaveConfig \
 -d "save=1" -d "submit-url=/index.asp" -o config_export.bin
# -> 32768 bytes: "6V03 7ffa" + obfuscated data

# 2. re-upload the identical bytes (round-trip, zero net change)
curl -X POST http://<device>/goform/formUploadConfig \
 -F "submit-url=/index.asp" -F "binary=@config_export.bin"
# -> HTTP 200; handler executes full parse+checksum+flash-write path
```

**Observed results (2026-10-21, rehosted firmware):**
- The round-trip above is accepted (HTTP 200), proving the write path runs
 unauthenticated.
- In a separate lab-only demonstration, a crafted archive with a single value
 changed (SSID `edimax.setup` → `PWNED-TEST`, checksum fixed to 0) was
 accepted: flash md5 changed (`1ca369d2…` → `dca22b2a…`), and after restart
 the running device served the injected SSID (verified via the export
 function decode).

Control: an upload failing the checksum is rejected, confirming the checksum
is the only integrity gate — and it is attacker-rebalanceable.

## Impact

Adjacent attacker, no credentials on a factory-default device:

- overwrite administrator credentials → full management takeover;
- enable remote management → convert the issue to remote (WAN) reachability;
- plant configuration values consumed by boot scripts — e.g. an SSID
 containing `';command;'` is stored verbatim and `/var/flash.inc` (a dump of
 the whole configuration) is **sourced as a shell script** by
 `/bin/init_ap.sh` at boot, giving persistent root command execution;
- silently enable UPnP, re-arming the miniigd CVE-2014-8361 RCE path on this
 firmware (verified present in v1.16).

## CVSS 3.1

`AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` — **8.8 (High)**
(Unauthenticated adjacent write of the full configuration including
credentials; confidentiality via the clear-text credential store.)

## Discovery

Vendor notified: pending.
