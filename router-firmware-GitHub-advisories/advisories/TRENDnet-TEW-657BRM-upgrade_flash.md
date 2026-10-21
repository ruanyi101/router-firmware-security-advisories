# Security Advisory: Stack buffer overflow in TRENDnet TEW-657BRM `upgrade_flash.cgi`

**Status:** Draft; CVE not assigned or confirmed  
**Product:** TRENDnet TEW-657BRM, hardware v1.0R, firmware 1.00.1  
**Component:** `/usr/sbin/upgrade_flash.cgi`  
**Weakness:** CWE-121 (Stack-based Buffer Overflow); related unchecked pointer use  
**Access:** Web administrator authentication and LAN-side access appear to be required  
**Testing:** Static analysis and re-hosted QEMU-MIPS validation described in the supplied archive

## Summary

The `upgrade_flash.cgi` firmware-update handler derives a length from a
multipart upload body's first line and copies that content into a
128-byte stack buffer using `strncpy`. The code does not adequately bound
the length by the destination size. It also fails to check one delimiter
search result before computing the length.

The supplied firmware research documents a process crash with an invalid
delimiter, overwrite of saved stack metadata with a long delimiter, and
program-counter control at the `main()` epilogue in an emulated
firmware-update success path. Execution of arbitrary code on physical
hardware was not demonstrated.

## Root cause and validation

- The input length is derived from the position of a line delimiter in
  attacker-controlled multipart upload data.
- A copy using that length targets a 128-byte local array.
- The research notes record overwritten saved registers and a GDB capture
  of `pc = 0x5758595a` after the update-success path returns.

**Important test limitation:** The re-hosted environment used documented
patches to simulate hardware-dependent LAN checks, product/firmware checks,
checksum acceptance, and safe handling of shutdown operations. The notes
state that the vulnerable copy was not patched. These modifications must
be disclosed to any reviewer; the full success-path result cannot be
presented as an unmodified physical-device exploit.

## Impact and scope

The observed vulnerability class is a stack out-of-bounds write. The test
environment demonstrates control-flow corruption on a success path, but
the real-device exploitability, device-side upgrade flow, and any
post-exploitation impact remain unconfirmed. This issue is distinct from
the unauthenticated `mini_httpd` redirect overflow.

## Remediation

Replace this unsupported device where feasible; until then restrict
management access to trusted administrators, disable remote management,
and avoid performing firmware upgrades over untrusted networks.

## Disclosure

Vendor contact, CVE assignment, and independent reproduction remain to be
confirmed by the researcher. Source: supplied
`CVE-TBD-upgrade_flash-cgi-boundary-stack-overflow/README.md`.
