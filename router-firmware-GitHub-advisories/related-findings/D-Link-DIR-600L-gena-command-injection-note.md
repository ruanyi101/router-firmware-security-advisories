# Additional affected-version research note: D-Link DIR-600L `gena.cgi`

**Purpose:** Support duplicate review and potential affected-product update,
not an assertion of a newly assigned CVE.

**Product:** DIR-600L, hardware revision B, firmware 2.17b02  
**Weakness:** CWE-78 (OS Command Injection)  
**Component:** UPnP GENA subscription handler `gena.cgi`

The supplied research traces a client-controlled `service` parameter through
a subscription handler into a shell-command string later executed by `xmldb`.
In a re-hosted qemu-mipsel experiment, a test request reportedly caused a
non-destructive marker file to appear in temporary storage. This was a
demonstration in emulation; the physical device's UPnP service has not been
independently reproduced as part of this report.

The pattern resembles prior GENA command-injection reports affecting other
D-Link products, including CVE-2019-17621. The report should be used to ask
the relevant CNA whether this is an additional affected product/version
or whether the specific root cause is distinct. Do not request a new CVE
without making that comparison first.

**Disclosure state:** Vendor contact and any CVE assignment unverified.  
**Source:** Supplied DIR-600L package,
`CVE-TBD-gena-cgi-service-command-injection/README.md`.
