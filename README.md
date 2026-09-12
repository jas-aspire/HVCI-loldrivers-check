# HVCI LOLDrivers Check

A PowerShell tool for **Windows security research, malware analysis, and Windows internals research**.

This project was forked from [Trail of Bits' HVCI-loldrivers-check](https://github.com/trailofbits/HVCI-loldrivers-check) and updated to work with the current LOLDrivers API and Microsoft's Vulnerable Driver Blocklist.

## What it does

The tool downloads:

* The current **LOLDrivers** database
* Microsoft's **Vulnerable Driver Blocklist**

It then compares known vulnerable drivers against Microsoft's Code Integrity policy to determine which drivers have corresponding `Deny` rules.

Matching is performed using:

* SHA256
* SHA1
* MD5
* Authentihashes
* Driver filenames

The results are printed to the console and saved as:

```text
%TEMP%\lol_drivers_policy_results.json
```

## Why?

Vulnerable Windows drivers are an important area of **malware and kernel-security research**, particularly in research surrounding **BYOVD (Bring Your Own Vulnerable Driver)** attacks.

This tool provides a simple way to study:

* Windows Code Integrity
* HVCI / Memory Integrity
* Vulnerable drivers
* Microsoft's driver blocklist
* Driver hashes and Authentihashes
* Code Integrity policy XML
* Blocklist coverage and potential gaps

It is intended for **defensive research and Windows internals learning** and does not load or exploit drivers.

## Usage

Run from PowerShell:

```powershell
.\check_allowed_drivers.ps1
```

The script automatically downloads the required databases, extracts Microsoft's policy, performs the comparison, and prints the results.

If PowerShell prevents the script from running because of your local execution-policy configuration, use your normal authorized method for running reviewed PowerShell scripts rather than disabling security protections system-wide.

## Output

Example:

```text
[1/4] Downloading LOLDrivers database...
[2/4] Downloading VulnerableDriverBlockList...
[3/4] Parsing VulnerableDriverBlockList XML...
[4/4] Comparing LOLDrivers against blocklist...

Matched drivers: ...
Not matched: ...
```

### Example Screenshots

![Example output](https://github.com/jas-aspire/HVCI-loldrivers-check/raw/refs/heads/main/Screenshot%202026-09-12%20170443.png)

![Example results](https://github.com/jas-aspire/HVCI-loldrivers-check/raw/refs/heads/main/Screenshot%202026-09-12%20170452.png)

A `Not Matched` result means the tool did not find a corresponding Microsoft hash or filename rule. It does **not** necessarily mean the driver can load on a particular Windows system.

## Attribution

Forked from:

**Trail of Bits — HVCI-loldrivers-check**

https://github.com/trailofbits/HVCI-loldrivers-check

See `LICENSE` for licensing information.

## Disclaimer

For authorized cybersecurity research, malware analysis, security testing, and educational use only.
