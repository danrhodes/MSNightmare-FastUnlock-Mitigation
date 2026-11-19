# MSNightmare-FastUnlock-Mitigation

Mitigations for https://github.com/MSNightmare/FastUnlock can be deployed via RMM or ran locally.
<img width="694" height="365" alt="image" src="https://github.com/user-attachments/assets/a761153a-f234-4f19-9a3f-c4d834e23741" />

Anyone with physical access can attempt to launch Narrator from the Windows lock screen. Blocking Narrator closes that path until Microsoft ships a fix.

This repo blocks `Narrator.exe` with a WDAC deny policy. No reboot is required.

### Use

1. Download `block.ps1` and `revert.ps1`.
2. Run `block.ps1` in 64-bit PowerShell. Runtime: about 1 min.
3. Verify: lock the machine and toggle Narrator twice. Both attempts must show the App Control block message.
4. Roll back with `revert.ps1`.

Log: `C:\ProgramData\BlockNarrator\run.log`

### Requirements

- Windows 11 22H2 or later, or Server 2025 (`CiTool.exe` present)
- Windows PowerShell 5.1

### Limits

- Narrator stops working for all users, including accessibility users. Exclude those devices.
- The policy matches the file hash. Rerun Deploy weekly. Each Narrator update invalidates the old hash.
- Not a patch. Remove the policy once Microsoft releases a fix.

### Reference

- Vulnerability: https://github.com/MSNightmare/FastUnlock
