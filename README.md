# Detection Lab

Hands-on detection engineering project: emulating adversary techniques with
Atomic Red Team, collecting telemetry via Sysmon and Windows Event Logs, then
building and validating detections in Splunk and mapped to MITRE ATT&CK.

## Environment
- Windows 10 VM
- Sysmon config: [sysmonconfig-export.xml](./sysmonconfig-export.xml)
- Splunk Enterprise
- Atomic Red Team 

## Structure
Each technique has its own folder: `T####-technique-name/`
- `rules/` - Sigma and/or YARA rule(s) for the technique
- `tests/` - one subfolder per Atomic Red Team test validated against the rules
  - `testN-test-name/`
    - `report.md` - writeup (Intro, Detection Queries & Artifacts, References)
    - `artifacts/` - evidence screenshots for that test

## Techniques Covered
| Technique | Tactic |
|-----------|--------|
| [T1053.005 – Scheduled Task/Job](T1053.005-scheduled-task/) | Persistence |
| [T1003.001 – OS Credential Dumping](T1003.001-os-credential-dumping/) | Credential access |