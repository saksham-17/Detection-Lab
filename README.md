# Detection Lab

Hands-on detection engineering : emulating adversary techniques with 
Atomic Red Team, collecting telemetry via Sysmon, and building/validating 
detections in Splunk, mapped to MITRE ATT&CK.

## Structure
Each technique has its own folder: `T####-technique-name/`
- report.md — writeup (flow, detection logic, query, output, false positives)
- rulename.yml — Sigma rule
- images/ — evidence screenshots

## Techniques covered
- [ ] T1053.005 – Scheduled Task/Job