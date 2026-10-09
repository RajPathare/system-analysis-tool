# System Analysis Tool v1.3.1

## Changes
- Event Log Details tab displays up to 30 critical/error System events from the last 7 days with timestamp, level, provider/source, event ID, and a short message.
- Event count remains a triage signal only; inspect event details before diagnosing.
- Latest installed hotfix date is returned as a formatted ISO date where available.
- Pending Windows Updates is a separate read-only Windows Update Agent search. The tool does not download or install updates.
- Overview shows the pending-update query as Passed, Review, or Unknown.
- Existing checks, findings, startup inventory, top-process view, and JSON export remain.

## Build
1. Extract the ZIP fully to a normal folder.
2. Double-click `build_windows.bat`.
3. Test `dist\SystemAnalysisTool\SystemAnalysisTool.exe`.
4. Compile `installer\SystemAnalysisTool.iss` with Inno Setup to create `SystemAnalysisTool-Setup-1.3.1.exe`.

End users only need the final installer, not Python or developer tools.

## Notes and limitations
- Windows Update Agent search can be slow or unavailable on some managed systems; it is read-only and never installs updates.
- Only up to 30 event details are displayed, while the count query is capped at 100 events.
- Event messages may contain machine/user-specific details; review JSON reports before sharing.
- A baseline scanner cannot guarantee a system is malware-free.
- No automatic remediation in this release.


## v1.3.1 hotfix
- Corrected PowerShell output construction for the latest installed hotfix query, which could return a parser error on Windows.
