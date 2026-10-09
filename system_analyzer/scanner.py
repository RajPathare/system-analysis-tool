"""Read-only Windows system diagnostics for System Analysis Tool."""
from __future__ import annotations

import datetime as dt
import json
import os
import platform
import subprocess
import sys
from typing import Any

import psutil


def _powershell_json(script: str, timeout: int = 12) -> tuple[Any | None, str | None]:
    """Run a read-only PowerShell query and parse its JSON output."""
    if os.name != "nt":
        return None, "Windows-only check"
    try:
        completed = subprocess.run(
            ["powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", script],
            capture_output=True, text=True, timeout=timeout, encoding="utf-8", errors="replace",
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        if completed.returncode != 0:
            msg = (completed.stderr or completed.stdout or "PowerShell command failed").strip()
            return None, msg[:500]
        output = completed.stdout.strip()
        if not output:
            return None, "No data returned"
        return json.loads(output), None
    except subprocess.TimeoutExpired:
        return None, f"Timed out after {timeout}s"
    except Exception as exc:
        return None, str(exc)[:500]


def _finding(severity: str, category: str, title: str, evidence: str,
             recommendation: str, verification: str, confidence: str = "Medium") -> dict[str, str]:
    return {
        "severity": severity, "category": category, "title": title,
        "evidence": evidence, "recommendation": recommendation,
        "verification": verification, "confidence": confidence,
    }


def _windows_security_checks() -> tuple[list[dict[str, str]], dict[str, Any]]:
    findings: list[dict[str, str]] = []
    details: dict[str, Any] = {}

    defender_script = (
        "$ErrorActionPreference='Stop'; "
        "$s=Get-MpComputerStatus; "
        "[pscustomobject]@{AMServiceEnabled=$s.AMServiceEnabled; "
        "AntivirusEnabled=$s.AntivirusEnabled; RealTimeProtectionEnabled=$s.RealTimeProtectionEnabled; "
        "AntivirusSignatureLastUpdated=$(if($s.AntivirusSignatureLastUpdated){$s.AntivirusSignatureLastUpdated.ToString('o')}else{$null})} "
        "| ConvertTo-Json -Compress"
    )
    data, error = _powershell_json(defender_script)
    if data is None:
        details["defender"] = {"status": "Unknown", "reason": error}
        findings.append(_finding(
            "Info", "Security", "Microsoft Defender status could not be verified",
            f"The Defender status query did not return usable data: {error}",
            "Open Windows Security > Virus & threat protection and confirm that your active security provider is enabled. On a managed computer, check with IT before changing settings.",
            "Re-run the scan and confirm the security provider is reporting protection status.",
            "Low",
        ))
    else:
        details["defender"] = data
        if data.get("AntivirusEnabled") is False or data.get("AMServiceEnabled") is False:
            findings.append(_finding(
                "High", "Security", "Microsoft Defender antivirus appears disabled",
                f"AMServiceEnabled={data.get('AMServiceEnabled')}; AntivirusEnabled={data.get('AntivirusEnabled')}",
                "Open Windows Security > Virus & threat protection and check your active antivirus provider. If this is a managed device or another antivirus is installed, verify the intended protection with IT before changing anything.",
                "Re-run the scan and confirm an active antivirus provider is enabled.",
                "Medium",
            ))
        if data.get("RealTimeProtectionEnabled") is False:
            findings.append(_finding(
                "High", "Security", "Defender real-time protection appears disabled",
                "RealTimeProtectionEnabled=False",
                "Review Windows Security > Virus & threat protection. If another approved antivirus manages protection, confirm its status; otherwise enable real-time protection. Do not bypass organization policy.",
                "Re-run the scan and confirm real-time protection is enabled where Defender is the active provider.",
                "Medium",
            ))

    firewall_script = (
        "$ErrorActionPreference='Stop'; "
        "Get-NetFirewallProfile | Select-Object Name,Enabled | ConvertTo-Json -Compress"
    )
    fw, fw_error = _powershell_json(firewall_script)
    if fw is None:
        details["firewall"] = {"status": "Unknown", "reason": fw_error}
        findings.append(_finding(
            "Info", "Security", "Windows Firewall status could not be verified",
            f"The firewall query did not return usable data: {fw_error}",
            "Open Windows Security > Firewall & network protection and review Domain, Private, and Public profiles. On a managed device, consult IT before changing firewall policy.",
            "Re-run the scan and verify the expected firewall profiles are enabled.",
            "Low",
        ))
    else:
        profiles = fw if isinstance(fw, list) else [fw]
        details["firewall"] = profiles
        disabled = [str(p.get("Name", "Unknown")) for p in profiles if p.get("Enabled") is False]
        if disabled:
            findings.append(_finding(
                "High", "Security", "One or more Windows Firewall profiles are disabled",
                "Disabled profiles: " + ", ".join(disabled),
                "Review Windows Security > Firewall & network protection. Enable the relevant profile unless a documented, centrally managed security design requires otherwise.",
                "Re-run the scan and confirm the expected profiles are enabled.",
                "Medium",
            ))
    return findings, details


def _startup_inventory() -> tuple[list[dict[str, str]], str | None]:
    if os.name != "nt":
        return [], "Windows-only inventory"
    try:
        import winreg
        entries: list[dict[str, str]] = []
        locations = [
            (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run", "Current user"),
            (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run", "Local machine"),
            (winreg.HKEY_LOCAL_MACHINE, r"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run", "Local machine 32-bit"),
        ]
        for hive, path, scope in locations:
            try:
                with winreg.OpenKey(hive, path) as key:
                    index = 0
                    while True:
                        try:
                            name, value, _ = winreg.EnumValue(key, index)
                            entries.append({"scope": scope, "name": str(name), "command": str(value)})
                            index += 1
                        except OSError:
                            break
            except OSError:
                continue
        return entries, None
    except Exception as exc:
        return [], str(exc)[:500]


def run_scan() -> dict[str, Any]:
    """Collect a point-in-time snapshot and produce explainable risk findings."""
    started = dt.datetime.now().astimezone()
    findings: list[dict[str, str]] = []
    details: dict[str, Any] = {}

    # Sample CPU briefly so the displayed reading is more useful than the first non-blocking sample.
    try:
        cpu = psutil.cpu_percent(interval=0.8)
    except Exception:
        cpu = None
    mem = psutil.virtual_memory()
    try:
        system_drive = os.environ.get("SystemDrive", "C:") + "\\"
        disk = psutil.disk_usage(system_drive)
        disk_data = {"path": system_drive, "total_bytes": disk.total, "used_bytes": disk.used,
                     "free_bytes": disk.free, "percent": disk.percent}
    except Exception as exc:
        disk_data = {"status": "Unknown", "reason": str(exc)}
        disk = None

    details["performance"] = {
        "cpu_percent": cpu,
        "memory": {"total_bytes": mem.total, "available_bytes": mem.available,
                   "used_bytes": mem.used, "percent": mem.percent},
        "system_disk": disk_data,
    }

    if cpu is not None and cpu >= 90:
        findings.append(_finding(
            "Medium", "Performance", "CPU utilization is very high",
            f"CPU utilization was {cpu:.0f}% during the scan sample.",
            "Open Task Manager > Processes, sort by CPU, and identify whether a known workload, update, or application is responsible. Investigate unknown processes before ending them.",
            "Re-scan when the computer is idle and compare CPU utilization.",
        ))
    if mem.percent >= 90:
        findings.append(_finding(
            "High", "Performance", "Memory utilization is critically high",
            f"RAM utilization was {mem.percent:.0f}%; available memory was {mem.available / (1024**3):.2f} GiB.",
            "Use Task Manager > Processes to identify memory-heavy applications. Save work before closing apps, and check whether usage remains high after a restart.",
            "Re-scan and confirm memory utilization has returned to a sustainable level.",
        ))
    elif mem.percent >= 80:
        findings.append(_finding(
            "Medium", "Performance", "Memory utilization is elevated",
            f"RAM utilization was {mem.percent:.0f}%.",
            "Review Task Manager for unusually large or steadily growing processes. High usage can be normal for workloads; investigate if you also experience slowdowns.",
            "Re-scan during typical usage and check whether performance issues persist.",
        ))
    if disk is not None:
        free_gib = disk.free / (1024**3)
        if disk.percent >= 95 or free_gib < 5:
            findings.append(_finding(
                "High", "Storage", "System drive has very little free space",
                f"{disk_data['path']} is {disk.percent:.0f}% used with {free_gib:.2f} GiB free.",
                "Open Settings > System > Storage to review cleanup suggestions. Inspect large files and installed apps; preview items before deleting them and do not delete unknown system files.",
                "Re-scan and confirm free space has increased.",
            ))
        elif disk.percent >= 85 or free_gib < 15:
            findings.append(_finding(
                "Medium", "Storage", "System drive space is getting low",
                f"{disk_data['path']} is {disk.percent:.0f}% used with {free_gib:.2f} GiB free.",
                "Review Settings > System > Storage, temporary files, downloads, and large applications. Check files before removing them.",
                "Re-scan and confirm there is enough free space for updates and normal workloads.",
            ))

    # Process snapshot, best effort. A high-resource process is evidence to investigate, not proof of malware.
    processes = []
    try:
        for proc in psutil.process_iter(["pid", "name", "memory_info", "cpu_percent", "exe"]):
            try:
                info = proc.info
                rss = info.get("memory_info").rss if info.get("memory_info") else 0
                processes.append({
                    "pid": info.get("pid"), "name": info.get("name") or "Unknown",
                    "memory_bytes": rss, "cpu_percent": info.get("cpu_percent") or 0,
                    "executable": info.get("exe"),
                })
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue
        processes.sort(key=lambda p: p["memory_bytes"], reverse=True)
        details["top_processes_by_memory"] = processes[:10]
    except Exception as exc:
        details["top_processes_by_memory"] = {"status": "Unknown", "reason": str(exc)[:300]}

    startup, startup_error = _startup_inventory()
    details["startup_entries"] = startup
    if startup_error:
        details["startup_inventory_status"] = {"status": "Unknown", "reason": startup_error}
    if startup:
        findings.append(_finding(
            "Info", "Configuration", "Startup applications were inventoried",
            f"Found {len(startup)} entries in common Windows Run registry locations. This is an inventory, not a malware verdict.",
            "Review the names and commands below. Disable an entry only if you recognize it and understand its purpose; use Settings > Apps > Startup or Task Manager rather than deleting registry values directly.",
            "After reviewing, re-run the scan and compare the inventory. Investigate unknown entries with a trusted security tool.",
            "Low",
        ))

    if os.name == "nt":
        security_findings, security_details = _windows_security_checks()
        findings.extend(security_findings)
        details["security"] = security_details
    else:
        findings.append(_finding("Info", "Platform", "Some checks require Windows",
            f"Current platform: {platform.platform()}",
            "Run this tool on Windows 11 to use Windows-specific security checks.",
            "Re-run on Windows 11.", "High"))

    # Additional read-only Windows diagnostics. Treat unavailable data as Unknown,
    # and avoid interpreting every system event as a fault.
    details.setdefault("windows_diagnostics", {})
    windows_diag = details["windows_diagnostics"]

    # Physical disk health: depends on Windows storage provider / permissions.
    disk_health_script = (
        "$ErrorActionPreference='Stop'; "
        "$d=Get-PhysicalDisk | Select-Object FriendlyName,HealthStatus,OperationalStatus,MediaType,Size; "
        "$d | ConvertTo-Json -Compress"
    )
    physical_disks, disk_health_error = _powershell_json(disk_health_script, timeout=15)
    if physical_disks is None:
        windows_diag["physical_disk_health"] = {"status": "Unknown", "reason": disk_health_error}
        findings.append(_finding(
            "Info", "Storage", "Physical drive health could not be verified",
            f"Windows did not return physical disk health data: {disk_health_error}",
            "Open Windows Settings > System > Storage > Advanced storage settings > Disks & volumes, if available, or use the PC manufacturer's diagnostic utility. A missing status does not itself mean the drive is failing.",
            "Run the scan again and compare the returned health status.",
            "Low",
        ))
    else:
        disks = physical_disks if isinstance(physical_disks, list) else [physical_disks]
        windows_diag["physical_disk_health"] = disks
        unhealthy = []
        unknown_health = []
        for d in disks:
            hs = str(d.get("HealthStatus", "")).lower()
            op = d.get("OperationalStatus")
            op_values = op if isinstance(op, list) else [op]
            op_text = ", ".join(str(x) for x in op_values if x is not None)
            if hs and hs not in ("healthy", "unknown"):
                unhealthy.append(f"{d.get('FriendlyName', 'Drive')}: HealthStatus={d.get('HealthStatus')}, OperationalStatus={op_text}")
            elif not hs or hs == "unknown":
                unknown_health.append(str(d.get("FriendlyName", "Drive")))
        if unhealthy:
            findings.append(_finding(
                "High", "Storage", "Windows reports a physical disk health concern",
                "; ".join(unhealthy),
                "Back up important files promptly. Check the drive manufacturer's diagnostic utility and arrange service or replacement if the warning is confirmed. Avoid intensive repair operations before a backup.",
                "Recheck drive health after backup and diagnostics.",
                "Medium",
            ))
        elif unknown_health:
            checks_note = "Health status unavailable or unknown for: " + ", ".join(unknown_health)
            windows_diag["physical_disk_health_note"] = checks_note

    # Recent System log events: retain a small, useful sample for triage.
    # Event counts are signals only; actual source/ID/message context is required.
    events_script = (
        "$ErrorActionPreference='Stop'; "
        "$since=(Get-Date).AddDays(-7); "
        "$e=@(Get-WinEvent -FilterHashtable @{LogName='System'; Level=1,2; StartTime=$since} -MaxEvents 100 -ErrorAction SilentlyContinue); "
        "$items=@($e | Select-Object -First 30 | ForEach-Object { "
        "[pscustomobject]@{TimeCreated=$(if($_.TimeCreated){$_.TimeCreated.ToString('o')}else{$null}); "
        "Level=$(if($_.LevelDisplayName){$_.LevelDisplayName}else{[string]$_.Level}); "
        "ProviderName=$_.ProviderName; Id=$_.Id; RecordId=$_.RecordId; "
        "Message=$(if($_.Message){($_.Message -replace '[\\r\\n]+',' ').Substring(0,[Math]::Min(600,($_.Message -replace '[\\r\\n]+',' ').Length))}else{'No event message available'})} }); "
        "[pscustomobject]@{ReturnedEvents=@($e).Count; MostRecentEvent=$(if(@($e).Count -gt 0 -and $e[0].TimeCreated){$e[0].TimeCreated.ToString('o')}else{$null}); Events=$items} | ConvertTo-Json -Compress -Depth 5"
    )
    event_data, event_error = _powershell_json(events_script, timeout=22)
    if event_data is None:
        windows_diag["recent_system_events"] = {"status": "Unknown", "reason": event_error, "events": []}
    else:
        windows_diag["recent_system_events"] = event_data
        event_count = int(event_data.get("ReturnedEvents") or 0)
        if event_count >= 20:
            findings.append(_finding(
                "Medium", "Stability", "Multiple critical/error System log events were found",
                f"Windows returned {event_count} critical/error System log events from the last 7 days (query capped at 100). The Event Log Details tab shows up to 30 events with source, ID, time, and message. Counts alone do not identify root cause.",
                "Review recurring sources and event IDs, especially events that align with symptoms or shutdown/restart times. Use the event details to investigate; do not apply generic fixes based only on the count.",
                "After investigating a recurring issue, re-scan and compare event IDs, sources, timestamps, and counts.",
                "Low",
            ))

    # Installed hotfix inventory, with date formatted as an ISO string.
    hotfix_script = (
        "$ErrorActionPreference='Stop'; "
        "$h=Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 1; "
        "if($null -eq $h){ "
        "$out=[pscustomobject]@{Status='No hotfix data returned';HotFixID=$null;Description=$null;InstalledOn=$null}; "
        "} else { "
        "$installed=$null; if($h.InstalledOn){$installed=$h.InstalledOn.ToString('yyyy-MM-dd')}; "
        "$out=[pscustomobject]@{Status='Available';HotFixID=$h.HotFixID;Description=$h.Description;InstalledOn=$installed}; "
        "}; "
        "$out | ConvertTo-Json -Compress"
    )
    hotfix, hotfix_error = _powershell_json(hotfix_script, timeout=18)
    if hotfix is None:
        windows_diag["latest_hotfix"] = {"status": "Unknown", "reason": hotfix_error}
    else:
        windows_diag["latest_hotfix"] = hotfix

    # Query Windows Update Agent for visible, uninstalled software updates. Read-only:
    # this searches for updates but does not download or install them.
    pending_updates_script = (
        "$ErrorActionPreference='Stop'; "
        "$session=New-Object -ComObject Microsoft.Update.Session; "
        "$searcher=$session.CreateUpdateSearcher(); "
        "$result=$searcher.Search(\"IsInstalled=0 and IsHidden=0 and Type='Software'\"); "
        "$items=@(); "
        "for($i=0; $i -lt $result.Updates.Count; $i++){ "
        "$u=$result.Updates.Item($i); "
        "$kbs=@(); try{$kbs=@($u.KBArticleIDs)}catch{}; "
        "$items += [pscustomobject]@{Title=$u.Title;KBArticleIDs=$kbs;MsrcSeverity=$u.MsrcSeverity;IsDownloaded=$u.IsDownloaded; "
        "IsMandatory=$u.IsMandatory;RebootRequired=$u.RebootRequired} "
        "}; "
        "[pscustomobject]@{ResultCode=$result.ResultCode;Count=$result.Updates.Count;Updates=@($items | Select-Object -First 50)} | ConvertTo-Json -Compress -Depth 5"
    )
    pending, pending_error = _powershell_json(pending_updates_script, timeout=45)
    if pending is None:
        windows_diag["pending_windows_updates"] = {"status": "Unknown", "reason": pending_error, "updates": []}
    else:
        windows_diag["pending_windows_updates"] = pending
        pending_count = int(pending.get("Count") or 0)
        if pending_count > 0:
            update_titles = [str(u.get("Title", "Untitled update")) for u in pending.get("Updates", [])[:5]]
            findings.append(_finding(
                "Medium", "Updates", "Windows reports available software updates",
                f"The Windows Update Agent returned {pending_count} visible, uninstalled software update(s). Examples: " + "; ".join(update_titles),
                "Open Settings > Windows Update, review the offered updates and your organization's maintenance policy, then install updates through the normal Windows Update workflow when appropriate. This tool does not download or install updates.",
                "Re-run the pending-update check after Windows Update completes and any required restart has been performed.",
                "Medium",
            ))

    # Build explicit check statuses so successful checks are visible in the GUI.
    checks: list[dict[str, str]] = []
    perf = details.get("performance", {})
    checks.append({
        "name": "CPU utilization",
        "status": "Warning" if cpu is not None and cpu >= 90 else ("Passed" if cpu is not None else "Unknown"),
        "evidence": f"{cpu:.1f}% utilization during sample" if cpu is not None else "CPU utilization could not be read",
        "category": "Performance",
    })
    checks.append({
        "name": "Memory utilization",
        "status": "Warning" if mem.percent >= 90 else ("Review" if mem.percent >= 80 else "Passed"),
        "evidence": f"{mem.percent:.1f}% used; {mem.available / (1024**3):.2f} GiB available",
        "category": "Performance",
    })
    if disk is not None:
        disk_free_gib = disk.free / (1024**3)
        disk_status = "Warning" if disk.percent >= 95 or disk_free_gib < 5 else ("Review" if disk.percent >= 85 or disk_free_gib < 15 else "Passed")
        checks.append({
            "name": "System drive space", "status": disk_status,
            "evidence": f"{disk.percent:.1f}% used; {disk_free_gib:.1f} GiB free",
            "category": "Storage",
        })
    else:
        checks.append({"name": "System drive space", "status": "Unknown",
                       "evidence": disk_data.get("reason", "Drive usage could not be read"), "category": "Storage"})

    security = details.get("security", {})
    defender = security.get("defender", {})
    if isinstance(defender, dict) and defender.get("status") == "Unknown":
        checks.append({"name": "Microsoft Defender", "status": "Unknown",
                       "evidence": defender.get("reason", "Status unavailable"), "category": "Security"})
    elif isinstance(defender, dict):
        enabled = defender.get("AntivirusEnabled") is True and defender.get("AMServiceEnabled") is True
        realtime = defender.get("RealTimeProtectionEnabled") is True
        checks.append({"name": "Microsoft Defender antivirus", "status": "Passed" if enabled else "Warning",
                       "evidence": f"AntivirusEnabled={defender.get('AntivirusEnabled')}; AMServiceEnabled={defender.get('AMServiceEnabled')}",
                       "category": "Security"})
        checks.append({"name": "Real-time protection", "status": "Passed" if realtime else "Warning",
                       "evidence": f"RealTimeProtectionEnabled={defender.get('RealTimeProtectionEnabled')}",
                       "category": "Security"})
    fw = security.get("firewall")
    if isinstance(fw, dict) and fw.get("status") == "Unknown":
        checks.append({"name": "Windows Firewall", "status": "Unknown",
                       "evidence": fw.get("reason", "Status unavailable"), "category": "Security"})
    elif isinstance(fw, list):
        for profile in fw:
            enabled = profile.get("Enabled") in (True, 1, "True", "true")
            checks.append({"name": f"Firewall — {profile.get('Name', 'Unknown')} profile",
                           "status": "Passed" if enabled else "Warning",
                           "evidence": f"Enabled={profile.get('Enabled')}", "category": "Security"})

    physical = windows_diag.get("physical_disk_health")
    if isinstance(physical, dict) and physical.get("status") == "Unknown":
        checks.append({"name": "Physical drive health", "status": "Unknown",
                       "evidence": physical.get("reason", "Windows could not provide drive health"), "category": "Storage"})
    elif isinstance(physical, list):
        for d in physical:
            hs = str(d.get("HealthStatus", "Unknown"))
            op = d.get("OperationalStatus", "Unknown")
            status = "Passed" if hs.lower() == "healthy" else ("Warning" if hs.lower() not in ("unknown", "") else "Unknown")
            checks.append({"name": f"Drive health — {d.get('FriendlyName', 'Physical disk')}",
                           "status": status, "evidence": f"HealthStatus={hs}; OperationalStatus={op}",
                           "category": "Storage"})
    events = windows_diag.get("recent_system_events")
    if isinstance(events, dict) and events.get("status") == "Unknown":
        checks.append({"name": "Recent System log events", "status": "Unknown",
                       "evidence": events.get("reason", "Event log query unavailable"), "category": "Stability"})
    elif isinstance(events, dict):
        count = int(events.get("ReturnedEvents") or 0)
        checks.append({"name": "Recent System log events", "status": "Review" if count >= 20 else "Passed",
                       "evidence": f"{count} critical/error event(s) returned from the last 7 days (query capped at 100); event counts need context",
                       "category": "Stability"})
    hotfix_data = windows_diag.get("latest_hotfix")
    if isinstance(hotfix_data, dict) and hotfix_data.get("status") == "Unknown":
        checks.append({"name": "Latest installed hotfix", "status": "Unknown",
                       "evidence": hotfix_data.get("reason", "Hotfix inventory unavailable"), "category": "Updates"})
    elif isinstance(hotfix_data, dict):
        hotfix_date = hotfix_data.get("InstalledOn") or "date unavailable"
        hotfix_id = hotfix_data.get("HotFixID") or hotfix_data.get("Status", "No hotfix data returned")
        checks.append({"name": "Latest installed hotfix", "status": "Passed" if hotfix_data.get("HotFixID") else "Review",
                       "evidence": f"{hotfix_id}; installed {hotfix_date}. Installed-hotfix inventory is not the same as pending-update status.",
                       "category": "Updates"})
    else:
        checks.append({"name": "Latest installed hotfix", "status": "Unknown",
                       "evidence": "Installed hotfix inventory unavailable.", "category": "Updates"})

    pending_data = windows_diag.get("pending_windows_updates")
    if isinstance(pending_data, dict) and pending_data.get("status") == "Unknown":
        checks.append({"name": "Pending Windows Updates", "status": "Unknown",
                       "evidence": pending_data.get("reason", "Windows Update Agent query unavailable"), "category": "Updates"})
    elif isinstance(pending_data, dict):
        pending_count = int(pending_data.get("Count") or 0)
        result_code = pending_data.get("ResultCode", "unknown")
        if pending_count:
            update_examples = [str(u.get("Title", "Untitled update")) for u in pending_data.get("Updates", [])[:3]]
            evidence = f"{pending_count} visible software update(s) reported by Windows Update Agent; search result code={result_code}."
            if update_examples:
                evidence += " Examples: " + "; ".join(update_examples)
            checks.append({"name": "Pending Windows Updates", "status": "Review", "evidence": evidence, "category": "Updates"})
        else:
            checks.append({"name": "Pending Windows Updates", "status": "Passed",
                           "evidence": f"No visible uninstalled software updates were returned by Windows Update Agent (result code={result_code}). Managed update policies or scan failures can affect results.",
                           "category": "Updates"})
    else:
        checks.append({"name": "Pending Windows Updates", "status": "Unknown",
                       "evidence": "Pending-update status was not returned.", "category": "Updates"})

    checks.append({
        "name": "Startup entries inventory",
        "status": "Review" if startup else ("Unknown" if startup_error else "Passed"),
        "evidence": f"{len(startup)} common Run-key entries inventoried; entries are not automatically treated as malicious",
        "category": "Configuration",
    })

    # No issue detected is not the same as proof of a secure system.
    severity_rank = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}
    findings.sort(key=lambda f: severity_rank.get(f["severity"], 5))
    completed = dt.datetime.now().astimezone()
    return {
        "tool": "System Analysis Tool",
        "version": "1.3.1",
        "scan_started": started.isoformat(),
        "scan_completed": completed.isoformat(),
        "system": {
            "platform": platform.platform(),
            "os": platform.system(),
            "os_release": platform.release(),
            "machine": platform.machine(),
            "python_version": sys.version.split()[0],
        },
        "summary": {
            "finding_count": len(findings),
            "critical": sum(f["severity"] == "Critical" for f in findings),
            "high": sum(f["severity"] == "High" for f in findings),
            "medium": sum(f["severity"] == "Medium" for f in findings),
            "low": sum(f["severity"] == "Low" for f in findings),
            "info": sum(f["severity"] == "Info" for f in findings),
        },
        "findings": findings,
        "checks": checks,
        "details": details,
        "limitations": [
            "A baseline scan cannot guarantee that a computer is free of malware or vulnerabilities.",
            "High resource usage and unfamiliar startup entries are not, by themselves, proof of malicious activity.",
            "Windows security checks can be unavailable or incomplete depending on permissions and device policy.",
            "Disk free space does not measure physical drive health.",
        ],
    }
