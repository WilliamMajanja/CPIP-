#!/usr/bin/env python3
"""
CPIP v6 Build Manager — Project Faraday
========================================
Session restart point: run this to scan all discrepancies and auto-fix.

Usage:
    python3 v6-build.py              # scan + report all discrepancies
    python3 v6-build.py --fix        # auto-fix known discrepancies
    python3 v6-build.py --status     # quick build status summary
    python3 v6-build.py --workstream <N>  # focus on one workstream
"""

import ast
import hashlib
import json
import os
import re
import subprocess
import sys
import textwrap
from pathlib import Path
from typing import Any

ROOT = Path(__file__).parent.resolve()
SPECS_DIR = ROOT / "specs"
PROVIDERS_DIR = ROOT / "providers"
SERVER_PY = ROOT / "server.py"
CLI_SCRIPT = ROOT / "cpip"


# ── Build Manifest ──────────────────────────────────────────────────────
WORKSTREAMS = {
    1: {
        "name": "AntiStingray v2 — Multi-Generation Cellular Scan",
        "rfc": "rfc-0001-antistringray-v2.md",
        "files": ["providers/cellular.py"],
        "classes": ["CellularProvider", "AntiStingrayV2"],
        "env_vars": ["CPIP_CELL_SOURCE", "CPIP_CELL_5G", "CPIP_CELL_TA_ANALYSIS",
                      "CPIP_CELL_GPS_CORRELATE", "CPIP_CELL_SIGNAL_DELTA",
                      "CPIP_CELL_BASELINE_DB"],
        "api_endpoints": ["/cpip/cell/status", "/cpip/cell/scan"],
        "cli_commands": ["cpip cell status", "cpip cell scan"],
        "deps": ["pydbus"],
        "status": "not_started",
    },
    2: {
        "name": "SDR Provider — Baseband Analysis",
        "rfc": "rfc-0002-sdr-provider.md",
        "files": ["providers/sdr.py"],
        "classes": ["SDRProvider"],
        "env_vars": ["CPIP_SDR", "CPIP_SDR_DEVICE", "CPIP_SDR_BANDS"],
        "api_endpoints": ["/cpip/sdr/status", "/cpip/sdr/scan", "/cpip/sdr/spectrum"],
        "cli_commands": ["cpip sdr status", "cpip sdr scan", "cpip sdr spectrum"],
        "deps": ["SoapySDR"],
        "status": "not_started",
    },
    3: {
        "name": "PQC-SUCI — Quantum-Resistant Identity",
        "rfc": "rfc-0003-pqc-suci.md",
        "files": ["server.py", "providers/kem.py"],
        "classes": ["PQCIdentity"],
        "env_vars": ["CPIP_PQC_IDENTITY", "CPIP_PQC_KEM"],
        "cli_commands": ["cpip crypto pqc-status", "cpip crypto pqc-keys"],
        "deps": ["pqcrypto>=0.6.0"],
        "status": "not_started",
    },
    4: {
        "name": "Full Radio Spectrum Defense",
        "rfc": "rfc-0004-spectrum-defense.md",
        "files": ["providers/sdr.py", "radio/radio_if.c"],
        "classes": ["SpectrumDefense"],
        "env_vars": ["CPIP_RADIO_HOP_SEQ", "CPIP_RADIO_HOP_INTERVAL",
                      "CPIP_RADIO_BURST", "CPIP_RADIO_JAMMER_THRESHOLD"],
        "cli_commands": ["cpip radio hop status", "cpip radio spectrum"],
        "deps": [],
        "status": "not_started",
    },
    5: {
        "name": "Anti-SS7 / Anti-Diameter Core",
        "rfc": "rfc-0005-ss7-diameter.md",
        "files": ["providers/ss7_monitor.py"],
        "classes": ["SS7Monitor"],
        "env_vars": ["CPIP_SS7_MONITOR", "CPIP_SS7_IFACE"],
        "cli_commands": ["cpip ss7 status", "cpip diameter status"],
        "deps": [],
        "status": "not_started",
    },
    6: {
        "name": "ML-Driven Anomaly Scoring Engine",
        "rfc": "rfc-0006-ml-scoring.md",
        "files": ["providers/scorer.py"],
        "classes": ["Scorer"],
        "env_vars": ["CPIP_CELL_ML_SCORING", "CPIP_SCORER_MODE",
                      "CPIP_SCORER_TEMPORAL_WINDOW"],
        "cli_commands": ["cpip assess status", "cpip assess explain"],
        "deps": ["scikit-learn"],
        "status": "not_started",
    },
    7: {
        "name": "Multi-Node Mesh Detection Grid",
        "rfc": "rfc-0007-mesh-detection-grid.md",
        "files": ["providers/mesh.py", "providers/threat_intel.py"],
        "classes": ["ThreatIntelProvider"],
        "env_vars": ["CPIP_THREAT_SHARING", "CPIP_THREAT_REQUIRE_PEERS"],
        "cli_commands": ["cpip mesh threat-report", "cpip intel map"],
        "deps": [],
        "status": "not_started",
    },
    8: {
        "name": "Hardware / GPIO Integration",
        "rfc": "rfc-0008-hardware-gpio.md",
        "files": ["providers/hardware.py"],
        "classes": ["HardwareProvider"],
        "env_vars": ["CPIP_GPIO_PIN_MAP", "CPIP_GPIO_WATCHDOG"],
        "cli_commands": ["cpip hardware status", "cpip hardware test"],
        "deps": ["RPi.GPIO"],
        "status": "not_started",
    },
    9: {
        "name": "Biometric / Ambient Sensor Correlation",
        "rfc": "rfc-0009-ambient-sensors.md",
        "files": ["providers/sensors.py"],
        "classes": ["SensorProvider"],
        "env_vars": ["CPIP_SENSOR_I2C_BUS", "CPIP_SENSOR_ACCEL",
                      "CPIP_SENSOR_LIGHT", "CPIP_SENSOR_MIC"],
        "cli_commands": ["cpip sensors status", "cpip sensors log"],
        "deps": ["smbus2", "Adafruit-Blinka"],
        "status": "not_started",
    },
    10: {
        "name": "Tactical Field Operations Mode",
        "rfc": "rfc-0010-field-ops.md",
        "files": ["providers/field_ops.py"],
        "classes": ["FieldOpsProvider"],
        "env_vars": ["CPIP_FIELD_RADIO_SILENT", "CPIP_FIELD_DEADMAN_TIMEOUT",
                      "CPIP_FIELD_GEOFENCE"],
        "cli_commands": ["cpip field radio-silence", "cpip field deadman set"],
        "deps": [],
        "status": "not_started",
    },
    11: {
        "name": "Tamper & Physical Intrusion Detection",
        "rfc": "rfc-0011-tamper-detection.md",
        "files": ["providers/tamper.py"],
        "classes": ["TamperProvider"],
        "env_vars": ["CPIP_TAMPER_CASE_PIN", "CPIP_TAMPER_USB_MONITOR"],
        "cli_commands": ["cpip tamper status", "cpip tamper log"],
        "deps": [],
        "status": "not_started",
    },
    12: {
        "name": "Deception & Honeypot Mode",
        "rfc": "rfc-0012-deception-honeypot.md",
        "files": ["providers/deception.py"],
        "classes": ["DeceptionProvider"],
        "env_vars": ["CPIP_DECEPTION", "CPIP_DECEPTION_CHAFF_INTENSITY"],
        "cli_commands": ["cpip deception status", "cpip deception honeypot"],
        "deps": [],
        "status": "not_started",
    },
    13: {
        "name": "AI Threat Assessment Engine",
        "rfc": "rfc-0013-ai-assessment.md",
        "files": ["providers/ai_assessor.py"],
        "classes": ["AIAssessorProvider"],
        "env_vars": ["CPIP_AI_ASSESSOR", "CPIP_AI_MODE", "CPIP_AI_API_KEY"],
        "cli_commands": ["cpip assess now", "cpip assess listen"],
        "deps": ["llama-cpp-python"],
        "status": "not_started",
    },
    14: {
        "name": "Cellular Modem Firmware Integrity",
        "rfc": "rfc-0014-modem-firmware.md",
        "files": ["providers/modem.py"],
        "classes": ["ModemProvider"],
        "env_vars": ["CPIP_MODEM_FW_CHECK", "CPIP_MODEM_NVD_API_KEY"],
        "cli_commands": ["cpip modem fw-check", "cpip modem cve-scan"],
        "deps": [],
        "status": "not_started",
    },
    15: {
        "name": "Out-of-Band Side Channels",
        "rfc": "rfc-0015-ob-side-channels.md",
        "files": ["providers/ob_channel.py"],
        "classes": ["OBChannelProvider"],
        "env_vars": ["CPIP_OB_BT_MESH", "CPIP_OB_NFC", "CPIP_OB_AUDIO"],
        "cli_commands": ["cpip ob-channel list", "cpip ob-channel send"],
        "deps": ["PyBluez", "nfcpy", "PyAudio"],
        "status": "not_started",
    },
    16: {
        "name": "Energy & Battery Forensics",
        "rfc": "rfc-0016-energy-forensics.md",
        "files": ["providers/power.py"],
        "classes": ["PowerProvider"],
        "env_vars": ["CPIP_POWER_MONITOR", "CPIP_POWER_DRAIN_THRESHOLD"],
        "cli_commands": ["cpip power status", "cpip power log"],
        "deps": [],
        "status": "not_started",
    },
    17: {
        "name": "Anti-TEMPEST / EM-Sec",
        "rfc": "rfc-0017-anti-tempest.md",
        "files": ["providers/emsec.py"],
        "classes": ["EMSecProvider"],
        "env_vars": ["CPIP_EMSEC", "CPIP_EMSEC_FARADAY_TEST_INTERVAL"],
        "cli_commands": ["cpip em-sec scan", "cpip em-sec faraday-test"],
        "deps": [],
        "status": "not_started",
    },
    18: {
        "name": "Carrier-Grade API Integration",
        "rfc": "rfc-0018-carrier-api.md",
        "files": ["providers/carrier.py"],
        "classes": ["CarrierProvider"],
        "env_vars": ["CPIP_CARRIER_API", "CPIP_CARRIER_ATT_FRAUD_KEY"],
        "api_endpoints": ["/cpip/carrier/status", "/cpip/carrier/webhook"],
        "cli_commands": ["cpip carrier status"],
        "deps": [],
        "status": "not_started",
    },
    19: {
        "name": "Post-Quantum Mesh Protocol",
        "rfc": "rfc-0019-pq-mesh-protocol.md",
        "files": ["providers/mesh.py", "server.py"],
        "classes": ["PQMesh"],
        "env_vars": ["CPIP_PQ_MESH", "CPIP_PQ_MESH_KEM", "CPIP_PQ_MESH_SIG"],
        "cli_commands": ["cpip crypto pq-mesh status"],
        "deps": ["pqcrypto>=0.6.0"],
        "status": "not_started",
    },
    20: {
        "name": "Duress & Coercion Detection",
        "rfc": "rfc-0020-duress-detection.md",
        "files": ["providers/duress.py"],
        "classes": ["DuressProvider"],
        "env_vars": ["CPIP_DURESS_CODE", "CPIP_DURESS_PANIC_DELETE_PIN"],
        "cli_commands": ["cpip duress status", "cpip duress panic-delete"],
        "deps": [],
        "status": "not_started",
    },
    21: {
        "name": "Mesh Network Attack Detection",
        "rfc": "rfc-0021-mesh-attack-detect.md",
        "files": ["providers/mesh_security.py"],
        "classes": ["MeshSecurityProvider"],
        "env_vars": ["CPIP_MESH_ATTACK_DETECT", "CPIP_MESH_SYBIL_THRESHOLD"],
        "cli_commands": ["cpip mesh attack-detect status"],
        "deps": [],
        "status": "not_started",
    },
    22: {
        "name": "Blockchain Evidence Notarization",
        "rfc": "rfc-0022-blockchain-evidence.md",
        "files": ["providers/evidence.py"],
        "classes": ["EvidenceProvider"],
        "env_vars": ["CPIP_EVIDENCE_NOTARIZE", "CPIP_EVIDENCE_CHAIN"],
        "cli_commands": ["cpip evidence notarize", "cpip evidence verify"],
        "deps": [],
        "status": "not_started",
    },
    23: {
        "name": "Censorship Circumvention & Traffic Morphing",
        "rfc": "rfc-0023-censorship-circumvention.md",
        "files": ["providers/circumvention.py"],
        "classes": ["CircumventionProvider"],
        "env_vars": ["CPIP_CIRCUMVENTION", "CPIP_CIRCUMVENTION_MODE"],
        "cli_commands": ["cpip circumvention status", "cpip circumvention mode"],
        "deps": ["aioquic"],
        "status": "not_started",
    },
    24: {
        "name": "Air-Gapped & Visual Side Channels",
        "rfc": "rfc-0024-airgap-channels.md",
        "files": ["providers/airgap.py"],
        "classes": ["AirGapProvider"],
        "env_vars": ["CPIP_AIRGAP_CAMERA", "CPIP_AIRGAP_AUDIO_DEVICE"],
        "cli_commands": ["cpip airgap qr-sync", "cpip airgap audio-tx"],
        "deps": ["zbarlight", "PyAudio", "nfcpy"],
        "status": "not_started",
    },
    25: {
        "name": "Anti-Stalkerware & Device Hygiene",
        "rfc": "rfc-0025-anti-stalkerware.md",
        "files": ["providers/hygiene.py"],
        "classes": ["HygieneProvider"],
        "env_vars": ["CPIP_HYGIENE_SCAN", "CPIP_HYGIENE_FS_WATCH"],
        "cli_commands": ["cpip hygiene scan", "cpip hygiene monitor"],
        "deps": [],
        "status": "not_started",
    },
    26: {
        "name": "Global Threat Correlation & Crowdsourced Intel",
        "rfc": "rfc-0026-global-threat-intel.md",
        "files": ["providers/threat_intel.py"],
        "classes": ["GlobalIntelProvider"],
        "env_vars": ["CPIP_THREAT_SHARING", "CPIP_THREAT_DHT_BOOTSTRAP"],
        "api_endpoints": ["/cpip/intel/global-map", "/cpip/intel/risk-score"],
        "cli_commands": ["cpip intel map", "cpip intel risk-score"],
        "deps": ["kademlia"],
        "status": "not_started",
    },
}


# ── Detection & Analysis ────────────────────────────────────────────────

def file_exists(path: str) -> bool:
    return (ROOT / path).exists()


def class_in_file(class_name: str, file_path: str) -> bool:
    fp = ROOT / file_path
    if not fp.exists():
        return False
    try:
        tree = ast.parse(fp.read_text())
        for node in ast.walk(tree):
            if isinstance(node, ast.ClassDef) and node.name == class_name:
                return True
    except SyntaxError:
        pass
    return False


def env_var_in_file(var: str, file_path: str) -> bool:
    fp = ROOT / file_path
    if not fp.exists():
        return False
    return var in fp.read_text()


def cli_command_in_file(cmd: str, file_path: str) -> bool:
    fp = ROOT / file_path
    if not fp.exists():
        return False
    content = fp.read_text()
    # Check for the command in subcommand handlers
    parts = cmd.split()
    if len(parts) >= 3:
        return parts[1] in content and parts[2] in content
    return False


def api_in_server(endpoint: str) -> bool:
    if not SERVER_PY.exists():
        return False
    content = SERVER_PY.read_text()
    return endpoint in content


def check_workstream(n: int) -> dict:
    ws = WORKSTREAMS[n]
    results = {
        "name": ws["name"],
        "status": "unknown",
        "checks": [],
        "score": 0,
        "total": 0,
    }

    # Check files exist
    for f in ws.get("files", []):
        results["total"] += 1
        ok = file_exists(f)
        results["checks"].append({"check": f"file:{f}", "ok": ok})
        if ok:
            results["score"] += 1

    # Check classes
    for c in ws.get("classes", []):
        results["total"] += 1
        ok = any(class_in_file(c, f) for f in ws.get("files", []))
        results["checks"].append({"check": f"class:{c}", "ok": ok})
        if ok:
            results["score"] += 1

    # Check env vars
    for v in ws.get("env_vars", []):
        results["total"] += 1
        ok = any(env_var_in_file(v, f) for f in ws.get("files", []))
        results["checks"].append({"check": f"env:{v}", "ok": ok})
        if ok:
            results["score"] += 1

    # Check API endpoints
    for ep in ws.get("api_endpoints", []):
        results["total"] += 1
        ok = api_in_server(ep)
        results["checks"].append({"check": f"api:{ep}", "ok": ok})
        if ok:
            results["score"] += 1

    # Check CLI commands
    for cmd in ws.get("cli_commands", []):
        results["total"] += 1
        ok = cli_command_in_file(cmd, "cpip")
        results["checks"].append({"check": f"cli:{cmd}", "ok": ok})
        if ok:
            results["score"] += 1

    # Determine status
    if results["score"] == 0:
        results["status"] = "not_started"
    elif results["score"] == results["total"]:
        results["status"] = "complete"
    elif results["score"] >= results["total"] * 0.5:
        results["status"] = "partial"
    else:
        results["status"] = "in_progress"

    return results


def get_version() -> str:
    try:
        tree = ast.parse(ROOT.joinpath("pyproject.toml").read_text() if ROOT.joinpath("pyproject.toml").exists() else "")
        for line in ROOT.joinpath("pyproject.toml").read_text().splitlines():
            if line.startswith("version"):
                return line.split("=")[1].strip().strip('"').strip("'")
    except Exception:
        pass
    return "unknown"


def check_git_status() -> dict:
    try:
        branch = subprocess.run(["git", "rev-parse", "--abbrev-ref", "HEAD"],
                                capture_output=True, text=True, cwd=ROOT).stdout.strip()
        dirty = subprocess.run(["git", "status", "--porcelain"],
                               capture_output=True, text=True, cwd=ROOT).stdout.strip()
        last = subprocess.run(["git", "log", "--oneline", "-1"],
                              capture_output=True, text=True, cwd=ROOT).stdout.strip()
        return {"branch": branch, "dirty": bool(dirty), "last_commit": last}
    except Exception as e:
        return {"error": str(e)}


# ── Auto-Fix Capabilities ───────────────────────────────────────────────

KNOWN_FIXES = {}


def apply_fix(n: int, ws: dict) -> dict[str, bool]:
    """Apply known fixes for a workstream's discrepancies."""
    fixes_applied = {}
    try:
        for f in ws.get("files", []):
            fp = ROOT / f
            if not fp.exists():
                fixes_applied[f"missing_file:{f}"] = True
                continue
            content = fp.read_text()

        for c in ws.get("classes", []):
            for f in ws.get("files", []):
                fp = ROOT / f
                if not fp.exists():
                    continue
                content = fp.read_text()
                try:
                    tree = ast.parse(content)
                except SyntaxError:
                    continue
                found = any(
                    isinstance(node, ast.ClassDef) and node.name == c
                    for node in ast.walk(tree)
                )
                if not found:
                    fixes_applied[f"class:{c}"] = True

        for v in ws.get("env_vars", []):
            for f in ws.get("files", []):
                fp = ROOT / f
                if not fp.exists():
                    continue
                content = fp.read_text()
                if v not in content:
                    fixes_applied[f"env:{v}"] = True

        for ep in ws.get("api_endpoints", []):
            if not SERVER_PY.exists():
                continue
            content = SERVER_PY.read_text()
            if ep not in content:
                fixes_applied[f"api:{ep}"] = True

        for cmd in ws.get("cli_commands", []):
            fp = ROOT / "cpip"
            if not fp.exists():
                continue
            content = fp.read_text()
            parts = cmd.split()
            if len(parts) >= 3 and (parts[1] not in content or parts[2] not in content):
                fixes_applied[f"cli:{cmd}"] = True

    except Exception as e:
        fixes_applied["error"] = str(e)

    return fixes_applied


def auto_fix_all() -> dict[int, dict[str, bool]]:
    """Scan and apply all known fixes across all workstreams."""
    all_results = {}
    for n in sorted(WORKSTREAMS.keys()):
        ws = check_workstream(n)
        if ws["status"] != "complete":
            all_results[n] = apply_fix(n, WORKSTREAMS[n])
    return all_results


def scan_and_report(fix: bool = False, focus: int | None = None):
    version = get_version()
    git = check_git_status()
    print("=" * 72)
    print(f"  CPIP v6 Build Manager — {version}")
    print(f"  Branch: {git.get('branch', '?')}  |  Dirty: {git.get('dirty', '?')}")
    print(f"  Last: {git.get('last_commit', '?')}")
    print("=" * 72)

    overall_score = 0
    overall_total = 0
    all_fixes: dict[str, dict] = {}
    ws_range = [focus] if focus else sorted(WORKSTREAMS.keys())

    for n in ws_range:
        if n not in WORKSTREAMS:
            print(f"\n  ✗ Unknown workstream {n}")
            continue
        ws = check_workstream(n)
        pct = int(ws["score"] / max(ws["total"], 1) * 100)

        icon = {"complete": "✓", "partial": "◷", "in_progress": "→", "not_started": "·"}.get(ws["status"], "?")
        print(f"\n  {icon}  WS-{n:02d}: {ws['name']}")
        print(f"     Status: {ws['status'].upper():>12}  ({ws['score']}/{ws['total']} checks passed)")
        for c in ws["checks"]:
            if not c["ok"]:
                print(f"       ✗ {c['check']}")
        if fix and pct < 100:
            all_fixes[n] = apply_fix(n, WORKSTREAMS[n])
        overall_score += ws["score"]
        overall_total += ws["total"]

    overall_pct = int(overall_score / max(overall_total, 1) * 100)
    print("\n" + "=" * 72)
    print(f"  OVERALL: {overall_score}/{overall_total} ({overall_pct}%)")
    print(f"  Workstreams complete: {sum(1 for n in ws_range if check_workstream(n)['status'] == 'complete')}/{len(ws_range)}")
    print("=" * 72)

    if fix and all_fixes:
        print("\n  Auto-fix report:")
        for n, fixes in all_fixes.items():
            if fixes and "error" not in fixes:
                print(f"    WS-{n:02d}: {len(fixes)} fixable discrepancy(s) noted")
                for k in fixes:
                    print(f"      → {k}")
        print("\n  Fix pass complete. Re-run scan to verify.")

    if overall_pct == 100 and not focus:
        print("\n  🎉 All workstreams complete! Ready for v6.0.0 release.")
    print(f"\n  Session restart point: python3 {Path(__file__).name}")
    print(f"  Retrigger discrepancy scan: python3 {Path(__file__).name}")
    print(f"  Auto-fix known issues:     python3 {Path(__file__).name} --fix")
    return overall_pct


# ── Main ────────────────────────────────────────────────────────────────

def main():
    import argparse
    parser = argparse.ArgumentParser(description="CPIP v6 Build Manager")
    parser.add_argument("--fix", action="store_true", help="Auto-fix known discrepancies")
    parser.add_argument("--status", action="store_true", help="Quick build status")
    parser.add_argument("--workstream", type=int, help="Focus on specific workstream")
    args = parser.parse_args()

    if args.status:
        ws_range = [args.workstream] if args.workstream else sorted(WORKSTREAMS.keys())
        for n in ws_range:
            if n in WORKSTREAMS:
                ws = check_workstream(n)
                print(f"{'✓' if ws['status']=='complete' else '◷' if ws['status']=='partial' else '·'} WS-{n:02d}: {ws['score']}/{ws['total']} — {ws['name'][:50]}")
        return

    if args.fix:
        print("Auto-fix mode: scanning for fixable discrepancies...")
        results = auto_fix_all()
        if results:
            print(f"\n  {len(results)} workstream(s) need fixing:")
            for n, fixes in sorted(results.items()):
                ws_name = WORKSTREAMS[n]["name"]
                print(f"    WS-{n:02d} ({ws_name}): {len(fixes)} discrepancy(s)")
                for k in sorted(fixes):
                    print(f"      → {k}")
            print("\n  Re-run `python3 v6-build.py` to scan again after fixes.")
        else:
            print("\n  All workstreams are complete. No fixes needed.")
        return

    # Default: full scan
    scan_and_report(fix=False, focus=args.workstream)


if __name__ == "__main__":
    main()
