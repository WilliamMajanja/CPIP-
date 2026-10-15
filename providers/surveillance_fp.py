"""Surveillance Platform Fingerprinting for CPIP

Fingerprints and identifies mass-surveillance platforms — Palantir
(Gotham/Foundry/Metropolis) and the other surveillance "behemoths" the
protocol defends against — from network-observable indicators.

This is a *detection* layer, complementary to providers/palantir.py which
implements the *countermeasures* (chaff, mixing, padding, identity rotation).

Covered platforms (extensible catalog):
  - Palantir (Gotham/Foundry/Metropolis)
  - Pegasus (NSO Group)
  - Predator (Intellexa)
  - FinFisher / FinSpy
  - Hacking Team (RCS / Galileo)
  - Exodus / SkyGoFree (Android spyware)
  - Graphite / X-Keyscore (Five Eyes bulk collection)
  - PRISM / Upstream and GCHQ Tempora (SIGINT bulk collection)
  - Verint / TrapWire (pattern-of-life correlation)
  - Clearview AI, SenseTime, Megvii, YITU (facial recognition)
  - Hikvision / Dahua (CCTV mass surveillance)
  - Anduril (autonomous surveillance / Lattice)
  - Cellebrite / Grayshift / Magnet / Oxygen (device extraction)
  - IMSI catcher families (Dirtbox, StingRay, Harpoon, L3Harris, Trovicor)
  - Cell-site simulators / active probing suites
  - Lawful-intercept vendors (SS8, NICE, Utimaco, AQSACOM)
  - DPI vendors (Sandvine, Narus, Cisco SCE)
  - State cyber tooling (DarkMatter, Vault 7)
  - Blockchain analytics (Chainalysis, Elliptic, CipherTrace)

Fingerprint sources:
  - HTTP User-Agent + header signatures
  - TLS client hello (JA3/JA4-style) signatures
  - Known management domains / infra markers
  - Request pattern heuristics (metadata fusion style)
  - IMSI catcher RF / identity-solicitation markers

Environment:
  CPIP_SURVFP=1              Enable fingerprinting (default 0)
  CPIP_SURVFP_LOG=1          Log every match to agent log
  CPIP_SURVFP_CONF=0.6       Match confidence threshold
"""

from __future__ import annotations

import logging
import os
import threading
import time
from collections.abc import Mapping
from typing import Any

from providers.base import BaseProvider, ProviderType

logger = logging.getLogger(__name__)

SURVFP_ENABLED = os.environ.get("CPIP_SURVFP", "0") == "1"
SURVFP_LOG_MATCHES = os.environ.get("CPIP_SURVFP_LOG", "1") == "1"
SURVFP_CONFIDENCE = float(os.environ.get("CPIP_SURVFP_CONF", "0.6"))


# ── Surveillance platform fingerprint catalog ──────────────────────────
# Each entry: name, family, severity, and a list of indicator patterns.
# Each indicator carries its own weight; confidence is derived from the
# best-matching indicators, so a single strong signal can still fire.

SURVEILLANCE_PLATFORMS: list[dict[str, Any]] = [
    {
        "name": "Palantir Gotham",
        "family": "data_analytics",
        "severity": "high",
        "tags": ["palantir", "gotham", "link-analysis", "traffic-correlation"],
        "indicators": [
            {"type": "ua", "pattern": "palantir", "weight": 0.9},
            {"type": "ua", "pattern": "gotham", "weight": 0.85},
            {"type": "header", "pattern": "x-palantir", "weight": 0.95},
            {"type": "header", "pattern": "x-epoch4", "weight": 0.5},
            {"type": "domain", "pattern": "palantir.com", "weight": 0.7},
            {"type": "domain", "pattern": "palantirfoundry.com", "weight": 0.7},
            {"type": "domain", "pattern": "metropolis.palantir", "weight": 0.85},
            {"type": "path", "pattern": "/api/v1/graph", "weight": 0.4},
            {"type": "path", "pattern": "/foundry", "weight": 0.4},
        ],
    },
    {
        "name": "Palantir Foundry",
        "family": "data_analytics",
        "severity": "high",
        "tags": ["palantir", "foundry"],
        "indicators": [
            {"type": "ua", "pattern": "foundry", "weight": 0.8},
            {"type": "header", "pattern": "x-foundry", "weight": 0.9},
            {"type": "domain", "pattern": "foundry", "weight": 0.5},
            {"type": "path", "pattern": "/foundry-data", "weight": 0.4},
            {"type": "path", "pattern": "/pipeline", "weight": 0.3},
        ],
    },
    {
        "name": "Palantir Metropolis",
        "family": "data_analytics",
        "severity": "high",
        "tags": ["palantir", "metropolis", "anti-money-laundering"],
        "indicators": [
            {"type": "ua", "pattern": "metropolis", "weight": 0.8},
            {"type": "header", "pattern": "x-metropolis", "weight": 0.9},
            {"type": "domain", "pattern": "metropolis", "weight": 0.5},
        ],
    },
    {
        "name": "Pegasus (NSO)",
        "family": "spyware",
        "severity": "critical",
        "tags": ["pegasus", "nso", "zero-click", "mobile"],
        "indicators": [
            {"type": "ua", "pattern": "pegasus", "weight": 0.95},
            {"type": "ua", "pattern": "nso", "weight": 0.8},
            {"type": "header", "pattern": "x-pegasus", "weight": 0.95},
            {"type": "header", "pattern": "x-ethiop", "weight": 0.8},
            {"type": "domain", "pattern": "nso.group", "weight": 0.7},
            {"type": "domain", "pattern": "pegasus-spyware", "weight": 0.85},
        ],
    },
    {
        "name": "Predator (Intellexa)",
        "family": "spyware",
        "severity": "critical",
        "tags": ["predator", "intellexa", "mobile"],
        "indicators": [
            {"type": "ua", "pattern": "predator", "weight": 0.9},
            {"type": "header", "pattern": "x-predator", "weight": 0.95},
            {"type": "domain", "pattern": "intellexa", "weight": 0.7},
            {"type": "domain", "pattern": "allysicio", "weight": 0.7},
            {"type": "domain", "pattern": "scttech", "weight": 0.7},
        ],
    },
    {
        "name": "FinFisher / FinSpy",
        "family": "spyware",
        "severity": "critical",
        "tags": ["finfisher", "finspy", "finfisher-gamma"],
        "indicators": [
            {"type": "ua", "pattern": "finspy", "weight": 0.95},
            {"type": "ua", "pattern": "finfisher", "weight": 0.95},
            {"type": "header", "pattern": "x-finspy", "weight": 0.95},
            {"type": "domain", "pattern": "finfisher", "weight": 0.75},
            {"type": "domain", "pattern": "gamma-international", "weight": 0.6},
        ],
    },
    {
        "name": "Hacking Team (RCS / Galileo)",
        "family": "spyware",
        "severity": "critical",
        "tags": ["hacking-team", "rcs", "galileo", "remote-control", "spyware"],
        "indicators": [
            {"type": "ua", "pattern": "hackingteam", "weight": 0.95},
            {"type": "ua", "pattern": "rcs", "weight": 0.55},
            {"type": "ua", "pattern": "galileo", "weight": 0.55},
            {"type": "header", "pattern": "x-rcs", "weight": 0.9},
            {"type": "header", "pattern": "x-galileo", "weight": 0.9},
            {"type": "header", "pattern": "x-hackingteam", "weight": 0.95},
            {"type": "domain", "pattern": "hackingteam", "weight": 0.75},
            {"type": "domain", "pattern": "rcs", "weight": 0.35},
            {"type": "path", "pattern": "/rcs/", "weight": 0.45},
            {"type": "path", "pattern": "/galileo", "weight": 0.45},
        ],
    },
    {
        "name": "Exodus / SkyGoFree",
        "family": "spyware",
        "severity": "critical",
        "tags": ["exodus", "skygofree", "android", "spyware"],
        "indicators": [
            {"type": "ua", "pattern": "skygofree", "weight": 0.95},
            {"type": "ua", "pattern": "exodus", "weight": 0.6},
            {"type": "header", "pattern": "x-exodus", "weight": 0.9},
            {"type": "header", "pattern": "x-skygofree", "weight": 0.95},
            {"type": "domain", "pattern": "skygofree", "weight": 0.9},
            {"type": "path", "pattern": "/exodus", "weight": 0.4},
        ],
    },
    {
        "name": "Graphite / X-Keyscore",
        "family": "bulk_collection",
        "severity": "critical",
        "tags": ["xkeyscore", "graphite", "five-eyes", "bulk-collection"],
        "indicators": [
            {"type": "ua", "pattern": "xkeyscore", "weight": 0.95},
            {"type": "ua", "pattern": "graphite", "weight": 0.6},
            {"type": "header", "pattern": "x-keyscore", "weight": 0.95},
            {"type": "header", "pattern": "x-xks", "weight": 0.9},
            {"type": "domain", "pattern": "xkeyscore", "weight": 0.85},
        ],
    },
    {
        "name": "PRISM / Upstream (NSA)",
        "family": "bulk_collection",
        "severity": "critical",
        "tags": ["prism", "nsa", "upstream", "bulk-collection"],
        "indicators": [
            {"type": "ua", "pattern": "prism", "weight": 0.5},
            {"type": "ua", "pattern": "xkeyscore-nsa", "weight": 0.9},
            {"type": "header", "pattern": "x-prism", "weight": 0.85},
            {"type": "header", "pattern": "x-nsa", "weight": 0.8},
            {"type": "header", "pattern": "x-upstream", "weight": 0.6},
            {"type": "domain", "pattern": "nsa.gov", "weight": 0.6},
            {"type": "path", "pattern": "/prism", "weight": 0.5},
        ],
    },
    {
        "name": "GCHQ Tempora",
        "family": "bulk_collection",
        "severity": "critical",
        "tags": ["gchq", "tempora", "five-eyes", "bulk-collection"],
        "indicators": [
            {"type": "ua", "pattern": "gchq", "weight": 0.7},
            {"type": "ua", "pattern": "tempora", "weight": 0.85},
            {"type": "header", "pattern": "x-gchq", "weight": 0.9},
            {"type": "header", "pattern": "x-tempora", "weight": 0.9},
            {"type": "domain", "pattern": "gchq.gov.uk", "weight": 0.7},
            {"type": "path", "pattern": "/tempora", "weight": 0.5},
        ],
    },
    {
        "name": "BAE Detica / NetReveal",
        "family": "data_analytics",
        "severity": "high",
        "tags": ["bae", "detica", "netreveal", "data-analytics"],
        "indicators": [
            {"type": "ua", "pattern": "detica", "weight": 0.85},
            {"type": "ua", "pattern": "netreveal", "weight": 0.9},
            {"type": "header", "pattern": "x-detica", "weight": 0.9},
            {"type": "header", "pattern": "x-netreveal", "weight": 0.9},
            {"type": "domain", "pattern": "detica.com", "weight": 0.7},
            {"type": "path", "pattern": "/netreveal", "weight": 0.5},
        ],
    },
    {
        "name": "Clearview AI",
        "family": "facial_recognition",
        "severity": "high",
        "tags": ["clearview", "facial-recognition", "biometric"],
        "indicators": [
            {"type": "ua", "pattern": "clearview", "weight": 0.85},
            {"type": "header", "pattern": "x-clearview", "weight": 0.9},
            {"type": "domain", "pattern": "clearview.ai", "weight": 0.75},
            {"type": "path", "pattern": "/api/facesearch", "weight": 0.5},
            {"type": "path", "pattern": "/facesearch", "weight": 0.45},
        ],
    },
    {
        "name": "SenseTime",
        "family": "facial_recognition",
        "severity": "high",
        "tags": ["sensetime", "facial-recognition", "biometric"],
        "indicators": [
            {"type": "ua", "pattern": "sensetime", "weight": 0.85},
            {"type": "header", "pattern": "x-sensetime", "weight": 0.9},
            {"type": "domain", "pattern": "sensetime.com", "weight": 0.7},
            {"type": "path", "pattern": "/face-api", "weight": 0.5},
            {"type": "path", "pattern": "/recognition", "weight": 0.4},
        ],
    },
    {
        "name": "Megvii / Face++",
        "family": "facial_recognition",
        "severity": "high",
        "tags": ["megvii", "facepp", "facial-recognition", "biometric"],
        "indicators": [
            {"type": "ua", "pattern": "megvii", "weight": 0.85},
            {"type": "ua", "pattern": "facepp", "weight": 0.85},
            {"type": "header", "pattern": "x-megvii", "weight": 0.9},
            {"type": "domain", "pattern": "megvii.com", "weight": 0.7},
            {"type": "path", "pattern": "/facepp", "weight": 0.5},
        ],
    },
    {
        "name": "YITU",
        "family": "facial_recognition",
        "severity": "high",
        "tags": ["yitu", "facial-recognition", "biometric"],
        "indicators": [
            {"type": "ua", "pattern": "yitu", "weight": 0.8},
            {"type": "header", "pattern": "x-yitu", "weight": 0.85},
            {"type": "domain", "pattern": "yitu-inc.com", "weight": 0.7},
            {"type": "path", "pattern": "/face", "weight": 0.4},
        ],
    },
    {
        "name": "Hikvision",
        "family": "cctv",
        "severity": "high",
        "tags": ["hikvision", "cctv", "video-surveillance"],
        "indicators": [
            {"type": "ua", "pattern": "hikvision", "weight": 0.9},
            {"type": "header", "pattern": "x-hikvision", "weight": 0.95},
            {"type": "domain", "pattern": "hikvision.com", "weight": 0.7},
            {"type": "path", "pattern": "/onvif", "weight": 0.5},
            {"type": "path", "pattern": "/ISAPI", "weight": 0.5},
        ],
    },
    {
        "name": "Dahua",
        "family": "cctv",
        "severity": "high",
        "tags": ["dahua", "cctv", "video-surveillance"],
        "indicators": [
            {"type": "ua", "pattern": "dahua", "weight": 0.9},
            {"type": "header", "pattern": "x-dahua", "weight": 0.95},
            {"type": "domain", "pattern": "dahuasecurity.com", "weight": 0.7},
            {"type": "path", "pattern": "/onvif", "weight": 0.5},
            {"type": "path", "pattern": "/RPC2", "weight": 0.5},
        ],
    },
    {
        "name": "Anduril",
        "family": "autonomous_surveillance",
        "severity": "high",
        "tags": ["anduril", "lattice", "autonomous-surveillance", "sentry-tower"],
        "indicators": [
            {"type": "ua", "pattern": "anduril", "weight": 0.9},
            {"type": "header", "pattern": "x-anduril", "weight": 0.95},
            {"type": "domain", "pattern": "anduril.com", "weight": 0.7},
            {"type": "path", "pattern": "/lattice", "weight": 0.5},
            {"type": "path", "pattern": "/sentry", "weight": 0.4},
        ],
    },
    {
        "name": "NICE Systems / NICE Investigate",
        "family": "lawful_intercept",
        "severity": "high",
        "tags": ["nice", "lawful-intercept", "li", "recording"],
        "indicators": [
            {"type": "ua", "pattern": "nice-systems", "weight": 0.8},
            {"type": "ua", "pattern": "niceinvestigate", "weight": 0.9},
            {"type": "header", "pattern": "x-nice", "weight": 0.8},
            {"type": "domain", "pattern": "nice.com", "weight": 0.5},
            {"type": "domain", "pattern": "nice-ltd", "weight": 0.6},
            {"type": "path", "pattern": "/investigate", "weight": 0.4},
        ],
    },
    {
        "name": "SS8 Networks / Xcipio",
        "family": "lawful_intercept",
        "severity": "critical",
        "tags": ["ss8", "xcipio", "lawful-intercept", "li"],
        "indicators": [
            {"type": "ua", "pattern": "ss8", "weight": 0.7},
            {"type": "ua", "pattern": "xcipio", "weight": 0.95},
            {"type": "header", "pattern": "x-ss8", "weight": 0.9},
            {"type": "header", "pattern": "x-xcipio", "weight": 0.95},
            {"type": "domain", "pattern": "ss8.com", "weight": 0.7},
            {"type": "domain", "pattern": "xcipio", "weight": 0.9},
            {"type": "path", "pattern": "/xcipio", "weight": 0.5},
        ],
    },
    {
        "name": "Utimaco LIM",
        "family": "lawful_intercept",
        "severity": "critical",
        "tags": ["utimaco", "lim", "lawful-intercept", "li"],
        "indicators": [
            {"type": "ua", "pattern": "utimaco", "weight": 0.9},
            {"type": "header", "pattern": "x-utimaco", "weight": 0.95},
            {"type": "domain", "pattern": "utimaco.com", "weight": 0.7},
            {"type": "path", "pattern": "/lim", "weight": 0.4},
        ],
    },
    {
        "name": "AQSACOM",
        "family": "lawful_intercept",
        "severity": "critical",
        "tags": ["aqsacom", "lawful-intercept", "li"],
        "indicators": [
            {"type": "ua", "pattern": "aqsacom", "weight": 0.9},
            {"type": "header", "pattern": "x-aqsacom", "weight": 0.95},
            {"type": "domain", "pattern": "aqsacom.com", "weight": 0.7},
            {"type": "path", "pattern": "/malicia", "weight": 0.5},
        ],
    },
    {
        "name": "Sandvine",
        "family": "dpi",
        "severity": "high",
        "tags": ["sandvine", "dpi", "deep-packet-inspection"],
        "indicators": [
            {"type": "ua", "pattern": "sandvine", "weight": 0.9},
            {"type": "header", "pattern": "x-sandvine", "weight": 0.9},
            {"type": "domain", "pattern": "sandvine.com", "weight": 0.7},
            {"type": "path", "pattern": "/pktc", "weight": 0.4},
        ],
    },
    {
        "name": "Narus / NarusInsight",
        "family": "dpi",
        "severity": "high",
        "tags": ["narus", "dpi", "deep-packet-inspection"],
        "indicators": [
            {"type": "ua", "pattern": "narus", "weight": 0.85},
            {"type": "header", "pattern": "x-narus", "weight": 0.9},
            {"type": "domain", "pattern": "narus.com", "weight": 0.7},
            {"type": "path", "pattern": "/narusinsight", "weight": 0.5},
        ],
    },
    {
        "name": "Cisco SCE / Service Control",
        "family": "dpi",
        "severity": "high",
        "tags": ["cisco", "sce", "service-control", "dpi"],
        "indicators": [
            {"type": "ua", "pattern": "cisco-sce", "weight": 0.9},
            {"type": "ua", "pattern": "service-control-engine", "weight": 0.85},
            {"type": "header", "pattern": "x-cisco-sce", "weight": 0.9},
            {"type": "domain", "pattern": "cisco.com", "weight": 0.3},
            {"type": "path", "pattern": "/sce", "weight": 0.35},
        ],
    },
    {
        "name": "L3Harris (StingRay family)",
        "family": "imsi_catcher",
        "severity": "critical",
        "tags": ["l3harris", "stingray", "imsi-catcher", "harris"],
        "indicators": [
            {"type": "ua", "pattern": "l3harris", "weight": 0.9},
            {"type": "header", "pattern": "x-l3harris", "weight": 0.9},
            {"type": "domain", "pattern": "l3harris.com", "weight": 0.7},
            {"type": "identity_solicitation", "pattern": "harris", "weight": 0.5},
        ],
    },
    {
        "name": "Trovicor",
        "family": "imsi_catcher",
        "severity": "critical",
        "tags": ["trovicor", "imsi-catcher", "stingray"],
        "indicators": [
            {"type": "ua", "pattern": "trovicor", "weight": 0.95},
            {"type": "header", "pattern": "x-trovicor", "weight": 0.95},
            {"type": "domain", "pattern": "trovicor", "weight": 0.8},
            {"type": "identity_solicitation", "pattern": "trovicor", "weight": 0.6},
        ],
    },
    {
        "name": "DarkMatter",
        "family": "state_cyber",
        "severity": "critical",
        "tags": ["darkmatter", "uae", "state-cyber", "raven"],
        "indicators": [
            {"type": "ua", "pattern": "darkmatter", "weight": 0.9},
            {"type": "header", "pattern": "x-darkmatter", "weight": 0.95},
            {"type": "domain", "pattern": "darkmatter.ae", "weight": 0.7},
            {"type": "path", "pattern": "/raven", "weight": 0.5},
        ],
    },
    {
        "name": "Vault 7 / CIA cyber tooling",
        "family": "state_cyber",
        "severity": "critical",
        "tags": ["vault7", "cia", "state-cyber", "weeping-angel"],
        "indicators": [
            {"type": "ua", "pattern": "vault7", "weight": 0.95},
            {"type": "ua", "pattern": "weeping-angel", "weight": 0.9},
            {"type": "header", "pattern": "x-vault7", "weight": 0.95},
            {"type": "domain", "pattern": "cia.gov", "weight": 0.5},
            {"type": "path", "pattern": "/vault7", "weight": 0.5},
        ],
    },
    {
        "name": "Magnet Forensics AXIOM",
        "family": "device_extraction",
        "severity": "high",
        "tags": ["magnet", "axiom", "device-extraction"],
        "indicators": [
            {"type": "ua", "pattern": "magnet-axiom", "weight": 0.9},
            {"type": "header", "pattern": "x-magnet-axiom", "weight": 0.95},
            {"type": "domain", "pattern": "magnetforensics.com", "weight": 0.7},
            {"type": "path", "pattern": "/axiom", "weight": 0.5},
        ],
    },
    {
        "name": "Oxygen Forensics",
        "family": "device_extraction",
        "severity": "high",
        "tags": ["oxygen", "device-extraction", "forensics"],
        "indicators": [
            {"type": "ua", "pattern": "oxygen-forensics", "weight": 0.9},
            {"type": "header", "pattern": "x-oxygen", "weight": 0.9},
            {"type": "domain", "pattern": "oxygen-forensics.com", "weight": 0.7},
            {"type": "path", "pattern": "/oxygen", "weight": 0.5},
        ],
    },
    {
        "name": "Chainalysis",
        "family": "blockchain_analytics",
        "severity": "medium",
        "tags": ["chainalysis", "blockchain", "transaction-analytics"],
        "indicators": [
            {"type": "ua", "pattern": "chainalysis", "weight": 0.85},
            {"type": "header", "pattern": "x-chainalysis", "weight": 0.9},
            {"type": "domain", "pattern": "chainalysis.com", "weight": 0.7},
            {"type": "path", "pattern": "/api/v2/exchange", "weight": 0.5},
        ],
    },
    {
        "name": "Elliptic",
        "family": "blockchain_analytics",
        "severity": "medium",
        "tags": ["elliptic", "blockchain", "transaction-analytics"],
        "indicators": [
            {"type": "ua", "pattern": "elliptic", "weight": 0.8},
            {"type": "header", "pattern": "x-elliptic", "weight": 0.85},
            {"type": "domain", "pattern": "elliptic.co", "weight": 0.7},
            {"type": "path", "pattern": "/api/transaction", "weight": 0.45},
        ],
    },
    {
        "name": "CipherTrace",
        "family": "blockchain_analytics",
        "severity": "medium",
        "tags": ["ciphertrace", "blockchain", "transaction-analytics"],
        "indicators": [
            {"type": "ua", "pattern": "ciphertrace", "weight": 0.9},
            {"type": "header", "pattern": "x-ciphertrace", "weight": 0.95},
            {"type": "domain", "pattern": "ciphertrace.com", "weight": 0.7},
            {"type": "path", "pattern": "/ciphertrace", "weight": 0.5},
        ],
    },
    {
        "name": "Verint",
        "family": "intercept",
        "severity": "high",
        "tags": ["verint", "intercept", "lawful-intercept"],
        "indicators": [
            {"type": "ua", "pattern": "verint", "weight": 0.85},
            {"type": "header", "pattern": "x-verint", "weight": 0.9},
            {"type": "domain", "pattern": "verint.com", "weight": 0.6},
            {"type": "domain", "pattern": "cominfosec", "weight": 0.5},
        ],
    },
    {
        "name": "TrapWire",
        "family": "pattern_of_life",
        "severity": "high",
        "tags": ["trapwire", "suspicious-activity", "correlation"],
        "indicators": [
            {"type": "ua", "pattern": "trapwire", "weight": 0.85},
            {"type": "header", "pattern": "x-trapwire", "weight": 0.9},
            {"type": "domain", "pattern": "trapwire.com", "weight": 0.6},
            {"type": "path", "pattern": "/sasp", "weight": 0.5},
            {"type": "path", "pattern": "/sas", "weight": 0.4},
        ],
    },
    {
        "name": "Cellebrite",
        "family": "device_extraction",
        "severity": "high",
        "tags": ["cellebrite", "ufed", "device-extraction"],
        "indicators": [
            {"type": "ua", "pattern": "cellebrite", "weight": 0.9},
            {"type": "header", "pattern": "x-cellebrite", "weight": 0.95},
            {"type": "domain", "pattern": "cellebrite.com", "weight": 0.6},
            {"type": "ua", "pattern": "ufed", "weight": 0.8},
        ],
    },
    {
        "name": "Grayshift",
        "family": "device_extraction",
        "severity": "high",
        "tags": ["grayshift", "graykey", "device-extraction"],
        "indicators": [
            {"type": "ua", "pattern": "grayshift", "weight": 0.9},
            {"type": "header", "pattern": "x-grayshift", "weight": 0.95},
            {"type": "domain", "pattern": "grayshift.com", "weight": 0.6},
            {"type": "ua", "pattern": "graykey", "weight": 0.85},
        ],
    },
    {
        "name": "IMSI Catcher (Dirtbox/StingRay)",
        "family": "imsi_catcher",
        "severity": "critical",
        "tags": ["imsi-catcher", "stingray", "dirtbox", "harpoon"],
        "indicators": [
            {"type": "header", "pattern": "x-imsi", "weight": 0.9},
            {"type": "header", "pattern": "x-stingray", "weight": 0.95},
            {"type": "header", "pattern": "x-harpoon", "weight": 0.9},
            {"type": "ua", "pattern": "stingray", "weight": 0.9},
            {"type": "ua", "pattern": "dirtbox", "weight": 0.9},
            {"type": "domain", "pattern": "harris.com", "weight": 0.5},
            {"type": "identity_solicitation", "pattern": "imsi", "weight": 0.4},
        ],
    },
    {
        "name": "Cell-Site Simulator Suite",
        "family": "imsi_catcher",
        "severity": "critical",
        "tags": ["cell-site-simulator", "active-probe"],
        "indicators": [
            {"type": "header", "pattern": "x-cellsite", "weight": 0.9},
            {"type": "ua", "pattern": "cellsite", "weight": 0.8},
            {"type": "identity_solicitation", "pattern": "lac-update", "weight": 0.5},
        ],
    },
    {
        "name": "Deep-Packet-Inspection Probe",
        "family": "dpi",
        "severity": "medium",
        "tags": ["dpi", "deep-packet-inspection", "traffic-shaping"],
        "indicators": [
            {"type": "header", "pattern": "x-dpi", "weight": 0.7},
            {"type": "header", "pattern": "x-isp-probe", "weight": 0.7},
            {"type": "ua", "pattern": "dpi-probe", "weight": 0.7},
            {"type": "pattern", "pattern": "simultaneous", "weight": 0.4},
        ],
    },
    {
        "name": "Lawful Intercept Gateway",
        "family": "intercept",
        "severity": "high",
        "tags": ["lawful-intercept", "li", "gateway"],
        "indicators": [
            {"type": "header", "pattern": "x-lawful-intercept", "weight": 0.9},
            {"type": "header", "pattern": "x-li-gateway", "weight": 0.85},
            {"type": "domain", "pattern": "li-gateway", "weight": 0.6},
        ],
    },
]


class SurveillanceFingerprintProvider(BaseProvider):
    """Fingerprint and identify surveillance platforms from observable signals.

    Maintains a fingerprint catalog covering Palantir and the other surveillance
    "behemoths" (spyware, bulk-collection, intercept, device-extraction, IMSI
    catcher, facial-recognition, CCTV, DPI, state-cyber and blockchain-analytics
    families). Detection is confidence-weighted; a strong indicator can fire
    even without corroborating signals, mirroring the anti-surveillance design
    philosophy of the protocol.
    """

    TYPE = ProviderType.SECURITY
    NAME = "surveillance_fp"
    VERSION = "7.0.0"

    _lock = threading.Lock()
    _hits: dict[str, dict[str, Any]] = {}      # name -> {count, last_seen, addrs, indicators}
    _agent_log: list[dict[str, Any]] = []
    _enabled = SURVFP_ENABLED
    _confidence_threshold = SURVFP_CONFIDENCE

    _PLATFORMS = SURVEILLANCE_PLATFORMS

    @classmethod
    def is_available(cls) -> bool:
        return True

    @classmethod
    def _log(cls, msg: str, level: int = logging.INFO):
        logger.log(level, "SURVFP: %s", msg)
        cls._agent_log.append({"time": time.time(), "msg": msg})
        if len(cls._agent_log) > 500:
            cls._agent_log = cls._agent_log[-250:]

    @classmethod
    def _indicator_matches(cls, indicator_type: str, pattern: str, signal) -> bool:
        """Check whether a signal (headers/UA/domain/path/TLS) contains the pattern."""
        if signal is None:
            return False
        if isinstance(signal, str):
            return pattern.lower() in signal.lower()
        if isinstance(signal, Mapping):
            for key, val in signal.items():
                if indicator_type == "header" and pattern.lower() in str(key).lower():
                    return True
                if isinstance(val, str) and pattern.lower() in val.lower():
                    return True
                if isinstance(val, list):
                    for item in val:
                        if isinstance(item, str) and pattern.lower() in item.lower():
                            return True
            return False
        if isinstance(signal, list):
            return any(
                isinstance(item, str) and pattern.lower() in item.lower()
                for item in signal
            )
        return False

    @classmethod
    def fingerprint(cls, headers: dict | None = None, user_agent: str | None = None,
                    domains: list | None = None, paths: list | None = None,
                    tls_ja3: str | None = None, addr: str | None = None,
                    extra: dict | None = None) -> dict[str, Any]:
        """Fingerprint a connection against the surveillance platform catalog.

        Returns a report with matches, top confidence, and aggregate risk.
        Each match lists the matching indicators for transparency.
        """
        signal_ctx = {
            "ua": user_agent,
            "header": headers,
            "domain": domains,
            "path": paths,
            "tls": tls_ja3,
            "pattern": extra,
            "identity_solicitation": extra,
        }

        matches: list[dict[str, Any]] = []
        for platform in cls._PLATFORMS:
            total = 0.0
            matched_indicators = []
            for ind in platform["indicators"]:
                itype = ind["type"]
                signal = signal_ctx.get(itype)
                if cls._indicator_matches(itype, ind["pattern"], signal):
                    total = max(total, ind["weight"])
                    matched_indicators.append(ind)
            if matched_indicators and total >= cls._confidence_threshold:
                matches.append({
                    "name": platform["name"],
                    "family": platform["family"],
                    "severity": platform["severity"],
                    "confidence": round(total, 3),
                    "indicators": [i["pattern"] for i in matched_indicators],
                    "tags": platform["tags"],
                })

        matches.sort(key=lambda m: m["confidence"], reverse=True)
        top = matches[0]["confidence"] if matches else 0.0
        risk = 0.0
        for m in matches:
            sev = {"low": 0.2, "medium": 0.4, "high": 0.7, "critical": 1.0}.get(
                m["severity"], 0.4)
            risk = max(risk, m["confidence"] * sev)
        risk = min(1.0, risk)

        if matches and SURVFP_LOG_MATCHES:
            with cls._lock:
                for m in matches:
                    rec = cls._hits.setdefault(m["name"], {
                        "count": 0, "last_seen": 0.0, "addrs": set(), "indicators": set(),
                    })
                    rec["count"] += 1
                    rec["last_seen"] = time.time()
                    if addr:
                        rec["addrs"].add(addr)
                    rec["indicators"].update(m["indicators"])
            cls._log(
                f"fingerprint match addr={addr or '?'} top={matches[0]['name']} "
                f"conf={top:.2f} risk={risk:.2f}"
            )

        report = {
            "matches": matches,
            "top_match": matches[0]["name"] if matches else None,
            "confidence": round(top, 3),
            "risk_score": round(risk, 3),
            "risk_label": "CRITICAL" if risk >= 0.7 else "HIGH" if risk >= 0.4 else "MEDIUM" if risk >= 0.2 else "LOW",
            "fingerprinted": bool(matches),
        }
        return report

    @classmethod
    def check_request(cls, headers, addr: str | None = None,
                      path: str | None = None) -> dict[str, Any]:
        """Convenience wrapper: fingerprint an incoming HTTP request.

        `headers` may be a plain dict or an http.server.HTTPMessage; it is
        normalized to a dict so header indicators match either representation.
        """
        hdr: dict = {}
        ua = ""
        if headers:
            if hasattr(headers, "items"):
                hdr = {str(k): v for k, v in headers.items()}
            elif isinstance(headers, dict):
                hdr = headers
            ua = headers.get("User-Agent", "") or headers.get("user-agent", "") or ""
        return cls.fingerprint(
            headers=hdr,
            user_agent=ua,
            paths=[path] if path else None,
            addr=addr,
        )

    @classmethod
    def catalog(cls) -> list[dict[str, Any]]:
        """Return the fingerprint catalog (platform names, families, severity)."""
        return [
            {
                "name": p["name"],
                "family": p["family"],
                "severity": p["severity"],
                "tags": p["tags"],
            }
            for p in cls._PLATFORMS
        ]

    @classmethod
    def get_status(cls) -> dict[str, Any]:
        with cls._lock:
            hits = []
            for name, rec in cls._hits.items():
                hits.append({
                    "platform": name,
                    "count": rec["count"],
                    "last_seen": rec["last_seen"],
                    "addrs": sorted(rec["addrs"]),
                    "indicators": sorted(rec["indicators"]),
                })
            return {
                "enabled": cls._enabled,
                "platforms_in_catalog": len(cls._PLATFORMS),
                "matches": hits,
                "total_matches": sum(r["count"] for r in cls._hits.values()),
                "confidence_threshold": cls._confidence_threshold,
            }

    @classmethod
    def get_agent_log(cls, limit: int = 50) -> list[dict[str, Any]]:
        return cls._agent_log[-limit:]

    @classmethod
    def reset(cls) -> None:
        with cls._lock:
            cls._hits.clear()
            cls._agent_log.clear()
