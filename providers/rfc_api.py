"""Central HTTP router for RFC-0001..0026 feature endpoints.

Each entry maps a /cpip/... path to a provider-backed action. Returns
(status_code, payload) tuples, or None when the path is not an RFC route.
"""
from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger(__name__)


def _fmt(e: BaseException) -> str:
    return f"{type(e).__name__}: {e}"


# ── RFC-0001 AntiStingray v2 ──────────────────────────────────────────
def _cell_status() -> tuple[int, dict]:
    from providers.cellular import AntiStingrayV2
    return 200, AntiStingrayV2.get_status()


def _cell_history(params: dict) -> tuple[int, dict]:
    from providers.cellular import AntiStingrayV2
    limit = int(params.get("limit", [50])[0])
    history = AntiStingrayV2.get_history(limit)
    return 200, {"count": len(history), "history": history}


def _cell_scan(body: dict) -> tuple[int, dict]:
    from providers.cellular import AntiStingrayV2
    return 200, AntiStingrayV2.scan()


def _cell_baseline_reset() -> tuple[int, dict]:
    from providers.cellular import AntiStingrayV2
    return 200, AntiStingrayV2.reset_baseline()


# ── RFC-0002 SDR Provider ─────────────────────────────────────────────
def _sdr_status() -> tuple[int, dict]:
    from providers.sdr import SDRProvider
    return 200, SDRProvider.get_status()


def _sdr_spectrum() -> tuple[int, dict]:
    from providers.sdr import SDRProvider
    return 200, SDRProvider.get_spectrum()


def _sdr_scan(body: dict) -> tuple[int, dict]:
    from providers.sdr import SDRProvider
    band = (body or {}).get("band", "")
    return 200, SDRProvider.scan(band)


def _sdr_capture(body: dict) -> tuple[int, dict]:
    from providers.sdr import SDRProvider
    duration = int((body or {}).get("duration", 10) or 10)
    return 200, SDRProvider.capture(duration)


# ── RFC-0003 PQC-SUCI ────────────────────────────────────────────────
def _pqc_status() -> tuple[int, dict]:
    from providers.kem import PQCIdentity
    return 200, PQCIdentity.get_status()


def _pqc_keys(body: dict) -> tuple[int, dict]:
    from providers.kem import PQCIdentity
    action = (body or {}).get("action", "generate")
    if action == "rotate":
        return 200, PQCIdentity.rotate()
    material = PQCIdentity.generate_identity()
    return 200, {
        "status": "keys_generated",
        "mode": PQCIdentity.MODE,
        "kem_algorithm": PQCIdentity.KEM_ALGORITHM,
        "kem_public_key": material.get("pubkey", b"").hex() or None,
        "ecdh_public_key": material.get("ecdh_pubkey", b"").decode() or None,
        "private_key_material": "retained in process memory; never returned",
    }


def _pqc_handshake(body: dict) -> tuple[int, dict]:
    from providers.kem import PQCIdentity
    peer_pem = (body or {}).get("peer_pubkey", "")
    try:
        peer = bytes.fromhex(peer_pem) if peer_pem else None
    except ValueError:
        return 400, {"error": "peer_pubkey must be hexadecimal ML-KEM public key bytes"}
    return 200, PQCIdentity.handshake(peer)


# ── RFC-0004 Spectrum Defense / Radio ─────────────────────────────────
def _radio_status() -> tuple[int, dict]:
    from providers.sdr import SpectrumDefense
    return 200, SpectrumDefense.get_status()


def _radio_spectrum() -> tuple[int, dict]:
    from providers.sdr import SDRProvider
    return 200, SDRProvider.get_spectrum()


def _radio_hop(params: dict, body: dict) -> tuple[int, dict]:
    from providers.sdr import SpectrumDefense
    action = (body or {}).get("action") or (params.get("action", [""])[0])
    if action == "sequence":
        channels = (body or {}).get("channels", "")
        result = SpectrumDefense.set_hop_sequence(channels)
        code = 400 if "error" in result else 200
        return code, result
    if action == "start":
        SpectrumDefense.start()
        return 200, {"status": "started"}
    if action == "stop":
        SpectrumDefense.stop()
        return 200, {"status": "stopped"}
    return 400, {"error": f"Unknown radio hop action: {action}"}


def _radio_fingerprint(body: dict) -> tuple[int, dict]:
    from providers.sdr import SpectrumDefense
    cell_id = (body or {}).get("cell_id", "")
    if not cell_id:
        return 400, {"error": "Missing 'cell_id'"}
    power = float((body or {}).get("power_dbm", 0) or 0)
    cfo = float((body or {}).get("cfo_hz", 0) or 0)
    return 200, SpectrumDefense.fingerprint_tower(cell_id, power, cfo)


# ── RFC-0005 SS7 / Diameter ───────────────────────────────────────────
def _ss7_status() -> tuple[int, dict]:
    from providers.ss7_monitor import SS7Monitor
    return 200, SS7Monitor.get_status()


def _ss7_log(params: dict) -> tuple[int, dict]:
    from providers.ss7_monitor import SS7Monitor
    lines = int(params.get("lines", [20])[0])
    return 200, {"count": 0, "log": SS7Monitor.get_log(lines)}


def _diameter_status() -> tuple[int, dict]:
    from providers.ss7_monitor import SS7Monitor
    status = SS7Monitor.get_status()
    status["protocol"] = "diameter"
    status["ports"] = [3868]
    return 200, status


def _sigfw_alerts() -> tuple[int, dict]:
    from providers.ss7_monitor import SS7Monitor
    return 200, {"alerts": SS7Monitor.get_status().get("recent_alerts", [])}


# ── RFC-0006 ML Scoring ───────────────────────────────────────────────
def _scorer_status() -> tuple[int, dict]:
    from providers.scorer import Scorer
    return 200, Scorer.get_status()


def _scorer_explain() -> tuple[int, dict]:
    from providers.scorer import Scorer
    return 200, Scorer.explain()


def _scorer_history() -> tuple[int, dict]:
    from providers.scorer import Scorer
    return 200, {"count": 0, "history": Scorer.get_history()}


def _scorer_baselines() -> tuple[int, dict]:
    from providers.scorer import Scorer
    return 200, Scorer.get_baselines() if hasattr(Scorer, "get_baselines") else {"baselines": {}}


# ── RFC-0007 / RFC-0026 Threat Intel ──────────────────────────────────
def _intel_status() -> tuple[int, dict]:
    from providers.threat_intel import ThreatIntelProvider
    return 200, ThreatIntelProvider.get_status()


def _intel_map() -> tuple[int, dict]:
    from providers.threat_intel import GlobalIntelProvider
    features = GlobalIntelProvider.get_map_data()
    return 200, {"count": len(features), "features": features}


def _intel_risk(params: dict) -> tuple[int, dict]:
    from providers.threat_intel import GlobalIntelProvider
    mcc = str(params.get("mcc", [""])[0])
    mnc = str(params.get("mnc", [""])[0])
    if not mcc or not mnc:
        return 400, {"error": "Both 'mcc' and 'mnc' are required"}
    return 200, GlobalIntelProvider.risk_score(mcc, mnc)


def _intel_share(body: dict) -> tuple[int, dict]:
    from providers.threat_intel import ThreatIntelProvider
    enabled = (body or {}).get("enabled", True)
    if not isinstance(enabled, bool):
        return 400, {"error": "'enabled' must be a boolean"}
    return 200, ThreatIntelProvider.set_sharing_enabled(enabled)


def _intel_verify(body: dict) -> tuple[int, dict]:
    from providers.threat_intel import GlobalIntelProvider
    cell_id = (body or {}).get("cell_id", "")
    if not cell_id:
        return 400, {"error": "Missing 'cell_id'"}
    return 200, GlobalIntelProvider.verify_cell(cell_id)


# ── RFC-0008 Hardware / GPIO ──────────────────────────────────────────
def _hardware_status() -> tuple[int, dict]:
    from providers.hardware import HardwareProvider
    return 200, HardwareProvider.get_status()


def _hardware_test(body: dict) -> tuple[int, dict]:
    from providers.hardware import HardwareProvider
    pin = int((body or {}).get("pin", 0) or 0)
    duration = float((body or {}).get("duration", 0.5) or 0.5)
    return 200, HardwareProvider.test_pin(pin, duration)


def _hardware_watchdog(body: dict) -> tuple[int, dict]:
    from providers.hardware import HardwareProvider
    action = (body or {}).get("action", "status")
    if action == "enable":
        return HardwareProvider.enable_watchdog()
    if action == "disable":
        return HardwareProvider.disable_watchdog()
    return 200, HardwareProvider.watchdog_status()


# ── RFC-0009 Ambient Sensors ──────────────────────────────────────────
def _sensors_status() -> tuple[int, dict]:
    from providers.sensors import SensorProvider
    return 200, SensorProvider.get_status()


def _sensors_log() -> tuple[int, dict]:
    from providers.sensors import SensorProvider
    return 200, SensorProvider.get_log() if hasattr(SensorProvider, "get_log") else {"log": []}


def _sensors_calibrate(body: dict) -> tuple[int, dict]:
    from providers.sensors import SensorProvider
    return 200, SensorProvider.calibrate()


# ── RFC-0010 Field Operations ─────────────────────────────────────────
def _field_status() -> tuple[int, dict]:
    from providers.field_ops import FieldOpsProvider
    return 200, FieldOpsProvider.get_status()


def _field_radio_silence(body: dict) -> tuple[int, dict]:
    from providers.field_ops import FieldOpsProvider
    duration = int((body or {}).get("duration", 3600) or 3600)
    return 200, FieldOpsProvider.set_radio_silence(duration)


def _field_deadman(body: dict) -> tuple[int, dict]:
    from providers.field_ops import FieldOpsProvider
    action = (body or {}).get("action", "arm")
    if action == "arm":
        return 200, FieldOpsProvider.deadman_arm()
    if action == "disarm":
        return 200, FieldOpsProvider.deadman_disarm()
    if action == "rearm":
        return 200, FieldOpsProvider.deadman_rearm()
    if action == "set":
        return 200, FieldOpsProvider.set_deadman_timeout(int((body or {}).get("timeout", 300)))
    return 400, {"error": f"Unknown deadman action: {action}"}


def _field_geofence(body: dict) -> tuple[int, dict]:
    from providers.field_ops import FieldOpsProvider
    gpx = (body or {}).get("file", "")
    if gpx:
        return 200, FieldOpsProvider.load_geofence_text(gpx)
    return 400, {"error": "Missing 'file' (GPX/KML content)"}


def _field_sweep(body: dict) -> tuple[int, dict]:
    from providers.field_ops import FieldOpsProvider
    bands = (body or {}).get("bands", "")
    result = FieldOpsProvider.plan_sweep(bands) if hasattr(FieldOpsProvider, "plan_sweep") else {"error": "plan_sweep unavailable"}
    return (400 if "error" in result else 200), result


# ── RFC-0011 Tamper Detection ─────────────────────────────────────────
def _tamper_status() -> tuple[int, dict]:
    from providers.tamper import TamperProvider
    return 200, TamperProvider.get_status()


def _tamper_log() -> tuple[int, dict]:
    from providers.tamper import TamperProvider
    return 200, {"count": 0, "log": TamperProvider.get_log()}


def _tamper_test(body: dict) -> tuple[int, dict]:
    from providers.tamper import TamperProvider
    return 200, TamperProvider.report_event("test", "low", "Manual tamper test")


# ── RFC-0012 Deception / Honeypot ─────────────────────────────────────
def _deception_status() -> tuple[int, dict]:
    from providers.deception import DeceptionProvider
    return 200, DeceptionProvider.get_status()


def _deception_chaff(body: dict) -> tuple[int, dict]:
    from providers.deception import DeceptionProvider
    intensity = (body or {}).get("intensity", "")
    return 200, DeceptionProvider.set_chaff_intensity(intensity)


def _deception_honeypot(body: dict) -> tuple[int, dict]:
    from providers.deception import DeceptionProvider
    action = (body or {}).get("action", "enable")
    return 200, DeceptionProvider.set_honeypot(action != "disable")


# ── RFC-0013 AI Assessment ────────────────────────────────────────────
def _ai_status() -> tuple[int, dict]:
    from providers.ai_assessor import AIAssessorProvider
    return 200, AIAssessorProvider.get_status()


def _ai_assess(body: dict) -> tuple[int, dict]:
    from providers.ai_assessor import AIAssessorProvider
    events = (body or {}).get("events", [])
    score = float((body or {}).get("score", 0) or 0)
    location = (body or {}).get("location", "")
    result = AIAssessorProvider.assess(events, score, location)
    return (400 if "error" in result else 200), result


def _ai_summary(body: dict) -> tuple[int, dict]:
    from providers.ai_assessor import AIAssessorProvider
    return 200, AIAssessorProvider.get_summary() if hasattr(AIAssessorProvider, "get_summary") else {"summary": "none"}


# ── RFC-0014 Modem Firmware ───────────────────────────────────────────
def _modem_status() -> tuple[int, dict]:
    from providers.modem import ModemProvider
    return 200, ModemProvider.get_status()


def _modem_fw_check() -> tuple[int, dict]:
    from providers.modem import ModemProvider
    return 200, ModemProvider.check_firmware_integrity()


def _modem_fw_history() -> tuple[int, dict]:
    from providers.modem import ModemProvider
    return 200, ModemProvider.get_fw_history() if hasattr(ModemProvider, "get_fw_history") else {"history": []}


def _modem_cve_scan(body: dict) -> tuple[int, dict]:
    from providers.modem import ModemProvider
    return 200, ModemProvider.scan_cves()


# ── RFC-0015 Out-of-Band Side Channels ────────────────────────────────
def _ob_channel_status() -> tuple[int, dict]:
    from providers.ob_channel import OBChannelProvider
    return 200, OBChannelProvider.get_status()


def _ob_channel_list() -> tuple[int, dict]:
    from providers.ob_channel import OBChannelProvider
    channels = OBChannelProvider.list_channels()
    return 200, {"count": len(channels), "channels": channels}


def _ob_channel_send(body: dict) -> tuple[int, dict]:
    from providers.ob_channel import OBChannelProvider
    peer = (body or {}).get("peer", "")
    message = (body or {}).get("message", "")
    channel = (body or {}).get("channel") or OBChannelProvider._selected
    if not peer or not message:
        return 400, {"error": "Missing 'peer' or 'message'"}
    if not channel:
        return 400, {"error": "Missing 'channel'; select a channel first"}
    result = OBChannelProvider.send(channel, peer, message)
    return (501 if "error" in result else 200), result


def _ob_channel_select(body: dict) -> tuple[int, dict]:
    from providers.ob_channel import OBChannelProvider
    name = (body or {}).get("name", "")
    if not name:
        return 400, {"error": "Missing 'name'"}
    return 200, OBChannelProvider.select(name) if hasattr(OBChannelProvider, "select") else {"error": "select unavailable"}


def _ob_channel_test(body: dict) -> tuple[int, dict]:
    from providers.ob_channel import OBChannelProvider
    name = (body or {}).get("name", "")
    return 200, OBChannelProvider.test(name) if hasattr(OBChannelProvider, "test") else {"error": "test unavailable"}


# ── RFC-0016 Energy / Battery Forensics ───────────────────────────────
def _power_status() -> tuple[int, dict]:
    from providers.power import PowerProvider
    return 200, PowerProvider.get_status()


def _power_log(params: dict) -> tuple[int, dict]:
    from providers.power import PowerProvider
    minutes = int(params.get("minutes", [30])[0])
    return 200, {"count": 0, "log": PowerProvider.get_log(minutes)}


def _power_baseline_reset() -> tuple[int, dict]:
    from providers.power import PowerProvider
    return 200, PowerProvider.reset_baseline() if hasattr(PowerProvider, "reset_baseline") else {"error": "reset_baseline unavailable"}


# ── RFC-0017 Anti-TEMPEST / EM-Sec ────────────────────────────────────
def _emsec_status() -> tuple[int, dict]:
    from providers.emsec import EMSecProvider
    return 200, EMSecProvider.get_status()


def _emsec_scan(body: dict) -> tuple[int, dict]:
    from providers.emsec import EMSecProvider
    return 200, EMSecProvider.scan_emissions() if hasattr(EMSecProvider, "scan_emissions") else {"error": "unavailable"}


def _emsec_faraday(body: dict) -> tuple[int, dict]:
    from providers.emsec import EMSecProvider
    return 200, EMSecProvider._test_faraday() if hasattr(EMSecProvider, "_test_faraday") else {"error": "unavailable"}


def _emsec_tempest(body: dict) -> tuple[int, dict]:
    from providers.emsec import EMSecProvider
    return 200, EMSecProvider.tempest_detect() if hasattr(EMSecProvider, "tempest_detect") else {"error": "unavailable"}


# ── RFC-0018 Carrier API ──────────────────────────────────────────────
def _carrier_status() -> tuple[int, dict]:
    from providers.carrier import CarrierProvider
    return 200, CarrierProvider.get_status()


def _carrier_webhook(body: dict) -> tuple[int, dict]:
    from providers.carrier import CarrierProvider
    return 200, CarrierProvider.process_webhook_event(body or {})


def _carrier_register_webhook(body: dict) -> tuple[int, dict]:
    from providers.carrier import CarrierProvider
    url = (body or {}).get("url", "")
    result = CarrierProvider.register_webhook(url)
    return (400 if "error" in result else 200), result


def _carrier_history() -> tuple[int, dict]:
    from providers.carrier import CarrierProvider
    return 200, CarrierProvider.get_history()


# ── RFC-0019 PQ Mesh ──────────────────────────────────────────────────
def _pq_mesh_status() -> tuple[int, dict]:
    from providers.mesh import PQMesh
    return 200, PQMesh.get_status()


def _pq_mesh_enforce(body: dict) -> tuple[int, dict]:
    from providers.mesh import PQMesh
    enabled = (body or {}).get("enabled", True)
    return 200, PQMesh.set_enforce(bool(enabled))


def _pq_mesh_handshake(body: dict) -> tuple[int, dict]:
    peer_key = (body or {}).get("peer_pubkey", "")
    if not peer_key:
        return 400, {"error": "Missing 'peer_pubkey' (hex ML-KEM public key)"}
    return _pqc_handshake(body)


# ── RFC-0020 Duress ───────────────────────────────────────────────────
def _duress_status() -> tuple[int, dict]:
    from providers.duress import DuressProvider
    return 200, DuressProvider.get_status()


def _duress_set_code(body: dict) -> tuple[int, dict]:
    from providers.duress import DuressProvider
    phrase = (body or {}).get("phrase", "")
    if not phrase:
        return 400, {"error": "Missing 'phrase'"}
    return 200, DuressProvider.set_code(phrase)


def _duress_test(body: dict) -> tuple[int, dict]:
    from providers.duress import DuressProvider
    phrase = (body or {}).get("phrase", "")
    return 200, DuressProvider.check_command(phrase) if hasattr(DuressProvider, "check_command") else {"duress": False}


def _duress_panic(body: dict) -> tuple[int, dict]:
    from providers.duress import DuressProvider
    return 200, DuressProvider.panic_delete()


# ── RFC-0021 Mesh Attack Detection ────────────────────────────────────
def _mesh_security_status() -> tuple[int, dict]:
    from providers.mesh_security import MeshSecurityProvider
    return 200, MeshSecurityProvider.get_status()


def _mesh_security_graph() -> tuple[int, dict]:
    from providers.mesh_security import MeshSecurityProvider
    return 200, MeshSecurityProvider.get_graph()


def _mesh_security_peers() -> tuple[int, dict]:
    from providers.mesh_security import MeshSecurityProvider
    return 200, MeshSecurityProvider.get_peers() if hasattr(MeshSecurityProvider, "get_peers") else {"peers": []}


# ── RFC-0022 Blockchain Evidence ──────────────────────────────────────
def _evidence_status() -> tuple[int, dict]:
    from providers.evidence import EvidenceProvider
    return 200, EvidenceProvider.get_status()


def _evidence_notarize(body: dict) -> tuple[int, dict]:
    from providers.evidence import EvidenceProvider
    eid = (body or {}).get("id", "")
    if not eid:
        return 400, {"error": "Missing 'id'"}
    return 200, EvidenceProvider.notarize(eid)


def _evidence_verify(body: dict) -> tuple[int, dict]:
    from providers.evidence import EvidenceProvider
    eid = (body or {}).get("id", "")
    if not eid:
        return 400, {"error": "Missing 'id'"}
    return 200, EvidenceProvider.verify(eid)


def _evidence_notarize_all() -> tuple[int, dict]:
    from providers.evidence import EvidenceProvider
    return 200, EvidenceProvider.notarize_all()


def _evidence_chain() -> tuple[int, dict]:
    from providers.evidence import EvidenceProvider
    return 200, EvidenceProvider.get_chain() if hasattr(EvidenceProvider, "get_chain") else {"chain": []}


# ── RFC-0023 Circumvention ────────────────────────────────────────────
def _circumvention_status() -> tuple[int, dict]:
    from providers.circumvention import CircumventionProvider
    return 200, CircumventionProvider.get_status()


def _circumvention_mode(body: dict) -> tuple[int, dict]:
    from providers.circumvention import CircumventionProvider
    mode = (body or {}).get("mode", "")
    if not mode:
        return 400, {"error": "Missing 'mode'"}
    return 200, CircumventionProvider.set_mode(mode)


def _circumvention_front(body: dict) -> tuple[int, dict]:
    from providers.circumvention import CircumventionProvider
    domain = (body or {}).get("domain", "")
    if not domain:
        return 400, {"error": "Missing 'domain'"}
    return 200, CircumventionProvider.set_front_domain(domain)


# ── RFC-0024 Airgap ───────────────────────────────────────────────────
def _airgap_status() -> tuple[int, dict]:
    from providers.airgap import AirGapProvider
    return 200, AirGapProvider.get_status()


def _airgap_qr_send(body: dict) -> tuple[int, dict]:
    from providers.airgap import AirGapProvider
    data = (body or {}).get("data", (body or {}).get("file", ""))
    result = AirGapProvider.qr_send(data)
    return (400 if "error" in result else 200), result


def _airgap_audio_tx(body: dict) -> tuple[int, dict]:
    from providers.airgap import AirGapProvider
    message = (body or {}).get("message", "")
    return 200, AirGapProvider.audio_tx(message)


def _airgap_nfc_pair(body: dict) -> tuple[int, dict]:
    from providers.airgap import AirGapProvider
    peer = (body or {}).get("peer", "")
    return 200, AirGapProvider.nfc_pair(peer)


def _airgap_audio_rx() -> tuple[int, dict]:
    from providers.airgap import AirGapProvider
    return 200, AirGapProvider.audio_rx() if hasattr(AirGapProvider, "audio_rx") else {"error": "audio-rx unavailable"}


# ── RFC-0025 Hygiene ──────────────────────────────────────────────────
def _hygiene_status() -> tuple[int, dict]:
    from providers.hygiene import HygieneProvider
    return 200, HygieneProvider.get_status()


def _hygiene_scan(body: dict) -> tuple[int, dict]:
    from providers.hygiene import HygieneProvider
    mode = (body or {}).get("mode", "full")
    if mode == "quick":
        return 200, HygieneProvider.scan_processes()
    return 200, HygieneProvider.scan_full()


def _hygiene_quarantine(body: dict) -> tuple[int, dict]:
    from providers.hygiene import HygieneProvider
    proc = (body or {}).get("process", "")
    if not proc:
        return 400, {"error": "Missing 'process'"}
    return 200, HygieneProvider.quarantine(proc)


# ── Router table ──────────────────────────────────────────────────────
_GET_ROUTES: dict[str, Any] = {
    "/cpip/cell/status": _cell_status,
    "/cpip/cell/history": _cell_history,
    "/cpip/sdr/status": _sdr_status,
    "/cpip/sdr/spectrum": _sdr_spectrum,
    "/cpip/crypto/pqc-status": _pqc_status,
    "/cpip/radio/status": _radio_status,
    "/cpip/radio/spectrum": _radio_spectrum,
    "/cpip/ss7/status": _ss7_status,
    "/cpip/ss7/log": _ss7_log,
    "/cpip/diameter/status": _diameter_status,
    "/cpip/sigfw/alerts": _sigfw_alerts,
    "/cpip/scorer/status": _scorer_status,
    "/cpip/scorer/explain": _scorer_explain,
    "/cpip/scorer/history": _scorer_history,
    "/cpip/scorer/baselines": _scorer_baselines,
    "/cpip/intel/status": _intel_status,
    "/cpip/intel/map": _intel_map,
    "/cpip/intel/global-map": _intel_map,
    "/cpip/intel/risk-score": _intel_risk,
    "/cpip/hardware/status": _hardware_status,
    "/cpip/sensors/status": _sensors_status,
    "/cpip/sensors/log": _sensors_log,
    "/cpip/field/status": _field_status,
    "/cpip/tamper/status": _tamper_status,
    "/cpip/tamper/log": _tamper_log,
    "/cpip/deception/status": _deception_status,
    "/cpip/ai/status": _ai_status,
    "/cpip/ai/summary": _ai_summary,
    "/cpip/modem/status": _modem_status,
    "/cpip/modem/fw-history": _modem_fw_history,
    "/cpip/ob-channel/status": _ob_channel_status,
    "/cpip/ob-channel/list": _ob_channel_list,
    "/cpip/power/status": _power_status,
    "/cpip/power/log": _power_log,
    "/cpip/emsec/status": _emsec_status,
    "/cpip/carrier/status": _carrier_status,
    "/cpip/carrier/history": _carrier_history,
    "/cpip/pq-mesh/status": _pq_mesh_status,
    "/cpip/duress/status": _duress_status,
    "/cpip/mesh-security/status": _mesh_security_status,
    "/cpip/mesh-security/graph": _mesh_security_graph,
    "/cpip/mesh-security/peers": _mesh_security_peers,
    "/cpip/evidence/status": _evidence_status,
    "/cpip/evidence/chain": _evidence_chain,
    "/cpip/circumvention/status": _circumvention_status,
    "/cpip/airgap/status": _airgap_status,
    "/cpip/hygiene/status": _hygiene_status,
}

_POST_ROUTES: dict[str, Any] = {
    "/cpip/cell/scan": _cell_scan,
    "/cpip/cell/baseline-reset": _cell_baseline_reset,
    "/cpip/sdr/scan": _sdr_scan,
    "/cpip/sdr/capture": _sdr_capture,
    "/cpip/crypto/pqc-keys": _pqc_keys,
    "/cpip/crypto/pqc-handshake": _pqc_handshake,
    "/cpip/crypto/pqc-rotate": _pqc_keys,
    "/cpip/radio/hop": _radio_hop,
    "/cpip/radio/fingerprint": _radio_fingerprint,
    "/cpip/intel/share": _intel_share,
    "/cpip/intel/verify": _intel_verify,
    "/cpip/hardware/test": _hardware_test,
    "/cpip/hardware/watchdog": _hardware_watchdog,
    "/cpip/sensors/calibrate": _sensors_calibrate,
    "/cpip/field/radio-silence": _field_radio_silence,
    "/cpip/field/deadman": _field_deadman,
    "/cpip/field/geofence": _field_geofence,
    "/cpip/field/sweep": _field_sweep,
    "/cpip/tamper/test": _tamper_test,
    "/cpip/deception/chaff": _deception_chaff,
    "/cpip/deception/honeypot": _deception_honeypot,
    "/cpip/deception/honeypot-spawn": _deception_honeypot,
    "/cpip/ai/assess": _ai_assess,
    "/cpip/modem/fw-check": _modem_fw_check,
    "/cpip/modem/cve-scan": _modem_cve_scan,
    "/cpip/ob-channel/send": _ob_channel_send,
    "/cpip/ob-channel/select": _ob_channel_select,
    "/cpip/ob-channel/test": _ob_channel_test,
    "/cpip/power/baseline-reset": _power_baseline_reset,
    "/cpip/emsec/scan": _emsec_scan,
    "/cpip/emsec/faraday-test": _emsec_faraday,
    "/cpip/emsec/tempest-detect": _emsec_tempest,
    "/cpip/carrier/webhook": _carrier_webhook,
    "/cpip/carrier/register-webhook": _carrier_register_webhook,
    "/cpip/pq-mesh/enforce": _pq_mesh_enforce,
    "/cpip/pq-mesh/handshake": _pq_mesh_handshake,
    "/cpip/duress/set-code": _duress_set_code,
    "/cpip/duress/test": _duress_test,
    "/cpip/duress/panic-delete": _duress_panic,
    "/cpip/evidence/notarize": _evidence_notarize,
    "/cpip/evidence/verify": _evidence_verify,
    "/cpip/evidence/notarize-all": _evidence_notarize_all,
    "/cpip/circumvention/mode": _circumvention_mode,
    "/cpip/circumvention/front": _circumvention_front,
    "/cpip/airgap/qr-send": _airgap_qr_send,
    "/cpip/airgap/audio-tx": _airgap_audio_tx,
    "/cpip/airgap/nfc-pair": _airgap_nfc_pair,
    "/cpip/airgap/audio-rx": _airgap_audio_rx,
    "/cpip/hygiene/scan": _hygiene_scan,
    "/cpip/hygiene/quarantine": _hygiene_quarantine,
}


def route_get(path: str, params: dict) -> tuple[int, dict] | None:
    handler = _GET_ROUTES.get(path)
    if handler is None:
        return None
    try:
        if handler.__code__.co_argcount >= 1 and "params" in handler.__code__.co_varnames:
            result = handler(params)
        else:
            result = handler()
        return _normalize_result(result)
    except Exception as e:
        logger.warning("RFC GET %s error: %s", path, e)
        return 500, {"error": _fmt(e), "endpoint": path}


def route_post(path: str, body: dict, params: dict) -> tuple[int, dict] | None:
    handler = _POST_ROUTES.get(path)
    if handler is None:
        return None
    try:
        argnames = handler.__code__.co_varnames[:handler.__code__.co_argcount]
        if argnames[:1] == ("params",):
            result = handler(params, body)
        elif len(argnames) >= 2:
            result = handler(body, params)
        elif len(argnames) == 1:
            result = handler(body)
        else:
            result = handler()
        return _normalize_result(result)
    except Exception as e:
        logger.warning("RFC POST %s error: %s", path, e)
        return 500, {"error": _fmt(e), "endpoint": path}


def _normalize_result(result: tuple[int, dict]) -> tuple[int, dict]:
    """Never report provider errors as successful HTTP responses."""
    status, payload = result
    if status < 400 and isinstance(payload, dict) and payload.get("error"):
        error = str(payload["error"]).lower()
        status = 501 if "not implemented" in error or "backend is not" in error else 503 if "unavailable" in error or "not enabled" in error else 400
    return status, payload
