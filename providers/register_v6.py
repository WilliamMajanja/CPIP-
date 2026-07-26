"""Auto-register all v6 providers into the provider registry."""
import logging

from providers.registry import ProviderRegistry
from providers.cellular import CellularProvider
from providers.sdr import SDRProvider
from providers.scorer import Scorer
from providers.threat_intel import ThreatIntelProvider
from providers.hardware import HardwareProvider
from providers.sensors import SensorProvider
from providers.field_ops import FieldOpsProvider
from providers.tamper import TamperProvider
from providers.deception import DeceptionProvider
from providers.ai_assessor import AIAssessorProvider
from providers.modem import ModemProvider
from providers.ss7_monitor import SS7Monitor
from providers.ob_channel import OBChannelProvider
from providers.power import PowerProvider
from providers.emsec import EMSecProvider
from providers.carrier import CarrierProvider
from providers.duress import DuressProvider
from providers.mesh_security import MeshSecurityProvider
from providers.evidence import EvidenceProvider
from providers.circumvention import CircumventionProvider
from providers.airgap import AirGapProvider
from providers.hygiene import HygieneProvider

logger = logging.getLogger(__name__)

ALL_V6_PROVIDERS = [
    CellularProvider,
    SDRProvider,
    Scorer,
    ThreatIntelProvider,
    HardwareProvider,
    SensorProvider,
    FieldOpsProvider,
    TamperProvider,
    DeceptionProvider,
    AIAssessorProvider,
    ModemProvider,
    SS7Monitor,
    OBChannelProvider,
    PowerProvider,
    EMSecProvider,
    CarrierProvider,
    DuressProvider,
    MeshSecurityProvider,
    EvidenceProvider,
    CircumventionProvider,
    AirGapProvider,
    HygieneProvider,
]


def register_all():
    count = 0
    for provider_cls in ALL_V6_PROVIDERS:
        try:
            ProviderRegistry.register(provider_cls)
            count += 1
        except Exception as e:
            logger.error("Failed to register %s: %s", provider_cls.__name__, e)
    logger.info("Registered %d/%d v6 providers", count, len(ALL_V6_PROVIDERS))
    return count


def start_all():
    started = []
    for provider_cls in ALL_V6_PROVIDERS:
        try:
            if hasattr(provider_cls, "start"):
                provider_cls.start()
                started.append(provider_cls.__name__)
        except Exception as e:
            logger.debug("Start %s: %s", provider_cls.__name__, e)
    return started
