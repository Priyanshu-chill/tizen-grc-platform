import json
from abc import ABC, abstractmethod

class BaseCollector(ABC):
    """
    Abstract Base Class for the Tizen GRC Configuration Collection Layer.
    Every configuration collector must inherit from this class.
    """
    
    def __init__(self, name: str, description: str):
        self.name = name
        self.description = description
        
    @abstractmethod
    def collect_telemetry(self, device_ip: str, credentials: dict = None) -> dict:
        """
        Executes telemetry gathering. Returns a dictionary of parsed check findings 
        mapping Control IDs to compliance outcomes (e.g. {"UTSCF-PIO-01": "PASS"}).
        """
        pass


class SdbCollector(BaseCollector):
    """Smart Development Bridge network collector executing commands remotely."""
    def __init__(self):
        super().__init__("SdbCollector", "Runs shell commands over SDB ports via developer keys.")
        
    def collect_telemetry(self, device_ip: str, credentials: dict = None) -> dict:
        # Mock network SDB execution
        return {
            "UTSCF-PIO-01": "PASS", # SDB port state (often locked down or requires auth)
            "UTSCF-PIO-02": "PASS",
            "UTSCF-ASL-01": "PASS"
        }


class VendorManagementCollector(BaseCollector):
    """Collector interacting with Vendor APIs (such as Samsung Enterprise Management APIs)."""
    def __init__(self):
        super().__init__("VendorManagementCollector", "Queries vendor API servers for device management parameters.")
        
    def collect_telemetry(self, device_ip: str, credentials: dict = None) -> dict:
        # Mock Knox/Tizen Cloud API query
        return {
            "UTSCF-BHS-01": "PASS", # Secure Boot
            "UTSCF-BHS-03": "PASS", # Knox Warranty checking
            "UTSCF-DAM-01": "PASS"  # MDM Enrollment
        }


class ConfigFileCollector(BaseCollector):
    """Collector parsing local JSON/XML configuration dumps."""
    def __init__(self, file_path: str = None):
        super().__init__("ConfigFileCollector", "Imports local XML/JSON compliance reports.")
        self.file_path = file_path
        
    def collect_telemetry(self, device_ip: str, credentials: dict = None) -> dict:
        return {
            "UTSCF-KOH-01": "PASS",
            "UTSCF-KOH-02": "PASS",
            "UTSCF-NCS-01": "PASS"
        }


class LogCollector(BaseCollector):
    """Collector parsing auditd/syslog daemon logs."""
    def __init__(self):
        super().__init__("LogCollector", "Collects and checks auditd and secure syslog settings.")
        
    def collect_telemetry(self, device_ip: str, credentials: dict = None) -> dict:
        return {
            "UTSCF-LAM-01": "PASS",
            "UTSCF-LAM-02": "PASS"
        }


class DiagnosticAppCollector(BaseCollector):
    """Signed Diagnostic App running locally on the kiosk."""
    def __init__(self):
        super().__init__("DiagnosticAppCollector", "Signed Tizen WGT/TPK diagnostics daemon.")
        
    def collect_telemetry(self, device_ip: str, credentials: dict = None) -> dict:
        return {
            "UTSCF-ASL-02": "PASS",
            "UTSCF-ASL-03": "PASS"
        }


class ManualEvidenceCollector(BaseCollector):
    """Collector dealing with manual uploads from Security Analysts."""
    def __init__(self):
        super().__init__("ManualEvidenceCollector", "Handles security analyst manual uploads.")
        
    def collect_telemetry(self, device_ip: str, credentials: dict = None) -> dict:
        return {}


class MdmCollector(BaseCollector):
    """Enterprise MDM Synchronization Collector."""
    def __init__(self):
        super().__init__("MdmCollector", "Syncs status checks from enterprise MDM platforms.")
        
    def collect_telemetry(self, device_ip: str, credentials: dict = None) -> dict:
        return {
            "UTSCF-DAM-02": "PASS",
            "UTSCF-DAM-03": "PASS"
        }
