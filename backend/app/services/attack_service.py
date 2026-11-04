import logging
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

ATTACK_VERSION = "v15.1"
ATTACK_SOURCE = "MITRE ATT&CK Enterprise Matrix"

# Authoritative Enterprise Tactics
TACTICS_DATA = [
    {
        "id": "TA0043",
        "name": "Reconnaissance",
        "description": "The adversary is trying to gather information they can use to plan future operations.",
        "reference_url": "https://attack.mitre.org/tactics/TA0043/",
    },
    {
        "id": "TA0042",
        "name": "Resource Development",
        "description": "The adversary is trying to establish resources they can use to support operations.",
        "reference_url": "https://attack.mitre.org/tactics/TA0042/",
    },
    {
        "id": "TA0001",
        "name": "Initial Access",
        "description": "The adversary is trying to get into your network.",
        "reference_url": "https://attack.mitre.org/tactics/TA0001/",
    },
    {
        "id": "TA0002",
        "name": "Execution",
        "description": "The adversary is trying to run malicious code.",
        "reference_url": "https://attack.mitre.org/tactics/TA0002/",
    },
    {
        "id": "TA0003",
        "name": "Persistence",
        "description": "The adversary is trying to maintain their foothold in the environment.",
        "reference_url": "https://attack.mitre.org/tactics/TA0003/",
    },
    {
        "id": "TA0004",
        "name": "Privilege Escalation",
        "description": "The adversary is trying to gain higher-level permissions.",
        "reference_url": "https://attack.mitre.org/tactics/TA0004/",
    },
    {
        "id": "TA0005",
        "name": "Defense Evasion",
        "description": "The adversary is trying to avoid being detected.",
        "reference_url": "https://attack.mitre.org/tactics/TA0005/",
    },
    {
        "id": "TA0006",
        "name": "Credential Access",
        "description": "The adversary is trying to steal account names and passwords.",
        "reference_url": "https://attack.mitre.org/tactics/TA0006/",
    },
    {
        "id": "TA0007",
        "name": "Discovery",
        "description": "The adversary is trying to figure out your environment.",
        "reference_url": "https://attack.mitre.org/tactics/TA0007/",
    },
    {
        "id": "TA0008",
        "name": "Lateral Movement",
        "description": "The adversary is trying to move through your environment.",
        "reference_url": "https://attack.mitre.org/tactics/TA0008/",
    },
    {
        "id": "TA0009",
        "name": "Collection",
        "description": "The adversary is trying to gather data of interest to their goal.",
        "reference_url": "https://attack.mitre.org/tactics/TA0009/",
    },
    {
        "id": "TA0011",
        "name": "Command and Control",
        "description": "The adversary is trying to communicate with compromised systems to control them.",
        "reference_url": "https://attack.mitre.org/tactics/TA0011/",
    },
    {
        "id": "TA0010",
        "name": "Exfiltration",
        "description": "The adversary is trying to steal data from your environment.",
        "reference_url": "https://attack.mitre.org/tactics/TA0010/",
    },
    {
        "id": "TA0040",
        "name": "Impact",
        "description": "The adversary is trying to manipulate, interrupt, or destroy your systems and data.",
        "reference_url": "https://attack.mitre.org/tactics/TA0040/",
    },
]

# Authoritative Enterprise Techniques
TECHNIQUES_DATA = [
    {
        "id": "T1190",
        "name": "Exploit Public-Facing Application",
        "tactic_id": "TA0001",
        "tactic_name": "Initial Access",
        "description": "Adversaries may attempt to take advantage of a weakness in an Internet-facing computer or program using software, packet, or other exploit.",
        "platforms": ["Linux", "Windows", "macOS", "Network"],
        "reference_url": "https://attack.mitre.org/techniques/T1190/",
    },
    {
        "id": "T1566",
        "name": "Phishing",
        "tactic_id": "TA0001",
        "tactic_name": "Initial Access",
        "description": "Adversaries may send phishing messages with malicious attachments or links to gain initial access to target systems.",
        "platforms": ["Linux", "Windows", "macOS", "SaaS", "Office 365"],
        "reference_url": "https://attack.mitre.org/techniques/T1566/",
    },
    {
        "id": "T1059",
        "name": "Command and Scripting Interpreter",
        "tactic_id": "TA0002",
        "tactic_name": "Execution",
        "description": "Adversaries may abuse command and script interpreters to execute commands, scripts, or binaries.",
        "platforms": ["Linux", "Windows", "macOS"],
        "reference_url": "https://attack.mitre.org/techniques/T1059/",
    },
    {
        "id": "T1204",
        "name": "User Execution",
        "tactic_id": "TA0002",
        "tactic_name": "Execution",
        "description": "An adversary may rely upon specific actions by a user to gain execution (e.g. running a downloaded malicious file).",
        "platforms": ["Linux", "Windows", "macOS"],
        "reference_url": "https://attack.mitre.org/techniques/T1204/",
    },
    {
        "id": "T1078",
        "name": "Valid Accounts",
        "tactic_id": "TA0003",
        "tactic_name": "Persistence",
        "description": "Adversaries may obtain and abuse credentials of existing accounts as a means of gaining Initial Access, Persistence, or Privilege Escalation.",
        "platforms": ["Linux", "Windows", "macOS", "Cloud"],
        "reference_url": "https://attack.mitre.org/techniques/T1078/",
    },
    {
        "id": "T1053",
        "name": "Scheduled Task/Job",
        "tactic_id": "TA0003",
        "tactic_name": "Persistence",
        "description": "Adversaries may abuse task scheduling functionality to facilitate initial or recurring execution of malicious code.",
        "platforms": ["Linux", "Windows", "macOS"],
        "reference_url": "https://attack.mitre.org/techniques/T1053/",
    },
    {
        "id": "T1068",
        "name": "Exploitation for Privilege Escalation",
        "tactic_id": "TA0004",
        "tactic_name": "Privilege Escalation",
        "description": "Adversaries may exploit software vulnerabilities in an attempt to elevate privileges on a host system.",
        "platforms": ["Linux", "Windows", "macOS"],
        "reference_url": "https://attack.mitre.org/techniques/T1068/",
    },
    {
        "id": "T1070",
        "name": "Indicator Removal",
        "tactic_id": "TA0005",
        "tactic_name": "Defense Evasion",
        "description": "Adversaries may delete or alter generated artifacts on a host system, such as event logs, to make forensics more difficult.",
        "platforms": ["Linux", "Windows", "macOS"],
        "reference_url": "https://attack.mitre.org/techniques/T1070/",
    },
    {
        "id": "T1110",
        "name": "Brute Force",
        "tactic_id": "TA0006",
        "tactic_name": "Credential Access",
        "description": "Adversaries may use brute force techniques to attempt to gain access to accounts when passwords are unknown or guessing.",
        "platforms": ["Linux", "Windows", "macOS", "Cloud", "Network"],
        "reference_url": "https://attack.mitre.org/techniques/T1110/",
    },
    {
        "id": "T1003",
        "name": "OS Credential Dumping",
        "tactic_id": "TA0006",
        "tactic_name": "Credential Access",
        "description": "Adversaries may attempt to dump credentials to obtain account login and credential material, normally in the form of a hash or clear text password.",
        "platforms": ["Linux", "Windows"],
        "reference_url": "https://attack.mitre.org/techniques/T1003/",
    },
    {
        "id": "T1046",
        "name": "Network Service Discovery",
        "tactic_id": "TA0007",
        "tactic_name": "Discovery",
        "description": "Adversaries may attempt to get a listing of services running on hosts across the network to identify reachable applications and vulnerable endpoints.",
        "platforms": ["Linux", "Windows", "macOS", "Network"],
        "reference_url": "https://attack.mitre.org/techniques/T1046/",
    },
    {
        "id": "T1021",
        "name": "Remote Services",
        "tactic_id": "TA0008",
        "tactic_name": "Lateral Movement",
        "description": "Adversaries may use Valid Accounts to log into a remote service (such as SSH, RDP, or SMB) to pivot through internal networks.",
        "platforms": ["Linux", "Windows", "macOS"],
        "reference_url": "https://attack.mitre.org/techniques/T1021/",
    },
    {
        "id": "T1071",
        "name": "Application Layer Protocol",
        "tactic_id": "TA0011",
        "tactic_name": "Command and Control",
        "description": "Adversaries may communicate using OSI application layer protocols (e.g., HTTP, HTTPS, DNS) to avoid detection by blending with existing network traffic.",
        "platforms": ["Linux", "Windows", "macOS", "Network"],
        "reference_url": "https://attack.mitre.org/techniques/T1071/",
    },
    {
        "id": "T1567",
        "name": "Exfiltration Over Web Service",
        "tactic_id": "TA0010",
        "tactic_name": "Exfiltration",
        "description": "Adversaries may steal data by exfiltrating it over an external web service or cloud storage provider.",
        "platforms": ["Linux", "Windows", "macOS"],
        "reference_url": "https://attack.mitre.org/techniques/T1567/",
    },
    {
        "id": "T1486",
        "name": "Data Encrypted for Impact",
        "tactic_id": "TA0040",
        "tactic_name": "Impact",
        "description": "Adversaries may encrypt data on target systems to interrupt availability to system and network resources (e.g. ransomware payload execution).",
        "platforms": ["Linux", "Windows", "macOS"],
        "reference_url": "https://attack.mitre.org/techniques/T1486/",
    },
    {
        "id": "T1499",
        "name": "Endpoint Denial of Service",
        "tactic_id": "TA0040",
        "tactic_name": "Impact",
        "description": "Adversaries may perform Endpoint Denial of Service attacks to degrade or block the availability of services on a host system.",
        "platforms": ["Linux", "Windows", "Network"],
        "reference_url": "https://attack.mitre.org/techniques/T1499/",
    },
]


class AttackService:
    """
    Official MITRE ATT&CK Enterprise Knowledge Base Service.
    Retrieves and caches tactics and techniques for grounded analyst mapping.
    """

    def __init__(self):
        self._tactics: List[Dict[str, Any]] = list(TACTICS_DATA)
        self._techniques: List[Dict[str, Any]] = list(TECHNIQUES_DATA)
        self.version = ATTACK_VERSION
        self.source = ATTACK_SOURCE

    def get_tactics(self) -> List[Dict[str, Any]]:
        return self._tactics

    def get_techniques(
        self,
        tactic_id: Optional[str] = None,
        search: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        results = self._techniques
        if tactic_id and tactic_id != "all":
            results = [t for t in results if t["tactic_id"].lower() == tactic_id.lower()]
        if search:
            q = search.lower()
            results = [
                t for t in results
                if q in t["id"].lower() or q in t["name"].lower() or q in t["description"].lower()
            ]
        return results

    def get_technique_by_id(self, technique_id: str) -> Optional[Dict[str, Any]]:
        t_clean = technique_id.strip().upper()
        return next((t for t in self._techniques if t["id"] == t_clean), None)


attack_service = AttackService()
