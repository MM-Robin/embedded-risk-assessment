
# models.py
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional
import math


# ── Enums ──────────────────────────────────────────────────────────────

class ControlType(Enum):
    PREVENTIVE = "Preventive"
    DETECTIVE  = "Detective"
    CORRECTIVE = "Corrective"


class ControlStatus(Enum):
    IMPLEMENTED     = "Implemented"
    PARTIAL         = "Partial"
    NOT_IMPLEMENTED = "Not Implemented"
    NOT_APPLICABLE  = "N/A"

class RiskCategory(Enum):
    NETWORK = "Network"
    PHYSICAL = "Physical"
    FIRMWARE = "Firmware"

class AttackVector(Enum):
    NETWORK  = ("N", 0.85, "Exploitable remotely over the network")
    ADJACENT = ("A", 0.62, "Exploitable from an adjacent network")
    LOCAL = ("L", 0.55, "Requires local access to the device")
    PHYSICAL = ("P", 0.2, "Requires physical access to the device")

class AttackComplexity(Enum):
    LOW = ("L", 0.77, "Low complexity attack")
    HIGH = ("H", 0.44, "High complexity attack")  

class PrivilegesRequired(Enum):
    NONE = ("N", 0.85, "No privileges required")
    LOW = ("L", 0.62, "Low privileges required")
    HIGH = ("H", 0.27, "High privileges required")

class UserInteraction(Enum):
    NONE = ("N", 0.85, "No user interaction required")
    REQUIRED = ("R", 0.62, "User interaction required")

class Scope(Enum):
    UNCHANGED = ("U", "Impact stays within component")
    CHANGED = ("C", "Impact extends beyond component")

class Impact(Enum):
    HIGH = ("H", 0.56)
    LOW = ("L", 0.22)
    NONE = ("N", 0.00)

# ── Dataclasses ────────────────────────────────────────────────────────
@dataclass
class CVSSVector:
    attack_vector: AttackVector
    attack_complexity: AttackComplexity
    privileges_required: PrivilegesRequired
    user_interaction: UserInteraction
    scope: Scope
    confidentiality: Impact
    integrity: Impact
    availability: Impact

    def base_score(self) -> float:
        # step 1 : extract numeric weights
        av = self.attack_vector.value[1]
        ac = self.attack_complexity.value[1]
        pr = self.privileges_required.value[1]
        ui = self.user_interaction.value[1]
        c = self.confidentiality.value[1]
        i = self.integrity.value[1]
        a = self.availability.value[1]

        #step 2 :  PR adjustment based on scope changed
        if self.scope == Scope.CHANGED:
            pr = {
                PrivilegesRequired.NONE: 0.85,
                PrivilegesRequired.LOW: 0.50,
                PrivilegesRequired.HIGH: 0.50,
            }[self.privileges_required]
        
        # step 3 : calculate Sub-Score
        iss = 1 - ((1 -c) * (1 - i) * (1 - a))

        #step 4 : Impact Score (formula differs based on scope)
        if self.scope == Scope.UNCHANGED:
            impact = 6.42 * iss
        else:
            impact = 7.52 * (iss -0.029) - 3.25 * ((iss -0.02) ** 15)

        # step 5 : Exploitability Score
        exploitability = 8.22 * av * ac * pr * ui

        # step 6 : Base Score with roundup
        if impact <= 0:
            return 0.0
        
        # step 7 : base score with Roundup
        if self.scope == Scope.UNCHANGED:
            raw = min(impact + exploitability, 10)
        else:
            raw = min(1.08 * (impact + exploitability), 10)

        return math.ceil(raw * 10) / 10 # round up to 1 decimal place
    
    def severity(self) -> str:
        score = self.base_score()
        if score == 0.0: return "None"
        if score < 4.0: return "Low"
        if score < 7.0: return "Medium"
        if score < 9.0: return "High"
        return "Critical"

@dataclass
class Control:
    id:           str
    name:         str
    type:         ControlType      # must be a ControlType, not a string
    status:       ControlStatus    # must be a ControlStatus
    owner:        str
    description:  str
    nis2_article: Optional[str] = None   # e.g. "Art. 21(2)(a)", or None


@dataclass
class Risk:
    id:            str
    threat:        str
    component:     str
    description:   str
    cvss:          Optional[CVSSVector] = None      #CVSS field is optional, as not all risks may have a CVSS assessment
    controls:      list[Control] = field(default_factory=list)
    remediation:   str           = ""
    nis2_relevant: bool          = False
    category: RiskCategory = RiskCategory.NETWORK   # default to NETWORK, can be overriddden

@dataclass
class EmbeddedSystem:
    name:         str
    architecture: str
    interfaces:   list[str]
    firmware_ver: str
    os:           str
    risks:        list[Risk] = field(default_factory=list)
