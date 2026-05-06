from models import (
    Risk, Control, CVSSVector, RiskCategory,
    AttackVector, AttackComplexity, PrivilegesRequired,
    UserInteraction, Scope, Impact,
    ControlType, ControlStatus
)



def build_risk_register() -> list[Risk]:
    risks = []

    #  Risk -- R-001 -------------------------
    r1 = Risk(
        id          = "R-001",
        threat      = "Remote Code Execution via Ethernet",
        component   = "TCP/IP Stack / Network Driver",
        description = (
            "Attacker sends malformed TCP packets to trigger a buffer overflow "
            "in the unvalidated network driver, gaining arbitrary code execution "
            "on the Cortex-M4 core from an adjacent network position."
        ),
        cvss = CVSSVector(
            attack_vector = AttackVector.ADJACENT,
            attack_complexity = AttackComplexity.LOW,
            privileges_required = PrivilegesRequired.NONE,
            user_interaction = UserInteraction.NONE,
            scope = Scope.CHANGED,
            confidentiality = Impact.HIGH,
            integrity = Impact.HIGH,
            availability = Impact.HIGH, 
        ),
        controls    = [
            Control(
                id = "C-001",
                name = "Network Input Validation",
                type = ControlType.PREVENTIVE,
                status = ControlStatus.PARTIAL,
                owner = "Firmware Team",
                description = (
                    "Partial bounds checks exist — full sanitisation not implemented."),
                nis2_article = "Art. 21(2)(g)"
            ),   
            Control(
                id = "C-002",
                name = "MPU Region Isolation",
                type = ControlType.PREVENTIVE,
                status = ControlStatus.NOT_IMPLEMENTED,
                owner = "Embedded Security",
                description = (
                    "Memory Protection Unit not configured for network stack regions."),
                nis2_article = "Art. 21(2)(a)"
            )
        ],
        remediation = ("Apply bounds checking on all network buffers. Enable MPU region "
            "protection. Update to a patched TCP/IP stack (LwIP >= 2.2.0)."),
        nis2_relevant = True,
        category = RiskCategory.NETWORK,
    )
    risks.append(r1)

    # Risk -- R-002 -------------------------
    r2 = Risk(
        id = "R-002",
        threat = "JTAG Firmware Tampering",
        component = "JTAG Interface",
        description = (
            "Unauthorised physical access to JTAG port allows firmware dumping and tampering, "
            "potentially leading to persistent backdoors or extraction of sensitive data."
        ),
        cvss = CVSSVector(
            attack_vector =  AttackVector.PHYSICAL,
            attack_complexity = AttackComplexity.LOW,
            privileges_required = PrivilegesRequired.NONE,
            user_interaction = UserInteraction.NONE,
            scope = Scope.CHANGED,
            confidentiality = Impact.HIGH,
            integrity = Impact.HIGH,
            availability = Impact.HIGH,
        ),
        controls = [
            Control(
                id = "C-003",
                name = "JTAG disabled in production",
                type = ControlType.PREVENTIVE,
                status = ControlStatus.NOT_IMPLEMENTED,
                owner = "Hardware Team",
                description = "JTAG interface is not disabled or protected in production builds.",
                nis2_article = "Art. 21(2)(h)"
            ),
            Control(
                id = "C-004",
                name = "Secure Boot/Firmware Signing",
                type = ControlType.PREVENTIVE,
                status = ControlStatus.NOT_IMPLEMENTED,
                owner = "Embedded Security",
                description = "No secure boot or firmware signing mechanism to prevent tampering.",
                nis2_article = "Art. 21(2)(h)"
            ),
            Control(
                id = "C-005",
                name = "Tamper Detection",
                type = ControlType.DETECTIVE,
                status = ControlStatus.PARTIAL,
                owner = "Hardware Team",
                description = "Tamper-evident seals exist but no active tamper detection is implemented.",
                nis2_article = "Art. 21(2)(a)"
            )
        ],
        remediation = ("Implement JTAG authentication and disable in production builds. "
            "Introduce secure boot with firmware signing. Add active tamper detection mechanisms."),
        nis2_relevant = True,
        category = RiskCategory.PHYSICAL,
    )
    risks.append(r2)

    # Risk -- R-003 --------------------------------
    r3 = Risk(
        id = "R-003",
        threat = "Hardcoded Credentials in Firmware",
        component = "Firmware",
        description = ("During development, a programmer hardcoded an API key" \
        "and default admin password directly into the firmware binary to make testing easier" \
        "and never removed them before production. When an attacker extracts the firmware (via JTAG,"
        " or by downloading an OTA update image), they run strings firmware.bin and find the credentials"
        " in plaintext within seconds. "
        ),
        cvss = CVSSVector(
            attack_vector = AttackVector.LOCAL,
            attack_complexity = AttackComplexity.LOW,
            privileges_required = PrivilegesRequired.NONE,
            user_interaction = UserInteraction.NONE,
            scope = Scope.CHANGED,
            confidentiality = Impact.HIGH,
            integrity = Impact.HIGH,
            availability = Impact.LOW,
        ),
        controls = [
            Control(
                id = "C-006",
                name = "Secure key storage",
                type = ControlType.PREVENTIVE,
                status = ControlStatus.NOT_IMPLEMENTED,
                owner = "Embedded Security",
                description = "secure key storage mechanism (e.g. hardware-backed keystore) not implemented,"
                " allowing hardcoded keys to be easily extracted.",
                nis2_article = "Art. 21(2)(h)"
            ),
            Control(
                id = "C-007",
                name = "Firmware static analysis (SAST)",
                type = ControlType.DETECTIVE,
                status = ControlStatus.NOT_IMPLEMENTED,
                owner = "DevOps Team",
                description = "No static analysis tools are integrated into the CI/CD pipeline to detect"
                " hardcoded credentials or secrets in firmware code.",
                nis2_article = "Art. 21(2)(g)"
            ),
            Control(
                id = "C-008",
                name = "Credential Rotation Policy",
                type = ControlType.CORRECTIVE,
                status = ControlStatus.NOT_IMPLEMENTED,
                owner = "Security Team",
                description = "No policy or mechanism for regular credential rotation, increasing risk if keys are compromised.",
                nis2_article = "Art. 21(2)(i)"
            )
        ],
        remediation = ("Remove hardcoded credentials from firmware. Implement a secure key storage solution,"
        " such as a hardware-backed keystore. Integrate static analysis tools into the CI/CD pipeline "
        "to detect hardcoded secrets. Establish a credential rotation policy to limit the impact of "
        "potential key compromise."),
        nis2_relevant = True,
        category = RiskCategory.FIRMWARE,
    )

    risks.append(r3)

    r4 = Risk(
        id          = "R-004",
        threat      = "Man-in-the-Middle Attack on OTA Firmware Update",
        component   = "OTA Update Mechanism / UART Bootloader",
        description = (
            "Firmware updates are delivered without cryptographic signature verification. "
            "An attacker positioned between the update server and the device intercepts "
            "the update channel and delivers a malicious firmware image. "
            "The device installs it without question, achieving persistent code execution."
        ),
        cvss = CVSSVector(
            attack_vector       = AttackVector.ADJACENT,
            attack_complexity   = AttackComplexity.HIGH,
            privileges_required = PrivilegesRequired.NONE,
            user_interaction    = UserInteraction.NONE,
            scope               = Scope.UNCHANGED,
            confidentiality     = Impact.LOW,
            integrity           = Impact.HIGH,
            availability        = Impact.HIGH,
        ),
        controls = [
            Control(
                id          = "C-010",
                name        = "Firmware Update Signature Verification",
                type        = ControlType.PREVENTIVE,
                status      = ControlStatus.NOT_IMPLEMENTED,
                owner       = "Embedded Security",
                description = "No cryptographic check on received firmware packages.",
                nis2_article= "Art. 21(2)(h)"
            ),
            Control(
                id          = "C-011",
                name        = "Encrypted OTA Channel (TLS)",
                type        = ControlType.PREVENTIVE,
                status      = ControlStatus.PARTIAL,
                owner       = "Firmware Team",
                description = "TLS used for server connection but not for UART update path.",
                nis2_article= "Art. 21(2)(j)"
            ),
        ],
        remediation   = (
            "Implement ECDSA signature verification on all firmware updates. "
            "Use TLS 1.3 for the full update channel. Add anti-rollback counters "
            "in OTP fuses to prevent downgrade attacks."
        ),
        nis2_relevant = False,
        category      = RiskCategory.NETWORK,
    )
    risks.append(r4)

    # ── R-005 — FreeRTOS Privilege Escalation ──────────────────────────
    r5 = Risk(
        id          = "R-005",
        threat      = "Privilege Escalation via FreeRTOS Task Isolation Failure",
        component   = "FreeRTOS Task Scheduler / MPU",
        description = (
            "Low-privilege FreeRTOS tasks can read and write memory regions of "
            "high-privilege tasks due to missing MPU configuration. A compromised "
            "low-privilege task (e.g. a sensor driver) can overwrite the stack of "
            "the main security task and escalate to full system control."
        ),
        cvss = CVSSVector(
            attack_vector       = AttackVector.LOCAL,
            attack_complexity   = AttackComplexity.HIGH,
            privileges_required = PrivilegesRequired.LOW,
            user_interaction    = UserInteraction.NONE,
            scope               = Scope.CHANGED,
            confidentiality     = Impact.HIGH,
            integrity           = Impact.HIGH,
            availability        = Impact.LOW,
        ),
        controls = [
            Control(
                id          = "C-012",
                name        = "FreeRTOS MPU Task Isolation",
                type        = ControlType.PREVENTIVE,
                status      = ControlStatus.NOT_IMPLEMENTED,
                owner       = "Firmware Team",
                description = "MPU regions not configured — all tasks share full memory access.",
                nis2_article= "Art. 21(2)(a)"
            ),
            Control(
                id          = "C-013",
                name        = "Runtime Integrity Monitoring",
                type        = ControlType.DETECTIVE,
                status      = ControlStatus.NOT_IMPLEMENTED,
                owner       = "Embedded Security",
                description = "No watchdog or integrity check monitoring task behaviour at runtime.",
                nis2_article= "Art. 21(2)(g)"
            ),
        ],
        remediation   = (
            "Configure FreeRTOS MPU regions per task with least-privilege memory access. "
            "Separate security-critical tasks into privileged mode only. "
            "Implement a runtime integrity monitor using the hardware watchdog timer."
        ),
        nis2_relevant = False,
        category      = RiskCategory.FIRMWARE,
    )
    risks.append(r5)
 
    # ── R-006 — Unauthenticated UART Console ───────────────────────────
    r6 = Risk(
        id          = "R-006",
        threat      = "Unauthorised Access via Unprotected UART Console",
        component   = "UART Debug Console",
        description = (
            "The UART debug console is accessible without authentication and exposes "
            "a root shell. An attacker with physical access can dump memory, modify "
            "runtime configuration, and disable security features — all without "
            "any credentials."
        ),
        cvss = CVSSVector(
            attack_vector       = AttackVector.PHYSICAL,
            attack_complexity   = AttackComplexity.LOW,
            privileges_required = PrivilegesRequired.NONE,
            user_interaction    = UserInteraction.NONE,
            scope               = Scope.UNCHANGED,
            confidentiality     = Impact.HIGH,
            integrity           = Impact.HIGH,
            availability        = Impact.LOW,
        ),
        controls = [
            Control(
                id          = "C-014",
                name        = "UART Console Disabled in Production",
                type        = ControlType.PREVENTIVE,
                status      = ControlStatus.NOT_IMPLEMENTED,
                owner       = "Firmware Team",
                description = "Debug console is enabled in production builds via compile-time flag.",
                nis2_article= "Art. 21(2)(i)"
            ),
            Control(
                id          = "C-015",
                name        = "Physical Access Control",
                type        = ControlType.PREVENTIVE,
                status      = ControlStatus.IMPLEMENTED,
                owner       = "Facilities",
                description = "Device installed in locked cabinet — access requires authorisation.",
                nis2_article= "Art. 21(2)(a)"
            ),
        ],
        remediation   = (
            "Disable UART console in production builds using a compile-time flag. "
            "If console access is required for maintenance, implement HMAC-based "
            "challenge-response authentication before granting shell access."
        ),
        nis2_relevant = False,
        category      = RiskCategory.PHYSICAL,
    )
    risks.append(r6)
 

    return risks