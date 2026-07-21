import re

SECURITY_SIGNATURES = {
    "failed_login": "AUTH_BRUTE_FORCE_ATTEMPT",
    "sqli": "CRIT_EXPLOIT_ATTEMPT // SQLi_DETECTION",
    "brute_force": "AUTH_THRESHOLD_EXCEEDED",
    "xss": "PAYLOAD_INJECTION // XSS_CROSS_SITE",
    "path_traversal": "FILE_ACCESS_VIOLATION // LFI_ATTEMPT",
    "broken_access": "IDOR_ACCESS_ATTEMPT // UNAUTHORIZED_RESOURCE",
    "csrf": "CSRF_TOKEN_MISSING // CSRF_ATTACK",
    "rce": "REMOTE_CODE_EXECUTION_ATTEMPT // RCE_DETECTION",
    "ssrf": "SERVER_SIDE_REQUEST_FORGERY // SSRF_DETECTION",
    "xxe": "XML_EXTERNAL_ENTITY_ATTEMPT // XXE_DETECTION",
    "data_exfiltration": "DATA_LEAKAGE_ATTEMPT // EXFILTRATION_DETECTED",
    "malware_upload": "MALICIOUS_FILE_UPLOAD // MALWARE_DETECTED",
    "mass_scan": "RECON_SCAN_DETECTED // MASSIVE_REQUESTS",
    "mass_assignment": "BULK_OPERATION_ATTEMPT // MASS_ASSIGNMENT",
    "config_exposure": "SENSITIVE_CONFIG_EXPOSED // CONFIG_LEAK",
    "clickjacking": "CLICKJACKING_ATTEMPT // UI_REDRESSING",
    "session_hijack": "SESSION_HIJACKING_ATTEMPT // SESSION_COMPROMISE",
    "timing_attack/credential_guessing": "TIMING_ATTACK_DETECTED // CREDENTIAL_GUESSING",
    "success": "SYS_AUTH_GRANTED // ADMIN_SESSION",
}

THREAT_REGEX_MAP = {
    "sqli": re.compile(
        r"('|\b--\b|#|\bUNION\b|\bSELECT\b|\bINSERT\b|\bUPDATE\b|\bDELETE\b|\bOR\s+['\"]?\d+['\"]?\s*=\s*['\"]?\d+)",
        re.IGNORECASE,
    ),
    "xss": re.compile(
        r"(<script.*?>|javascript:|onload=|onerror=|alert\(|confirm\(|<img\s+src|eval\(|setTimeout\()",
        re.IGNORECASE,
    ),
    "path_traversal": re.compile(
        r"(\.\./|\.\.\\|/etc/passwd|/etc/shadow|win\.ini|boot\.ini|\\windows\\|/proc/self/)",
        re.IGNORECASE,
    ),
    "rce": re.compile(
        r"(\bwhoami\b|\bid\b|\bcat\s+|\btac\s+|\bsh\b|\bbash\b|cmd\.exe|powershell|\|\s*\w+|\bcurl\b|\bwget\b|\bnc\s+)",
        re.IGNORECASE,
    ),
    "ssrf": re.compile(
        r"(\b127\.0\.0\.1\b|\blocalhost\b|\b169\.254\.169\.254\b|metadata\.google\.internal|0\.0\.0\.0|::1)",
        re.IGNORECASE,
    ),
    "xxe": re.compile(
        r"(<!ENTITY|<!DOCTYPE|SYSTEM|PUBLIC|%\s*\w+\s*SYSTEM)",
        re.IGNORECASE,
    ),
}


def analyze_payload_signature(raw_input: str) -> str:
    """DEEP PACKET INSPECTION HANDSHAKE."""
    if not raw_input:
        return SECURITY_SIGNATURES["failed_login"]

    for threat_key, regex_pattern in THREAT_REGEX_MAP.items():
        if regex_pattern.search(raw_input):
            return SECURITY_SIGNATURES[threat_key]

    return SECURITY_SIGNATURES["failed_login"]
