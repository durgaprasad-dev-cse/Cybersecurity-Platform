import base64
import os
import re
from urllib.parse import urlparse

import requests


# ============================================================
# VIRUSTOTAL CONFIGURATION
# ============================================================

VT_API_URL = "https://www.virustotal.com/api/v3"


# ============================================================
# CREATE VIRUSTOTAL URL ID
# ============================================================

def create_url_id(url):
    """
    Convert a URL into the ID format required by
    the VirusTotal URL report API.
    """

    encoded = base64.urlsafe_b64encode(
        url.encode("utf-8")
    ).decode("utf-8")

    return encoded.rstrip("=")


# ============================================================
# GET VIRUSTOTAL REPORT
# ============================================================

def get_virustotal_report(url):
    """
    Ask VirusTotal whether it already has a report
    for the supplied URL.
    """

    api_key = os.getenv("VIRUSTOTAL_API_KEY")

    if not api_key:
        return {
            "available": False,
            "status": "NO_API_KEY",
            "message": "VirusTotal API key is not configured."
        }

    url_id = create_url_id(url)

    endpoint = f"{VT_API_URL}/urls/{url_id}"

    headers = {
        "x-apikey": api_key
    }

    try:
        response = requests.get(
            endpoint,
            headers=headers,
            timeout=15
        )

        # ----------------------------------------------------
        # Existing VirusTotal report
        # ----------------------------------------------------

        if response.status_code == 200:
            return {
                "available": True,
                "status": "OK",
                "data": response.json()
            }

        # ----------------------------------------------------
        # URL not found in VirusTotal
        # ----------------------------------------------------

        if response.status_code == 404:
            return {
                "available": False,
                "status": "NOT_FOUND",
                "message": "VirusTotal does not currently have a report for this URL."
            }

        # ----------------------------------------------------
        # API rate limit
        # ----------------------------------------------------

        if response.status_code == 429:
            return {
                "available": False,
                "status": "RATE_LIMITED",
                "message": "VirusTotal API rate limit reached."
            }

        # ----------------------------------------------------
        # Invalid API key / permission problem
        # ----------------------------------------------------

        if response.status_code in (401, 403):
            return {
                "available": False,
                "status": "AUTH_ERROR",
                "message": "VirusTotal API key is invalid or does not have permission."
            }

        # ----------------------------------------------------
        # Other API error
        # ----------------------------------------------------

        return {
            "available": False,
            "status": "API_ERROR",
            "message": f"VirusTotal returned HTTP {response.status_code}."
        }

    except requests.exceptions.Timeout:
        return {
            "available": False,
            "status": "TIMEOUT",
            "message": "Connection to VirusTotal timed out."
        }

    except requests.exceptions.RequestException as error:
        return {
            "available": False,
            "status": "REQUEST_ERROR",
            "message": f"VirusTotal request failed: {error}"
        }


# ============================================================
# PARSE VIRUSTOTAL RESULT
# ============================================================

def parse_virustotal_report(data):
    """
    Extract useful information from the VirusTotal API response.
    """

    try:
        attributes = data["data"]["attributes"]

        stats = attributes.get(
            "last_analysis_stats",
            {}
        )

        results = attributes.get(
            "last_analysis_results",
            {}
        )

        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        harmless = stats.get("harmless", 0)
        undetected = stats.get("undetected", 0)
        timeout = stats.get("timeout", 0)

        vendor_detections = []

        for vendor_name, vendor_data in results.items():

            category = vendor_data.get(
                "category",
                ""
            )

            result = vendor_data.get(
                "result"
            )

            if category in ("malicious", "suspicious"):

                vendor_detections.append({
                    "vendor": vendor_name,
                    "category": category,
                    "result": result or "Detection reported"
                })

        # Put malicious detections first
        vendor_detections.sort(
            key=lambda item: (
                0 if item["category"] == "malicious" else 1,
                item["vendor"].lower()
            )
        )

        # ----------------------------------------------------
        # Determine VirusTotal verdict
        # ----------------------------------------------------

        if malicious > 0:
            verdict = "MALICIOUS"

        elif suspicious > 0:
            verdict = "SUSPICIOUS"

        elif harmless > 0:
            verdict = "CLEAN"

        else:
            verdict = "UNDETECTED"

        return {
            "verdict": verdict,
            "malicious": malicious,
            "suspicious": suspicious,
            "harmless": harmless,
            "undetected": undetected,
            "timeout": timeout,
            "vendor_detections": vendor_detections
        }

    except (KeyError, TypeError, AttributeError):
        return {
            "verdict": "UNKNOWN",
            "malicious": 0,
            "suspicious": 0,
            "harmless": 0,
            "undetected": 0,
            "timeout": 0,
            "vendor_detections": []
        }


# ============================================================
# LOCAL URL ANALYSIS
# ============================================================

def local_url_analysis(url):

    parsed = urlparse(url)

    hostname = parsed.hostname or ""

    scheme = parsed.scheme.lower()

    path = parsed.path or ""

    query = parsed.query or ""

    full_url = url.lower()

    indicators = []

    suspicious_keywords = [
        "login",
        "verify",
        "verification",
        "account",
        "password",
        "update",
        "secure",
        "security",
        "confirm",
        "bank",
        "wallet",
        "free",
        "reward",
        "prize",
        "claim"
    ]

    # --------------------------------------------------------
    # HTTPS
    # --------------------------------------------------------

    https = scheme == "https"

    if not https:
        indicators.append(
            "The URL does not use HTTPS."
        )

    # --------------------------------------------------------
    # IP address instead of domain
    # --------------------------------------------------------

    ip_address = False

    try:
        import ipaddress

        if hostname:
            ipaddress.ip_address(hostname)
            ip_address = True

            indicators.append(
                "The URL uses an IP address instead of a normal domain name."
            )

    except ValueError:
        ip_address = False

    # --------------------------------------------------------
    # Suspicious keywords
    # --------------------------------------------------------

    found_keywords = []

    for keyword in suspicious_keywords:

        if keyword in full_url:

            found_keywords.append(keyword)

    if found_keywords:

        indicators.append(
            "Suspicious keywords detected: "
            + ", ".join(found_keywords)
        )

    # --------------------------------------------------------
    # @ symbol
    # --------------------------------------------------------

    if "@" in full_url:

        indicators.append(
            "The URL contains an @ symbol."
        )

    # --------------------------------------------------------
    # Very long URL
    # --------------------------------------------------------

    if len(url) > 150:

        indicators.append(
            "The URL is unusually long."
        )

    # --------------------------------------------------------
    # Encoded characters
    # --------------------------------------------------------

    if "%" in full_url:

        indicators.append(
            "The URL contains encoded characters."
        )

    # --------------------------------------------------------
    # Possible script/code patterns
    # --------------------------------------------------------

    suspicious_patterns = [
        "javascript:",
        "<script",
        "%3cscript",
        "data:text/html",
        "vbscript:",
        "onerror=",
        "onload="
    ]

    found_patterns = []

    for pattern in suspicious_patterns:

        if pattern in full_url:

            found_patterns.append(pattern)

    if found_patterns:

        indicators.append(
            "Potentially dangerous URL patterns detected: "
            + ", ".join(found_patterns)
        )

    # --------------------------------------------------------
    # Many subdomains
    # --------------------------------------------------------

    domain_parts = hostname.split(".")

    if len(domain_parts) >= 5:

        indicators.append(
            "The domain contains an unusually large number of subdomains."
        )

    # --------------------------------------------------------
    # Calculate local risk score
    # --------------------------------------------------------

    risk_score = 0

    if not https:
        risk_score += 1

    if ip_address:
        risk_score += 2

    if found_keywords:
        risk_score += len(found_keywords)

    if "@" in full_url:
        risk_score += 2

    if len(url) > 150:
        risk_score += 1

    if "%" in full_url:
        risk_score += 1

    if found_patterns:
        risk_score += 4

    if len(domain_parts) >= 5:
        risk_score += 2

    if risk_score >= 6:

        local_risk = "HIGH RISK"

    elif risk_score >= 3:

        local_risk = "SUSPICIOUS"

    else:

        local_risk = "LOW RISK"

    return {
        "hostname": hostname,
        "scheme": scheme,
        "https": https,
        "ip_address": ip_address,
        "risk_score": risk_score,
        "local_risk": local_risk,
        "found_keywords": found_keywords,
        "indicators": indicators,
        "path": path,
        "query": query
    }


# ============================================================
# MAIN URL ANALYZER
# ============================================================

def analyze_url(url):

    url = url.strip()

    # --------------------------------------------------------
    # Add HTTPS if the user did not enter a protocol
    # --------------------------------------------------------

    if not re.match(
        r"^https?://",
        url,
        re.IGNORECASE
    ):

        url = "https://" + url

    # --------------------------------------------------------
    # Local analysis
    # --------------------------------------------------------

    local_result = local_url_analysis(url)

    # --------------------------------------------------------
    # VirusTotal analysis
    # --------------------------------------------------------

    vt_response = get_virustotal_report(url)

    # --------------------------------------------------------
    # Base result
    # --------------------------------------------------------

    result = {
        "url": url,

        "domain": local_result["hostname"],

        "protocol": local_result["scheme"],

        "https": local_result["https"],

        "ip_address": local_result["ip_address"],

        "risk_score": local_result["risk_score"],

        "local_risk": local_result["local_risk"],

        "found_keywords": local_result["found_keywords"],

        "indicators": local_result["indicators"],

        "vt_available": vt_response["available"],

        "vt_status": vt_response["status"],

        "vt_message": vt_response.get(
            "message",
            ""
        ),

        "vt_verdict": "UNKNOWN",

        "vt_malicious": 0,

        "vt_suspicious": 0,

        "vt_harmless": 0,

        "vt_undetected": 0,

        "vt_timeout": 0,

        "vendor_detections": []
    }

    # ========================================================
    # VIRUSTOTAL AVAILABLE
    # ========================================================

    if vt_response["available"]:

        vt_result = parse_virustotal_report(
            vt_response["data"]
        )

        result["vt_verdict"] = vt_result["verdict"]

        result["vt_malicious"] = vt_result["malicious"]

        result["vt_suspicious"] = vt_result["suspicious"]

        result["vt_harmless"] = vt_result["harmless"]

        result["vt_undetected"] = vt_result["undetected"]

        result["vt_timeout"] = vt_result["timeout"]

        result["vendor_detections"] = vt_result[
            "vendor_detections"
        ]

        # ----------------------------------------------------
        # VirusTotal says malicious
        # ----------------------------------------------------

        if vt_result["verdict"] == "MALICIOUS":

            result["risk_level"] = "MALICIOUS / PHISHING"

            result["risk_score"] = max(
                10,
                local_result["risk_score"]
            )

            result["recommendation"] = (
                "VirusTotal reports malicious or phishing "
                "detections for this URL. Do not open the "
                "link or enter passwords, OTPs, banking "
                "information, or other personal information."
            )

        # ----------------------------------------------------
        # VirusTotal says suspicious
        # ----------------------------------------------------

        elif vt_result["verdict"] == "SUSPICIOUS":

            result["risk_level"] = "SUSPICIOUS"

            result["risk_score"] = max(
                6,
                local_result["risk_score"]
            )

            result["recommendation"] = (
                "VirusTotal reports suspicious activity "
                "associated with this URL. Avoid opening "
                "the link unless you can verify its source."
            )

        # ----------------------------------------------------
        # VirusTotal says clean
        # ----------------------------------------------------

        elif vt_result["verdict"] == "CLEAN":

            result["risk_level"] = "SAFE / CLEAN"

            result["risk_score"] = 0

            result["recommendation"] = (
                "No malicious or suspicious detections were "
                "reported by the available VirusTotal analysis. "
                "This does not guarantee that the URL is completely safe."
            )

        # ----------------------------------------------------
        # VirusTotal has no clear verdict
        # ----------------------------------------------------

        else:

            result["risk_level"] = "UNDETECTED"

            result["risk_score"] = local_result["risk_score"]

            result["recommendation"] = (
                "VirusTotal did not provide a clear malicious "
                "or suspicious verdict for this URL. The URL "
                "should still be treated cautiously."
            )

    # ========================================================
    # VIRUSTOTAL NOT AVAILABLE
    # ========================================================

    else:

        # ----------------------------------------------------
        # High local risk
        # ----------------------------------------------------

        if local_result["risk_score"] >= 6:

            result["risk_level"] = "HIGH RISK"

            result["recommendation"] = (
                "Strong suspicious indicators were detected "
                "by local URL analysis. VirusTotal reputation "
                "data was not available, so this result is "
                "not a confirmed malicious verdict."
            )

        # ----------------------------------------------------
        # Medium local risk
        # ----------------------------------------------------

        elif local_result["risk_score"] >= 3:

            result["risk_level"] = "SUSPICIOUS"

            result["recommendation"] = (
                "Some suspicious indicators were detected. "
                "VirusTotal reputation data was not available."
            )

        # ----------------------------------------------------
        # Low local risk
        # ----------------------------------------------------

        else:

            result["risk_level"] = "UNKNOWN"

            result["recommendation"] = (
                "No strong indicators were detected by local "
                "analysis, but VirusTotal reputation data was "
                "not available. This does NOT prove that the "
                "URL is safe."
            )

    return result