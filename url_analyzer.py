import os
import re
import time
import base64
from urllib.parse import urlparse

import requests


# =========================================================
# VIRUSTOTAL CONFIGURATION
# =========================================================

VT_API_URL = "https://www.virustotal.com/api/v3"

REQUEST_TIMEOUT = 15

# Do not make the user wait too long.
ANALYSIS_WAIT_SECONDS = 20

# Poll every 2 seconds.
POLL_INTERVAL = 2


# =========================================================
# PHISHING KEYWORDS
# =========================================================

PHISHING_KEYWORDS = [
    "login",
    "signin",
    "sign-in",
    "verify",
    "verification",
    "secure",
    "security",
    "account",
    "update",
    "confirm",
    "password",
    "credential",
    "authenticate",
    "authentication",
    "wallet",
    "payment",
    "billing",
    "banking",
    "recover",
    "unlock",
    "suspended",
    "urgent",
    "alert",
    "support",
    "reset"
]


# =========================================================
# COMMONLY IMPERSONATED BRANDS
# =========================================================

COMMON_BRANDS = [
    "paypal",
    "microsoft",
    "office365",
    "outlook",
    "google",
    "gmail",
    "apple",
    "icloud",
    "amazon",
    "facebook",
    "instagram",
    "whatsapp",
    "linkedin",
    "netflix",
    "dropbox",
    "docusign",
    "adobe",
    "github",
    "steam",
    "coinbase",
    "binance"
]


# =========================================================
# URL ID
# =========================================================

def create_url_id(url):

    encoded = base64.urlsafe_b64encode(
        url.encode("utf-8")
    ).decode("utf-8")

    return encoded.rstrip("=")


# =========================================================
# API KEY
# =========================================================

def get_api_key():

    return os.getenv("VIRUSTOTAL_API_KEY")


# =========================================================
# LOCAL URL ANALYSIS
# =========================================================

def local_url_analysis(url):

    indicators = []
    phishing_indicators = []
    suspicious_patterns = []

    score = 0

    parsed = urlparse(url)

    scheme = parsed.scheme.lower()

    hostname = parsed.hostname or ""

    hostname_lower = hostname.lower()

    full_url_lower = url.lower()


    # =====================================================
    # HTTP / HTTPS
    # =====================================================

    if scheme == "https":

        indicators.append(
            "HTTPS is enabled. This encrypts the connection, "
            "but HTTPS alone does not prove that the website is safe."
        )

    elif scheme == "http":

        indicators.append(
            "HTTP is being used. The connection is not encrypted."
        )

        score += 1

    else:

        indicators.append(
            "The URL does not use HTTP or HTTPS."
        )

        score += 3


    # =====================================================
    # IP ADDRESS
    # =====================================================

    ip_pattern = re.compile(
        r"^(?:\d{1,3}\.){3}\d{1,3}$"
    )

    if ip_pattern.match(hostname):

        suspicious_patterns.append(
            "The URL uses an IP address instead of a domain name."
        )

        score += 2


    # =====================================================
    # @ SYMBOL
    # =====================================================

    if "@" in url:

        suspicious_patterns.append(
            "The URL contains an '@' character."
        )

        score += 3


    # =====================================================
    # VERY LONG URL
    # =====================================================

    if len(url) > 150:

        suspicious_patterns.append(
            "The URL is unusually long."
        )

        score += 1


    # =====================================================
    # MANY SUBDOMAINS
    # =====================================================

    if hostname.count(".") >= 4:

        suspicious_patterns.append(
            "The domain contains many subdomain levels."
        )

        score += 2


    # =====================================================
    # MANY ENCODED CHARACTERS
    # =====================================================

    encoded_count = len(
        re.findall(
            r"%[0-9a-fA-F]{2}",
            url
        )
    )

    if encoded_count >= 5:

        suspicious_patterns.append(
            "The URL contains many encoded characters."
        )

        score += 2


    # =====================================================
    # PUNYCODE
    # =====================================================

    if "xn--" in hostname_lower:

        suspicious_patterns.append(
            "The domain uses Punycode/IDN encoding."
        )

        score += 2


    # =====================================================
    # MANY HYPHENS
    # =====================================================

    if hostname.count("-") >= 3:

        suspicious_patterns.append(
            "The domain contains several hyphens."
        )

        score += 1


    # =====================================================
    # PHISHING KEYWORDS
    # =====================================================

    found_keywords = []

    for keyword in PHISHING_KEYWORDS:

        if keyword in full_url_lower:

            found_keywords.append(keyword)

    if found_keywords:

        for keyword in found_keywords[:10]:

            phishing_indicators.append(
                f"Phishing-related keyword detected: '{keyword}'."
            )

        score += min(
            len(found_keywords),
            4
        )


    # =====================================================
    # BRAND IMPERSONATION
    # =====================================================

    detected_brands = []

    for brand in COMMON_BRANDS:

        if brand in hostname_lower:

            detected_brands.append(brand)

    if detected_brands:

        for brand in detected_brands:

            phishing_indicators.append(
                f"The hostname contains the brand name '{brand}'."
            )

        score += 3


    # =====================================================
    # BRAND + PHISHING KEYWORD
    # =====================================================

    if detected_brands and found_keywords:

        phishing_indicators.append(
            "A commonly impersonated brand appears together "
            "with phishing-related terminology."
        )

        score += 3


    # =====================================================
    # CREDENTIAL PATH
    # =====================================================

    credential_terms = [
        "login",
        "signin",
        "verify",
        "password",
        "credential",
        "authenticate",
        "account"
    ]

    credential_matches = []

    for term in credential_terms:

        if term in parsed.path.lower():

            credential_matches.append(term)

    if credential_matches:

        phishing_indicators.append(
            "The URL path contains account or credential-related terms."
        )

        score += 2


    # =====================================================
    # QUERY STRING
    # =====================================================

    if len(parsed.query) > 100:

        suspicious_patterns.append(
            "The URL contains a large query string."
        )

        score += 1


    # =====================================================
    # LOCAL VERDICT
    # =====================================================

    if phishing_indicators:

        if score >= 8:

            verdict = "HIGH RISK"

        else:

            verdict = "SUSPICIOUS"

    elif score >= 6:

        verdict = "SUSPICIOUS"

    elif score >= 3:

        verdict = "LOW RISK"

    else:

        verdict = "NO OBVIOUS RISK"


    return {
        "score": score,
        "verdict": verdict,
        "indicators": indicators,
        "phishing_indicators": phishing_indicators,
        "suspicious_patterns": suspicious_patterns,
        "https": scheme == "https",
        "http": scheme == "http",
        "hostname": hostname
    }


# =========================================================
# SUBMIT URL TO VIRUSTOTAL
# =========================================================

def submit_url_to_virustotal(url):

    api_key = get_api_key()

    if not api_key:

        return {
            "success": False,
            "error": "VirusTotal API key is not configured."
        }


    headers = {
        "accept": "application/json",
        "x-apikey": api_key,
        "content-type": "application/x-www-form-urlencoded"
    }


    try:

        response = requests.post(
            f"{VT_API_URL}/urls",
            headers=headers,
            data={
                "url": url
            },
            timeout=REQUEST_TIMEOUT
        )


        if response.status_code == 200:

            data = response.json()

            analysis_id = (
                data
                .get("data", {})
                .get("id")
            )

            if analysis_id:

                return {
                    "success": True,
                    "analysis_id": analysis_id
                }

            return {
                "success": False,
                "error": "VirusTotal did not return an analysis ID."
            }


        if response.status_code == 401:

            return {
                "success": False,
                "error": (
                    "VirusTotal rejected the API key "
                    "or the account is not active."
                )
            }


        if response.status_code == 403:

            return {
                "success": False,
                "error": (
                    "VirusTotal denied access to this API request."
                )
            }


        if response.status_code == 429:

            return {
                "success": False,
                "error": (
                    "VirusTotal API rate limit reached. "
                    "Please try again later."
                )
            }


        try:

            error_data = response.json()

            error_message = (
                error_data
                .get("error", {})
                .get("message")
            )

        except Exception:

            error_message = None


        return {
            "success": False,
            "error": (
                error_message
                or
                f"VirusTotal returned HTTP {response.status_code}."
            )
        }


    except requests.Timeout:

        return {
            "success": False,
            "error": "VirusTotal request timed out."
        }


    except requests.RequestException as error:

        return {
            "success": False,
            "error": f"VirusTotal connection error: {error}"
        }


# =========================================================
# GET ANALYSIS
# =========================================================

def get_virustotal_analysis(analysis_id):

    api_key = get_api_key()

    if not api_key:

        return {
            "success": False,
            "error": "VirusTotal API key is not configured."
        }


    headers = {
        "accept": "application/json",
        "x-apikey": api_key
    }


    try:

        response = requests.get(
            f"{VT_API_URL}/analyses/{analysis_id}",
            headers=headers,
            timeout=REQUEST_TIMEOUT
        )


        if response.status_code != 200:

            return {
                "success": False,
                "error": (
                    "VirusTotal analysis request returned "
                    f"HTTP {response.status_code}."
                )
            }


        data = response.json()

        attributes = (
            data
            .get("data", {})
            .get("attributes", {})
        )


        return {
            "success": True,
            "status": attributes.get(
                "status",
                "unknown"
            ),
            "stats": attributes.get(
                "stats",
                {}
            ),
            "results": attributes.get(
                "results",
                {}
            )
        }


    except requests.Timeout:

        return {
            "success": False,
            "error": "VirusTotal analysis request timed out."
        }


    except requests.RequestException as error:

        return {
            "success": False,
            "error": f"VirusTotal connection error: {error}"
        }


# =========================================================
# WAIT FOR ANALYSIS
# =========================================================

def wait_for_virustotal_analysis(
    analysis_id
):

    start_time = time.time()

    while True:

        elapsed = (
            time.time() - start_time
        )

        if elapsed >= ANALYSIS_WAIT_SECONDS:

            return {
                "success": False,
                "timeout": True,
                "error": (
                    "VirusTotal analysis is still "
                    "processing."
                )
            }


        result = get_virustotal_analysis(
            analysis_id
        )


        if not result["success"]:

            return result


        status = result["status"]


        # =================================================
        # COMPLETED
        # =================================================

        if status == "completed":

            return result


        # =================================================
        # QUEUED / IN PROGRESS
        # =================================================

        if status in [
            "queued",
            "in-progress"
        ]:

            time.sleep(
                POLL_INTERVAL
            )

            continue


        # =================================================
        # UNKNOWN STATUS
        # =================================================

        return {
            "success": False,
            "timeout": False,
            "error": (
                "VirusTotal returned an unexpected "
                f"analysis status: {status}"
            )
        }


# =========================================================
# GET EXISTING URL REPORT
# =========================================================

def get_virustotal_url_report(url):

    api_key = get_api_key()

    if not api_key:

        return {
            "success": False,
            "error": "VirusTotal API key is not configured."
        }


    url_id = create_url_id(url)


    headers = {
        "accept": "application/json",
        "x-apikey": api_key
    }


    try:

        response = requests.get(
            f"{VT_API_URL}/urls/{url_id}",
            headers=headers,
            timeout=REQUEST_TIMEOUT
        )


        if response.status_code == 200:

            data = response.json()

            attributes = (
                data
                .get("data", {})
                .get("attributes", {})
            )

            return {
                "success": True,
                "attributes": attributes
            }


        if response.status_code == 404:

            return {
                "success": False,
                "error": (
                    "VirusTotal does not have a URL report yet."
                )
            }


        if response.status_code == 401:

            return {
                "success": False,
                "error": (
                    "VirusTotal API authentication failed."
                )
            }


        if response.status_code == 429:

            return {
                "success": False,
                "error": (
                    "VirusTotal API rate limit reached."
                )
            }


        return {
            "success": False,
            "error": (
                f"VirusTotal returned HTTP "
                f"{response.status_code}."
            )
        }


    except requests.Timeout:

        return {
            "success": False,
            "error": (
                "VirusTotal URL report request timed out."
            )
        }


    except requests.RequestException as error:

        return {
            "success": False,
            "error": (
                f"VirusTotal connection error: {error}"
            )
        }


# =========================================================
# PARSE VIRUSTOTAL URL REPORT
# =========================================================

def parse_virustotal_results(
    attributes
):

    stats = attributes.get(
        "last_analysis_stats",
        {}
    )


    results = attributes.get(
        "last_analysis_results",
        {}
    )


    malicious = stats.get(
        "malicious",
        0
    )

    suspicious = stats.get(
        "suspicious",
        0
    )

    harmless = stats.get(
        "harmless",
        0
    )

    undetected = stats.get(
        "undetected",
        0
    )

    timeout = stats.get(
        "timeout",
        0
    )


    vendor_detections = []

    phishing_detections = []

    suspicious_detections = []


    for engine_name, result in results.items():

        category = (
            result
            .get("category", "")
            .lower()
        )


        raw_result = (
            result
            .get("result", "")
            or ""
        ).lower()


        normalized_result = (
            result
            .get("result", "")
            or ""
        )


        detection = {
            "engine": (
                result.get(
                    "engine_name",
                    engine_name
                )
            ),
            "category": category,
            "result": normalized_result
        }


        if category == "malicious":

            vendor_detections.append(
                detection
            )


        elif category == "suspicious":

            suspicious_detections.append(
                detection
            )


        if (
            "phish" in raw_result
            or
            "phishing" in raw_result
        ):

            phishing_detections.append(
                detection
            )


    # =====================================================
    # VERDICT
    # =====================================================

    if malicious > 0:

        verdict = "MALICIOUS"

    elif suspicious > 0:

        verdict = "SUSPICIOUS"

    elif harmless > 0:

        verdict = "CLEAN"

    else:

        verdict = "UNDETECTED"


    # =====================================================
    # PHISHING VERDICT
    # =====================================================

    if phishing_detections:

        phishing_verdict = (
            "PHISHING DETECTED"
        )

    elif malicious > 0:

        phishing_verdict = (
            "POSSIBLE PHISHING / MALICIOUS"
        )

    elif suspicious > 0:

        phishing_verdict = (
            "POSSIBLE PHISHING"
        )

    else:

        phishing_verdict = (
            "NO PHISHING DETECTION"
        )


    return {

        "verdict": verdict,

        "phishing_verdict":
            phishing_verdict,

        "malicious":
            malicious,

        "suspicious":
            suspicious,

        "harmless":
            harmless,

        "undetected":
            undetected,

        "timeout":
            timeout,

        "total_detections":
            malicious + suspicious,

        "vendor_detections":
            vendor_detections,

        "phishing_detections":
            phishing_detections,

        "suspicious_detections":
            suspicious_detections,

        "final_url":
            attributes.get(
                "last_final_url"
            ),

        "redirect_chain":
            attributes.get(
                "redirection_chain",
                []
            ),

        "http_response_code":
            attributes.get(
                "last_http_response_code"
            ),

        "categories":
            attributes.get(
                "categories",
                {}
            ),

        "targeted_brand":
            attributes.get(
                "targeted_brand",
                {}
            ),

        "title":
            attributes.get(
                "title"
            )
    }


# =========================================================
# ANALYZE URL
# =========================================================

def analyze_url(url):

    url = url.strip()


    # =====================================================
    # VALIDATION
    # =====================================================

    if not url:

        return {
            "risk_level": "UNKNOWN",
            "risk_score": 0,
            "verdict": "UNKNOWN",
            "phishing_verdict": "UNKNOWN",
            "url": "",
            "message": "Please enter a URL."
        }


    parsed = urlparse(url)


    if parsed.scheme.lower() not in [
        "http",
        "https"
    ]:

        return {
            "risk_level": "UNKNOWN",
            "risk_score": 0,
            "verdict": "INVALID URL",
            "phishing_verdict": "UNKNOWN",
            "url": url,
            "message": (
                "Enter a complete URL beginning "
                "with http:// or https://."
            )
        }


    if not parsed.hostname:

        return {
            "risk_level": "UNKNOWN",
            "risk_score": 0,
            "verdict": "INVALID URL",
            "phishing_verdict": "UNKNOWN",
            "url": url,
            "message": (
                "The URL does not contain a valid hostname."
            )
        }


    # =====================================================
    # LOCAL ANALYSIS
    # =====================================================

    local_result = local_url_analysis(
        url
    )


    # =====================================================
    # INITIAL RESULT
    # =====================================================

    result = {

        "url": url,

        "risk_level": "UNKNOWN",

        "risk_score":
            local_result["score"],

        "verdict": "UNKNOWN",

        "phishing_verdict":
            "NOT DETERMINED",

        "local_verdict":
            local_result["verdict"],

        "https":
            local_result["https"],

        "http":
            local_result["http"],

        "hostname":
            local_result["hostname"],

        "indicators":
            local_result["indicators"],

        "phishing_indicators":
            local_result["phishing_indicators"],

        "suspicious_patterns":
            local_result["suspicious_patterns"],

        "virustotal_available":
            False,

        "virustotal_error":
            None,

        "malicious": 0,

        "suspicious": 0,

        "harmless": 0,

        "undetected": 0,

        "timeout": 0,

        "total_detections": 0,

        "vendor_detections": [],

        "phishing_detections": [],

        "suspicious_detections": [],

        "final_url": None,

        "redirect_chain": [],

        "http_response_code": None,

        "categories": {},

        "targeted_brand": {},

        "title": None,

        "message": ""
    }


    # =====================================================
    # VIRUSTOTAL
    # =====================================================

    api_key = get_api_key()


    if not api_key:

        result["virustotal_error"] = (
            "VirusTotal API key is not configured."
        )


    else:

        # =================================================
        # STEP 1: SUBMIT URL
        # =================================================

        submission = submit_url_to_virustotal(
            url
        )


        if submission["success"]:

            analysis_id = (
                submission["analysis_id"]
            )


            # =============================================
            # STEP 2: WAIT FOR ANALYSIS
            # =============================================

            analysis = wait_for_virustotal_analysis(
                analysis_id
            )


            if analysis["success"]:

                # =========================================
                # STEP 3: GET URL REPORT
                # =========================================

                report = get_virustotal_url_report(
                    url
                )


                if report["success"]:

                    vt_result = parse_virustotal_results(
                        report["attributes"]
                    )


                    result.update(
                        vt_result
                    )


                    result[
                        "virustotal_available"
                    ] = True


                else:

                    # -------------------------------------
                    # IMPORTANT FALLBACK
                    # -------------------------------------

                    # If analysis completed but the URL
                    # report is not immediately available,
                    # use the analysis statistics/results.

                    if (
                        analysis.get("stats")
                        or
                        analysis.get("results")
                    ):

                        temporary_attributes = {

                            "last_analysis_stats":
                                analysis.get(
                                    "stats",
                                    {}
                                ),

                            "last_analysis_results":
                                analysis.get(
                                    "results",
                                    {}
                                )
                        }


                        vt_result = parse_virustotal_results(
                            temporary_attributes
                        )


                        result.update(
                            vt_result
                        )


                        result[
                            "virustotal_available"
                        ] = True


                    else:

                        result[
                            "virustotal_error"
                        ] = report["error"]


            else:

                # -----------------------------------------
                # ANALYSIS STILL PROCESSING
                # -----------------------------------------

                # Instead of immediately showing
                # "VirusTotal unavailable", try to obtain
                # the existing URL report.

                existing_report = (
                    get_virustotal_url_report(
                        url
                    )
                )


                if existing_report["success"]:

                    vt_result = parse_virustotal_results(
                        existing_report["attributes"]
                    )


                    result.update(
                        vt_result
                    )


                    result[
                        "virustotal_available"
                    ] = True


                else:

                    result[
                        "virustotal_error"
                    ] = (
                        "VirusTotal submitted the URL, "
                        "but the analysis is still processing. "
                        "Local analysis is shown below."
                    )


        else:

            # ---------------------------------------------
            # SUBMISSION FAILED
            # ---------------------------------------------

            # Try existing VirusTotal report before
            # declaring VirusTotal unavailable.

            existing_report = (
                get_virustotal_url_report(
                    url
                )
            )


            if existing_report["success"]:

                vt_result = parse_virustotal_results(
                    existing_report["attributes"]
                )


                result.update(
                    vt_result
                )


                result[
                    "virustotal_available"
                ] = True


            else:

                result[
                    "virustotal_error"
                ] = submission["error"]


    # =====================================================
    # FINAL CLASSIFICATION
    # =====================================================

    if result["virustotal_available"]:

        vt_verdict = result["verdict"]


        if vt_verdict == "MALICIOUS":

            result["risk_level"] = "HIGH RISK"

            result["message"] = (
                "VirusTotal reports malicious detections "
                "for this URL. Do not open the link or "
                "enter credentials."
            )


        elif vt_verdict == "SUSPICIOUS":

            result["risk_level"] = "SUSPICIOUS"

            result["message"] = (
                "VirusTotal reports suspicious activity "
                "associated with this URL."
            )


        elif vt_verdict == "CLEAN":

            if local_result["verdict"] in [
                "HIGH RISK",
                "SUSPICIOUS"
            ]:

                result["risk_level"] = "SUSPICIOUS"

                result["message"] = (
                    "VirusTotal did not report malicious "
                    "detections, but local analysis found "
                    "suspicious characteristics. "
                    "Do not treat this URL as automatically safe."
                )

            else:

                result["risk_level"] = "LOW RISK"

                result["message"] = (
                    "VirusTotal did not report malicious "
                    "detections in the available results. "
                    "This does not guarantee that the URL "
                    "is completely safe."
                )


        else:

            result["risk_level"] = "UNKNOWN"

            result["message"] = (
                "VirusTotal did not provide a definitive "
                "malicious or clean verdict."
            )


    else:

        # =================================================
        # LOCAL FALLBACK
        # =================================================

        local_verdict = local_result["verdict"]


        if local_verdict == "HIGH RISK":

            result["risk_level"] = "HIGH RISK"

            result["verdict"] = "LOCAL HIGH RISK"

            result["message"] = (
                "VirusTotal was unavailable, but local "
                "analysis detected several suspicious "
                "characteristics."
            )


        elif local_verdict == "SUSPICIOUS":

            result["risk_level"] = "SUSPICIOUS"

            result["verdict"] = "LOCAL SUSPICIOUS"

            result["message"] = (
                "VirusTotal is still processing the URL. "
                "Local analysis found suspicious characteristics."
            )


        elif local_verdict == "LOW RISK":

            result["risk_level"] = "LOW RISK"

            result["verdict"] = "LOCAL LOW RISK"

            result["message"] = (
                "VirusTotal is still processing the URL. "
                "Local analysis did not find major suspicious indicators."
            )


        else:

            result["risk_level"] = "UNKNOWN"

            result["verdict"] = "UNKNOWN"

            result["message"] = (
                "VirusTotal is still processing the URL and "
                "local analysis found no obvious malicious indicators. "
                "This does not guarantee that the URL is safe."
            )


    # =====================================================
    # FINAL PHISHING ASSESSMENT
    # =====================================================

    if result["phishing_detections"]:

        result["phishing_verdict"] = (
            "PHISHING DETECTED"
        )


    elif (
        result["virustotal_available"]
        and
        result["verdict"] == "MALICIOUS"
    ):

        result["phishing_verdict"] = (
            "POSSIBLE PHISHING / MALICIOUS"
        )


    elif result["phishing_indicators"]:

        result["phishing_verdict"] = (
            "POSSIBLE PHISHING"
        )


    elif result["virustotal_available"]:

        result["phishing_verdict"] = (
            "NO PHISHING DETECTION"
        )


    else:

        result["phishing_verdict"] = (
            "NOT DETERMINED"
        )


    return result