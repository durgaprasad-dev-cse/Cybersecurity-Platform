import hashlib
import os
import re
import time
import zipfile

import requests


VIRUSTOTAL_API = "https://www.virustotal.com/api/v3"


def get_api_key():
    """Read VirusTotal API key from an environment variable."""
    return os.getenv("VIRUSTOTAL_API_KEY")

# Permissions that deserve attention during security analysis.
SUSPICIOUS_PERMISSIONS = {
    "android.permission.READ_SMS": "Can read SMS messages.",
    "android.permission.RECEIVE_SMS": "Can receive SMS messages.",
    "android.permission.SEND_SMS": "Can send SMS messages.",
    "android.permission.CALL_PHONE": "Can initiate phone calls.",
    "android.permission.READ_CALL_LOG": "Can read call history.",
    "android.permission.WRITE_CALL_LOG": "Can modify call history.",
    "android.permission.READ_CONTACTS": "Can read contacts.",
    "android.permission.WRITE_CONTACTS": "Can modify contacts.",
    "android.permission.RECORD_AUDIO": "Can record audio.",
    "android.permission.CAMERA": "Can access the camera.",
    "android.permission.ACCESS_FINE_LOCATION": "Can access precise location.",
    "android.permission.ACCESS_COARSE_LOCATION": "Can access approximate location.",
    "android.permission.ACCESS_BACKGROUND_LOCATION": (
        "Can access location while running in the background."
    ),
    "android.permission.READ_EXTERNAL_STORAGE": (
        "Can read external storage."
    ),
    "android.permission.WRITE_EXTERNAL_STORAGE": (
        "Can write to external storage."
    ),
    "android.permission.REQUEST_INSTALL_PACKAGES": (
        "Can request installation of other packages."
    ),
    "android.permission.SYSTEM_ALERT_WINDOW": (
        "Can display windows over other applications."
    ),
    "android.permission.BIND_ACCESSIBILITY_SERVICE": (
        "Can use Android Accessibility Service capabilities."
    ),
    "android.permission.RECEIVE_BOOT_COMPLETED": (
        "Can start after device boot."
    ),
    "android.permission.INTERNET": (
        "Can communicate with Internet services."
    ),
    "android.permission.FOREGROUND_SERVICE": (
        "Can run foreground services."
    ),
}


def get_api_key():
    """Read VirusTotal API key from an environment variable."""

    return os.getenv("VIRUSTOTAL_API_KEY")


def calculate_sha256(file_path):
    """Calculate SHA-256 hash without loading the entire APK into memory."""

    sha256 = hashlib.sha256()

    with open(file_path, "rb") as file:
        while True:
            chunk = file.read(1024 * 1024)

            if not chunk:
                break

            sha256.update(chunk)

    return sha256.hexdigest()


def extract_strings(data):
    """
    Extract readable ASCII and UTF-16LE strings from binary APK data.

    AndroidManifest.xml inside an APK is commonly binary XML, so this
    lightweight analyzer does not claim to fully parse it.
    """

    strings = set()

    ascii_matches = re.findall(rb"[ -~]{4,}", data)

    for item in ascii_matches:
        try:
            strings.add(item.decode("utf-8", errors="ignore"))
        except Exception:
            pass

    utf16_matches = re.findall(
        rb"(?:[\x20-\x7e]\x00){4,}",
        data
    )

    for item in utf16_matches:
        try:
            decoded = item.decode("utf-16le", errors="ignore")
            strings.add(decoded)
        except Exception:
            pass

    return strings


def inspect_apk_structure(file_path):
    """
    Perform local static inspection of an APK.

    This does NOT execute the APK.
    """

    result = {
        "valid_apk": False,
        "size": os.path.getsize(file_path),
        "sha256": calculate_sha256(file_path),
        "file_count": 0,
        "dex_files": [],
        "native_libraries": [],
        "permissions": [],
        "suspicious_permissions": [],
        "suspicious_files": [],
        "urls": [],
        "domains": [],
        "activities": [],
        "services": [],
        "receivers": [],
        "providers": [],
        "risk_score": 0,
        "indicators": [],
    }

    try:
        with zipfile.ZipFile(file_path, "r") as apk:

            bad_zip = apk.testzip()

            if bad_zip is not None:
                result["indicators"].append(
                    f"Corrupted APK archive entry detected: {bad_zip}"
                )
                return result

            result["valid_apk"] = True

            names = apk.namelist()
            result["file_count"] = len(names)

            # -----------------------------
            # DEX files
            # -----------------------------

            for name in names:
                if name.lower().endswith(".dex"):
                    result["dex_files"].append(name)

            if len(result["dex_files"]) > 5:
                result["risk_score"] += 1

                result["indicators"].append(
                    "The APK contains an unusually high number of DEX files."
                )

            # -----------------------------
            # Native libraries
            # -----------------------------

            for name in names:
                lower_name = name.lower()

                if lower_name.startswith("lib/") and lower_name.endswith(".so"):
                    result["native_libraries"].append(name)

            if result["native_libraries"]:
                result["indicators"].append(
                    "Native shared libraries are included in the APK."
                )

            # -----------------------------
            # Suspicious filenames
            # -----------------------------

            suspicious_file_patterns = [
                "frida",
                "xposed",
                "magisk",
                "substrate",
                "payload",
                "meterpreter",
                "credential",
                "keylogger",
                "stealer",
            ]

            for name in names:
                lower_name = name.lower()

                for pattern in suspicious_file_patterns:

                    if pattern in lower_name:

                        result["suspicious_files"].append(name)

                        break

            if result["suspicious_files"]:

                result["risk_score"] += 3

                result["indicators"].append(
                    "Potentially suspicious filenames or security-tool "
                    "related artifacts were found."
                )

            # -----------------------------
            # AndroidManifest.xml
            # -----------------------------

            if "AndroidManifest.xml" not in names:

                result["indicators"].append(
                    "AndroidManifest.xml was not found."
                )

            else:

                manifest_data = apk.read("AndroidManifest.xml")

                strings = extract_strings(manifest_data)

                all_strings = "\n".join(strings)

                # -------------------------
                # Permissions
                # -------------------------

                for permission in SUSPICIOUS_PERMISSIONS:

                    short_name = permission.split(".")[-1]

                    if (
                        permission in all_strings
                        or short_name in all_strings
                    ):

                        result["permissions"].append(permission)

                        if permission in (
                            "android.permission.INTERNET",
                            "android.permission.FOREGROUND_SERVICE",
                            "android.permission.RECEIVE_BOOT_COMPLETED",
                        ):
                            continue

                        description = SUSPICIOUS_PERMISSIONS[
                            permission
                        ]

                        result["suspicious_permissions"].append(
                            {
                                "permission": permission,
                                "description": description,
                            }
                        )

                if result["suspicious_permissions"]:

                    result["risk_score"] += min(
                        len(result["suspicious_permissions"]),
                        6
                    )

                # -------------------------
                # Components
                # -------------------------

                component_patterns = {
                    "activities": "activity",
                    "services": "service",
                    "receivers": "receiver",
                    "providers": "provider",
                }

                for key, component in component_patterns.items():

                    pattern = rf"{component}"

                    if re.search(pattern, all_strings, re.IGNORECASE):

                        result[key].append(
                            f"{component.title()} declarations detected"
                        )

                # -------------------------
                # URLs
                # -------------------------

                urls = re.findall(
                    r"https?://[^\s\"'<>]+",
                    all_strings,
                    re.IGNORECASE
                )

                result["urls"] = sorted(set(urls))

                if result["urls"]:

                    result["indicators"].append(
                        "Network URLs were found inside the APK."
                    )

                # -------------------------
                # Domains
                # -------------------------

                domains = re.findall(
                    r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b",
                    all_strings
                )

                result["domains"] = sorted(set(domains))

                # -------------------------
                # Suspicious keywords
                # -------------------------

                suspicious_keywords = [
                    "keylogger",
                    "password",
                    "credential",
                    "stealer",
                    "ransom",
                    "spy",
                    "backdoor",
                    "payload",
                    "meterpreter",
                    "botnet",
                    "wallet",
                ]

                found_keywords = []

                lower_content = all_strings.lower()

                for keyword in suspicious_keywords:

                    if keyword in lower_content:

                        found_keywords.append(keyword)

                if found_keywords:

                    result["risk_score"] += min(
                        len(found_keywords),
                        4
                    )

                    result["indicators"].append(
                        "Security-sensitive keywords were found in "
                        "the APK's embedded strings."
                    )

        # -----------------------------
        # Final local verdict
        # -----------------------------

        if not result["valid_apk"]:

            result["risk_level"] = "INVALID"

        elif result["risk_score"] >= 7:

            result["risk_level"] = "HIGH RISK"

        elif result["risk_score"] >= 3:

            result["risk_level"] = "SUSPICIOUS"

        else:

            result["risk_level"] = "NO OBVIOUS INDICATORS"

        return result

    except zipfile.BadZipFile:

        result["indicators"].append(
            "The uploaded file is not a valid ZIP/APK archive."
        )

        result["risk_level"] = "INVALID"

        return result

    except Exception as error:

        result["indicators"].append(
            f"Local APK analysis error: {error}"
        )

        result["risk_level"] = "ANALYSIS ERROR"

        return result


def get_virustotal_file_report(sha256):
    """Retrieve an existing VirusTotal file report by SHA-256."""

    api_key = get_api_key()

    if not api_key:
        return None, "VirusTotal API key is not configured."

    url = f"{VIRUSTOTAL_API}/files/{sha256}"

    headers = {
        "x-apikey": api_key
    }

    try:

        response = requests.get(
            url,
            headers=headers,
            timeout=20
        )

        if response.status_code == 200:
            return response.json(), None

        if response.status_code == 404:
            return None, "File hash was not found in VirusTotal."

        if response.status_code == 401:
            return None, "VirusTotal API key is invalid or inactive."

        if response.status_code == 403:
            return None, "VirusTotal API access was denied."

        if response.status_code == 429:
            return None, "VirusTotal API rate limit reached."

        return None, (
            f"VirusTotal returned HTTP {response.status_code}."
        )

    except requests.RequestException as error:

        return None, f"VirusTotal connection error: {error}"


def upload_apk_to_virustotal(file_path):
    """
    Upload an APK to VirusTotal.

    VirusTotal's standard file upload endpoint supports files
    smaller than 32 MB. Larger files require the upload URL flow.
    """

    api_key = get_api_key()

    if not api_key:
        return None, "VirusTotal API key is not configured."

    file_size = os.path.getsize(file_path)

    if file_size > 32 * 1024 * 1024:

        return None, (
            "This APK is larger than 32 MB. "
            "The current implementation intentionally does not "
            "upload large APKs through the standard endpoint."
        )

    url = f"{VIRUSTOTAL_API}/files"

    headers = {
        "x-apikey": api_key
    }

    try:

        with open(file_path, "rb") as file:

            response = requests.post(
                url,
                headers=headers,
                files={
                    "file": (
                        os.path.basename(file_path),
                        file,
                        "application/vnd.android.package-archive"
                    )
                },
                timeout=60
            )

        if response.status_code in (200, 201):

            data = response.json()

            analysis_id = (
                data.get("data", {})
                .get("id")
            )

            return analysis_id, None

        if response.status_code == 401:
            return None, (
                "VirusTotal API key is invalid or inactive."
            )

        if response.status_code == 403:
            return None, (
                "VirusTotal API access was denied."
            )

        if response.status_code == 429:
            return None, (
                "VirusTotal API rate limit reached."
            )

        return None, (
            f"VirusTotal upload failed with HTTP "
            f"{response.status_code}: {response.text[:300]}"
        )

    except requests.RequestException as error:

        return None, f"VirusTotal upload error: {error}"


def get_virustotal_analysis(analysis_id):
    """Retrieve a VirusTotal analysis object."""

    api_key = get_api_key()

    if not api_key:
        return None, "VirusTotal API key is not configured."

    url = f"{VIRUSTOTAL_API}/analyses/{analysis_id}"

    headers = {
        "x-apikey": api_key
    }

    try:

        response = requests.get(
            url,
            headers=headers,
            timeout=20
        )

        if response.status_code == 200:

            return response.json(), None

        if response.status_code == 401:
            return None, (
                "VirusTotal API key is invalid or inactive."
            )

        if response.status_code == 403:
            return None, (
                "VirusTotal API access was denied."
            )

        if response.status_code == 429:
            return None, (
                "VirusTotal API rate limit reached."
            )

        return None, (
            f"VirusTotal analysis request failed "
            f"with HTTP {response.status_code}."
        )

    except requests.RequestException as error:

        return None, f"VirusTotal connection error: {error}"


def wait_for_analysis(analysis_id):
    """
    Wait briefly for VirusTotal analysis.

    We deliberately use a small number of requests because
    the public VirusTotal API has rate limits.
    """

    last_error = None

    for attempt in range(3):

        data, error = get_virustotal_analysis(
            analysis_id
        )

        if error:

            last_error = error

            break

        attributes = (
            data.get("data", {})
            .get("attributes", {})
        )

        status = attributes.get("status")

        if status == "completed":

            return data, None

        if attempt < 2:

            time.sleep(2)

    if last_error:

        return None, last_error

    return None, (
        "VirusTotal analysis is still processing. "
        "The local APK analysis is available below."
    )


def parse_virustotal_file_report(data):
    """Convert VirusTotal's raw file report into UI-friendly data."""

    if not data:

        return None

    attributes = (
        data.get("data", {})
        .get("attributes", {})
    )

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

    detections = []

    for engine_name, result in results.items():

        category = result.get("category")

        if category in ("malicious", "suspicious"):

            detections.append(
                {
                    "engine": engine_name,
                    "category": category,
                    "result": result.get(
                        "result",
                        "Detection"
                    ),
                }
            )

    if malicious > 0:

        verdict = "MALICIOUS"

    elif suspicious > 0:

        verdict = "SUSPICIOUS"

    else:

        verdict = "NO MALICIOUS DETECTION"

    return {
        "verdict": verdict,
        "malicious": malicious,
        "suspicious": suspicious,
        "harmless": harmless,
        "undetected": undetected,
        "timeout": timeout,
        "total_engines": len(results),
        "detections": detections,
        "sha256": attributes.get("sha256"),
        "sha1": attributes.get("sha1"),
        "md5": attributes.get("md5"),
        "file_type": attributes.get("type_description"),
        "file_size": attributes.get("size"),
        "reputation": attributes.get("reputation"),
        "meaningful_name": attributes.get("meaningful_name"),
        "tags": attributes.get("tags", []),
        "popular_threat_classification": (
            attributes.get(
                "popular_threat_classification"
            )
        ),
    }


def analyze_apk(file_path, original_filename):
    """
    Complete APK analysis.

    Flow:
        1. Local static analysis
        2. SHA-256 calculation
        3. Existing VirusTotal hash lookup
        4. Upload if no existing report
        5. Brief analysis polling
        6. VirusTotal result parsing
    """

    local_result = inspect_apk_structure(
        file_path
    )

    local_result["filename"] = original_filename

    sha256 = local_result["sha256"]

    # --------------------------------------------------
    # Try existing VirusTotal report first.
    # This saves an unnecessary upload when VT already
    # knows the APK.
    # --------------------------------------------------

    vt_report, vt_error = get_virustotal_file_report(
        sha256
    )

    if vt_report:

        local_result["virustotal"] = (
            parse_virustotal_file_report(
                vt_report
            )
        )

        local_result["virustotal_message"] = (
            "Existing VirusTotal report found for this "
            "file hash."
        )

        return local_result

    # --------------------------------------------------
    # Upload the APK if no existing report exists.
    # --------------------------------------------------

    analysis_id, upload_error = upload_apk_to_virustotal(
        file_path
    )

    if not analysis_id:

        local_result["virustotal"] = None

        local_result["virustotal_message"] = (
            upload_error
            or vt_error
            or "VirusTotal analysis unavailable."
        )

        return local_result

    # --------------------------------------------------
    # Wait briefly for analysis.
    # --------------------------------------------------

    analysis_data, analysis_error = wait_for_analysis(
        analysis_id
    )

    if analysis_data:

        attributes = (
            analysis_data
            .get("data", {})
            .get("attributes", {})
        )

        results = attributes.get(
            "results"
        )

        stats = attributes.get(
            "stats"
        )

        if results is not None or stats is not None:

            fake_report = {
                "data": {
                    "attributes": {
                        "last_analysis_results": (
                            results or {}
                        ),
                        "last_analysis_stats": (
                            stats or {}
                        ),
                        "sha256": sha256,
                        "size": local_result["size"],
                    }
                }
            }

            local_result["virustotal"] = (
                parse_virustotal_file_report(
                    fake_report
                )
            )

            local_result["virustotal_message"] = (
                "VirusTotal analysis completed."
            )

            return local_result

    # --------------------------------------------------
    # If analysis is still running, try one final
    # existing hash report.
    # --------------------------------------------------

    final_report, final_error = (
        get_virustotal_file_report(
            sha256
        )
    )

    if final_report:

        local_result["virustotal"] = (
            parse_virustotal_file_report(
                final_report
            )
        )

        local_result["virustotal_message"] = (
            "VirusTotal report retrieved after upload."
        )

        return local_result

    # --------------------------------------------------
    # Transparent fallback.
    # --------------------------------------------------

    local_result["virustotal"] = None

    local_result["virustotal_message"] = (
        analysis_error
        or final_error
        or "VirusTotal analysis is still processing."
    )

    return local_result