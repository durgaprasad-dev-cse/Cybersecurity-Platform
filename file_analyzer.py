import hashlib
import os
import zipfile


MAX_FILE_SIZE = 10 * 1024 * 1024  # 10 MB


def calculate_sha256(file_path):
    """Calculate SHA-256 hash of a file."""

    sha256 = hashlib.sha256()

    with open(file_path, "rb") as file:

        while True:

            data = file.read(8192)

            if not data:
                break

            sha256.update(data)

    return sha256.hexdigest()


def analyze_apk(file_path):
    """
    Perform basic static APK analysis.

    The APK is treated as a ZIP archive.
    It is NEVER executed.
    """

    result = {
        "file_type": "APK",
        "sha256": calculate_sha256(file_path),
        "package_files": [],
        "permissions": [],
        "suspicious_indicators": [],
        "risk_score": 0,
        "risk_level": "LOW RISK"
    }

    try:

        with zipfile.ZipFile(file_path, "r") as apk:

            files = apk.namelist()

            result["package_files"] = files[:30]

            # ------------------------------------------
            # Check AndroidManifest.xml
            # ------------------------------------------

            if "AndroidManifest.xml" not in files:

                result["risk_score"] += 2

                result["suspicious_indicators"].append(
                    "AndroidManifest.xml was not found."
                )

            # ------------------------------------------
            # Check for native libraries
            # ------------------------------------------

            native_files = [
                file for file in files
                if file.startswith("lib/")
            ]

            if native_files:

                result["suspicious_indicators"].append(
                    f"{len(native_files)} native library file(s) detected."
                )

            # ------------------------------------------
            # Permission-related strings
            # ------------------------------------------

            manifest_data = b""

            try:
                manifest_data = apk.read("AndroidManifest.xml")

            except Exception:
                pass

            permission_names = [
                b"READ_SMS",
                b"SEND_SMS",
                b"RECEIVE_SMS",
                b"READ_CONTACTS",
                b"RECORD_AUDIO",
                b"ACCESS_FINE_LOCATION",
                b"ACCESS_COARSE_LOCATION",
                b"CAMERA",
                b"READ_PHONE_STATE",
                b"CALL_PHONE",
                b"REQUEST_INSTALL_PACKAGES"
            ]

            for permission in permission_names:

                if permission in manifest_data:

                    permission_text = permission.decode()

                    result["permissions"].append(permission_text)

            # ------------------------------------------
            # Risk indicators
            # ------------------------------------------

            high_risk_permissions = [
                "READ_SMS",
                "SEND_SMS",
                "RECEIVE_SMS",
                "REQUEST_INSTALL_PACKAGES"
            ]

            for permission in result["permissions"]:

                if permission in high_risk_permissions:

                    result["risk_score"] += 2

                    result["suspicious_indicators"].append(
                        f"Potentially sensitive permission detected: {permission}"
                    )

            # ------------------------------------------
            # Suspicious file types
            # ------------------------------------------

            suspicious_extensions = [
                ".dex",
                ".so"
            ]

            for file in files:

                lower_file = file.lower()

                for extension in suspicious_extensions:

                    if lower_file.endswith(extension):

                        # These files are normal in many APKs,
                        # so don't automatically mark them malicious.
                        break

        # ------------------------------------------
        # Final risk level
        # ------------------------------------------

        if result["risk_score"] >= 6:

            result["risk_level"] = "HIGH RISK"

        elif result["risk_score"] >= 3:

            result["risk_level"] = "SUSPICIOUS"

        else:

            result["risk_level"] = "LOW RISK"

    except zipfile.BadZipFile:

        result["risk_level"] = "HIGH RISK"

        result["risk_score"] = 10

        result["suspicious_indicators"].append(
            "The uploaded file does not appear to be a valid APK archive."
        )

    except Exception as error:

        result["risk_level"] = "SUSPICIOUS"

        result["suspicious_indicators"].append(
            f"Static analysis error: {str(error)}"
        )

    return result


def analyze_file(file_path, original_filename):
    """
    Analyze uploaded files without executing them.
    """

    file_size = os.path.getsize(file_path)

    extension = os.path.splitext(
        original_filename
    )[1].lower()

    result = {
        "filename": original_filename,
        "extension": extension,
        "size": file_size,
        "sha256": calculate_sha256(file_path),
        "risk_level": "LOW RISK",
        "risk_score": 0,
        "indicators": []
    }

    # ------------------------------------------
    # Size check
    # ------------------------------------------

    if file_size > MAX_FILE_SIZE:

        result["risk_score"] += 3

        result["indicators"].append(
            "The file exceeds the recommended upload size."
        )

    # ------------------------------------------
    # APK
    # ------------------------------------------

    if extension == ".apk":

        apk_result = analyze_apk(file_path)

        result["apk_analysis"] = apk_result

        result["risk_score"] += apk_result["risk_score"]

        result["indicators"].extend(
            apk_result["suspicious_indicators"]
        )

    # ------------------------------------------
    # Executable files
    # ------------------------------------------

    executable_extensions = [
        ".exe",
        ".dll",
        ".bat",
        ".cmd",
        ".scr",
        ".msi"
    ]

    if extension in executable_extensions:

        result["risk_score"] += 3

        result["indicators"].append(
            "Executable file detected. Do not run files from unknown sources."
        )

    # ------------------------------------------
    # Script files
    # ------------------------------------------

    script_extensions = [
        ".js",
        ".vbs",
        ".ps1",
        ".sh"
    ]

    if extension in script_extensions:

        result["risk_score"] += 2

        result["indicators"].append(
            "Script file detected. Scripts from unknown sources can execute commands."
        )

    # ------------------------------------------
    # Final classification
    # ------------------------------------------

    if result["risk_score"] >= 6:

        result["risk_level"] = "HIGH RISK"

    elif result["risk_score"] >= 3:

        result["risk_level"] = "SUSPICIOUS"

    else:

        result["risk_level"] = "LOW RISK"

    return result