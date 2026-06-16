import os
import sys
import time
import glob
import shutil
import subprocess
import json
import signal
import hashlib
import base64
import re
import pandas as pd
import zipfile
import numpy as np
from filelock import FileLock, Timeout
import logging
from logging.handlers import RotatingFileHandler
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from datetime import datetime, timezone

# === USER CONFIGURATION ===
GCP_PROJECT_ID = "nld-data-pltf-acquiring-prod"  # change dev/qa/prod as needed
GCLOUD_PATH = r"D:\Tools\google-cloud-sdk-517.0.0-windows-x86_64-bundled-python\google-cloud-sdk\bin\gcloud.cmd"
DIRECTORY_PATH = "//swnas-01.core.zone/pwcdataswan$/SrcFiles/INPUT/TDS"


# <<< MODIFIED: Renamed variables for clarity and consistency
PROCESSED_FILES_DIRECTORY = f"{DIRECTORY_PATH}/PROCESSED"
IN_DIRECTORY = f"{DIRECTORY_PATH}/IN"
ARCHIVE_DIRECTORY = f"{DIRECTORY_PATH}/temp_processing"  # New temporary folder
STAGING_DIRECTORY = f"{DIRECTORY_PATH}/staging_files"

ie_archive_folder = f"{DIRECTORY_PATH}/ictf_files_archive"
error_folder = f"{DIRECTORY_PATH}/error_files"
service_account_key = r"D:\Tools\google-cloud-sdk-517.0.0-windows-x86_64-bundled-python\google-cloud-sdk\bin\config_files_cloudsetup_authent\nld-data-pltf-acquiring-prod-5abd33991c30.json"
kms_key_name = "projects/nld-data-pltf-acquiring-prod/locations/europe/keyRings/prod_swan_inbound_encryption-PhwwT/cryptoKeys/prod_swan_inbound_encryption_kms_key"

DEFAULT_GCS_BUCKET = f"gs://{GCP_PROJECT_ID}-swan-inbound/in/swan-inbound"
RE_PROCESSING_GCS_FOLDER = f"gs://{GCP_PROJECT_ID}-swan-inbound/in/re_processing_files"
RE_PROCESSING_CHECK_INTERVAL_SECONDS = 10 * 60  # 10 minutes
critical_error_log_name = "ie-uploader-activity"
activity_log_name = "ie-uploader-activity"

IE_ACQUIRER_IDS = {"00673072009", "00673005005", "00673002008"}

is_ctrlc_exit = False
gcloud_auth_success = False
FILE_STABILITY_WAIT_SECONDS = 300 # Wait up to 5 minutes for a file to become stable
HEARTBEAT_INTERVAL_SECONDS = 300  # 5 minutes
STAGING_RETRY_INTERVAL_SECONDS = 20 * 60  # 20 minutes
STAGING_MAX_RETRIES = 10
RETRY_CONDITION_MESSAGE = "The file will only be retried after a new/updated timestamp is detected."
MANUAL_REVIEW_MESSAGE = "Review the source file for data/lock issues, then update its timestamp to trigger retry."
GCP_OPERATION_MAX_RETRIES = 10
GCP_RETRY_DELAY_SECONDS = 60

# Logging setup
log_file_path = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "ie-uploader.log"
)
logger = logging.getLogger("IEUploaderLogger")
logger.setLevel(logging.DEBUG)
file_handler = RotatingFileHandler(
    log_file_path, maxBytes=5 * 1024 * 1024, backupCount=3, encoding="utf-8"
)
formatter = logging.Formatter("%(asctime)s [%(levelname)s] [%(funcName)s] - %(message)s")
file_handler.setFormatter(formatter)
logger.addHandler(file_handler)
console_handler = logging.StreamHandler()
console_handler.setFormatter(formatter)
logger.addHandler(console_handler)


def log_and_print(
    message: str, level="info"
):  # This function is kept for compatibility with existing calls.
    getattr(logger, level.lower(), logger.info)(message)


def ensure_directory_exists(path):
    if not os.path.exists(path):
        log_and_print(f"Creating directory at {path}", "info")
        os.makedirs(path, exist_ok=True)


ensure_directory_exists(PROCESSED_FILES_DIRECTORY)
ensure_directory_exists(IN_DIRECTORY)
ensure_directory_exists(error_folder)
ensure_directory_exists(ie_archive_folder)
ensure_directory_exists(ARCHIVE_DIRECTORY)  # Ensure the new temp folder exists
ensure_directory_exists(STAGING_DIRECTORY)


def authenticate_gcloud(force_reauthenticate=False):
    global gcloud_auth_success
    if gcloud_auth_success and not force_reauthenticate:
        logger.debug("gcloud authentication already active. Skipping re-authentication.")
        return True

    logger.info("Authenticating with gcloud service account...")
    if not os.path.exists(service_account_key):
        raise Exception(f"Key file not found: {service_account_key}")
    # <<< FIX: Use 'cmd /c' to run the .cmd file and pass arguments as a list
    command = [
        'cmd', '/c',
        GCLOUD_PATH,
        "auth",
        "activate-service-account",
        f"--key-file={service_account_key}",
    ]
    result = subprocess.run(
        command,
        capture_output=True,
    )
    if result.returncode != 0:
        stderr_msg = result.stderr.decode().strip()
        logger.error(f"gcloud auth error: {stderr_msg}")
        gcloud_auth_success = False
        raise Exception("Failed to authenticate with gcloud. Exiting.")
    logger.info("gcloud authentication successful.")
    gcloud_auth_success = True
    return True


def wait_file_ready(file_path, total_wait_seconds=FILE_STABILITY_WAIT_SECONDS, check_interval_seconds=2):
    """
    Waits for a file to be stable (size not changing and not locked) for a specified duration.
    """
    start_time = time.time()
    last_size = -1
    
    while time.time() - start_time < total_wait_seconds:
        try:
            if not os.path.exists(file_path):
                logger.warning(f"File '{os.path.basename(file_path)}' no longer exists. Skipping.")
                return False, "File disappeared"

            current_size = os.path.getsize(file_path)
            
            if current_size == last_size:
                # Size is stable, now check if it's locked
                try:
                    with open(file_path, 'rb'):
                        pass # Successfully opened, so it's not locked
                    
                    if current_size > 0:
                        logger.debug(f"File '{os.path.basename(file_path)}' is stable, unlocked, and not empty.")
                        return True, "File is stable"
                    else:
                        logger.warning(f"File '{os.path.basename(file_path)}' is stable but empty.")
                        return False, "File is empty"
                except (IOError, PermissionError):
                    logger.debug(f"File '{os.path.basename(file_path)}' size is stable but file is locked. Waiting...")
            
            last_size = current_size
            time.sleep(check_interval_seconds)

        except FileNotFoundError:
            logger.warning(f"File '{os.path.basename(file_path)}' was removed during stability check. Skipping.")
            return False, "File disappeared"

    logger.warning(f"File '{os.path.basename(file_path)}' did not stabilize within the {total_wait_seconds} second wait period.")
    return False, "File is unstable or locked"


def get_file_md5_base64(file_path):
    try:
        hash_md5 = hashlib.md5()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_md5.update(chunk)
        md5_b64 = base64.b64encode(hash_md5.digest()).decode()
        logger.debug(f"MD5 (base64) for '{file_path}': {md5_b64}")
        return md5_b64
    except Exception as e:
        logger.error(
            f"Could not compute MD5 hash for '{file_path}'. Error: {str(e)}",
            exc_info=True,
        )
        return None


def build_unique_path(directory, file_name):
    base_name, ext = os.path.splitext(file_name)
    candidate = os.path.join(directory, file_name)
    if not os.path.exists(candidate):
        return candidate

    timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
    suffix = 1
    while True:
        candidate_name = f"{base_name}_{timestamp}_{suffix}{ext}"
        candidate = os.path.join(directory, candidate_name)
        if not os.path.exists(candidate):
            return candidate
        suffix += 1


def _move_file_to_directory(file_path, destination_directory, action):
    file_name = os.path.basename(file_path)
    if not os.path.exists(file_path):
        logger.warning(f"Skip move for '{file_name}'. File no longer exists. Action: {action}")
        return None

    destination_path = build_unique_path(destination_directory, file_name)
    shutil.move(file_path, destination_path)
    logger.info(f"Moved '{file_name}' to '{destination_path}'. Action: {action}")
    return destination_path


def safe_remove_file(file_path):
    if not file_path or not os.path.exists(file_path):
        return
    try:
        os.remove(file_path)
    except Exception as e:
        logger.warning(f"Failed to remove temporary file '{file_path}': {e}", exc_info=True)


def move_to_error_folder(file_path, reason):
    file_name = os.path.basename(file_path)
    try:
        dest_path = _move_file_to_directory(file_path, error_folder, f"error | {reason}")
        if not dest_path:
            return

        send_cloud_log_entry(
            severity="ERROR",
            message=f"'{file_name}' moved to error folder. Reason: {reason}",
            log_name=critical_error_log_name,
            data={
                "event_type": "FileMoveToError",
                "file": file_name,
                "reason": reason,
                "destination_path": dest_path,
            },
        )
    except Exception as e:
        logger.critical(
            f"Failed to move '{file_name}' to error folder: {str(e)}", exc_info=True
        )

def move_to_staging_folder(file_path, reason):
    """Moves a file to the staging folder for a later retry attempt."""
    file_name = os.path.basename(file_path)
    try:
        is_already_in_staging = False
        # samefile handles symlinks and path aliases when both paths exist;
        # normalized absolute path comparison is used as a safe fallback.
        try:
            if os.path.exists(file_path) and os.path.exists(STAGING_DIRECTORY):
                is_already_in_staging = os.path.samefile(os.path.dirname(file_path), STAGING_DIRECTORY)
        except OSError:
            pass
        if not is_already_in_staging:
            staging_dir_abs = os.path.normpath(os.path.abspath(STAGING_DIRECTORY))
            file_dir_abs = os.path.normpath(os.path.abspath(os.path.dirname(file_path)))
            is_already_in_staging = (file_dir_abs == staging_dir_abs)

        if is_already_in_staging:
            logger.info(f"File '{file_name}' is already in staging. Keeping it for retry. Reason: {reason}")
            send_cloud_log_entry(
                severity="WARNING",
                message=f"File '{file_name}' remains in staging for retry. Reason: {reason}",
                log_name=activity_log_name,
                data={
                    "event_type": "FileRetainedInStaging",
                    "file": file_name,
                    "reason": reason,
                    "destination_path": file_path,
                },
            )
            return file_path

        dest_path = _move_file_to_directory(file_path, STAGING_DIRECTORY, f"staging | {reason}")
        if not dest_path:
            return

        send_cloud_log_entry(
            severity="WARNING",
            message=f"File '{file_name}' was moved to the staging folder for retry. Reason: {reason}",
            log_name=activity_log_name,
            data={
                "event_type": "FileMoveToStaging",
                "file": file_name,
                "reason": reason,
                "destination_path": dest_path,
            },
        )
    except Exception as e:
        logger.critical(
            f"CRITICAL: Failed to move '{file_name}' to staging folder. It will be retried from the source folder. Error: {str(e)}",
            exc_info=True,
        )


def move_to_archive_folder(file_path, reason):
    file_name = os.path.basename(file_path)
    try:
        destination = _move_file_to_directory(file_path, ie_archive_folder, f"archive | {reason}")
        if not destination:
            logger.warning(f"Skip archive move for '{file_name}'. File no longer exists.")
        return destination
    except Exception as e:
        logger.error(f"Failed to move '{file_name}' to archive folder. Reason: {reason}. Error: {e}", exc_info=True)
        return None


def find_archived_file_match(file_name):
    """
    Return an archived file path when a duplicate is found by name.

    Parameters:
        file_name (str): File name to search for in the archive folder.

    Returns:
        str | None: The matched archived file path (exact or collision-variant)
        if found; otherwise None.

    Checks exact file name first. If not found, checks collision-safe variants
    generated by this script (e.g. `name_YYYYMMDDHHMMSS_1.ext`).
    """
    if not file_name:
        return None
    if not os.path.isdir(ie_archive_folder):
        logger.warning(f"Archive directory does not exist or is inaccessible: '{ie_archive_folder}'")
        return None

    exact_path = os.path.join(ie_archive_folder, file_name)
    if os.path.exists(exact_path):
        return exact_path

    base_name, ext = os.path.splitext(file_name)
    pattern = os.path.join(ie_archive_folder, f"{base_name}_*{ext}")
    matches = sorted(glob.glob(pattern))
    if matches:
        return matches[0]
    return None


def is_authentication_error(error_text):
    text = (error_text or "").lower()
    auth_keywords = (
        "unauthenticated",
        "authentication",
        "permission denied",
        "invalid_grant",
        "not have permission",
        "access denied",
        "forbidden",
        "account disabled",
        "credentials",
        "failed to retrieve token",
        "request had insufficient authentication scopes",
    )
    return any(keyword in text for keyword in auth_keywords)

def send_cloud_log_entry(
    severity="INFO", message="", log_name="ie-uploader-activity", data=None
):
    max_retries = GCP_OPERATION_MAX_RETRIES
    base_delay_seconds = GCP_RETRY_DELAY_SECONDS

    if data is None:
        data = {}
    payload = {
        "severity": severity,
        "message": message,
        "script_name": os.path.abspath(sys.argv[0]),
        "host": os.environ.get("COMPUTERNAME", ""),
        "watch_folder": PROCESSED_FILES_DIRECTORY,
        "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }
    payload.update(data)
    # The payload is a single string argument for the --json-payload flag.
    # json.dumps ensures it's a valid JSON string.
    json_payload_str = json.dumps(payload)

    for attempt in range(max_retries):
        try:
            # Pass the JSON payload as a separate argument to avoid shell quoting issues on Windows.
            command = [
                'cmd', '/c',
                GCLOUD_PATH,
                "logging",
                "write",
                log_name,
                json_payload_str,
                f"--project={GCP_PROJECT_ID}",
            ]
            result = subprocess.run(
                command,
                capture_output=True,
                check=False, # Explicitly set to False to handle errors manually
            )
            if result.returncode == 0:
                logger.debug(
                    f"Sent log to Cloud Logging (logName: {log_name}, severity: {severity})."
                )
                return # Success, exit the function
            else:
                # Raise an exception to be caught and retried
                raise Exception(
                    f"gcloud logging write command failed with exit code {result.returncode}: {result.stderr.decode().strip()}"
                )
        except Exception as e:
            logger.warning(
                f"Attempt {attempt + 1}/{max_retries} to send log failed. Error: {str(e)}"
            )
            if attempt < max_retries - 1:
                delay = base_delay_seconds * (2 ** attempt) # Exponential backoff
                logger.info(f"Retrying in {delay} seconds...")
                time.sleep(delay)
            else:
                logger.critical(f"Failed to send log entry to Google Cloud after {max_retries} attempts.", exc_info=True)
                # The original exception 'e' is available here if you need to re-raise it or handle it further.


def encrypt_upload_and_archive(file_path):
    file_name = os.path.basename(file_path)
    lock_path = file_path + ".lock"
    lock = FileLock(lock_path, timeout=1)

    try:
        with lock:
            return _process_locked_encrypt_file(file_path)
    except Timeout:
        logger.debug(f"File '{file_name}' is locked by another process. Skipping.")
        return False

def _process_locked_encrypt_file(file_path):
    max_retries = GCP_OPERATION_MAX_RETRIES
    retry_delay_seconds = GCP_RETRY_DELAY_SECONDS
    file_name = os.path.basename(file_path)

    # Determine the GCS object name based on the output file naming convention
    if "_" in file_name:
        gcs_object_name = file_name.split("_", 1)[-1]
    else:
        gcs_object_name = file_name
    gcs_path = f"{DEFAULT_GCS_BUCKET}/{gcs_object_name}"
    log_name = activity_log_name
    alert_name = "FileEncryptedUploadSuccess"
    logger.info(f"Starting encryption and upload for '{file_name}'")

    archived_zip_match = find_archived_file_match(file_name)
    if archived_zip_match:
        logger.warning(
            f"Duplicate detected before upload for '{file_name}'. "
            f"archived_zip_match='{archived_zip_match}'. "
            "Skipping GCS upload."
        )
        archive_path = move_to_archive_folder(file_path, "Duplicate detected before upload; skipped GCS upload")
        send_cloud_log_entry(
            severity="WARNING",
            message=f"Skipped upload for duplicate file '{file_name}' because it already exists in archive.",
            log_name=activity_log_name,
            data={
                "event_type": "DuplicateUploadSkipped",
                "file": file_name,
                "archive_path": archive_path,
                "archived_zip_match": archived_zip_match,
            },
        )
        return True

    # --- NEW: Retry loop for file stability check ---
    max_stability_retries = 5
    is_ready = False
    reason = "Unknown"
    encrypted_output_file_path = None
    last_exception = None
    timed_out = False
    for stability_attempt in range(max_stability_retries):
        logger.info(f"Checking file stability for '{file_name}' (Attempt {stability_attempt + 1}/{max_stability_retries})...")
        is_ready, reason = wait_file_ready(file_path)
        if is_ready:
            break # File is ready, exit the loop
        elif reason == "File disappeared" or reason == "File is empty":
            break # No point in retrying if file is gone or empty
        if stability_attempt < max_stability_retries - 1:
            logger.info(f"Will re-check stability for '{file_name}' in the next main loop cycle.")
    
    if not is_ready:
        logger.error(f"FAILURE: File '{file_name}' was not ready after {max_stability_retries} attempts. Reason: {reason}. Moving to error folder.")
        move_to_error_folder(file_path, f"File not stable after {max_stability_retries} attempts ({max_stability_retries * (FILE_STABILITY_WAIT_SECONDS/60):.0f} mins total). Reason: {reason}")
        return False

    for attempt in range(max_retries):
        # --- FIX: Create the temporary encrypted file in the ARCHIVE_DIRECTORY ---
        # This prevents the script from re-processing its own output.
        encrypted_output_file_name = file_name + ".enc"
        encrypted_output_file_path = os.path.join(ARCHIVE_DIRECTORY, encrypted_output_file_name)
        try:
            # 1. Generate a new Data Encryption Key (DEK) for each file.
            # --- Envelope Encryption (DEK) Implementation ---
            dek = AESGCM.generate_key(bit_length=256)
            logger.info(f"Generated a 256-bit DEK for '{file_name}'.")

            # 2. Encrypt (wrap) the DEK using the Cloud KMS key.
            logger.info(
                f"Attempt {attempt + 1}/{max_retries}: Wrapping the DEK for '{file_name}' using Cloud KMS..."
            )
            key_parts = kms_key_name.split('/')
            kms_project = key_parts[1]
            kms_location = key_parts[3]
            kms_keyring = key_parts[5]
            kms_key = key_parts[7]

            wrap_dek_command = [
                'cmd', '/c', GCLOUD_PATH, "kms", "encrypt",
                f"--project={kms_project}",
                f"--location={kms_location}",
                f"--keyring={kms_keyring}",
                f"--key={kms_key}",
                "--plaintext-file=-",      # Read plaintext from stdin
                "--ciphertext-file=-",     # Write ciphertext to stdout
            ]
            wrap_proc = subprocess.run(
                wrap_dek_command,
                input=dek,
                capture_output=True,
                check=True
            )
            wrapped_dek = wrap_proc.stdout
            logger.info(f"Successfully wrapped the DEK for '{file_name}'.")

            # 3. Encrypt the actual file data locally using the DEK.
            logger.info(f"Encrypting file content of '{file_name}' locally with the DEK.")
            with open(file_path, "rb") as f_in:
                plaintext_data = f_in.read()

            aes_gcm = AESGCM(dek)
            nonce = os.urandom(12)  # GCM recommended nonce size
            encrypted_data = aes_gcm.encrypt(nonce, plaintext_data, None)

            # 4. Write the combined encrypted file (wrapped_dek_len + wrapped_dek + nonce + encrypted_data).
            with open(encrypted_output_file_path, "wb") as f_out:
                f_out.write(len(wrapped_dek).to_bytes(4, 'big'))
                f_out.write(wrapped_dek)
                f_out.write(nonce)
                f_out.write(encrypted_data)
            logger.info(f"Created combined encrypted file: '{os.path.basename(encrypted_output_file_path)}'.")

            # 5. Upload the final encrypted file to GCS.
            logger.info(f"Uploading encrypted file '{os.path.basename(encrypted_output_file_path)}' to GCS path '{gcs_path}'...")
            upload_command = [
                'cmd', '/c', GCLOUD_PATH, "storage", "cp", encrypted_output_file_path, gcs_path,
                f"--project={GCP_PROJECT_ID}",
            ]
            subprocess.run(upload_command, capture_output=True, check=True, timeout=900)
            logger.info(f"SUCCESS: Upload of encrypted file '{gcs_object_name}' complete.")

            archive_path = move_to_archive_folder(file_path, "Encrypted upload successful")

            msg = f"[{alert_name}] '{gcs_object_name}' was encrypted via Envelope Encryption and uploaded to bucket."
            send_cloud_log_entry(
                severity="INFO",
                message=msg,
                log_name=log_name,
                data={
                    "event_type": alert_name,
                    "file": file_name,
                    "bucket_path": gcs_path,
                    "archive_path": archive_path,
                    "encryption_method": "manual-kms-envelope",
                },
            )
            logger.info("="*80 + "\n") # End of process separator
            # --- FIX: Clean up the temporary encrypted file on success ---
            if encrypted_output_file_path and os.path.exists(encrypted_output_file_path):
                os.remove(encrypted_output_file_path)
                logger.debug(f"Cleaned up temporary encrypted file: '{encrypted_output_file_path}'.")
            return True  # Success, exit the function

        except subprocess.TimeoutExpired:
            error_msg = f"Attempt {attempt + 1}/{max_retries} FAILED for '{file_name}' due to a timeout. The upload took too long."
            logger.error(error_msg)
            timed_out = True
            last_exception = Exception(error_msg)

        except Exception as e:
            last_exception = e
            logger.error(
                f"Attempt {attempt + 1}/{max_retries} FAILED for '{file_name}' with a gcloud/network exception: {str(e)}",
                exc_info=True,
            )
            # If the exception has stderr (from a subprocess failure), log it.
            if hasattr(e, 'stderr') and e.stderr:
                 logger.error(f"  Stderr: {e.stderr.decode()}")

        if attempt < max_retries - 1:
            logger.info(f"Retrying '{file_name}' after {retry_delay_seconds} seconds...")
            time.sleep(retry_delay_seconds)

    error_text = str(last_exception) if last_exception else "Unknown error"
    if hasattr(last_exception, "stderr") and last_exception.stderr:
        error_text = f"{error_text} | stderr: {last_exception.stderr.decode(errors='ignore')}"

    if timed_out:
        move_to_error_folder(file_path, "GCS upload timed out")
    elif is_authentication_error(error_text):
        logger.warning(f"Authentication/authorization issue detected for '{file_name}'. Moving to staging.")
        move_to_staging_folder(file_path, f"Authentication/authorization failure: {error_text}")
    else:
        logger.error(f"FAILURE: All attempts to process '{file_name}' failed. Moving to error folder.")
        move_to_error_folder(file_path, f"Upload failed after {max_retries} retries: {error_text}")
    logger.error("="*80 + "\n")
    # --- FIX: Clean up the temporary encrypted file on failure ---
    if encrypted_output_file_path and os.path.exists(encrypted_output_file_path):
        os.remove(encrypted_output_file_path)
        logger.debug(f"Cleaned up temporary encrypted file: '{encrypted_output_file_path}'.")

    return False


def process_ie_file(file_path):
    """
    Processes a raw IE file, filters it based on acquirer IDs, and writes
    the result to the zip_watch_folder for subsequent encryption and upload.
    """
    file_name = os.path.basename(file_path)
    lock_path = file_path + ".lock"
    lock = FileLock(lock_path, timeout=1)

    try:
        with lock:
            return _process_locked_ie_file(file_path)
    except Timeout:
        logger.debug(f"File '{file_name}' is locked by another process. Skipping.")
        return None

def _process_locked_ie_file(file_path):
    file_name = os.path.basename(file_path)

    logger.info("\n" + "="*80)
    logger.info(f"START: Copying, filtering, and zipping IE file '{file_name}'")

    # --- NEW: Retry loop for file stability check ---
    max_stability_retries = 5
    is_ready = False
    reason = "Unknown"
    for stability_attempt in range(max_stability_retries):
        logger.info(f"Checking IE file stability for '{file_name}' (Attempt {stability_attempt + 1}/{max_stability_retries})...")
        is_ready, reason = wait_file_ready(file_path)
        if is_ready:
            break # File is ready, exit the loop
        elif reason == "File disappeared" or reason == "File is empty":
            break # No point in retrying if file is gone or empty
        if stability_attempt < max_stability_retries - 1:
            logger.info(f"Will re-check stability for '{file_name}' in the next main loop cycle.")

    if not is_ready:
        logger.warning(
            f"FAILURE: IE File '{file_name}' was not ready after {max_stability_retries} attempts. "
            f"Reason: {reason}. Keeping source file in PROCESSED for manual review. "
            f"{MANUAL_REVIEW_MESSAGE} {RETRY_CONDITION_MESSAGE}"
        )
        logger.warning("="*80 + "\n")
        return None

    if "_" in file_name:
        output_file_name = file_name.split("_", 1)[-1]
    else:
        output_file_name = file_name

    in_copy_path = build_unique_path(IN_DIRECTORY, file_name)
    output_path = build_unique_path(IN_DIRECTORY, output_file_name)
    output_base_name = os.path.basename(output_path)
    zip_output_path = build_unique_path(IN_DIRECTORY, f"{output_base_name}.zip")
    try:
        shutil.copy2(file_path, in_copy_path)
        logger.info(f"Copied '{file_name}' from PROCESSED to IN as '{os.path.basename(in_copy_path)}'.")

        with open(in_copy_path, "r", encoding="windows-1252") as f:
            lines = [line.rstrip("\n") for line in f]

        df = pd.DataFrame({"line": lines})

        df["batch_sequence_start"] = df["line"].str.startswith("01")
        df["batch_sequence"] = df["batch_sequence_start"].cumsum()

        transaction_prefixes = ("11", "40", "43", "65", "61", "71")
        transaction_start = df["line"].str.startswith(transaction_prefixes).astype(int)
        df["transaction_start"] = transaction_start
        df["transaction_sequence"] = df["transaction_start"].cumsum()
        
        # --- REFACTORED: Use np.select for more efficient acquirer_id extraction ---
        conditions = [
            df['line'].str.startswith('11'),
            df['line'].str.startswith('40'),
            df['line'].str.startswith('43'),
            df['line'].str.startswith('61'),
            df['line'].str.startswith('65'),
            df['line'].str.startswith('71')
        ]
        choices = [
            df['line'].str.slice(start=7, stop=18),
            df['line'].str.slice(start=15, stop=26),
            df['line'].str.slice(start=15, stop=26),
            df['line'].str.slice(start=6, stop=17),
            df['line'].str.slice(start=4, stop=15),
            df['line'].str.slice(start=120, stop=131)
        ]
        df['acquirer_id'] = np.select(conditions, choices, default=None)

        df["acquirer_id"] = df.groupby("transaction_sequence")["acquirer_id"].transform(
            "first"
        )
        df.loc[df["line"].str.startswith(("01", "98", "99", "00")), "acquirer_id"] = (
            np.nan
        )

        filtered_df = df[
            (df["acquirer_id"].isin(IE_ACQUIRER_IDS)) | (df["acquirer_id"].isnull())
        ]

        # Write the filtered content to the output file
        with open(output_path, "w", encoding="utf-8") as f:
            for line in filtered_df["line"]:
                f.write(line + "\n")
        logger.info(
            f"Filtered content from '{file_name}' into '{output_base_name}'."
        )

        # --- NEW: Zip the processed file ---
        logger.info(f"Compressing '{output_base_name}' into '{os.path.basename(zip_output_path)}'...")
        with zipfile.ZipFile(zip_output_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
            zipf.write(output_path, arcname=output_base_name)
        
        # Clean up the original unzipped file
        safe_remove_file(output_path)

        logger.info(f"COMPLETED: Copy/filter/zip for '{file_name}'. Output is '{os.path.basename(zip_output_path)}'.")
        return zip_output_path

    except Exception as e:
        logger.error(f"Failed to process IE file '{file_name}': {e}", exc_info=True)
        logger.error("="*80 + "\n")
        logger.warning(
            f"Keeping source file '{file_name}' in PROCESSED due to processing error: {e}. "
            f"{MANUAL_REVIEW_MESSAGE} {RETRY_CONDITION_MESSAGE}"
        )
        safe_remove_file(zip_output_path)
        return None
    finally:
        safe_remove_file(in_copy_path)
        safe_remove_file(output_path)


def list_gcs_txt_files(gcs_folder):
    """Lists all .txt files in a GCS folder. Returns a list of full GCS paths."""
    command = [
        'cmd', '/c', GCLOUD_PATH, "storage", "ls",
        f"{gcs_folder}/*.txt",
        f"--project={GCP_PROJECT_ID}",
    ]
    try:
        result = subprocess.run(command, capture_output=True, check=False)
        if result.returncode != 0:
            stderr = result.stderr.decode(errors='ignore').strip()
            # An empty folder or no matching files is not an error
            if not stderr or "no URLs matched" in stderr.lower() or "One or more URLs matched no objects" in stderr:
                return []
            logger.warning(f"[RE-PROCESS] gcloud storage ls returned non-zero for '{gcs_folder}': {stderr}")
            return []
        output = result.stdout.decode(errors='ignore').strip()
        if not output:
            return []
        return [line.strip() for line in output.splitlines() if line.strip().endswith('.txt')]
    except Exception as e:
        logger.error(f"[RE-PROCESS] Failed to list GCS txt files in '{gcs_folder}': {e}", exc_info=True)
        return []


def download_gcs_file(gcs_path, local_path):
    """Downloads a single file from GCS to a local path. Returns True on success."""
    command = [
        'cmd', '/c', GCLOUD_PATH, "storage", "cp",
        gcs_path, local_path,
        f"--project={GCP_PROJECT_ID}",
    ]
    try:
        subprocess.run(command, capture_output=True, check=True, timeout=120)
        return True
    except subprocess.CalledProcessError as e:
        logger.error(
            f"[RE-PROCESS] Failed to download '{gcs_path}': {e.stderr.decode(errors='ignore').strip()}",
            exc_info=True,
        )
        return False
    except Exception as e:
        logger.error(f"[RE-PROCESS] Failed to download '{gcs_path}': {e}", exc_info=True)
        return False


def delete_gcs_file(gcs_path):
    """Deletes a file from GCS. Returns True on success."""
    command = [
        'cmd', '/c', GCLOUD_PATH, "storage", "rm",
        gcs_path,
        f"--project={GCP_PROJECT_ID}",
    ]
    try:
        subprocess.run(command, capture_output=True, check=True, timeout=60)
        logger.info(f"[RE-PROCESS] Deleted GCS trigger file: '{gcs_path}'")
        return True
    except Exception as e:
        logger.error(f"[RE-PROCESS] Failed to delete GCS file '{gcs_path}': {e}", exc_info=True)
        return False


def find_archived_file_for_reprocessing(file_name):
    """
    Searches the archive folder for a file whose name exactly matches file_name
    (e.g. IEXXXXXXXX.zip). Returns the archive file path if found, otherwise None.
    """
    if not file_name:
        return None
    return find_archived_file_match(file_name)


def _reprocess_encrypt_and_upload(archive_file_path, requested_name):
    """
    Re-encrypts an archived file and re-uploads it to GCS.
    Skips the duplicate check and does NOT move the archive file (it stays in archive).
    """
    max_retries = GCP_OPERATION_MAX_RETRIES
    retry_delay_seconds = GCP_RETRY_DELAY_SECONDS
    archive_file_name = os.path.basename(archive_file_path)

    if "_" in archive_file_name:
        gcs_object_name = archive_file_name.split("_", 1)[-1]
    else:
        gcs_object_name = archive_file_name
    gcs_path = f"{DEFAULT_GCS_BUCKET}/{gcs_object_name}"

    logger.info(
        f"[RE-PROCESS] Starting re-encryption and upload for '{archive_file_name}' "
        f"(requested: '{requested_name}') -> '{gcs_path}'"
    )

    encrypted_output_file_path = None
    last_exception = None
    timed_out = False

    for attempt in range(max_retries):
        encrypted_output_file_path = os.path.join(ARCHIVE_DIRECTORY, archive_file_name + ".enc")
        try:
            # 1. Generate a new DEK
            dek = AESGCM.generate_key(bit_length=256)
            logger.info(f"[RE-PROCESS] Generated 256-bit DEK for '{archive_file_name}'.")

            # 2. Wrap DEK using KMS
            logger.info(
                f"[RE-PROCESS] Attempt {attempt + 1}/{max_retries}: Wrapping DEK for '{archive_file_name}'..."
            )
            key_parts = kms_key_name.split('/')
            kms_project = key_parts[1]
            kms_location = key_parts[3]
            kms_keyring = key_parts[5]
            kms_key = key_parts[7]

            wrap_dek_command = [
                'cmd', '/c', GCLOUD_PATH, "kms", "encrypt",
                f"--project={kms_project}",
                f"--location={kms_location}",
                f"--keyring={kms_keyring}",
                f"--key={kms_key}",
                "--plaintext-file=-",
                "--ciphertext-file=-",
            ]
            wrap_proc = subprocess.run(wrap_dek_command, input=dek, capture_output=True, check=True)
            wrapped_dek = wrap_proc.stdout
            logger.info(f"[RE-PROCESS] Successfully wrapped DEK for '{archive_file_name}'.")

            # 3. Encrypt file content locally using the DEK
            with open(archive_file_path, "rb") as f_in:
                plaintext_data = f_in.read()

            aes_gcm = AESGCM(dek)
            nonce = os.urandom(12)
            encrypted_data = aes_gcm.encrypt(nonce, plaintext_data, None)

            # 4. Write combined encrypted file using envelope encryption format:
            #    [4 bytes big-endian wrapped_dek length][wrapped_dek][12-byte nonce][AES-GCM ciphertext]
            #    This format must match the corresponding decryption implementation.
            with open(encrypted_output_file_path, "wb") as f_out:
                f_out.write(len(wrapped_dek).to_bytes(4, 'big'))
                f_out.write(wrapped_dek)
                f_out.write(nonce)
                f_out.write(encrypted_data)
            logger.info(f"[RE-PROCESS] Created encrypted file: '{os.path.basename(encrypted_output_file_path)}'.")

            # 5. Upload encrypted file to GCS
            logger.info(
                f"[RE-PROCESS] Uploading '{os.path.basename(encrypted_output_file_path)}' to '{gcs_path}'..."
            )
            upload_command = [
                'cmd', '/c', GCLOUD_PATH, "storage", "cp",
                encrypted_output_file_path, gcs_path,
                f"--project={GCP_PROJECT_ID}",
            ]
            subprocess.run(upload_command, capture_output=True, check=True, timeout=900)
            logger.info(f"[RE-PROCESS] SUCCESS: Re-uploaded '{gcs_object_name}' to GCS.")

            send_cloud_log_entry(
                severity="INFO",
                message=f"[ReProcessSuccess] '{gcs_object_name}' was re-encrypted and re-uploaded from archive.",
                log_name=activity_log_name,
                data={
                    "event_type": "ReProcessFileSuccess",
                    "requested_name": requested_name,
                    "archive_file": archive_file_name,
                    "bucket_path": gcs_path,
                },
            )
            logger.info("=" * 80 + "\n")
            if encrypted_output_file_path and os.path.exists(encrypted_output_file_path):
                os.remove(encrypted_output_file_path)
                logger.debug(f"[RE-PROCESS] Cleaned up temp encrypted file: '{encrypted_output_file_path}'.")
            return True

        except subprocess.TimeoutExpired:
            error_msg = (
                f"[RE-PROCESS] Attempt {attempt + 1}/{max_retries} FAILED for '{archive_file_name}' "
                "due to timeout."
            )
            logger.error(error_msg)
            timed_out = True
            last_exception = Exception(error_msg)

        except Exception as e:
            last_exception = e
            logger.error(
                f"[RE-PROCESS] Attempt {attempt + 1}/{max_retries} FAILED for '{archive_file_name}': {e}",
                exc_info=True,
            )
            if hasattr(e, 'stderr') and e.stderr:
                logger.error(f"  Stderr: {e.stderr.decode(errors='ignore')}")

        if attempt < max_retries - 1:
            logger.info(f"[RE-PROCESS] Retrying '{archive_file_name}' after {retry_delay_seconds} seconds...")
            time.sleep(retry_delay_seconds)

    error_text = str(last_exception) if last_exception else "Unknown error"
    if hasattr(last_exception, "stderr") and last_exception.stderr:
        error_text = f"{error_text} | stderr: {last_exception.stderr.decode(errors='ignore')}"

    logger.error(
        f"[RE-PROCESS] FAILURE: All {max_retries} attempt(s) to re-process '{archive_file_name}' failed."
    )
    send_cloud_log_entry(
        severity="ERROR",
        message=(
            f"[ReProcessFailure] Failed to re-upload '{archive_file_name}' "
            f"after {max_retries} retries: {error_text}"
        ),
        log_name=critical_error_log_name,
        data={
            "event_type": "ReProcessFileFailure",
            "requested_name": requested_name,
            "archive_file": archive_file_name,
            "error": error_text,
        },
    )
    if encrypted_output_file_path and os.path.exists(encrypted_output_file_path):
        os.remove(encrypted_output_file_path)
        logger.debug(f"[RE-PROCESS] Cleaned up temp encrypted file: '{encrypted_output_file_path}'.")
    return False


def reprocess_archived_file(file_name):
    """
    Looks up a file by name in the archive folder and re-sends it with encryption.
    Logs a warning if the file is not found in the archive.
    """
    file_name = file_name.strip()
    if not file_name:
        return
    archive_path = find_archived_file_for_reprocessing(file_name)
    if not archive_path:
        logger.warning(
            f"[RE-PROCESS] GCS bucket .txt file name '{file_name}' not found in archive folder."
        )
        send_cloud_log_entry(
            severity="WARNING",
            message=(
                f"[ReProcessWarning] Re-processing requested for '{file_name}' "
                "but it was not found in the archive folder."
            ),
            log_name=activity_log_name,
            data={
                "event_type": "ReProcessFileNotFound",
                "requested_name": file_name,
                "archive_folder": ie_archive_folder,
            },
        )
        return
    logger.info(
        f"[RE-PROCESS] Found '{file_name}' in archive as '{os.path.basename(archive_path)}'. "
        "Initiating re-send."
    )
    _reprocess_encrypt_and_upload(archive_path, file_name)


def check_and_handle_reprocessing_requests():
    """
    Polls the GCS re_processing_files folder for .txt trigger files every 10 minutes.
    Each .txt file may contain one or more comma-separated file names to re-process from
    the swan archive folder. After processing, the trigger file is deleted from GCS.
    """
    logger.info(
        f"[RE-PROCESS] Checking for re-processing trigger files in '{RE_PROCESSING_GCS_FOLDER}'..."
    )
    try:
        authenticate_gcloud()
    except Exception as e:
        logger.error(
            f"[RE-PROCESS] Authentication failed. Skipping re-processing check. Error: {e}",
            exc_info=True,
        )
        return

    txt_files = list_gcs_txt_files(RE_PROCESSING_GCS_FOLDER)
    if not txt_files:
        logger.debug(
            f"[RE-PROCESS] No .txt trigger files found in '{RE_PROCESSING_GCS_FOLDER}'."
        )
        return

    logger.info(f"[RE-PROCESS] Found {len(txt_files)} trigger file(s): {txt_files}")

    for gcs_txt_path in txt_files:
        if is_ctrlc_exit:
            break
        local_tmp_path = os.path.join(
            ARCHIVE_DIRECTORY, f"_reprocess_trigger_{os.path.basename(gcs_txt_path)}"
        )
        try:
            logger.info(f"[RE-PROCESS] Processing trigger file: '{gcs_txt_path}'")
            if not download_gcs_file(gcs_txt_path, local_tmp_path):
                logger.error(
                    f"[RE-PROCESS] Failed to download trigger file '{gcs_txt_path}'. Skipping."
                )
                continue

            with open(local_tmp_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()

            # Normalise newlines to commas so users can separate names with either
            # commas or newlines (or a mix of both).
            normalised = content.replace("\r\n", ",").replace("\n", ",").replace("\r", ",")
            file_names = [name.strip() for name in normalised.split(",") if name.strip()]
            if not file_names:
                logger.warning(
                    f"[RE-PROCESS] Trigger file '{os.path.basename(gcs_txt_path)}' "
                    "is empty or contains no valid file names. Deleting trigger file."
                )
            else:
                logger.info(
                    f"[RE-PROCESS] Trigger file '{os.path.basename(gcs_txt_path)}' contains "
                    f"{len(file_names)} file name(s): {file_names}"
                )
                for file_name in file_names:
                    if is_ctrlc_exit:
                        break
                    reprocess_archived_file(file_name)

            # Delete the trigger file from GCS to prevent re-processing on the next check
            delete_gcs_file(gcs_txt_path)

        except Exception as e:
            logger.error(
                f"[RE-PROCESS] Error processing trigger file '{gcs_txt_path}': {e}",
                exc_info=True,
            )
        finally:
            safe_remove_file(local_tmp_path)


def handle_ctrlc(sig, frame):
    global is_ctrlc_exit
    logger.critical(
        "\nCtrl+C detected. Initiating graceful shutdown. Will exit after the current file is processed."
    )
    is_ctrlc_exit = True
    send_cloud_log_entry(
        severity="CRITICAL",
        message="Shutdown signal received (Ctrl+C or window close). Script will exit gracefully.",
        log_name=critical_error_log_name,
        data={"exit_type": "CtrlC", "event_type": "CriticalShutdown"},
    )


signal.signal(signal.SIGINT, handle_ctrlc)


def main():
    global is_ctrlc_exit, gcloud_auth_success
    # Take a snapshot of files present at startup to ignore them.
    logger.info(
        f"Scanning for existing files in '{PROCESSED_FILES_DIRECTORY}' to ignore..."
    )
    initial_ie_files = {}
    for existing_path in glob.glob(os.path.join(PROCESSED_FILES_DIRECTORY, "*")):
        if os.path.isfile(existing_path):
            try:
                initial_ie_files[existing_path] = os.path.getmtime(existing_path)
            except FileNotFoundError:
                logger.debug(f"Skipping vanished startup file during snapshot: '{existing_path}'")
                continue
    logger.info(f"Found {len(initial_ie_files)} existing files to ignore. Now watching for new files.")
    authenticate_gcloud()
    send_cloud_log_entry(
        severity="INFO",
        message="GCS IE Uploader script started and is now monitoring incoming files for upload.",
        log_name=activity_log_name,
        data={"event_type": "ScriptStartup"},
    )
    logger.info(
        f"Monitoring folders: '{PROCESSED_FILES_DIRECTORY}' and '{IN_DIRECTORY}'. Press Ctrl+C to stop."
    )

    last_heartbeat_time = time.time()
    last_reprocessing_check_time = 0  # Set to 0 so the first check runs on startup (trigger files may already be waiting)
    staging_retry_state = {}
    staging_retry_exhausted_logged = set()

    try:
        while True:
            if is_ctrlc_exit:
                break
            current_time = time.time()
            if current_time - last_heartbeat_time >= HEARTBEAT_INTERVAL_SECONDS:
                send_cloud_log_entry(
                    severity="INFO",
                    message="Heartbeat: IE Uploader script is running normally.",
                    log_name=activity_log_name,
                    data={"event_type": "Heartbeat"},
                )
                last_heartbeat_time = current_time
                logger.debug("Sent heartbeat log entry.")

            # --- Re-processing check: every 10 minutes ---
            if current_time - last_reprocessing_check_time >= RE_PROCESSING_CHECK_INTERVAL_SECONDS:
                check_and_handle_reprocessing_requests()
                last_reprocessing_check_time = current_time

            # --- PRIORITY 1: Process staged files ---
            # Use sorted order so retry order is deterministic across loop iterations.
            staged_files = sorted(glob.glob(os.path.join(STAGING_DIRECTORY, "*.zip")))
            staged_file_set = set(staged_files)
            for tracked_file in list(staging_retry_state.keys()):
                if tracked_file not in staged_file_set:
                    staging_retry_state.pop(tracked_file, None)
                    staging_retry_exhausted_logged.discard(tracked_file)

            if staged_files:
                logger.info(f"Found {len(staged_files)} file(s) in staging.")
                due_staged_files = []
                for file_path in staged_files:
                    state = staging_retry_state.setdefault(
                        file_path,
                        {"attempts": 0, "next_retry_time": current_time},
                    )
                    if state["attempts"] >= STAGING_MAX_RETRIES:
                        if file_path not in staging_retry_exhausted_logged:
                            send_cloud_log_entry(
                                severity="ERROR",
                                message=(
                                    f"Staged file '{os.path.basename(file_path)}' reached max retries "
                                    f"({state['attempts']}/{STAGING_MAX_RETRIES}) and will no longer be retried automatically."
                                ),
                                log_name=critical_error_log_name,
                                data={
                                    "event_type": "StagingRetryExhausted",
                                    "file": os.path.basename(file_path),
                                    "retry_attempts": state["attempts"],
                                    "retry_interval_seconds": STAGING_RETRY_INTERVAL_SECONDS,
                                },
                            )
                            staging_retry_exhausted_logged.add(file_path)
                        continue

                    if current_time >= state["next_retry_time"]:
                        due_staged_files.append(file_path)

                if due_staged_files:
                    try:
                        authenticate_gcloud(force_reauthenticate=True)
                    except Exception:
                        logger.warning(
                            "Authentication failed. Will retry due staged files later without blocking PROCESSED handling.",
                            exc_info=True,
                        )
                        next_retry_at = current_time + STAGING_RETRY_INTERVAL_SECONDS
                        for file_path in due_staged_files:
                            if file_path in staging_retry_state:
                                staging_retry_state[file_path]["next_retry_time"] = next_retry_at
                    else:
                        for file_path in due_staged_files:
                            if is_ctrlc_exit:
                                break
                            if not os.path.isfile(file_path):
                                staging_retry_state.pop(file_path, None)
                                staging_retry_exhausted_logged.discard(file_path)
                                continue

                            state = staging_retry_state[file_path]
                            attempt_no = state["attempts"] + 1
                            logger.info(
                                f"Retrying staged file: {os.path.basename(file_path)} "
                                f"(Attempt {attempt_no}/{STAGING_MAX_RETRIES})"
                            )
                            # Only an explicit True result is treated as success.
                            success = encrypt_upload_and_archive(file_path)
                            if success is True:
                                staging_retry_state.pop(file_path, None)
                                staging_retry_exhausted_logged.discard(file_path)
                            else:
                                state["attempts"] = attempt_no
                                state["next_retry_time"] = current_time + STAGING_RETRY_INTERVAL_SECONDS

            # --- Process NEW IE files ---
            # Check for files that were not present at startup.
            current_ie_files = glob.glob(os.path.join(PROCESSED_FILES_DIRECTORY, "*"))
            for file_path in current_ie_files:
                if is_ctrlc_exit: break
                if os.path.isfile(file_path):
                    try:
                        file_mtime = os.path.getmtime(file_path)
                    except FileNotFoundError:
                        logger.debug(f"Skipping vanished file during monitoring cycle: '{file_path}'")
                        continue

                    previous_mtime = initial_ie_files.get(file_path)
                    if previous_mtime is not None and file_mtime <= previous_mtime:
                        continue

                    zip_file_path = process_ie_file(file_path)
                    if zip_file_path:
                        encrypt_upload_and_archive(zip_file_path)
                    initial_ie_files[file_path] = file_mtime

            encrypt_files = glob.glob(os.path.join(IN_DIRECTORY, "*.zip"))
            for file_path in encrypt_files:
                if is_ctrlc_exit: break
                if os.path.isfile(file_path):
                    # This function now moves the original .zip file upon success or failure,
                    # so it won't be processed again in the next loop.
                    encrypt_upload_and_archive(file_path)

            time.sleep(1)


    except Exception as e:
        error_message = str(e)
        logger.critical(
            f"CRITICAL SCRIPT ERROR: Script terminated unexpectedly. Error: {error_message}",
            exc_info=True,
        )
        send_cloud_log_entry(
            severity="ERROR",
            message=f"GCS IE Uploader script terminated unexpectedly: {error_message}",
            log_name=critical_error_log_name,
            data={"error_type": "UnexpectedTermination", "full_error": error_message},
        )
        raise
    finally:
        logger.info(
            f"Script finished. Check Cloud Logging '{critical_error_log_name}' for details if an error occurred."
        )


def run_script_with_retries(max_retries=3, delay_seconds=10):
    attempt = 0
    while attempt < max_retries:
        try:
            main()
            break
        except Exception as e:
            attempt += 1
            logger.error(
                f"Attempt {attempt} of {max_retries} failed with exception: {str(e)}",
                exc_info=True,
            )
            if attempt < max_retries:
                logger.info(f"Retrying after {delay_seconds} seconds...")
                time.sleep(delay_seconds)
            else:
                logger.critical("Maximum retry attempts reached. Script will exit.")
                send_cloud_log_entry(
                    severity="CRITICAL",
                    message=f"IE Uploader script failed after {max_retries} retries. Manual intervention required.",
                    log_name=critical_error_log_name,
                    data={"event_type": "MaxRetryFailure"},
                )
                sys.exit(1)


if __name__ == "__main__":
    run_script_with_retries()
