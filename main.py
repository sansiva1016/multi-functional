# pip install cryptography


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
import logging
from logging.handlers import RotatingFileHandler
from filelock import FileLock, Timeout
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from datetime import datetime


# === USER CONFIGURATION ===
GCP_PROJECT_ID = "nld-data-pltf-acquiring-prod"  # change dev/qa/prod as needed
GCLOUD_PATH = r"D:\Tools\google-cloud-sdk-517.0.0-windows-x86_64-bundled-python\google-cloud-sdk\bin\gcloud.cmd"
DIRECTORY_PATH = r"\\swnas-01.core.zone\pwcdataswan$\TgtFiles"


zip_watch_folder = f"{DIRECTORY_PATH}/OutgoingCloud"
archive_folder = f"{DIRECTORY_PATH}/OutgoingCloud/archive"
swan_report_archive_folder = f"{DIRECTORY_PATH}/OutgoingCloud/swan_report_archive"
error_folder = f"{DIRECTORY_PATH}/OutgoingCloud/zipfile_error"
staging_folder = f"{DIRECTORY_PATH}/OutgoingCloud/zipfile_staging" # For files that can be retried
service_account_key = r"D:\Tools\google-cloud-sdk-517.0.0-windows-x86_64-bundled-python\google-cloud-sdk\bin\config_files_cloudsetup_authent\nld-data-pltf-acquiring-prod-5abd33991c30.json"
kms_key_name = "projects/nld-data-pltf-acquiring-prod/locations/europe/keyRings/prod_swan_inbound_encryption-PhwwT/cryptoKeys/prod_swan_inbound_encryption_kms_key"


bucket_name_patterns = {
"SWANDWH.XIMEDES.DEFPAY": f"gs://{GCP_PROJECT_ID}-swan-inbound/swan-report/out/ING/DEFPAY/",
"SWANDWH.XIMEDES.DEFACQTR": f"gs://{GCP_PROJECT_ID}-swan-inbound/swan-report/out/ING/DEFACQTR/",
"SWANDWH.RABOM201.DEFACQTR": f"gs://{GCP_PROJECT_ID}-swan-inbound/swan-report/out/RABO/DEFACQTR/",
"SWANDWH.RABOM201.DEFPAY": f"gs://{GCP_PROJECT_ID}-swan-inbound/swan-report/out/RABO/DEFPAY/",
"R0000030.INGTVPB.QM9013CA": f"gs://{GCP_PROJECT_ID}-swan-inbound/swan-report/out/ING/QMR_9013_CA/",
"R0000030.INGTVPB.QMRPFA": f"gs://{GCP_PROJECT_ID}-swan-inbound/swan-report/out/ING/QMR_PFA/",
"R0000030.INGTVPB.QM9011CB": f"gs://{GCP_PROJECT_ID}-swan-inbound/swan-report/out/ING/QMR_9011_CB/",
"R0000030.INGTVPB.QM9011CD": f"gs://{GCP_PROJECT_ID}-swan-inbound/swan-report/out/ING/QMR_9011_CD/",
"R0000030.INGTVPB.QM3106QC": f"gs://{GCP_PROJECT_ID}-swan-inbound/swan-report/out/ING/QMR_3106_QC/",
"R0000030.INGTVPB.QM3104QZ": f"gs://{GCP_PROJECT_ID}-swan-inbound/swan-report/out/ING/QMR_3104_QZ/",
"DEFAULT": f"gs://{GCP_PROJECT_ID}-swan-inbound/in/swan-inbound",
}

critical_error_log_name = "zip-uploader-activity"
activity_log_name = "zip-uploader-activity"
swan_report_log_name = "swan-report-uploader-activity"

ACQUIRER_IDS = {"673072009", "673072008", "673002008"}  # add any new acquirer IDs here
PATTERNS = [
    ("SWAN.FUTURO.W4TXFEE", 7),
    ("SWAN.FUTURO.W4TXPMT", 7),
    ("SWAN.FUTURO.ICTF", 6),
    ("SWAN.FUTURO.CIMTRM", 5),
    ("SWAN.FUTURO.CIM", 5),
]
SWAN_HISTORY_DATE_PATTERN = re.compile(
    # Expected file date segment format is ddmmyyyy (8 digits); calendar validity is not checked here.
    r"^SWAN\.FUTURO\.(W4TXFEE|W4TXPMT)\.673002008\.\d{8}\.zip$",
    re.IGNORECASE,
)

is_ctrlc_exit = False
gcloud_auth_success = False
HEARTBEAT_INTERVAL_SECONDS = 300  # 5 minutes

# Logging setup
log_file_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "zip-uploader.log")
logger = logging.getLogger("ZipUploaderLogger")
logger.setLevel(logging.DEBUG)
file_handler = RotatingFileHandler(log_file_path, maxBytes=5 * 1024 * 1024, backupCount=3, encoding='utf-8')
formatter = logging.Formatter("%(asctime)s %(levelname)s - %(message)s")
file_handler.setFormatter(formatter)
logger.addHandler(file_handler)
console_handler = logging.StreamHandler()
console_handler.setFormatter(formatter)
logger.addHandler(console_handler)


def log_and_print(message: str, level="info"): # This function is kept for compatibility with existing calls.
    getattr(logger, level.lower(), logger.info)(message)


def ensure_directory_exists(path):
    if not os.path.exists(path):
        log_and_print(f"Creating directory at {path}", "info")
        os.makedirs(path, exist_ok=True)


ensure_directory_exists(archive_folder)
ensure_directory_exists(error_folder)
ensure_directory_exists(swan_report_archive_folder)
ensure_directory_exists(staging_folder)


def authenticate_gcloud(max_retries=5, initial_backoff=250):
    global gcloud_auth_success
    attempt = 0
    backoff = initial_backoff
    while attempt < max_retries:
        logger.info(f"Authenticating with gcloud service account (Attempt {attempt + 1}/{max_retries})...")
        if not os.path.exists(service_account_key):
            raise Exception(f"Key file not found: {service_account_key}")
        try:
            result = subprocess.run(
                ['cmd', '/c', GCLOUD_PATH, "auth", "activate-service-account", f"--key-file={service_account_key}"],
                capture_output=True,
                check=True,
                timeout=120 # Add a timeout to the subprocess call
            )
            logger.info("gcloud authentication successful.")
            gcloud_auth_success = True
            return True
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as e:
            stderr_msg = e.stderr.decode().strip() if hasattr(e, 'stderr') and e.stderr else str(e)
            logger.error(f"gcloud auth error on attempt {attempt + 1}: {stderr_msg}")
            attempt += 1
            if attempt < max_retries:
                logger.info(f"Retrying in {backoff} seconds...")
                time.sleep(backoff)
                backoff *= 2  # Exponential backoff
    logger.critical("Maximum retry attempts reached for gcloud authentication. Exiting.")
    return False


def wait_file_ready(file_path, max_retries=10, sleep_seconds=1):
    retry_count = 0
    while retry_count < max_retries:
        try:
            if not os.path.exists(file_path):
                logger.warning(f"File '{os.path.basename(file_path)}' no longer exists. Skipping.")
                return False, "File disappeared"
            initial_size = os.path.getsize(file_path)
            time.sleep(sleep_seconds)
            current_size = os.path.getsize(file_path)
            if initial_size == current_size:
                if initial_size > 0:
                    logger.debug(f"File '{file_path}' is stable and not empty.")
                    return True, "File is stable"
                else: # File is stable but empty
                    logger.warning(f"File '{os.path.basename(file_path)}' is stable but empty.")
                    return False, "File is empty"
            retry_count += 1
            time.sleep(0.5)
        except FileNotFoundError:
            logger.warning(f"File '{os.path.basename(file_path)}' was removed during stability check. Skipping.")
            return False, "File disappeared"
    log_and_print(
        f"File '{file_path}' did not become stable or was empty after {max_retries} retries.",
        "warning",
    )
    return False, "File is unstable"


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
        logger.error(f"Could not compute MD5 hash for '{file_path}'. Error: {str(e)}", exc_info=True)
        return None


def file_name_matches(filename):
    """
    Determines if filename matches expected pattern.
    Handles optional extra segment and optional sequence part.
    Accepts filenames with or without sequence like Dxxxxxx.
    """
    name = filename
    if name.lower().endswith(".zip"):
        name = name[:-4]
    parts = name.split(".")
    if len(parts) < 4:
        return False
    prefix = ".".join(parts[:3])  # e.g. SWAN.FUTURO.ICTF

    for pattern_prefix, seq_length in PATTERNS:
        if prefix == pattern_prefix:
            # Case 1: Filename has an acquirer ID but no sequence.
            # e.g., SWAN.FUTURO.CIM.673002008
            if len(parts) == 4 and parts[3] in ACQUIRER_IDS:
                return True

            # Case 2: Filename has a sequence and an acquirer ID.
            # e.g., SWAN.FUTURO.ICTF.IE000001.673072009
            if len(parts) == 5:
                # Handle both [prefix].[sequence].[acquirer_id] and [prefix].[acquirer_id].[sequence]
                if parts[4] in ACQUIRER_IDS:
                    sequence_part = parts[3] # Sequence is the 4th part
                elif parts[3] in ACQUIRER_IDS:
                    sequence_part = parts[4] # Sequence is the 5th part
                else:
                    continue # Does not match a known structure

            # Case 3: Filename has a sequence but no acquirer ID.
            # e.g., SWAN.FUTURO.ICTF.IE000001
            elif len(parts) == 4 and parts[3] not in ACQUIRER_IDS:
                sequence_part = parts[3]
            else: # Does not match a known structure for this prefix
                continue
            # --- Validate the sequence part ---
            # For CIMTRM files, if sequence starts with 'D', it's an error.
            if prefix == "SWAN.FUTURO.CIMTRM" and sequence_part.startswith('D'):
                logger.warning(f"Invalid sequence for CIMTRM file '{filename}': sequence should not start with 'D'.")
                return False

            # Allow sequence with or without a leading 'D', 'I', or 'IE'
            if sequence_part.startswith('IE'):
                seq_num = sequence_part[2:]
            elif sequence_part.startswith(('D', 'I')):
                seq_num = sequence_part[1:]
            else:
                # If no prefix, check if the whole part is a digit of the right length
                # This handles cases where the sequence is just numbers.
                if sequence_part.isdigit() and len(sequence_part) == seq_length:
                    return True
                seq_num = sequence_part

            # Final check on the numeric part of the sequence
            if seq_num.isdigit() and len(seq_num) == seq_length:
                return True

    # If the loop completes without finding a match, the pattern is invalid.
    return False


def swan_report_pattern(filename):
    # Check if the filename starts with "SWANDWH.XIMEDES"
    return filename.startswith("SWANDWH.XIMEDES")

def swan_history_pattern(filename):
    return bool(SWAN_HISTORY_DATE_PATTERN.match(filename))


def move_to_error_folder(file_path, reason):
    file_name = os.path.basename(file_path)
    dest_path = os.path.join(error_folder, file_name)
    try:
        shutil.move(file_path, dest_path)
        logger.error(f"Moved '{file_name}' to error folder due to: {reason}")
        send_cloud_log_entry(
            severity="ERROR",
            message=f"File '{file_name}' was moved to the error folder. Reason: {reason}",
            log_name=critical_error_log_name,
            data={
                "event_type": "FileMoveToError",
                "file": file_name,
                "reason": reason,
            },
        )
    except Exception as e:
        logger.critical(f"Failed to move '{file_name}' to error folder: {str(e)}", exc_info=True)


def move_to_staging_folder(file_path, reason):
    """Moves a file to the staging folder for a later retry attempt."""
    file_name = os.path.basename(file_path)
    dest_path = os.path.join(staging_folder, file_name)
    try:
        shutil.move(file_path, dest_path)
        logger.warning(f"Moved '{file_name}' to staging folder for retry. Reason: {reason}")
        send_cloud_log_entry(
            severity="WARNING",
            message=f"File '{file_name}' was moved to the staging folder for retry. Reason: {reason}",
            log_name=activity_log_name,
            data={
                "event_type": "FileMoveToStaging",
                "file": file_name,
                "reason": reason,
            },
        )
    except Exception as e:
        logger.critical(f"CRITICAL: Failed to move '{file_name}' to staging folder. It will be retried from the source folder. Error: {str(e)}", exc_info=True)

def send_cloud_log_entry(severity="INFO", message="", log_name="zip-uploader-activity", data=None):
    if data is None:
        data = {}
    payload = {
        "severity": severity,
        "message": message,
        "script_name": os.path.abspath(sys.argv[0]),
        "host": os.environ.get("COMPUTERNAME", ""),
        "watch_folder": zip_watch_folder,
        "timestamp": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
    }
    payload.update(data)
    json_payload = json.dumps(payload)
    try:
        # Pass the JSON payload as a separate argument to avoid shell quoting issues.
        result = subprocess.run(
            [
                'cmd', '/c', GCLOUD_PATH, "logging", "write", log_name,
                json_payload,
                f"--project={GCP_PROJECT_ID}"
            ],
            capture_output=True,
            check=False # Handle non-zero exit codes manually
        )
        if result.returncode != 0:
            raise Exception(
                f"gcloud logging write command failed with exit code {result.returncode}: {result.stderr.decode().strip()}"
            )
        logger.debug(f"Sent log to Cloud Logging (logName: {log_name}, severity: {severity}).")
    except Exception as e:
        logger.critical(f"Failed writing log entry to Google Cloud Logging. Error: {str(e)}", exc_info=True)


def upload_and_archive_zip(file_path):
    file_name = os.path.basename(file_path)
    lock_path = file_path + ".lock"
    lock = FileLock(lock_path, timeout=1)

    try:
        with lock:
            # If we acquire the lock, process the file.
            # The original logic of upload_and_archive_zip goes here.
            return _process_locked_file(file_path)
    except Timeout:
        # Could not acquire lock, another process is handling it.
        logger.debug(f"File '{file_name}' is locked by another process. Skipping.")
        return False # Indicate that this file was not processed by this instance.

def _process_locked_file(file_path):
    file_name = os.path.basename(file_path)
    encrypted_file_name = f"{file_name}.enc"
    archive_dest = "" # Initialize archive destination

    # Refactored logic for pattern matching
    gcs_path = ""
    pattern_type = ""
    
    if swan_history_pattern(file_name):
        gcs_path = f"gs://{GCP_PROJECT_ID}-swan-inbound/in/swan-history/{file_name}"
        pattern_type = "SWAN_HISTORY"
    else:
        # Check for specific SWAN report patterns next
        for pattern, path in bucket_name_patterns.items():
            if pattern != "DEFAULT" and file_name.startswith(pattern):
                gcs_path = f"{path}{file_name}"
                pattern_type = "SWANDWH"
                break # Found a match, exit the loop

    if gcs_path:
        # Configure logging and archive destination for matched special patterns.
        if pattern_type == "SWANDWH":
            log_name = swan_report_log_name
            alert_name = "SwanReportFileUploadSuccess"
            archive_dest = os.path.join(swan_report_archive_folder, file_name)
        elif pattern_type == "SWAN_HISTORY":
            log_name = activity_log_name
            alert_name = "FileUploadSuccess"
            archive_dest = os.path.join(archive_folder, file_name)
    elif file_name_matches(file_name): # Check for other file types
        # The destination GCS object will have the original filename, not the .enc extension.
        gcs_path = f"{bucket_name_patterns['DEFAULT']}/{file_name}"
        archive_dest = os.path.join(archive_folder, file_name)
        log_name = activity_log_name
        alert_name = "FileUploadSuccess"
        pattern_type = "EXISTING"
    else:
        logger.warning(f"File '{file_name}' does NOT match expected patterns. Moving to error folder.")
        # This is a critical path. If moving to error fails, we must stop to prevent accidental upload.
        try:
            move_to_error_folder(file_path, "Filename pattern or acquirer/sequence ID mismatch")
            send_cloud_log_entry(
                severity="ERROR",
                message=f"File pattern mismatch for '{file_name}'. Moved to error folder.",
                log_name=critical_error_log_name,
                data={"event_type": "FilePatternMismatch", "file": file_name},
            )
        except Exception as e:
            # If we can't even move the bad file, we must exit to avoid processing it incorrectly.
            logger.critical(f"CRITICAL: Failed to move mismatched file '{file_name}' to error folder. Exiting to prevent incorrect processing. Error: {e}", exc_info=True)
            sys.exit(1) # Hard exit to stop the script immediately.
        return False

    logger.info(f"Processing file: '{file_name}'")

    is_ready, reason = wait_file_ready(file_path)
    if not is_ready:
        logger.warning(f"File '{file_name}' is not ready for upload. Reason: {reason}. Moving to error folder.")
        move_to_error_folder(file_path, f"File not stable or empty. Reason: {reason}")
        return False # Stop processing this file

    local_md5 = get_file_md5_base64(file_path)
    if not local_md5:
        logger.error(f"MD5 calculation failed for '{file_name}'. Skipping upload.")
        return False

    # --- Envelope Encryption (DEK) Implementation ---
    encrypted_output_file_path = os.path.join(os.path.dirname(file_path), encrypted_file_name)
    try:
        # 1. Generate a new Data Encryption Key (DEK) for each file.
        dek = AESGCM.generate_key(bit_length=256)
        logger.info(f"Generated a 256-bit DEK for '{file_name}'.")

        # 2. Encrypt (wrap) the DEK using the Cloud KMS key.
        logger.info(f"Wrapping the DEK for '{file_name}' using Cloud KMS.")
        key_parts = kms_key_name.split('/')
        kms_project = key_parts[1]
        kms_location = key_parts[3]
        kms_keyring = key_parts[5]
        kms_key = key_parts[7]

        # We pass the DEK via stdin to avoid temporary files for the key.
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
            # Prepend the length of the wrapped DEK as a fixed-size header (4 bytes).
            f_out.write(len(wrapped_dek).to_bytes(4, 'big'))
            f_out.write(wrapped_dek)
            f_out.write(nonce)
            f_out.write(encrypted_data)
        logger.info(f"Created combined encrypted file: '{os.path.basename(encrypted_output_file_path)}'.")

        # 5. Upload the final encrypted file to GCS.
        logger.info(f"Uploading encrypted file '{os.path.basename(encrypted_output_file_path)}' to GCS path '{gcs_path}'...")
        # Use os.path.normpath to ensure correct path separators for the OS
        norm_encrypted_path = os.path.normpath(encrypted_output_file_path)
        upload_result = subprocess.run(
            ['cmd', '/c', GCLOUD_PATH, "storage", "cp", norm_encrypted_path, gcs_path, f"--project={GCP_PROJECT_ID}"],
            capture_output=True,
        )

        if upload_result.returncode != 0:
            stderr_str = upload_result.stderr.decode().strip()
            # This is likely a network/auth error, so move to staging for retry.
            logger.error(f"FAILURE: Upload of encrypted file failed for '{file_name}'. Moving to staging. Error: {stderr_str}")
            move_to_staging_folder(file_path, "Upload of encrypted file failed")
            return False
        else:
            logger.info(f"SUCCESS: Upload of encrypted file succeeded for '{file_name}'.")
            # Archive the ORIGINAL file
            ensure_directory_exists(os.path.dirname(archive_dest))
            shutil.move(file_path, archive_dest)
            logger.info(f"Archived original file '{file_name}' to '{archive_dest}'.")
            msg = f"[{alert_name}] '{file_name}' was encrypted via Envelope Encryption and uploaded to bucket ({pattern_type}). Original file archived."
            send_cloud_log_entry(
                severity="INFO",
                message=msg,
                log_name=log_name,
                data={
                    "event_type": alert_name,
                    "file": file_name,
                    "bucket_path": gcs_path,
                    "archive_path": archive_dest,
                },
            )
            return True
    except subprocess.CalledProcessError as e:
        # This is a gcloud command failure, likely network/auth or permissions. Move to staging for retry.
        logger.error(f"FAILURE: A gcloud subprocess failed for '{file_name}'. Moving to staging. Stderr: {e.stderr.decode()}", exc_info=True)
        move_to_staging_folder(file_path, "A gcloud subprocess failed (e.g., KMS wrap or GCS cp)")
        return False
    except Exception as e:
        # A local file I/O error or other unexpected code issue. This is less likely to be retriable.
        logger.error(f"FAILURE: An unexpected exception occurred for '{file_name}': {str(e)}", exc_info=True)
        move_to_error_folder(file_path, f"Unexpected exception during processing: {str(e)}")
        return False
    finally:
        # Clean up the temporary encrypted file
        if os.path.exists(encrypted_output_file_path): # Add retry logic for cleanup
            cleanup_attempts = 3
            for i in range(cleanup_attempts):
                try:
                    os.remove(encrypted_output_file_path)
                    logger.info(f"Cleaned up temporary encrypted file: '{os.path.basename(encrypted_output_file_path)}'.")
                    break # Success, exit loop
                except OSError as e:
                    logger.warning(f"Attempt {i+1}/{cleanup_attempts} to remove temporary file '{os.path.basename(encrypted_output_file_path)}' failed. It may be locked. Error: {e}")
                    if i < cleanup_attempts - 1:
                        time.sleep(1) # Wait before retrying
                    else:
                        logger.error(f"Could not remove temporary file '{os.path.basename(encrypted_output_file_path)}' after {cleanup_attempts} attempts. Manual cleanup may be required.", exc_info=True)


def handle_ctrlc(sig, frame):
    global is_ctrlc_exit
    logger.critical("\nCtrl+C detected. Initiating graceful shutdown. Will exit after the current file is processed.")
    is_ctrlc_exit = True
    send_cloud_log_entry(
        severity="CRITICAL",
        message="Shutdown signal received (Ctrl+C or window close). Script will exit gracefully.",
        log_name=critical_error_log_name,
        data={"exit_type": "CtrlC", "event_type": "CriticalShutdown"},
    )


signal.signal(signal.SIGINT, handle_ctrlc)


def main():
    global is_ctrlc_exit
    if authenticate_gcloud():
        send_cloud_log_entry(
            severity="INFO",
            message="GCS ZIP Uploader script started and is now monitoring incoming files for upload.",
            log_name=activity_log_name,
            data={"event_type": "ScriptStartup"},
        )
        send_cloud_log_entry(
            severity="INFO",
            message="GCS Swan Report ZIP Uploader script started and is now monitoring incoming files for upload.",
            log_name=swan_report_log_name,
            data={"event_type": "SwanReportScriptStartup"},
        )
    else:
        logger.critical("Authentication failed. Script cannot start.")
        return # Exit if authentication fails

    logger.info(f"Monitoring ZIP folder: {zip_watch_folder} for new files. Press Ctrl+C to stop.")

    # --- MODIFIED: Add a timer for checking the staging folder. ---
    last_heartbeat_time = time.time()
    last_staging_check_time = 0 # Set to 0 to trigger an immediate check on first run
    STAGING_CHECK_INTERVAL_SECONDS = 1200 # 20 minutes

    try:
        while True:
            time.sleep(5) # Main loop delay to prevent busy-looping.
            if is_ctrlc_exit:
                break

            # Send heartbeat every HEARTBEAT_INTERVAL_SECONDS seconds
            current_time = time.time()
            if current_time - last_heartbeat_time > HEARTBEAT_INTERVAL_SECONDS:
                send_cloud_log_entry(
                    severity="INFO",
                    message="Heartbeat: ZIP Uploader script is running normally.",
                    log_name=activity_log_name,
                    data={"event_type": "Heartbeat"},
                )
                last_heartbeat_time = current_time
                logger.debug("Sent heartbeat log entry.")

            # --- MODIFIED: Process new files from the main watch folder on every loop. ---
            current_files = glob.glob(os.path.join(zip_watch_folder, "*.zip"))
            for file_path in current_files:
                if os.path.isfile(file_path):
                    upload_and_archive_zip(file_path)
            
            # --- MODIFIED: Periodically check the staging folder for files to retry. ---
            if current_time - last_staging_check_time >= STAGING_CHECK_INTERVAL_SECONDS:
                logger.info(f"Scheduled check: Looking for files to retry in '{staging_folder}'...")
                # Attempt to re-authenticate to ensure connection is fresh before retrying.
                if authenticate_gcloud(max_retries=1):
                    staged_files = glob.glob(os.path.join(staging_folder, "*.zip"))
                    if staged_files:
                        logger.info(f"Found {len(staged_files)} file(s) in staging. Attempting to process them.")
                        for file_path in staged_files:
                            if is_ctrlc_exit: break
                            if os.path.isfile(file_path):
                                logger.info(f"Retrying staged file: {os.path.basename(file_path)}")
                                upload_and_archive_zip(file_path)
                else:
                    logger.warning("Authentication failed. Cannot process staged files. Will try again in 20 minutes.")
                last_staging_check_time = current_time

    except Exception as e:
        error_message = str(e)
        logger.critical(f"CRITICAL SCRIPT ERROR: Script terminated unexpectedly. Error: {error_message}", exc_info=True)
        send_cloud_log_entry(
            severity="ERROR",
            message=f"GCS ZIP Uploader script terminated unexpectedly: {error_message}",
            log_name=critical_error_log_name,
            data={"error_type": "UnexpectedTermination", "full_error": error_message},
        )
        send_cloud_log_entry(
            severity="ERROR",
            message=f"GCS Swan Report ZIP Uploader script terminated unexpectedly: {error_message}",
            log_name=swan_report_log_name,
            data={"error_type": "UnexpectedTermination", "full_error": error_message},
        )
        raise
    finally:
        logger.info(f"Script finished. Check Cloud Logging '{critical_error_log_name}' and '{swan_report_log_name}' for details if an error occurred.")


def run_script_with_retries(max_retries=3, delay_seconds=10):
    attempt = 0
    while attempt < max_retries:
        try:
            main()
            # If main() exits, it's either a graceful shutdown or an unrecoverable auth failure.
            # In either case, we should break the retry loop.
            break
        except Exception as e:
            attempt += 1
            logger.error(f"Attempt {attempt} of {max_retries} failed with exception: {str(e)}", exc_info=True)
            if attempt < max_retries:
                logger.info(f"Retrying after {delay_seconds} seconds...")
                time.sleep(delay_seconds)
            else:
                logger.critical("Maximum retry attempts reached. Script will exit.")
                send_cloud_log_entry(
                    severity="CRITICAL",
                    message=f"ZIP uploader script failed after {max_retries} retries. Manual intervention required.",
                    log_name=critical_error_log_name,
                    data={"event_type": "MaxRetryFailure"},
                )
                sys.exit(1)


if __name__ == "__main__":
    run_script_with_retries()
