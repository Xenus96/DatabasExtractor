import base64
import binascii
import json
import os
import shutil
import sqlite3
import subprocess
import time
import xml.etree.ElementTree as ET
import re
import sys
import html
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import hmac
import hashlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from datetime import datetime, timedelta, timezone

# Logo
logo = """
  _____          _          _                  ______        _                      _               
 |  __ \        | |        | |                |  ____|      | |                    | |              
 | |  | |  __ _ | |_  __ _ | |__    __ _  ___ | |__   __  __| |_  _ __  __ _   ___ | |_  ___   _ __ 
 | |  | | / _` || __|/ _` || '_ \  / _` |/ __||  __|  \ \/ /| __|| '__|/ _` | / __|| __|/ _ \ | '__|
 | |__| || (_| || |_| (_| || |_) || (_| |\__ \| |____  >  < | |_ | |  | (_| || (__ | |_| (_) || |   
 |_____/  \__,_| \__|\__,_||_.__/  \__,_||___/|______|/_/\_\ \__||_|   \__,_| \___| \__|\___/ |_|    
                                                                                    
"""

# Script Information
script_name = "DatabasExtractor"
author = "Xenus96"
github_url = "https://github.com/Xenus96/DatabasExtractor/tree/main"
license_type = "Attribution-NonCommercial-NoDerivatives 4.0 International"
version = "1.5"  #

# Display the information
print("======================================================================================================")
print(logo)
print("======================================================================================================")
print(f"\nAuthor: {author}")
print(f"Script Name: {script_name} version {version}")
print(f"GitHub Repository: {github_url}")
print(f"License: {license_type}")
print("\nFor detailed documentation, visit the GitHub repository.\n")


# Automatically find adb.exe if not in PATH
def find_adb():
    # Try if adb is already in PATH
    if shutil.which("adb"):
        return "adb"

    # Drives to search (you can add more drives if needed)
    drives = ['C:\\', 'D:\\']

    print("\033[33m[+] Searching for 'adb.exe' on your system...\033[0m")
    for drive in drives:
        for root, dirs, files in os.walk(drive):
            if "adb.exe" in files:
                adb_path = os.path.join(root, "adb.exe")
                print(f"\033[32m[✓] Found adb.exe at:\033[0m {adb_path}")
                return f'"{adb_path}"'
    print("\033[31m[✕] Could not find adb.exe automatically. Please install ADB or add it to your PATH.\033[0m")
    return None

# Set ADB path globally
ADB = find_adb()
if not ADB:
    exit(1)


# A function to execute ADB commands
def run_adb_command(command):
    full_command = f"{ADB} {command}" if not command.strip().startswith("adb") else command.replace("adb", ADB, 1)
    result = subprocess.run(full_command, shell=True, capture_output=True, text=True, encoding='utf-8')  # Allowing ADB to pull files with utf-8 encoded names
    if result.returncode != 0:
        print(f"\033[31m[✕] Error executing command:\033[0m {full_command}")
        print(result.stderr)
        return None
    return result.stdout


# A function to check root access
def check_root_access():
    whoami_output = run_adb_command("adb shell su -c whoami")
    if whoami_output and whoami_output.strip() == "root":
        return True
    return False

# A function which opens Viber database binary files and execute the SQL command "PRAGMA wal_checkpoint(FULL);" to write all temporary data from "..-wal" file to the main database
def checkpoint_sqlite_wal(database_path):
    try:
        conn = sqlite3.connect(database_path, timeout=10)
        conn.execute('PRAGMA wal_checkpoint(FULL);')
        conn.close()
        print(f"\033[32m[✓] WAL checkpoint completed for:\033[0m {database_path}")
    except Exception as e:
        print(f"\033[31m[✕] Failed to checkpoint {database_path}:\033[0m {e}")


# A function to copy files on the device using 'cp' command and organize them into folders
def copy_files_from_device(remote_paths, local_dir, folder_name):

    # Create a folder for the messenger in the destination directory
    messenger_folder = f"{local_dir}/{folder_name}"
    run_adb_command(f"adb shell mkdir -p {messenger_folder}")                      # Use 'cp' command to copy files on the device

    # Copying files in a cycle
    for remote_path in remote_paths:
        file_name = os.path.basename(remote_path)
        destination_path = f"{messenger_folder}/{file_name}"

        # Use 'cp' command to copy files on the device
        copy_command = f"adb shell su -c 'cp -r {remote_path} {destination_path}'"
        result = run_adb_command(copy_command)
        # If the file which is being copied throws an error, then skip it
        if result is None:
            print(f"\033[33m[✕] Skipped {remote_path} due to copy error.\033[0m")
            continue
        print(f"\033[32m[✓] Copied\033[0m {remote_path} \033[32mto\033[0m {destination_path}")

    # Pulling the directory 'DatabasExtractor' from Mobile Device to the local computer into the C:/Users/%username%/Downloads
    print(f"\033[34m[+] Pulling for files from\033[0m {messenger_folder} \033[34mto the local computer...\033[0m")
    windows_folder_path = os.path.join(os.path.expanduser("~\Downloads"), "DatabasExtractor")

    if not (os.path.exists(windows_folder_path) and os.path.isdir(windows_folder_path)):
        # Creating a DatabasExtractor folder in Windows OS if it isn't there
        try:
            print(f"[+] Creating a new folder at {windows_folder_path}")
            os.mkdir(windows_folder_path)
            print(f"\033[32m[✓] Folder created at:\033[0m {windows_folder_path}")
        except Exception as e:
            print(f"\033[31m[✕] An error occurred:\033[0m {e}")

    # Pulling files one-by-one from the Mobile Device
    print(
        f"\033[34m[+] Pulling individual files from\033[0m {messenger_folder} \033[34mto\033[0m {windows_folder_path}...")

    # List files in the device folder
    file_list_output = run_adb_command(f'adb shell su -c "find {messenger_folder} -type f"')
    if not file_list_output:
        print(f"\033[31m[✕] Failed to list files in {messenger_folder}.\033[0m")
        return

    device_files = file_list_output.strip().split('\n')
    for device_file in device_files:
        relative_path = device_file.replace(messenger_folder + '/', '')
        local_file_path = os.path.join(windows_folder_path, folder_name, relative_path.replace('/', os.sep))

        # Ensure the local directory exists
        os.makedirs(os.path.dirname(local_file_path), exist_ok=True)

        # Pull the file. If the file throws an error, then skip it. The option '-a' allows to handle filenames with special character encodings
        pull_result = run_adb_command(f'adb pull -a "{device_file}" "{local_file_path}"')
        if pull_result is None:
            print(f"\033[33m[!] Skipped file due to pull error:\033[0m {device_file}")
        else:
            print(f"\033[32m[✓] Pulled:\033[0m {relative_path}")

    # Renaming extracted Viber files so they have the correct database form. If the files are already exist and renamed, then skip this process
    if folder_name == "Viber":
        windows_viber_folder = os.path.expanduser("~\Downloads\DatabasExtractor\Viber\com.viber.voip\databases/")

        # Perform WAL checkpoint before renaming
        try:
            checkpoint_sqlite_wal(f"{windows_viber_folder}/viber_data")
            checkpoint_sqlite_wal(f"{windows_viber_folder}/viber_messages")
            checkpoint_sqlite_wal(f"{windows_viber_folder}/viber_prefs")
        except Exception as e:
            print(f"\033[31m[!] Error during WAL checkpoint:\033[0m {e}")

        # Then safely rename
        try:
            os.rename(f"{windows_viber_folder}/viber_data", f"{windows_viber_folder}/viber_data.db")
            os.rename(f"{windows_viber_folder}/viber_messages", f"{windows_viber_folder}/viber_messages.db")
            os.rename(f"{windows_viber_folder}/viber_prefs", f"{windows_viber_folder}/viber_prefs.db")
        except FileExistsError as e:
            print(f"[!] Skipping the renaming process because of the {e} exception.")


    # Decrypting the Signal Messenger SQLCipher key
    elif folder_name == "Signal":
        # Reading the XML file with Signal AES GCM parameters
        xml_secrets_file_path = os.path.expanduser(
            "~\\Downloads\\DatabasExtractor\\Signal\\org.thoughtcrime.securesms\\shared_prefs\\org.thoughtcrime.securesms_preferences.xml")
        with open(xml_secrets_file_path, 'r', encoding='utf-8') as f:
            xml_content = f.read()

        # SQLCipher settings to decrypt the file "signal.db" in SQLCipher for DB Browser
        sqlcipher_settings = '''
SQLCipher parameters:
Encryption settings: Custom
Page size: 4096
KDF iterations: 1
HMAC algorithm: SHA-1
KDF algorithm: SHA-1
Plaintext Header Size: 0
'''

        try:
            # Extract Signal secrets from the XML file
            data, iv = extract_secrets_from_xml(xml_content, "pref_database_encrypted_secret")
            print("[+] Signal AES GCM parameters:")
            print(f"[+] Extracted ciphertext: {data}")
            print(f"[+] Extracted IV: {iv}")

            # Extracting the AES GCM Secret Key from the database "persistent.sqlite"
            persistent_database_file_path = os.path.expanduser("~\Downloads\DatabasExtractor\Signal\persistent.sqlite")
            hex_key = extract_specific_blob_segment(persistent_database_file_path)

            # Try to decrypt the SQLCipher key with the given HEX key. If fails then asks the user to input another HEX key.
            try:
                decrypted = aes_gcm_decrypt(data, iv, hex_key)
                print("\033[32m[✓] Decryption successful!\033[0m")
                print(f"[+] Decrypted key (hex/plaintext): {decrypted}")
            except ValueError as e:
                print(f"\033[31m[✕] Decryption failed:\033[0m {e}")

            # Saving the decrypted key
            sqlcipher_key_file_path = os.path.expanduser(
                "~\\Downloads\\DatabasExtractor\\Signal\\org.thoughtcrime.securesms\\databases\\sqlcipher_decrypted_key.txt")
            with open(sqlcipher_key_file_path, 'w') as file:
                file.write(f"SQLCipher decrypted key: {decrypted}\n")
                file.write(sqlcipher_settings) # Adding extra instructions for the user to simplify the use of the decrypted SQLCipher key
            print(f"[✓] Decrypted SQLCipher key was saved at: {sqlcipher_key_file_path}")

        except ValueError as e:
            print(f"\033[31m[✕] Error:\033[0m {e}")


# A function to delete the "DatabasExtractor" folder and all its contents on the Mobile Device
def delete_database_extractor_folder(local_dir):
    print(f"\n[+] Checking if {local_dir} exists on the device...")

    # Check if directory exists on the device
    check_cmd = f'adb shell "[ -d {local_dir} ]" && echo EXISTS || echo MISSING'
    result = run_adb_command(check_cmd).strip()

    if result == "EXISTS":
        print(f"[+] Deleting {local_dir} and all its contents...")
        run_adb_command(f"adb shell rm -rf {local_dir}")
        print(f"\033[32m[✓] Deleted {local_dir}.\033[0m")
    else:
        print(f"\033[33m[!] There is nothing to clean here — {local_dir} does not exist.\033[0m")


# A function to extract Signal's crypto parameters from the .xml file. The function accepts the path to the .xml file and the name of the parameter to be extracted
def extract_secrets_from_xml(xml_content: str, preference_name: str):
    try:
        root = ET.fromstring(xml_content)
        for elem in root.findall("string"):
            if elem.get("name") == preference_name:
                secret_json = json.loads(elem.text)
                return secret_json["data"], secret_json["iv"]
        raise ValueError(f"\033[31m[✕] Preference\033[0m '{preference_name}' \033[31mnot found in XML\033[0m")
    except (ET.ParseError, json.JSONDecodeError, KeyError) as e:
        raise ValueError(f"\033[31m[✕] Failed to extract secrets:\033[0m {str(e)}")


# A function to decrypt Signal's SQLCipher key with the algorithm AES in the mode GCM
def aes_gcm_decrypt(ciphertext_b64: str, iv_b64: str, hex_key: str):
    try:
        # Convert hex key to bytes (remove spaces if present)
        hex_key = hex_key.replace(" ", "")
        key = binascii.unhexlify(hex_key)

        # Decode base64 IV and ciphertext
        iv = base64.b64decode(iv_b64)
        ciphertext = base64.b64decode(ciphertext_b64)

        # Create AES-GCM cipher instance
        aesgcm = AESGCM(key)

        # Decrypt (GCM includes authentication)
        plaintext = aesgcm.decrypt(iv, ciphertext, None)

        try:
            return plaintext.decode('utf-8')
        except UnicodeDecodeError:
            return plaintext.hex()

    except (InvalidTag, binascii.Error, ValueError) as e:
        raise ValueError(f"\033[31m[✕] Decryption failed:\033[0m {str(e)}")


# A function to extract the AES GCM Secret Key of the Signal Messenger
def extract_specific_blob_segment(database_path: str) -> str:
    conn = None
    try:
        # Connect to the database
        conn = sqlite3.connect(database_path)
        cursor = conn.cursor()

        print(f"[✓] Connected to the 'persistent.sqlite' database: {database_path}")

        # Find in the database the ID of the row which has the string "SignalSecret" in it
        cursor.execute("SELECT id FROM keyentry WHERE alias = 'SignalSecret'")
        keyentry_row = cursor.fetchone()

        if not keyentry_row:
            raise ValueError("\033[31m[✕] 'SignalSecret' not found in the keyentry table\033[0m")

        keyentry_id = keyentry_row[0]
        print(f"[+] Found SignalSecret with ID: {keyentry_id} in the 'keyentry' table")

        # Searching for the Secret Key by using the found ID from the previous step
        cursor.execute("SELECT blob FROM blobentry WHERE keyentryid = ?", (keyentry_id,))
        blob_row = cursor.fetchone()

        if not blob_row or not blob_row[0]:
            raise ValueError(f"\033[31m[✕] No blob found for ID\033[0m {keyentry_id}")

        blob_data = blob_row[0]  # Copied raw bytes of the blob

        # Extract 16-byte segment (aka Secret Key) starting at byte 5 (index 5 to 21)
        if len(blob_data) < 21:
            raise ValueError("\033[31m[✕] Blob is too short to extract the required segment.\033[0m")

        extracted_segment = blob_data[5:21].hex() # Extracted Secret Key in HEX

        print(f"\n[✓] Extracted 16-byte segment of the Secret Key (HEX): {extracted_segment}")

        return extracted_segment

    except sqlite3.Error as e:
        print(f"\033[31m[✕] Database error:\033[0m {e}")
    except Exception as e:
        print(f"\033[31m[✕] Error:\033[0m {e}")
    finally: # Closing the connection to the database "persistent.sqlite"
        if conn:
            conn.close()


# ======================Signal Messenger Artefact decryption and formatting==========================

# A function to set the correct padding for Base64 encoded strings
def pad_base64(s: str) -> str:
    return s + '=' * ((4 - len(s) % 4) % 4)

# A function which does the AES CTR decryption
def aes_ctr_decrypt(key: bytes, ciphertext: bytes) -> bytes:
    iv = b'\x00' * 16  # The value of IV for AES-CTR in Signal is fixed to '0' (length of the fixed IV: 16 bytes)
    cipher = Cipher(algorithms.AES(key), modes.CTR(iv))
    decryptor = cipher.decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()

# A function which derives the Signal Messenger attachment decryption key via HMAC-SHA256
def hmac_sha256(key: bytes, data: bytes) -> bytes:
    return hmac.new(key, data, hashlib.sha256).digest()

# A function which transforms timestamps into human-readable date (primarily in the UTC+2 timezone)
def format_timestamp(key, value):
    # Combine keys from both key_value and contact fields (new keys can be added if necessary)
    timestamp_keys = {
        "account.registered_at", "pin.last_successful_entry", "storage.last_sync_time",
        "account.aci_last_signed_prekey_rotation_time",
        "account.aci_last_resort_kyber_prekey_rotation_time", "account.pni_last_signed_prekey_rotation_time",
        "account.pni_last_resort_kyber_prekey_rotation_time", "last_prekey_refresh_time",
        "misc.last_profile_refresh_time", "misc.linked_device.last_active_check_time",
        "misc.last_websocket_connect_time", "last_profile_fetch", "muted_until", "unregistered_timestamp", "timestamp",
        "deletion_timestamp", "last_force_update_timestamp"
    }

    try:
        if key in timestamp_keys:
            if isinstance(value, str):
                value = int(value)              # Transform timestamp from STRING into INTEGER
            if isinstance(value, int) and value > 1e12:
                dt = datetime.fromtimestamp(value / 1000, tz=timezone.utc) + timedelta(hours=2)             # Transforming INTEGER value of the timestamp into the real date and add +2 hours
                return f"{value} ({dt.strftime('%Y-%m-%d %H:%M:%S')} UTC+2)"
    except Exception as e:
        print(f"\033[31m[✕] Failed to format timestamp for\033[0m '{key}': {e}")
    return value


# A function to format numeric values of some keys from the specific Signal Messenger JSON files
def format_boolean_flag(key, value):
    # The list of numeric keys which has to be formatted as booleans (more keys can be added here if necessary)
    boolean_keys = {
        "settings.passphrase.timeout.enabled", "settings.screen.lock.enabled", "settings.passphrase.disabled",
        "releasechannel.has_updated_avatar", "settings.prefer.system.contact.photos", "mob_payments_enabled",
        "registration.complete", "account.has_linked_devices", "blocked", "hidden",
        "pni_signature_verified", "registered", "active", "read", "local_joined", "is_muted", "phone_number_discoverable"
    }
    # A formatting rule: if the key has the numeric value "0" then it is written as "0 (False)" in the HTML Report. The same logic for numeric values "1"
    if key in boolean_keys and isinstance(value, int):
        if value == 0:
            return f"{value} (False)"
        elif value == 1:
            return f"{value} (True)"
        else:
            return f"{value} (Unknown)"
    return value


# A function which operates the whole process of decryption of the Signal Messenger attachments
def decrypt_signal_attachment(secret_key_hex: str,
                               enc_secret_b64: str,
                               enc_secret_iv_b64: str,
                               data_random_hex: str,
                               mms_file_path: str,
                               output_path: str):
    # Decrypting the modernKey
    secret_key = bytes.fromhex(secret_key_hex)
    encrypted_secret = base64.b64decode(enc_secret_b64)
    secret_iv = base64.b64decode(enc_secret_iv_b64)

    # Create AES-GCM cipher instance
    aesgcm = AESGCM(secret_key)

    # Decrypting the JSON file which contains the "modernKey"
    decrypted_bytes = aesgcm.decrypt(secret_iv, encrypted_secret, None)

    # Decode the content of the decrypted JSON file and extract the value of the key "modernKey"
    json_str = decrypted_bytes.decode('utf-8')
    modern_key_base64 = json.loads(json_str)["modernKey"]
    modern_key = base64.b64decode(pad_base64(modern_key_base64))
    print(f"[+] Extracted modernKey: {modern_key.hex()}")

    # Derive multimedia_decryption_key using HMAC-SHA256
    data_random = bytes.fromhex(data_random_hex)
    multimedia_key = hmac_sha256(modern_key, data_random)
    print(f"[+] Derived multimedia_key (HMAC-SHA256 result): {multimedia_key.hex()}")

    # Decrypt .mms file using AES-CTR
    with open(mms_file_path, 'rb') as f:
        encrypted_attachment = f.read()

    decrypted_attachment = aes_ctr_decrypt(multimedia_key, encrypted_attachment)

    # Writing a decrypted attachment to the specified output directory
    with open(output_path, 'wb') as f:
        f.write(decrypted_attachment)

    print(f"\033[32m[✓] Decrypted attachment saved to:\033[0m {output_path}")


# A function which selects the certain keys from the specific JSON files and generates a well-designed HTML report about the User
def generate_signal_user_html_report(json_dir: str, output_path: str):
    # A function which automates the process of opening several JSON files
    def load_json(file_name):
        try:
            with open(os.path.join(json_dir, file_name), 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception as e:
            print(f"\033[31m[✕] Failed to load\033[0m {file_name}: {e}")
            return []  # If loading fails, return an empty list to avoid crashing

    # List of keys we want to extract and display in the "Account Information" section
    key_value_keys = [
        "account.username", "account.e164", "registration.complete", "registration.restore_method_token", "mob_payments_enabled",
        "registration.session_e164", "account.registered_at", "registration.session_id", "misc.last_profile_refresh_time",
        "storage.last_sync_time", "account.pni", "pin.last_successful_entry", "misc.last_websocket_connect_time",
        "account.pni_identity_public_key", "account.pni_identity_private_key",
        "account.pni_last_signed_prekey_rotation_time", "account.pni_last_resort_kyber_prekey_rotation_time",
        "account.aci", "account.aci_identity_public_key", "account.aci_identity_private_key",
        "account.aci_last_signed_prekey_rotation_time",  "account.aci_last_resort_kyber_prekey_rotation_time",
        "settings.screen.lock.enabled", "settings.screen.lock.timeout", "settings.passphrase.disabled",
        "settings.passphrase.timeout.enabled", "settings.passphrase.timeout", "settings.backups.schedule.hour",
        "settings.backups.schedule.minute", "releasechannel.has_updated_avatar",
        "settings.prefer.system.contact.photos", "emojiPref__search_language", "emojiPref__reactions_list",
        "kbs.initialRestoreMasterKey", "account.has_linked_devices", "misc.linked_device.last_active_check_time", "account.service_password",
        "last_prekey_refresh_time", "misc.cds_token",
    ]

    # Load necessary JSON files that contain user account, sessions, contacts, groups, calls, and chat folders data
    key_value_data = load_json("key_value.json")
    sessions = load_json("sessions.json")
    contacts = load_json("recipient.json")
    groups = load_json("groups.json")
    group_memberships = load_json("group_membership.json")
    calls = load_json("call.json")
    chat_folders = load_json("chat_folder.json")
    chat_folder_memberships = load_json("chat_folder_membership.json")

    # Basic HTML and CSS settings for the generated report
    html = ["<html><head><title>Signal Report</title><style>",
            "body { font-family: Arial; margin: 20px; }",
            "h2 { border-bottom: 2px solid #ccc; padding-bottom: 5px; }",
            "table { border-collapse: collapse; width: 100%; margin-bottom: 20px; }",
            "th, td { border: 1px solid #ccc; padding: 8px; text-align: left; }",
            "th { background-color: #f2f2f2; }",
            "</style></head><body>"]

    html.append("<h1>Signal Account Report</h1>")

    # Add the user's avatar if it exists
    avatar_path = os.path.join(json_dir, "avatar.jpg")
    if os.path.exists(avatar_path):
        html.append(f'<img src="{avatar_path}" alt="User Avatar" width="150"><br><br>')

    # --- Account Information Section ---
    html.append("<h2>Account Information</h2><table><tr><th>Key</th><th>Value</th></tr>")
    for entry in key_value_data:
        if entry.get("key") in key_value_keys:
            raw_value = entry.get("value", '')

            # Attempt to parse the value (e.g., timestamps or booleans)
            try:
                parsed_value = int(raw_value)
            except (ValueError, TypeError):
                parsed_value = raw_value

            # Apply formatting to timestamps and booleans
            formatted_value = format_timestamp(entry['key'], parsed_value)
            formatted_value = format_boolean_flag(entry['key'], formatted_value)

            html.append(f"<tr><td>{entry['key']}</td><td>{formatted_value}</td></tr>")
    html.append("</table>")

    # --- Sessions Section ---
    html.append("<h2>User Sessions</h2><table><tr><th>_id</th><th>account_id</th><th>address</th><th>device</th><th>record</th></tr>")
    for s in sessions:
        html.append(f"<tr><td>{s.get('_id','')}</td><td>{s.get('account_id','')}</td><td>{s.get('address','')}</td><td>{s.get('device','')}</td><td>{s.get('record','')}</td></tr>")
    html.append("</table>")

    # Define what fields we want from the contact list
    contact_fields = [
        ("ID", "_id"),
        ("Registered", "registered"),
        ("Profile Given Name", "profile_given_name"),
        ("Profile Joined Name", "profile_joined_name"),
        ("Sys Given Name", "system_given_name"),
        ("Sys Family Name", "system_family_name"),
        ("Sys Joined Name", "system_joined_name"),
        ("Nickname", "system_nickname"),
        ("Group ID", "group_id"),
        ("Distribution List ID", "distribution_list_id"),
        ("Phone", "e164"),
        ("Phone Number Discoverable", "phone_number_discoverable"),
        ("Email", "email"),
        ("Note", "note"),
        ("PNI", "pni"),
        ("PNI Verified", "pni_signature_verified"),
        ("ACI", "aci"),
        ("Blocked", "blocked"),
        ("Hidden", "hidden"),
        ("Muted Until", "muted_until"),
        ("Avatar", "profile_avatar"),
        ("Photo URI", "system_photo_uri"),
        ("Contact URI", "system_contact_uri"),
        ("Storage ID", "storage_service_id"),
        ("Last Profile Fetch", "last_profile_fetch"),
        ("Last Session Reset", "last_session_reset"),
        ("Message Expiration Time", "message_expiration_time"),
        ("Profile Key", "profile_key"),
        ("Credential", "profile_key_credential"),
        ("Unregistered At", "unregistered_timestamp"),
    ]

    # --- Contact List Section ---
    html.append("<h2>Contact List</h2><table><tr>")
    for header, _ in contact_fields:
        html.append(f"<th>{header}</th>")
    html.append("</tr>")

    # Define which contact fields should be treated as timestamps or booleans
    contact_timestamp_keys = {"last_profile_fetch", "mute_until", "unregistered_timestamp"}
    contact_boolean_keys = {"blocked", "hidden", "pni_signature_verified", "registered", "phone_number_discoverable"}

    for c in contacts:
        html.append("<tr>")
        for _, json_key in contact_fields:
            raw_value = c.get(json_key, 'None')

            try:
                parsed_value = int(raw_value)
            except (ValueError, TypeError):
                parsed_value = raw_value

            if json_key in contact_timestamp_keys:
                display_value = format_timestamp(json_key, parsed_value)
            elif json_key in contact_boolean_keys:
                display_value = format_boolean_flag(json_key, parsed_value)
            else:
                display_value = parsed_value

            html.append(f"<td>{display_value}</td>")
        html.append("</tr>")
    html.append("</table>")

    # --- Groups Membership Section ---
    html.append("<h2>Groups Membership</h2><table><tr>")
    group_fields = ["_id", "group_id", "recipient_id", "title", "avatar_key", "avatar_content_type",
                    "timestamp", "active", "distribution_id", "last_force_update_timestamp", "ID of the group member"]

    for field in group_fields:
        html.append(f"<th>{field}</th>")
    html.append("</tr>")

    # For each group, find members and create a row per member
    for g in groups:
        matching_members = [m for m in group_memberships if m.get("group_id") == g.get("group_id")]
        member_ids = [m.get("recipient_id", "") for m in matching_members] or [""]

        for member_id in member_ids:
            html.append("<tr>")
            for field in group_fields[:-1]:  # all except "ID of the group member"
                raw_value = g.get(field, '')
                try:
                    parsed_value = int(raw_value)
                except:
                    parsed_value = raw_value

                if field in {"timestamp", "last_force_update_timestamp"}:
                    display_value = format_timestamp(field, parsed_value)
                elif field == "active":
                    display_value = format_boolean_flag(field, parsed_value)
                else:
                    display_value = parsed_value

                html.append(f"<td>{display_value}</td>")
            html.append(f"<td>{member_id}</td>")
            html.append("</tr>")
    html.append("</table>")

    # --- In-App Calls Section ---
    html.append("<h2>In-App Calls</h2><table><tr>")
    call_fields = ["_id", "call_id", "message_id", "peer", "direction", "timestamp", "deletion_timestamp", "read",
                   "local_joined"]
    for field in call_fields:
        html.append(f"<th>{field}</th>")
    html.append("</tr>")

    for call in calls:
        html.append("<tr>")
        for field in call_fields:
            raw_value = call.get(field, '')
            try:
                parsed_value = int(raw_value)
            except:
                parsed_value = raw_value

            if field in {"timestamp", "deletion_timestamp"}:
                display_value = format_timestamp(field, parsed_value)
            elif field in {"read", "local_joined"}:
                display_value = format_boolean_flag(field, parsed_value)
            else:
                display_value = parsed_value

            html.append(f"<td>{display_value}</td>")
        html.append("</tr>")
    html.append("</table>")

    # --- Chat Folders Section ---
    html.append("<h2>Chat Folders</h2><table><tr>")
    folder_fields = ["_id", "name", "is_muted", "membership_type"]
    for field in folder_fields:
        html.append(f"<th>{field}</th>")
    html.append("</tr>")

    for folder in chat_folders:
        folder_id = folder.get("_id")
        membership = next((m for m in chat_folder_memberships if m.get("chat_folder_id") == folder_id), {})
        membership_type_value = membership.get("membership_type", '')

        if membership_type_value == 0:
            membership_display = "0 (Owner)"
        elif membership_type_value == 1:
            membership_display = "1 (Member)"
        else:
            membership_display = "Unknown"

        html.append("<tr>")
        for field in folder_fields:
            if field == "membership_type":
                html.append(f"<td>{membership_display}</td>")
            else:
                raw_value = folder.get(field, '')
                try:
                    parsed_value = int(raw_value)
                except:
                    parsed_value = raw_value

                if field == "is_muted":
                    display_value = format_boolean_flag(field, parsed_value)
                else:
                    display_value = parsed_value

                html.append(f"<td>{display_value}</td>")
        html.append("</tr>")
    html.append("</table>")

    # Close the HTML body
    html.append("</body></html>")

    # Write the generated HTML to the output file
    with open(output_path, 'w', encoding='utf-8') as f:
        f.write('\n'.join(html))

    # Print success message
    print(f"\033[32m[✓] HTML report generated at:\033[0m {output_path}")


# A function which generates Chat History HTML reports for each user's chat (private and group)
def generate_signal_chat_history_report(json_dir: str, output_base_dir: str):
    # Ensure the output directory exists
    os.makedirs(output_base_dir, exist_ok=True)

    # Define file extension groups for identifying media types (more file extensions can be added here is necessary)
    IMAGE_EXTENSIONS = ('.jpg', '.jpeg', '.png', '.gif', '.webp', '.bmp', '.tiff', '.heic')
    VIDEO_EXTENSIONS = ('.mp4', '.webm', '.mkv', '.mov', '.avi', '.flv', '.3gp', '.m4v')
    AUDIO_EXTENSIONS = ('.mp3', '.ogg', '.wav', '.m4a', '.flac', '.alac', '.aac', '.opus', '.amr', '.3ga', '.mpeg')
    DOCUMENT_EXTENSIONS = ('.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx', '.csv', '.txt', '.rtf', '.epub', '.mobi')
    ARCHIVE_EXTENSIONS = ('.zip', '.rar', '.7z', '.tar', '.gz', '.bz2', '.xz')

    # Helper function: Determine file type based on extension
    def detect_file_type(filename: str) -> str:
        lower = filename.lower()
        if lower.endswith(IMAGE_EXTENSIONS):
            return "image"
        elif lower.endswith(VIDEO_EXTENSIONS):
            return "video"
        elif lower.endswith(AUDIO_EXTENSIONS):
            return "audio"
        elif lower.endswith(DOCUMENT_EXTENSIONS + ARCHIVE_EXTENSIONS):
            return "document"
        else:
            return "unknown"

    # Helper function: Safely load JSON files
    def load_json(file_name):
        try:
            with open(os.path.join(json_dir, file_name), 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception as e:
            print(f"\033[31m[✕] Failed to load\033[0m {file_name}: {e}")
            return []

    # Helper function: Format Unix timestamps (milliseconds) nicely
    def format_clean_timestamp(ts: int) -> str:
        if ts and isinstance(ts, int) and ts > 0 and ts > 1e12:
            dt = datetime.fromtimestamp(ts / 1000, tz=timezone.utc) + timedelta(hours=2)
            return dt.strftime('%Y-%m-%d at %H:%M:%S (UTC+2)')
        return None

    # Helper function: Turn URLs into clickable links
    def format_body_with_links(text: str) -> str:
        url_pattern = re.compile(r'(https?://[^\s<>"]+)')
        return url_pattern.sub(r'<a href="\1" target="_blank">\1</a>', text)

    # Load all needed Signal database JSON files
    messages = load_json("message.json")
    recipients = load_json("recipient.json")
    attachments = load_json("attachment.json")
    key_values = load_json("key_value.json")
    groups = load_json("groups.json")
    threads = load_json("thread.json")

    # Try to find the current user's phone number (owner)
    owner_id = next((item.get("value") for item in key_values if item.get("key") == "account.e164"), None)
    if not owner_id:
        print("\033[31m[✕] Could not determine the owner's Signal ID (account.e164).\033[0m")
        return

    # Filter out threads that are not meaningful (Signal's system indicator)
    meaningful_threads = {t["_id"] for t in threads if t.get("meaningful_messages") == 1}
    messages = [m for m in messages if m.get("thread_id") in meaningful_threads]

    # Prepare lookup dictionaries for fast access later
    recipient_lookup = {}  # Maps recipient_id to name (or phone)
    phone_lookup = {}      # Maps recipient_id to phone
    group_title_lookup = {g.get("group_id"): g.get("title", "Unnamed Group") for g in groups}  # Group titles
    recipient_group_map = {}  # Maps recipient_id to group_id
    group_recipient_ids = set()  # Set of recipient IDs that represent groups

    # Populate lookup tables based on recipient information
    for r in recipients:
        rid = r.get("_id")
        phone = r.get("e164")
        group_id = r.get("group_id")
        name = r.get("profile_joined_name") or r.get("system_joined_name") or "Unknown"

        if not phone and group_id and group_id in group_title_lookup:
            # It's a group (no phone number)
            name = group_title_lookup[group_id]
            label = f"{name} (Group)"
            recipient_group_map[rid] = group_id
            group_recipient_ids.add(rid)
        else:
            # It's a personal chat
            label = f"{name} ({phone})" if phone else name

        recipient_lookup[rid] = label
        phone_lookup[rid] = phone

    # Build a lookup for attachments (message_id -> file part name)
    attachment_lookup = {}
    for a in attachments:
        mid = a.get("message_id")
        path = a.get("data_file", "")
        match = re.search(r"part\d+", path)
        if match:
            attachment_lookup[mid] = match.group(0)

    # Define base path to decrypted media files (change if needed)
    attachment_base_path = os.path.expanduser(r"~\\Downloads\\DatabasExtractor\\Signal\\org.thoughtcrime.securesms\\app_parts\\decrypted")

    # Group messages by their thread (chat conversation)
    thread_messages = {}
    for msg in messages:
        thread_id = msg.get("thread_id")
        if thread_id:
            thread_messages.setdefault(thread_id, []).append(msg)

    # Process each chat thread separately
    for thread_id, msgs in thread_messages.items():
        first_msg = msgs[0]

        from_id = first_msg.get("from_recipient_id")
        to_id = first_msg.get("to_recipient_id")
        from_phone = phone_lookup.get(from_id)
        to_phone = phone_lookup.get(to_id)

        # Decide who the partner is (other side of conversation)
        partner_id = to_id if from_phone == owner_id else from_id

        # Get partner's name (group or user)
        if partner_id in group_recipient_ids:
            group_id = recipient_group_map.get(partner_id)
            person = group_title_lookup.get(group_id, f"Group_{group_id}")
        else:
            person = recipient_lookup.get(partner_id, f"User_{partner_id}")

        # Make a filesystem-safe name for output file
        safe_name = re.sub(r'[^\w\-]', '_', person)
        output_path = os.path.join(output_base_dir, f"chat_with_{safe_name}.html")

        # Start building HTML report content
        html = ["<html><head><title>Chat History</title><style>",
                # Basic styles for formatting messages
                "body { font-family: Arial; background-color: #f5f5f5; padding: 20px; }",
                ".message { margin: 10px 0; max-width: 70%; padding: 10px; border-radius: 10px; position: relative; }",
                ".from { background-color: #d0eaff; align-self: flex-start; }",
                ".to { background-color: #e8ffe8; align-self: flex-end; }",
                ".container { display: flex; flex-direction: column; gap: 10px; }",
                ".sender { font-weight: bold; margin-bottom: 5px; }",
                ".timestamp { font-size: 0.8em; color: #666; margin-top: 5px; }",
                ".filename { font-size: 0.75em; color: #888; margin-top: 3px; }",
                "</style></head><body>",
                f"<h1>Chat with {person}</h1><div class='container'>"]

        # Process each message inside the thread
        for msg in msgs:
            from_id = msg.get("from_recipient_id")
            to_id = msg.get("to_recipient_id")
            mid = msg.get("_id")
            body = msg.get("body", "")
            msg_type = msg.get("type")
            from_phone = phone_lookup.get(from_id)

            # Choose style: 'to' = sent by owner, 'from' = received
            direction_class = "to" if from_phone == owner_id else "from"

            # Sender name
            sender = recipient_lookup.get(from_id, f"User {from_id}")

            # Handle and format timestamp
            raw_ts = msg.get("date_sent")
            try:
                raw_ts = int(raw_ts)
            except (ValueError, TypeError):
                raw_ts = 0

            formatted_ts = format_clean_timestamp(raw_ts)
            label = "Sent"
            timestamp_html = f"<div class='timestamp'>{label}: {formatted_ts}</div>" if formatted_ts else ""

            # Build the message block
            html.append(f"<div class='message {direction_class}'>")
            html.append(f"<div class='sender'>{sender}</div>")

            if msg_type == 2:
                # Group event: user added to group
                from_name = recipient_lookup.get(from_id, f"User {from_id}")
                to_name = recipient_lookup.get(to_id, f"User {to_id}")
                html.append(f"<div>{from_name} added {to_name} to the group</div>")
            elif msg_type == 12:
                # Call started
                html.append("<div><i>[Started a video or an audio call]</i></div>")
            elif body:
                # Normal text message
                html.append(f"<div>{format_body_with_links(body)}</div>")
            else:
                # Handle attachments if body is missing
                part_key = attachment_lookup.get(mid)
                if part_key:
                    found_file = None
                    # Try to find actual file by trying possible extensions
                    for ext in IMAGE_EXTENSIONS + VIDEO_EXTENSIONS + AUDIO_EXTENSIONS + DOCUMENT_EXTENSIONS + ARCHIVE_EXTENSIONS:
                        test_path = os.path.join(attachment_base_path, part_key + ext)
                        if os.path.exists(test_path):
                            found_file = test_path
                            break

                    if found_file:
                        # Embed or link attachment in HTML
                        path_uri = found_file.replace("\\", "/")
                        filename = os.path.basename(path_uri)
                        file_type = detect_file_type(path_uri)

                        if file_type == "image":
                            html.append(f"<img src='file:///{path_uri}' style='max-width:200px;'>")
                        elif file_type == "video":
                            html.append(f"<video controls width='250'><source src='file:///{path_uri}'></video>")
                        elif file_type == "audio":
                            html.append(f"<audio controls><source src='file:///{path_uri}'></audio>")
                        elif file_type == "document":
                            html.append(f"<a href='file:///{path_uri}' download>[Attachment: {filename}]</a>")
                        else:
                            html.append(f"<a href='file:///{path_uri}' download>[Unknown file type: {filename}]</a>")

                        html.append(f"<div class='filename'>{filename}</div>")
                    else:
                        # Attachment was missing
                        html.append("<div><i>[Missing attachment]</i></div>")
                else:
                    # If the message has no body and is not an attachment — then it is an empty message
                    html.append("<div><i>[Empty message]</i></div>")

            html.append(timestamp_html)
            html.append("</div>")  # Close message div

        html.append("</div></body></html>")  # Close container and body

        # Save the generated HTML file
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write('\n'.join(html))

        print(f"\033[32m[✓] Chat History report was saved at:\033[0m {output_path}")


# A function that extracts Signal Messenger artifacts and uses them to form readable HTML files and decrypts all user attachments
def extract_signal_artefacts():
    print("\n[+] Starting Signal artifact extraction and attachment decryption...")

    signal_dir = os.path.expanduser("~\\Downloads\\DatabasExtractor\\Signal\\org.thoughtcrime.securesms")
    xml_path = os.path.join(signal_dir, "shared_prefs", "org.thoughtcrime.securesms_preferences.xml")
    persistent_path = os.path.expanduser("~\\Downloads\\DatabasExtractor\\Signal\\persistent.sqlite")
    app_parts_dir = os.path.join(signal_dir, "app_parts")
    decrypted_dir = os.path.join(app_parts_dir, "decrypted")

    # Ensure the decrypted output directory exists
    os.makedirs(decrypted_dir, exist_ok=True)

    # Prompt user to input path to directory containing attachment.json and others
    json_dir = input("Enter full path to directory containing attachment.json and related JSON files: ").strip()
    attachment_json_path = os.path.join(json_dir, "attachment.json")

    if not os.path.exists(attachment_json_path):
        print("\033[31[✕] mattachment.json not found. Aborting decryption.\033[0m")
        return

    try:
        with open(attachment_json_path, 'r', encoding='utf-8') as aj:
            attachment_data = json.load(aj)
    except Exception as e:
        print(f"\033[31m[✕] Failed to load attachment.json: {e}\033[0m")
        return

    # Load XML content and extract enc_secret and IV
    with open(xml_path, 'r', encoding='utf-8') as f:
        xml_content = f.read()
    enc_secret_b64, enc_secret_iv_b64 = extract_secrets_from_xml(xml_content, "pref_attachment_encrypted_secret")

    # Extract secret_key from persistent.sqlite
    secret_key_hex = extract_specific_blob_segment(persistent_path)

    # Loop over .mms files in app_parts_dir
    for file_name in os.listdir(app_parts_dir):
        if file_name.endswith(".mms"):
            mms_path = os.path.join(app_parts_dir, file_name)

            # Find corresponding entry in attachment.json
            matched_entry = next((entry for entry in attachment_data if entry.get("data_file", "").endswith(file_name)), None)

            if not matched_entry:
                print(f"[!] Skipping {file_name} - No matching data_file entry in attachment.json.")
                continue

            try:
                data_random_b64 = matched_entry["data_random"]
                data_random_bytes = base64.b64decode(pad_base64(data_random_b64))
                data_random_hex = data_random_bytes.hex()

                content_type = matched_entry.get("content_type", "application/octet-stream")
                extension = content_type.split("/")[-1]
                output_path = os.path.join(decrypted_dir, os.path.splitext(file_name)[0] + f".{extension}")
            except Exception as e:
                print(f"\033[31[✕] Failed to prepare decryption for\033[0m {file_name}: {e}")
                continue

            try:
                decrypt_signal_attachment(
                    secret_key_hex,
                    enc_secret_b64,
                    enc_secret_iv_b64,
                    data_random_hex,
                    mms_path,
                    output_path
                )
            except Exception as e:
                print(f"\033[31[!] Failed to decrypt\033[0m {file_name}: {e}")

    # Generate General HTML report about the user
    html_output = os.path.join(json_dir, "Signal_User_Report.html")
    generate_signal_user_html_report(json_dir, html_output)
    # Generate the user's Chat History HTML reports
    chat_output_dir = os.path.join(json_dir, "Chats")
    generate_signal_chat_history_report(json_dir, chat_output_dir)

# ======================================================================================


# ======================Viber Messenger Artefact formatting=============================

# A function which generates the General User HTML Report based on the user artefacts from the Viber Messenger
def generate_viber_user_report(output_path: str):
     # Format timestamp from milliseconds to human-readable UTC+2 format
    def format_timestamp(value):
        try:
            value = int(value)
            if value > 1e12:
                dt = datetime.fromtimestamp(value / 1000, tz=timezone.utc) + timedelta(hours=2)
                return f"{value} ({dt.strftime('%Y-%m-%d %H:%M:%S')} UTC+2)"
        except:
            pass
        return value

    # Convert boolean flags (0/1) into more descriptive text
    def format_boolean(value):
        return f"{value} (True)" if str(value) == "1" else f"{value} (False)"

    # Extract primary Viber user account details from the messages database
    def query_user_account(db_path):
        try:
            conn = sqlite3.connect(db_path)
            cur = conn.cursor()
            cur.execute("""
                SELECT 
                    _id, viber_name, display_name, date_of_birth, number, encrypted_number, 
                    viber_id, member_id, dating_id, encrypted_member_id, has_photo, 
                    viber_image, up_date 
                FROM participants_info 
                WHERE participant_type = 0
            """)
            row = cur.fetchone()
            if row:
                columns = [desc[0] for desc in cur.description]
                return dict(zip(columns, row))
            return {}
        except Exception as e:
            print(f"[!] Failed to query account info: {e}")
            return {}
        finally:
            conn.close()

    # Setup directory paths for accessing Viber data
    viber_dir = os.path.expanduser("~\\Downloads\\DatabasExtractor\\Viber\\com.viber.voip")
    db_messages = os.path.join(viber_dir, "databases", "viber_messages.db")
    avatar_dir = os.path.join(viber_dir, "files", "User photos")

    # Initialize HTML report layout and styles
    html = ["<html><head><title>Viber User Report</title><style>",
            "body { font-family: Arial; margin: 20px; }",
            "h2 { border-bottom: 2px solid #ccc; padding-bottom: 5px; }",
            "table { border-collapse: collapse; width: 100%; margin-bottom: 20px; }",
            "th, td { border: 1px solid #ccc; padding: 8px; text-align: left; }",
            "th { background-color: #f2f2f2; }",
            "img { max-width: 150px; max-height: 150px; }",
            "</style></head><body>"]

    html.append("<h1>Viber Account Report</h1>")

    # ===== Account Information section ======
    html.append("<h2>Account Information</h2><table>")
    user_info = query_user_account(db_messages)

    if user_info:
        # If available, embed the user's avatar image into the report
        avatar_filename = user_info.get("viber_image", "")
        avatar_path = os.path.join(avatar_dir, avatar_filename)
        if avatar_filename and os.path.exists(avatar_path):
            html.append(f'<tr><td colspan="2"><img src="file:///{avatar_path}" alt="User Avatar"></td></tr>')

        # Display all account fields and format relevant ones
        for key, value in user_info.items():
            if key == "has_photo":
                value = format_boolean(value)
            elif key == "up_date":
                value = format_timestamp(value)
            html.append(f"<tr><th>{key}</th><td>{value}</td></tr>")
    else:
        html.append("<tr><td colspan='2'>No account information found.</td></tr>")
    html.append("</table>")

    # ===== User Sessions section ======
    html.append("<h2>User Sessions</h2><table>")
    html.append("<tr><th>Session ID</th><th>Started At</th><th>Product</th><th>Model</th><th>Manufacturer</th>"
                "<th>Disk (GB)</th><th>RAM (GB)</th><th>Emulator</th><th>OS Version</th><th>Rooted</th></tr>")

    # Analyze sessions from the crashlytics directory
    session_dir = os.path.join(viber_dir, "files", ".crashlytics.v3", "com.viber.voip", "open-sessions")
    if os.path.exists(session_dir):
        for session_id in os.listdir(session_dir):
            native_path = os.path.join(session_dir, session_id, "native")
            try:
                # Parse JSON session files for device and OS info
                with open(os.path.join(native_path, "device.json"), "r", encoding="utf-8") as f:
                    device_data = json.load(f)
                with open(os.path.join(native_path, "os.json"), "r", encoding="utf-8") as f:
                    os_data = json.load(f)
                with open(os.path.join(native_path, "session.json"), "r", encoding="utf-8") as f:
                    session_data = json.load(f)

                # Convert bytes to gigabytes
                def b2gb(b):
                    try:
                        return round(int(b) / (1024 ** 3), 2)
                    except:
                        return "N/A"

                # Convert session start timestamp
                started = session_data.get("started_at_seconds")
                started_fmt = format_timestamp(int(started) * 1000) if started else "N/A"

                html.append(f"<tr><td>{session_data.get('session_id', '')}</td>"
                            f"<td>{started_fmt}</td>"
                            f"<td>{device_data.get('build_product', '')}</td>"
                            f"<td>{device_data.get('build_model', '')}</td>"
                            f"<td>{device_data.get('build_manufacturer', '')}</td>"
                            f"<td>{b2gb(device_data.get('disk_space'))}</td>"
                            f"<td>{b2gb(device_data.get('total_ram'))}</td>"
                            f"<td>{device_data.get('is_emulator', '')}</td>"
                            f"<td>{os_data.get('version', '')}</td>"
                            f"<td>{os_data.get('is_rooted', '')}</td></tr>")
            except Exception as e:
                print(f"[!] Failed to parse session '{session_id}': {e}")
    else:
        html.append("<tr><td colspan='10'>No session data found.</td></tr>")
    html.append("</table>")

    # ===== Contact List section ======
    html.append("<h2>Contact List</h2><table>")
    html.append(
        "<tr><th>Avatar</th><th>Display Name</th><th>Phone Number</th><th>Date of Birth</th><th>Viber Photo</th>"
        "<th>Starred</th><th>Joined Date</th><th>Last Activity</th><th>Deleted</th><th>Blocked Date</th><th>Block Reason</th></tr>")

    db_data = os.path.join(viber_dir, "databases", "viber_data.db")
    thumbnails_dir = os.path.join(viber_dir, "files", "User photos", ".thumbnails")

    # Connect and fetch contact-related data from viber_data.db
    conn = sqlite3.connect(db_data)
    cur = conn.cursor()

    # Load main contact list
    cur.execute("SELECT * FROM phonebookcontact")
    contact_rows = cur.fetchall()
    contact_cols = [desc[0] for desc in cur.description]
    contacts = [dict(zip(contact_cols, row)) for row in contact_rows]

    # Map contact ID to associated phone numbers
    cur.execute("SELECT contact_id, data2 FROM phonebookdata")
    phone_data = cur.fetchall()
    phone_map = {}
    for contact_id, number in phone_data:
        phone_map.setdefault(contact_id, []).append(number)

    # Load additional number details (DOB, photos)
    cur.execute("SELECT canonized_number, date_of_birth, photo FROM vibernumbers")
    number_info = {row[0]: {"dob": row[1], "photo": row[2]} for row in cur.fetchall()}

    # Load blocked numbers
    cur.execute("SELECT canonized_number, blocked_date, block_reason FROM blockednumbers")
    blocked_map = {row[0]: {"blocked_date": row[1], "block_reason": row[2]} for row in cur.fetchall()}

    blocked_seen = set()
    unique_contacts = set()

    for contact in contacts:
        native_id = contact.get("native_id")
        display_name = contact.get("display_name", "")
        starred = format_boolean(contact.get("starred", 0))
        joined_date = format_timestamp(contact.get("joined_date"))
        last_activity = format_timestamp(contact.get("last_activity"))
        deleted = contact.get("deleted")
        native_photo_id = str(contact.get("native_photo_id", ""))

        numbers = phone_map.get(native_id, [])
        if not numbers:
            continue  # Skip contact if no associated phone numbers

        for phone in numbers:
            if phone in unique_contacts:
                continue  # Avoid duplicates
            unique_contacts.add(phone)

            dob = number_info.get(phone, {}).get("dob", "")
            photo = number_info.get(phone, {}).get("photo", "")
            blocked = blocked_map.get(phone, {})
            blocked_date = format_timestamp(blocked.get("blocked_date")) if "blocked_date" in blocked else ""
            block_reason = blocked.get("block_reason", "")
            if blocked:
                blocked_seen.add(phone)

            # Find a thumbnail avatar based on photo ID
            avatar_path = ""
            for fname in os.listdir(thumbnails_dir):
                if fname.startswith(native_photo_id) and fname.lower().endswith(".jpg"):
                    avatar_path = os.path.join(thumbnails_dir, fname)
                    break

            # Add contact row to table
            html.append("<tr>")
            html.append(f"<td><img src='file:///{avatar_path}'></td>" if avatar_path else "<td>N/A</td>")
            html.append(f"<td>{display_name}</td>")
            html.append(f"<td>{phone}</td>")
            html.append(f"<td>{dob}</td>")
            html.append(f"<td>{photo}</td>")
            html.append(f"<td>{starred}</td>")
            html.append(f"<td>{joined_date}</td>")
            html.append(f"<td>{last_activity}</td>")
            html.append(f"<td>{deleted}</td>")
            html.append(f"<td>{blocked_date}</td>")
            html.append(f"<td>{block_reason}</td>")
            html.append("</tr>")

    conn.close()
    html.append("</table>")

    # ===== Groups Membership (Public) =====
    html.append("<h2>Groups Membership (Public conversations)</h2><table>")
    html.append("<tr><th>ID</th><th>Group Name</th><th>Category</th><th>Subtitle</th><th>Icon</th></tr>")

    try:
        conn = sqlite3.connect(db_messages)
        cur = conn.cursor()
        cur.execute("SELECT _id, name, category, subtitle, icon FROM public_accounts")
        for row in cur.fetchall():
            html.append("<tr>")
            for col in row:
                html.append(f"<td>{col}</td>")
            html.append("</tr>")
    except Exception as e:
        print(f"[!] Error loading public_accounts: {e}")
    finally:
        conn.close()

    html.append("</table>")

    # ===== Groups Membership (Private Conversations) =====
    html.append("<h2>Groups Membership (Private conversations)</h2><table>")
    html.append("<tr><th>_id</th><th>group_id</th><th>name</th><th>group_role</th><th>icon_id</th><th>delete_token</th>"
                "<th>mute_notification</th><th>date</th><th>favourite_conversation</th><th>save_to_gallery</th><th>last_opened_timestamp</th></tr>")

    try:
        conn = sqlite3.connect(db_messages)
        cur = conn.cursor()
        cur.execute("""
            SELECT _id, group_id, name, group_role, icon_id, delete_token,
                   mute_notification, date, favourite_conversation,
                   save_to_gallery, last_opened_timestamp
            FROM conversations
            WHERE LENGTH(group_id) > 10
        """)
        for row in cur.fetchall():
            (_id, group_id, name, role, icon_id, token, mute, date,
             fav, save, last_opened) = row

            html.append("<tr>")
            html.append(f"<td>{_id}</td>")
            html.append(f"<td>{group_id}</td>")
            html.append(f"<td>{name}</td>")
            html.append(f"<td>{role}</td>")
            html.append(f"<td>{icon_id}</td>")
            html.append(f"<td>{token}</td>")
            html.append(f"<td>{'1 (True)' if mute else '0 (False)'}</td>")
            html.append(f"<td>{format_timestamp(date)}</td>")
            html.append(f"<td>{'1 (True)' if fav else '0 (False)'}</td>")
            if save == 1:
                html.append(f"<td>1 (Do not save media from this group to the local memory)</td>")
            elif save == 0:
                html.append(f"<td>0 (Save media from this group to the local memory)</td>")
            else:
                html.append(f"<td>{save}</td>")
            html.append(f"<td>{format_timestamp(last_opened)}</td>")
            html.append("</tr>")
    except Exception as e:
        print(f"[!] Error loading private group conversations: {e}")
    finally:
        conn.close()

    html.append("</table>")

    # ===== In-App Calls section ======
    html.append("<h2>In-App Calls</h2><table>")
    html.append("<tr><th>Call ID</th><th>Phone Number</th><th>Date</th><th>Duration (s)</th>"
                "<th>Start Reason</th><th>End Reason</th><th>Token</th><th>Group ID</th></tr>")

    db_data = os.path.join(viber_dir, "databases", "viber_data.db")
    try:
        # Connect to viber_data.db and extract call records
        conn = sqlite3.connect(db_data)
        cur = conn.cursor()

        cur.execute(
            "SELECT call_id, canonized_number, date, duration, start_reason, end_reason, token, group_id FROM calls")
        for row in cur.fetchall():
            call_id, number, date, duration, start_reason, end_reason, token, group_id = row
            date_fmt = format_timestamp(date)

            # Write each call record into the HTML table
            html.append("<tr>")
            html.append(f"<td>{call_id}</td>")
            html.append(f"<td>{number}</td>")
            html.append(f"<td>{date_fmt}</td>")
            html.append(f"<td>{duration}</td>")
            html.append(f"<td>{start_reason}</td>")
            html.append(f"<td>{end_reason}</td>")
            html.append(f"<td>{token}</td>")
            html.append(f"<td>{group_id}</td>")
            html.append("</tr>")
    except Exception as e:
        pass  # Prevents the HTML report from breaking if something goes wrong
    finally:
        conn.close()

    html.append("</table>")

    # ===== Chat Folders section ======
    html.append("<h2>Chat Folders</h2><table>")
    html.append("<tr><th>Folder ID</th><th>Folder Name</th><th>Chat ID(s)</th><th>Conversation ID(s)</th></tr>")

    try:
        conn = sqlite3.connect(db_messages)
        cur = conn.cursor()

        # Fetch all folders
        cur.execute("SELECT id, name FROM folders")
        folders = cur.fetchall()

        # Fetch mapping from folders_to_chats
        cur.execute("SELECT folder_id, chat_id, conversation_id FROM folders_to_chats")
        mapping = cur.fetchall()

        # Organize mappings by folder_id
        folder_map = {}
        for folder_id, chat_id, conv_id in mapping:
            folder_map.setdefault(folder_id, {"chat_ids": [], "conv_ids": []})
            folder_map[folder_id]["chat_ids"].append(str(chat_id))
            folder_map[folder_id]["conv_ids"].append(str(conv_id))

        for folder_id, name in folders:
            chats = ', '.join(folder_map.get(folder_id, {}).get("chat_ids", []))
            convs = ', '.join(folder_map.get(folder_id, {}).get("conv_ids", []))

            html.append("<tr>")
            html.append(f"<td>{folder_id}</td>")
            html.append(f"<td>{name}</td>")
            html.append(f"<td>{chats}</td>")
            html.append(f"<td>{convs}</td>")
            html.append("</tr>")
    except Exception as e:
        print(f"[!] Error loading chat folders: {e}")
        pass
    finally:
        conn.close()

    html.append("</table>")


    # Saving the report
    with open(output_path, 'w', encoding='utf-8') as f:
        f.write('\n'.join(html))
    print(f"\033[32m[✓] Viber User HTML report generated at:\033[0m {output_path}")


# A function which generates an HTML report for each user's in-messenger conversation based on the artefacts collected from the Viber Messenger
def generate_viber_chat_history_report(viber_dir):
    # Paths
    base_dir = viber_dir
    db_path = os.path.join(base_dir, "databases", "viber_messages.db")
    pulled_media_dir = os.path.join(base_dir, "PulledMedia")
    os.makedirs(pulled_media_dir, exist_ok=True)

    # ADB helper function which searches for the attachment by its URI
    def get_file_path_from_uri(uri: str):
        output = run_adb_command(f'adb shell content query --uri "{uri}"')
        if not output:
            return None
        match = re.search(r'_data=([^\r\n,]+)', output)
        return match.group(1).strip() if match else None

    # A helper function which is used to pull attachments from the Mobile Device to the "~/Downloads/DatabasExtractor/Viber/com.viber.voip/PulledMedia"
    def pull_media_file(content_uri: str):
        # If the link from the column "extra_uri" points to "internal_files", then we need to Base64 decode it
        if content_uri.startswith("content://com.viber.voip.provider.internal_files"):
            base64_part = content_uri.split("/")[-1].split("?")[0]
            if "%3D" in base64_part:
                base64_part = base64_part.split("%3D")[0] + "="
            try:
                decoded = base64.b64decode(base64_part).decode("utf-8")
                content_uri = decoded
            except Exception:
                pass

        file_path = get_file_path_from_uri(content_uri)
        if not file_path:
            return None
        file_name = os.path.basename(file_path)
        local_path = os.path.join(pulled_media_dir, file_name)

        # Pulling the found by the function "get_file_path_from_uri" attachment from the Mobile Device
        run_adb_command(f'adb pull "{file_path}" "{local_path}"')
        return local_path if os.path.exists(local_path) else None

    # A helper function which formats message timestamps to UTC+2
    def format_timestamp(ts):
        try:
            ts = int(ts)
            if ts > 1e12:
                dt = datetime.fromtimestamp(ts / 1000, tz=timezone.utc) + timedelta(hours=2)
                return dt.strftime('%Y-%m-%d at %H:%M:%S (UTC+2)')
        except:
            return ""
        return ""

    # A helper function which extracts only the http link and valuable text from the key "body" of the message if it is a JSON object
    def parse_body(body_str):
        try:
            data = json.loads(body_str)
            texts = []
            urls = set()

            for item in data:
                # Collect all text entries
                text = item.get("Text")
                if text:
                    texts.append(text.strip())

                # Collect all unique URLs
                url = item.get("Action", {}).get("parameters", {}).get("url")
                if url:
                    urls.add(url.strip())

            result = ""
            if texts:
                result += "<div>" + "<br>".join(texts) + "</div>"

            if urls:
                url = list(urls)[0]  # Take only the first unique URL
                result += f'<div><a href="{url}" target="_blank">{url}</a></div>'

            return result if result else body_str
        except Exception:
            return body_str

    # Load data
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()

    # Get info about the user from the table "participants_info" of the database "viber_messages.db"
    cur.execute("SELECT _id, number, viber_name, contact_id, participant_type, member_id, display_name FROM participants_info")
    participants_info_map = {row[0]: {
        "number": row[1],
        "name": row[6] if row[6] else (row[2] if row[2] else row[3]),  # Prefer display_name, then viber_name, then contact_id
        "type": row[4],
        "member_id": row[5]
    } for row in cur.fetchall()}
    # Build a correct reverse lookup: member_id → viber_name
    member_id_to_name = {}
    for p in participants_info_map.values():
        member_id = p.get("member_id")
        name = p.get("name")
        if member_id:
            member_id_to_name[member_id] = name

    # Get valuable info about all user conversations from the table "conversations" of the database "viber_messages.db"
    cur.execute("SELECT group_id, name FROM conversations")
    group_name_map = {row[0]: row[1] for row in cur.fetchall()}

    # Get valuable info about all conversation participants from the table "participants" of the database "viber_messages.db"
    cur.execute("SELECT conversation_id, participant_info_id FROM participants")
    conversation_participants = {}
    for cid, pid in cur.fetchall():
        conversation_participants.setdefault(cid, set()).add(pid)

    # Get necessary info about each user message from the table "messages" of the database "viber_messages.db"
    cur.execute("""
        SELECT _id, conversation_id, msg_date, send_type, body, extra_uri, destination_uri,
               group_id, msg_info_bin, msg_info, quoted_message_data, token
        FROM messages ORDER BY msg_date ASC
    """)
    messages = cur.fetchall()
    conn.close()

    # Group messages
    grouped = {}
    for msg in messages:
        (msg_id, cid, ts, send_type, body, extra_uri, dest_uri, group_id,
         msg_info_bin, msg_info, quoted_data, token) = msg

        group_key = group_id if group_id else cid
        grouped.setdefault(group_key, []).append({
            "id": msg_id,
            "cid": cid,
            "ts": ts,
            "send_type": send_type,
            "body": body,
            "extra_uri": extra_uri,
            "dest_uri": dest_uri,
            "group_id": group_id,
            "msg_info_bin": msg_info_bin,
            "msg_info": msg_info,
            "quoted_data": quoted_data,
            "token": token
        })

    # Chat History HTML Report generation
    for group_key, msgs in grouped.items():
        is_group = bool(msgs[0]["group_id"])
        if is_group:
            name = group_name_map.get(msgs[0]["group_id"], f"Group_{group_key}")
            file_name = f"Chat_with_{name}.html"
            title = f"Chat with {name}"
        else:
            pid_set = conversation_participants.get(msgs[0]["cid"], set())
            member = next((participants_info_map[pid] for pid in pid_set if participants_info_map[pid]["type"] != 0), None)
            if not member:
                continue
            name = member["name"]
            number = member["number"]
            file_name = f"Chat_with_{name}_({number}).html"
            title = f"Chat with {name} ({number})"

        # All Chat History reports will be saved at "~\Downloads\DatabasExtractor\Viber\com.viber.voip\Chats"
        chats_dir = os.path.join(base_dir, "Chats")
        # Check if the target folder exists
        os.makedirs(chats_dir, exist_ok=True)
        html_path = os.path.join(chats_dir, file_name)

        html = [
            "<html><head><title>Chat History</title><style>",
            "body { font-family: Arial; background-color: #f5f5f5; padding: 20px; }",
            ".message { margin: 10px 0; max-width: 70%; padding: 10px; border-radius: 10px; position: relative; }",
            ".from { background-color: #d0eaff; align-self: flex-start; }",
            ".to { background-color: #e8ffe8; align-self: flex-end; }",
            ".container { display: flex; flex-direction: column; gap: 10px; }",
            ".sender { font-weight: bold; margin-bottom: 5px; }",
            ".timestamp { font-size: 0.8em; color: #666; margin-top: 5px; }",
            ".filename { font-size: 0.75em; color: #888; margin-top: 3px; }",
            "</style></head><body>",
            f"<h1>{title}</h1><div class='container'>"
        ]

        # A list of file extensions which can be used to process different Viber attachments pulled from the Mobile Device
        document_extensions = [
            ".pdf", ".doc", ".docx", ".odt", ".rtf", ".tex", # Documents
            ".xls", ".xlsx", ".ods", ".csv",                 # Spreadsheets
            ".ppt", ".pptx", ".odp",                         # Presentations
            ".txt", ".md", ".log", ".ini", ".cfg", ".json", ".xml", ".yaml", ".yml", ".html", ".htm", ".js", ".py",
            ".java", ".cpp", ".c", ".cs",                    # Text & code
            ".zip", ".rar", ".7z", ".tar", ".gz", ".bz2", ".xz", ".iso", # Archives
            ".exe", ".msi", ".apk", ".bat", ".sh", ".jar",   # Executables & installers
            ".mp3", ".m4a", ".aac", ".wav", ".ogg", ".flac", ".amr",  # Audio
            ".mp4", ".mkv", ".webm", ".avi", ".mov", ".wmv", ".flv",  # Video
            ".jpg", ".jpeg", ".png", ".gif", ".webp", ".bmp", ".tiff", ".svg", ".heic", # Images
            ".epub", ".mobi", ".azw", ".azw3",               # E-books
            ".dwg", ".dxf", ".stl", ".obj", ".fbx"           # CAD/3D
        ]

        for m in msgs:
            direction = "to" if m["send_type"] == 1 else "from"
            participants = conversation_participants.get(m["cid"], set())
            sender = next((participants_info_map[pid] for pid in participants if
                           (participants_info_map[pid]["type"] == 0 and m["send_type"] == 1) or
                           (participants_info_map[pid]["type"] != 0 and m["send_type"] == 0)), None)

            if not sender:
                continue

            sender_name = sender["name"]
            sender_number = sender["number"]
            timestamp = format_timestamp(m["ts"])

            body = m["body"]
            if body and body.strip().startswith("[{"):
                body = parse_body(body)

            # If the body of the message is the string "(purple_heart)", then skip it
            elif body and "(purple_heart)" in body:
                continue

            # If the body of the message is the string "message_deleted/...", then find the name of the user who deleted the message by his member_id
            elif body and body.startswith("message_deleted/"):
                encoded_member_id = body.split("/", 1)[1]
                actual_member_id = encoded_member_id.replace("0#", "/")
                deleted_by = member_id_to_name.get(actual_member_id, "Unknown")
                body = f"<i>[Message deleted by {deleted_by}]</i>"

            # If the body of the message starts with the string "content://", then check the column "extra_uri"
            elif body and body.startswith("content://com.viber.voip"):
                # pull the attachment with the function "pull_media_file" by its "extra_uri"
                file_path = pull_media_file(m["extra_uri"])
                if file_path:
                    ext = os.path.splitext(file_path)[1].lower()
                    uri = file_path.replace("\\", "/")
                    if ext in [".jpg", ".jpeg", ".png", ".gif", ".webp"]:
                        body = f"<img src='file:///{uri}' style='max-width:200px;'><div class='filename'>{os.path.basename(uri)}</div>"
                    elif ext in [".mp4", ".webm", ".mkv", ".avi"]:
                        body = f"<video controls width='250'><source src='file:///{uri}'></video><div class='filename'>{os.path.basename(uri)}</div>"
                    elif ext in [".mp3", ".m4a", ".aac", ".wav"]:
                        body = f"<audio controls><source src='file:///{uri}'></audio><div class='filename'>{os.path.basename(uri)}</div>"
                    else:
                        body = f"<a href='file:///{uri}' target='_blank'>{os.path.basename(uri)}</a>"

            # If the body of the message contains the file extension '.m4a', then it is an audio message from the Viber folder "/.ppt"
            elif body and body.strip().lower().endswith(".m4a"):
                ptt_dir = os.path.join(base_dir, "files", ".ptt")
                ptt_path = os.path.join(ptt_dir, body.strip())
                if os.path.exists(ptt_path):
                    uri = ptt_path.replace("\\", "/")
                    body = f"""<audio controls>
                                 <source src="file:///{uri}" type="audio/mp4">
                                 Your browser does not support the audio element.
                               </audio><div class='filename'>{os.path.basename(uri)}</div>"""
                else:
                    body = f"<i>Voice message not found: {body}</i>"
            elif body:
                stripped_body = body.strip()
                lower_body = stripped_body.lower()
                ext = os.path.splitext(lower_body)[1]

                # If it's not audio or multimedia, but matches known attachments
                if ext in document_extensions and not lower_body.endswith(".m4a"):
                    remote_path = f"/storage/emulated/0/Download/{stripped_body}"
                    local_path = os.path.join(pulled_media_dir, stripped_body)
                    run_adb_command(f'adb pull "{remote_path}" "{local_path}"')
                    if os.path.exists(local_path):
                        uri = local_path.replace("\\", "/")
                        body = f"<a href='file:///{uri}' target='_blank'>{os.path.basename(uri)}</a><div class='filename'>Attachment</div>"
                    else:
                        body = f"<i>Attachment not found: {stripped_body}</i>"

            elif not body:
                body = "<i>[Empty message]</i>"

            html.append(f"<div class='message {direction}'>")
            html.append(f"<div class='sender'>{sender_name} ({sender_number})</div>")
            html.append(f"<div>{body}</div>")
            html.append(f"<div class='timestamp'>Sent: {timestamp}</div>")
            html.append("</div>")

        html.append("</div></body></html>")

        with open(html_path, "w", encoding="utf-8") as f:
            f.write("\n".join(html))
        print(f"\033[32m[✓] Viber Chat report saved:\033[0m {html_path}")



# Functions that do the process of extracting the artefacts of the Viber Messenger and transforming them into the .html files
def extract_viber_artefacts():
    print("\n[+] Starting Viber artifact extraction and report generation...")

    viber_dir = os.path.expanduser("~\\Downloads\\DatabasExtractor\\Viber\\com.viber.voip")
    user_report_path = os.path.join(viber_dir, "Viber_User_Report.html")

    # Generate Viber General User Report
    try:
        generate_viber_user_report(output_path=user_report_path)
        print(f"\033[32m[✓] Viber General User Report was successfully generated!\033[0m")
    except Exception as e:
        print(f"\033[31m[✕] Failed to generate General User Report:\033[0m {e}")

    # Generate Viber Chat History Reports
    try:
        generate_viber_chat_history_report(viber_dir)
        print(f"\033[32m[✓] Viber Chat Histories were successfully generated!\033[0m")
    except Exception as e:
        print(f"\033[31m[✕] Failed to generate Viber Chat Histories:\033[0m {e}")


# ======================================================================================


# ======================WhatsApp Messenger Artefact formatting==========================

# A function which generates the General User HTML Report based on the user artefacts from the WhatsApp Messenger
def generate_whatsapp_user_report(base_path: str, output_path: str):
    # Converts integer timestamps to readable UTC+2 datetime strings
    def format_timestamp(ts):
        try:
            ts = int(ts)
            if ts > 0:
                if ts > 1e12:  # Assume it's in milliseconds
                    dt = datetime.fromtimestamp(ts / 1000, tz=timezone.utc) + timedelta(hours=2)
                    return f"{ts} ({dt.strftime('%Y-%m-%d %H:%M:%S')} UTC+2)"
            return ts
        except:
            return ts  # Return original value if parsing fails

    # Converts boolean-like values to descriptive string representations
    def format_boolean(val, true_repr="1 (True)", false_repr="0 (False)", null_repr="False"):
        if val is None:
            return null_repr
        return true_repr if str(val) == "1" else false_repr

    # Converts seconds to a duration string in days and hours
    def format_duration(seconds):
        try:
            seconds = int(seconds)
            days, remainder = divmod(seconds, 86400)
            hours, _ = divmod(remainder, 3600)
            return f"{days}d {hours}h" if days > 0 else f"{hours}h"
        except:
            return seconds

    # Parses Android shared preferences XML and returns a dict of key-value pairs
    def parse_xml(xml_path):
        try:
            tree = ET.parse(xml_path)
            root = tree.getroot()
            return {elem.attrib['name']: elem.text for elem in root if elem.tag == 'string'}
        except:
            return {}

    # Executes a SQL query and returns the result as a list of dicts
    def query_db(db_path, query, args=()):
        try:
            conn = sqlite3.connect(db_path)
            cur = conn.cursor()
            cur.execute(query, args)
            rows = cur.fetchall()
            cols = [desc[0] for desc in cur.description]
            conn.close()
            return [dict(zip(cols, row)) for row in rows]
        except Exception as e:
            print(f"[!] Query failed on {db_path}: {e}")
            return []

    # Adds a table row to the HTML output
    def add_row(html_list, label, value):
        html_list.append(f"<tr><th>{label}</th><td>{value}</td></tr>")

    # Start building the HTML report
    html = ["""
    <html><head><title>WhatsApp User Report</title><style>
    body { font-family: Arial; margin: 20px; }
    h2 { border-bottom: 2px solid #ccc; padding-bottom: 5px; }
    table { border-collapse: collapse; width: 100%; margin-bottom: 20px; }
    th, td { border: 1px solid #ccc; padding: 8px; text-align: left; }
    th { background-color: #f2f2f2; }
    img { max-width: 150px; max-height: 150px; }
    </style></head><body>
    <h1>WhatsApp Account Report</h1>
    """]

    # === The "Account Information" section ===
    html.append("<h2>Account Information</h2><table>")

    # Show user's avatar if it exists
    avatar_path = os.path.join(base_path, "com.whatsapp", "files", "me.jpg")
    if os.path.exists(avatar_path):
        html.append(f'<tr><th>Avatar</th><td><img src="{avatar_path}" alt="User Avatar"></td></tr>')

    # Parse relevant shared preferences XML files
    register_prefs = parse_xml(os.path.join(base_path, "com.whatsapp", "shared_prefs", "register_phone_prefs.xml"))
    prefs_light = parse_xml(os.path.join(base_path, "com.whatsapp", "shared_prefs", "com.whatsapp_preferences_light.xml"))
    keystore = parse_xml(os.path.join(base_path, "com.whatsapp", "shared_prefs", "keystore.xml"))
    backup_prefs = parse_xml(os.path.join(base_path, "com.whatsapp", "shared_prefs", "backup_prefs.xml"))
    disappearing_prefs = parse_xml(os.path.join(base_path, "com.whatsapp", "shared_prefs", "disappearing_mode_prefs.xml"))

    # Display user phone number and country code
    phone_number = register_prefs.get("com.whatsapp.registration.RegisterPhone.phone_number", "")
    country_code = register_prefs.get("com.whatsapp.registration.RegisterPhone.country_code", "")
    add_row(html, "Phone Number", f"{country_code}{phone_number}")

    # Add additional preference data from the light preferences file
    for key in ["self_lid", "pref_client_auth_token", "pref_phone_number_of_logged_out_user",
                "pref_country_code_of_logged_out_user", "encrypted_rid", "pref_device_id", "phoneid_id",
                "settings_verification_email_address"]:
        if key in prefs_light:
            add_row(html, key, prefs_light[key])

    # Format timestamp keys
    for key in ["registration_success_time_ms", "last_login_time"]:
        if key in prefs_light:
            add_row(html, key, format_timestamp(prefs_light[key]))

    # Add encryption keys
    for key in ["client_static_keypair_pwd_enc", "client_static_keypair_enc"]:
        if key in keystore:
            add_row(html, key, keystore[key])

    # Google Drive backup account and method
    for key in ["gdrive_account_name", "backup_encryption_method"]:
        if key in backup_prefs:
            add_row(html, key, backup_prefs[key])

    # Format backup-related timestamps
    for key in ["BACKUP_LAST_CHECK_TIMESTAMP", "msg_restore_timestamp", "gdrive_last_successful_backup_timestamp", "msg_backup_timestamp"]:
        if key in backup_prefs:
            add_row(html, key, format_timestamp(backup_prefs[key]))

    # Disappearing mode settings
    if "disappearing_mode_duration_int" in disappearing_prefs:
        add_row(html, "disappearing_mode_duration", format_duration(disappearing_prefs["disappearing_mode_duration_int"]))
    if "disappearing_mode_timestamp" in disappearing_prefs:
        add_row(html, "disappearing_mode_timestamp", format_timestamp(disappearing_prefs["disappearing_mode_timestamp"]))

    # Additional metadata from props table
    props_path = os.path.join(base_path, "com.whatsapp", "databases", "msgstore.db")
    props_data = query_db(props_path, "SELECT key, value FROM props WHERE key IN (?, ?, ?, ?)", (
        "user_push_name", "status_ranking_map", "status_ranking_map_expiration", "db_migration_attempt_timestamp"))
    for row in props_data:
        key, value = row["key"], row["value"]
        if "timestamp" in key or "expiration" in key:
            value = format_timestamp(value)
        add_row(html, key, value)

    # Extract identity keys from axolotl.db
    axolotl_path = os.path.join(base_path, "com.whatsapp", "databases", "axolotl.db")
    identity_data = query_db(axolotl_path, "SELECT * FROM identities WHERE recipient_id = -1")
    if identity_data:
        row = identity_data[0]
        add_row(html, "public_key", row.get("public_key", ""))
        add_row(html, "private_key", row.get("private_key", ""))
        add_row(html, "timestamp", format_timestamp(row.get("timestamp", "")))

    # Match contact JID from wa.db
    wa_path = os.path.join(base_path, "com.whatsapp", "databases", "wa.db")
    contact_match = query_db(wa_path, "SELECT jid, raw_contact_id FROM wa_contacts WHERE number LIKE ?", (f"%{phone_number}%",))
    if contact_match:
        add_row(html, "jid (matched)", contact_match[0].get("jid", ""))
        add_row(html, "raw_contact_id", contact_match[0].get("raw_contact_id", ""))

    html.append("</table>")

    # === The "User Sessions" section ===
    # Display details about secure messaging sessions.
    # Each row corresponds to a session with another WhatsApp user/device, showing technical identifiers and the session record blob.
    html.append(
        "<h2>User Sessions</h2><table><tr><th>_id</th><th>recipient_id</th><th>device_id</th><th>recipient_account_id</th><th>record</th><th>timestamp</th></tr>")
    session_data = query_db(axolotl_path, "SELECT * FROM sessions")
    for row in session_data:
        html.append("<tr>")
        for key in ["_id", "recipient_id", "device_id", "recipient_account_id", "record", "timestamp"]:
            val = row.get(key, "")
            if key == "timestamp":
                val = format_timestamp(val)  # Format epoch timestamp to human-readable format in UTC+2
            html.append(f"<td>{val}</td>")
        html.append("</tr>")
    html.append("</table>")

    # === The "Contact List" section ===
    # Display all known contacts including display name, number, status, and business profile data if available.
    html.append(
        "<h2>Contact List</h2><table><tr><th>Display Name</th><th>Number</th><th>JID</th><th>Status</th><th>Status Timestamp</th><th>Business Email</th><th>Business Address</th><th>Business Description</th></tr>")
    contact_data = query_db(wa_path, "SELECT * FROM wa_contacts")
    for contact in contact_data:
        # Attempt to construct display name from available fields
        display_name = contact.get(
            "display_name") or f"{contact.get('given_name', '')} {contact.get('family_name', '')}".strip()
        if not display_name:
            # Fallback: check for verified business name
            jid_match = contact.get("jid")
            verified = query_db(wa_path, "SELECT verified_name FROM wa_vnames WHERE jid = ?", (jid_match,))
            display_name = verified[0]['verified_name'] if verified else jid_match

        # Retrieve optional business profile information
        business = query_db(wa_path, "SELECT email, address, business_description FROM wa_biz_profiles WHERE jid = ?",
                            (contact.get("jid"),))
        business = business[0] if business else {}

        html.append("<tr>")
        html.append(
            f"<td>{display_name}</td><td>{contact.get('number', '')}</td><td>{contact.get('jid', '')}</td><td>{contact.get('status', '')}</td><td>{format_timestamp(contact.get('status_timestamp', ''))}</td><td>{business.get('email', '')}</td><td>{business.get('address', '')}</td><td>{business.get('business_description', '')}</td>")
        html.append("</tr>")
    html.append("</table>")

    # === The "Groups Membership" section ===
    # Display membership of the user in WhatsApp groups including group metadata, member role, and group creator info.
    html.append(
        "<h2>Groups Membership</h2><table><tr><th>Group ID</th><th>User</th><th>Raw JID</th><th>Group Name</th><th>Member ID</th><th>Rank</th><th>Add Timestamp</th><th>Label</th><th>Creator JID</th></tr>")

    # Generate a consistent but unique background color per group for visual grouping
    def generate_group_color(group_id, opacity=0.35):
        hash_digest = hashlib.md5(str(group_id).encode()).hexdigest()
        r = int(hash_digest[0:2], 16)
        g = int(hash_digest[2:4], 16)
        b = int(hash_digest[4:6], 16)
        return f'rgba({r},{g},{b},{opacity})'

    # Fetch all group chats (server = 'g.us' indicates group JIDs)
    jid_data = query_db(props_path, "SELECT * FROM jid WHERE server = 'g.us'")
    for jid in jid_data:
        group_id = jid["_id"]
        # Retrieve all participants of the group
        participants = query_db(props_path, "SELECT * FROM group_participant_user WHERE group_jid_row_id = ?",
                                (group_id,))
        # Retrieve subject (group name) from chat table
        subject = query_db(props_path, "SELECT subject FROM chat WHERE jid_row_id = ?", (group_id,))
        raw_jid = jid.get("raw_string")
        # Get group creator info from admin settings
        creator_data = query_db(wa_path, "SELECT creator_jid FROM wa_group_admin_settings WHERE jid = ?", (raw_jid,))
        creator = creator_data[0]["creator_jid"] if creator_data else ""

        # Mark all members of the same group with unique color
        for p in participants:
            group_color = generate_group_color(group_id)
            html.append("<tr>")
            html.append(
                f'<td style="background-color:{group_color}">{group_id}</td><td>{jid.get("user")}</td><td>{raw_jid}</td><td>{subject[0]["subject"] if subject else ""}</td><td>{p.get("user_jid_row_id")}</td><td>{"2 (Admin)" if p.get("rank") == 2 else "0 (Member)"}</td><td>{format_timestamp(p.get("add_timestamp"))}</td><td>{p.get("label", "")}</td><td>{creator}</td>'
            )
            html.append("</tr>")
    html.append("</table>")

    # === The "In-App Calls" section ===
    # Show all recorded WhatsApp call logs including group calls.
    # Initial display is limited to 5 calls, with a button to reveal more.
    html.append(
        "<h2>In-App Calls</h2><button id=\"toggleCalls\" onclick=\"toggleCalls()\" style=\"font-size: 18px; padding: 10px 20px; background-color: #4CAF50; color: white; border: none; cursor: pointer; border-radius: 5px;\">Show more</button><table id=\"callsTable\"><tr><th>Call ID</th><th>Contact ID</th><th>From Me</th><th>Timestamp</th><th>Video Call</th><th>Duration (hh:mm:ss)</th><th>Group ID</th><th>Joinable</th><th>Creator Device ID</th></tr>")
    initial_limit = 5
    calls = query_db(props_path, "SELECT * FROM call_log")
    total_calls = len(calls)
    for i, call in enumerate(calls):
        if i >= initial_limit:
            html.append(f'<tr class="extraRow" style="display:none;">')  # Hidden by default
        else:
            html.append("<tr>")
        duration_secs = int(call.get("duration", 0))
        # Transform seconds into HH:MM:SS
        hh = duration_secs // 3600
        mm = (duration_secs % 3600) // 60
        ss = duration_secs % 60
        duration_fmt = f"{hh:02}:{mm:02}:{ss:02}"
        html.append(
            f"<td>{call.get('call_id')}</td><td>{call.get('jid_row_id')}</td><td>{format_boolean(call.get('from_me'))}</td><td>{format_timestamp(call.get('timestamp'))}</td><td>{format_boolean(call.get('video_call'))}</td><td>{duration_fmt}</td><td>{call.get('group_jid_row_id')}</td><td>{format_boolean(call.get('is_joinable_group_call'))}</td><td>{call.get('call_creator_device_jid_row_id')}</td>")
        html.append("</tr>")
    html.append("</table>")

    # JavaScript to toggle hidden call rows when "Show more"/"Show less" is clicked
    if total_calls > initial_limit:
        html.append("""<script>
        function toggleCalls() {
            var rows = document.querySelectorAll('.extraRow');
            var button = document.getElementById('toggleCalls');
            for (var i = 0; i < rows.length; i++) {
                rows[i].style.display = (rows[i].style.display === 'none') ? '' : 'none';
            }
            button.innerText = (button.innerText === 'Show more' ? 'Show less' : 'Show more');
        }
        </script>""")

    # === The "User Chats (All)" section ===
    # Provide an overview of all chats the user is involved in, including timestamps and status flags.
    html.append(
        "<h2>User Chats (All)</h2><table><tr><th>Chat with</th><th>Created</th><th>Last Message Row ID</th><th>Last Read</th><th>Archived</th><th>Limited Sharing</th></tr>")
    chats = query_db(props_path, "SELECT * FROM chat")
    for chat in chats:
        # Look up the corresponding JID (raw_string) for display
        jid_row = query_db(props_path, "SELECT raw_string FROM jid WHERE _id = ?", (chat.get("jid_row_id"),))
        raw_string = jid_row[0]["raw_string"] if jid_row else ""
        html.append("<tr>")
        html.append(
            f"<td>{raw_string}</td><td>{format_timestamp(chat.get('created_timestamp'))}</td><td>{chat.get('last_message_row_id')}</td><td>{chat.get('Last_read_message_row_id')}</td><td>{format_boolean(chat.get('archived'))}</td><td>{format_boolean(chat.get('limited_sharing'))}</td>")
        html.append("</tr>")
    html.append("</table>")

    # Finalize the HTML Report and write it to a disk
    html.append("</body></html>")
    with open(output_path, 'w', encoding='utf-8') as f:
        f.write('\n'.join(html))
    print(f"\033[32m[✓] WhatsApp HTML report generated at:\033[0m {output_path}")


# A function which generates an HTML report for each user's in-messenger conversation based on the artefacts collected from the WhatsApp Messenger
def generate_whatsapp_chat_history_report(db_path: str, media_root: str, output_dir: str):
    # Format UNIX timestamp (milliseconds) into readable string with UTC+2 offset
    def format_timestamp(ts):
        try:
            if ts > 1e12:
                dt = datetime.fromtimestamp(ts / 1000, tz=timezone.utc) + timedelta(hours=2)
                return dt.strftime('%Y-%m-%d at %H:%M:%S (UTC+2)')
        except:
            pass
        return 'Unknown'

    # Convert call duration (seconds) to HH:MM:SS
    def duration_to_hms(seconds):
        try:
            seconds = int(seconds)
            hours, remainder = divmod(seconds, 3600)
            minutes, seconds = divmod(remainder, 60)
            return f"{hours:02}:{minutes:02}:{seconds:02}"
        except:
            return "00:00:00"

    # Automatically link URLs in text
    def format_links(text):
        if not text:
            return ""
        return re.sub(r'(https?://[^\s<>"]+)', r'<a href="\1" target="_blank">\1</a>', text)

    # Attempt to extract fallback identity (user_push_name and phone number) from props and XML
    def get_fallback_identity():
        try:
            conn = sqlite3.connect(db_path)
            cur = conn.cursor()
            cur.execute("SELECT value FROM props WHERE key = 'user_push_name'")
            name = cur.fetchone()
            user_push_name = name[0] if name else None
        except:
            user_push_name = None
        finally:
            conn.close()

        # Try to extract country code and phone number from XML
        cc = pn = None
        try:
            xml_path = os.path.expanduser("~\\Downloads\\DatabasExtractor\\WhatsApp\\com.whatsapp\\shared_prefs\\register_phone_prefs.xml")
            if os.path.exists(xml_path):
                tree = ET.parse(xml_path)
                for elem in tree.findall("string"):
                    key = elem.attrib.get("name")
                    if key == "com.whatsapp.registration.RegisterPhone.country_code":
                        cc = elem.text
                    elif key == "com.whatsapp.registration.RegisterPhone.phone_number":
                        pn = elem.text
        except:
            pass

        # Combine name and number, or fall back if unavailable
        if user_push_name and cc and pn:
            return f"{user_push_name} ({cc}{pn})"
        elif user_push_name:
            return f"{user_push_name} (Unknown Number)"
        return "Me (Unknown Number)"

    # Connect to WhatsApp message DB
    os.makedirs(output_dir, exist_ok=True)
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()

    # Connect to wa.db to access contact display names
    wa_db_path = os.path.join(os.path.dirname(db_path), "wa.db")
    wa_conn = sqlite3.connect(wa_db_path)
    wa_conn.row_factory = sqlite3.Row
    wa_cur = wa_conn.cursor()

    try:
        # Build lookups for jid → phone and raw string, and for raw_string → display name
        jid_lookup = {}
        raw_to_display = {}
        for row in cur.execute("SELECT _id, user, raw_string FROM jid"):
            jid_lookup[row["_id"]] = (row["user"], row["raw_string"])
        for row in wa_cur.execute("SELECT jid, display_name FROM wa_contacts"):
            raw_to_display[row["jid"]] = row["display_name"]

        # Group messages by chat ID
        chats = {}
        for row in cur.execute("SELECT _id, chat_row_id, from_me, sender_jid_row_id, timestamp, text_data FROM message"):
            chats.setdefault(row["chat_row_id"], []).append(dict(row))

        # Preload supplementary data tables (calls, edits, links, media)
        call_map = {row["message_row_id"]: row["call_log_row_id"]
                    for row in cur.execute("SELECT message_row_id, call_log_row_id FROM message_call_log")}
        calls = {row["_id"]: dict(row)
                 for row in cur.execute("SELECT _id, video_call, duration FROM call_log")}
        missed_calls = {row["message_row_id"]: row["video_call"]
                        for row in cur.execute("SELECT message_row_id, video_call FROM missed_call_logs")}
        edits = {row["message_row_id"]: row["edited_timestamp"]
                 for row in cur.execute("SELECT message_row_id, edited_timestamp FROM message_edit_info")}
        links = {row["message_row_id"]: row
                 for row in cur.execute("SELECT message_row_id, description, page_title, url FROM message_text")}
        media = {row["message_row_id"]: row
                 for row in cur.execute("SELECT message_row_id, file_path, media_name FROM message_media")}

        fallback_identity = get_fallback_identity()

        # Process each chat
        for chat_id, messages in chats.items():
            if not any(msg["text_data"] or msg["_id"] in call_map or msg["_id"] in missed_calls or msg["_id"] in links or msg["_id"] in media for msg in messages):
                continue

            # Skip chats with no real content (no text, call, media, etc.)
            cur.execute("SELECT jid_row_id FROM chat WHERE _id=?", (chat_id,))
            jid_row = cur.fetchone()
            if not jid_row:
                continue

            # Resolve chat-level user info
            jid_id = jid_row["jid_row_id"]
            user, raw = jid_lookup.get(jid_id, (f"jid_{jid_id}", None))
            display_name = raw_to_display.get(raw)
            label = f"{display_name} ({user})" if display_name else user
            # The name of each Chat History report
            filename = f"Chat_with_{label.replace('/', '_')}.html"
            filepath = os.path.join(output_dir, filename)

            # Begin HTML structure
            html = ["<html><head><title>Chat History</title><style>",
                    "body { font-family: Arial; background-color: #f5f5f5; padding: 20px; }",
                    ".message { margin: 10px 0; max-width: 70%; padding: 10px; border-radius: 10px; position: relative; }",
                    ".from { background-color: #d0eaff; align-self: flex-start; }",
                    ".to { background-color: #e8ffe8; align-self: flex-end; }",
                    ".container { display: flex; flex-direction: column; gap: 10px; }",
                    ".sender { font-weight: bold; margin-bottom: 5px; }",
                    ".timestamp { font-size: 0.8em; color: #666; margin-top: 5px; }",
                    ".filename { font-size: 0.75em; color: #888; margin-top: 3px; }",
                    "</style></head><body>",
                    f"<h1>Chat with {label}</h1><div class='container'>"]

            # Render each message individually in the chat history. Set some base parameters for each message
            for msg in messages:
                sender_id = msg["sender_jid_row_id"]
                sender_user, sender_raw = jid_lookup.get(sender_id, (None, None))
                sender_display = raw_to_display.get(sender_raw)

                # Determine sender label for each message in the chat history
                if msg["from_me"]:
                    sender_label = fallback_identity if sender_user is None else f"Me ({sender_user})"
                else:
                    if sender_display and sender_user:
                        sender_label = f"{sender_display} ({sender_user})"
                    elif sender_user:
                        sender_label = sender_user
                    elif display_name and user:  # fallback to chat header label
                        sender_label = f"{display_name} ({user})"
                    else:
                        sender_label = "Unknown"

                # Determine the timestamp for each message
                timestamp = format_timestamp(msg["timestamp"])

                # Determine message direction (My messages are displayed on the right side and others - on the left side of the Chat History report)
                direction_class = "to" if msg["from_me"] else "from"

                html.append(f"<div class='message {direction_class}'>")
                html.append(f"<div class='sender'>{sender_label}</div>")

                # The actual body of each message
                if msg["text_data"]:
                    html.append(f"<div>{format_links(msg['text_data'])}</div>")
                    if msg["_id"] in edits:
                        html.append(f"<div class='timestamp'>Edited: {format_timestamp(edits[msg['_id']])}</div>")

                # Process attached Media in each message. The "_id" of each message is taken and used to search for attached media in the table "message_media" of the database "msgstore.db"
                if msg["_id"] in media:
                    m = media[msg["_id"]]
                    file_path = m["file_path"] if m["file_path"] else None
                    if file_path:
                        rel_path = "/" + "/".join(file_path.split("/")[1:])
                        abs_path = os.path.join(media_root, rel_path.strip("/").replace("/", os.sep))
                        url = f"file:///{abs_path.replace(os.sep, '/')}"
                        ext = os.path.splitext(file_path)[1].lower().strip('.')

                        # Defined file extensions and rules of how to render those attached Media in the chat
                        if ext in ["jpg", "jpeg", "png", "gif", "webp", "bmp", "svg"]: # Images
                            html.append(f"<img src='{url}' style='max-width:200px;'>")
                        elif ext in ["mp4", "webm", "mkv", "mov", "avi"]: # Videos
                            html.append(f"<video controls width='250'><source src='{url}'></video>")
                        elif ext in ["mp3", "m4a", "wav", "ogg", "opus", "flac", "aac"]: # Audio
                            html.append(f"<audio controls><source src='{url}'></audio>")
                        else:
                            html.append(f"<a href='{url}' download>{os.path.basename(url)}</a>")

                        if m["media_name"]:
                            html.append(f"<div class='filename'>{m['media_name']}</div>")
                    else:
                        # If no Media file was found on the Device, then display this message
                        html.append("<div><i>[Media present but missing file path]</i></div>")

                # Use the "_id" of each message to search for the info about user's In-app calls in the database "msgstore.db"
                elif msg["_id"] in call_map:
                    call = calls.get(call_map[msg["_id"]])
                    # If a record about the call was found, then display it in the Chat History report
                    if call:
                        t = duration_to_hms(call["duration"])
                        ctype = "video" if call["video_call"] == 1 else "audio"
                        # Define the correct article for the displayed text
                        article = "an" if ctype[0] in "aeiou" else "a"
                        html.append(f"<div>[Started {article} {ctype} call. Duration: {t}]</div>")
                # Search for the info about missed calls
                elif msg["_id"] in missed_calls:
                    missed = "video" if missed_calls[msg["_id"]] == 1 else "audio"
                    article = "an" if missed[0] in "aeiou" else "a"
                    html.append(f"<div>Missed {article} {missed} call from {user}</div>")
                # Search for the info about the http links sent by the members of a conversation
                elif msg["_id"] in links:
                    l = links[msg["_id"]]
                    html.append(f"<div>{l['description']}<br>{l['page_title']}<br><a href='{l['url']}' target='_blank'>{l['url']}</a></div>")
                # If the message body doesn't have any valuable or important data - then display such notification
                elif not msg["text_data"]:
                    html.append(f"<div><i>[Empty or unsupported message]</i></div>")

                html.append(f"<div class='timestamp'>Sent: {timestamp}</div>")
                html.append("</div>")

            html.append("</div></body></html>")

            # Saving the Chat History report
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write('\n'.join(html))
            print(f"\033[32m[✓] Chat history saved to:\033[0m {filepath}")

    # Display error messages
    except Exception as e:
        print(f"\033[31m[✕] Error:\033[0m {e}")
    # Close the created database connections
    finally:
        conn.close()
        wa_conn.close()


# Functions that do the process of extracting the artefacts of the WhatsApp Messenger and transforming them into the .html files
def extract_whatsapp_artefacts():
    print("\n[+] Starting WhatsApp artifact extraction and report generation...")

    # A list of paths to the important artefacts and output locations
    whatsapp_dir = os.path.expanduser("~\\Downloads\\DatabasExtractor\\WhatsApp")
    report_output_path = os.path.join(whatsapp_dir, "com.whatsapp", "WhatsApp_User_Report.html")
    chat_db_path = os.path.join(whatsapp_dir, "com.whatsapp", "databases", "msgstore.db")
    media_root = os.path.join(whatsapp_dir, "com.whatsapp", "WhatsApp", "Media")
    chats_output_dir = os.path.join(whatsapp_dir, "com.whatsapp", "Chats")

    # Generate WhatsApp General User Report
    try:
        generate_whatsapp_user_report(base_path=whatsapp_dir, output_path=report_output_path)
        print(f"\033[32m[✓] WhatsApp General User Report was successfully generated!\033[0m")
    except Exception as e:
        print(f"\033[31m[✕] Failed to generate WhatsApp User Report:\033[0m {e}")

    # Generate WhatsApp Chat History Reports
    try:
        generate_whatsapp_chat_history_report(db_path=chat_db_path, media_root=media_root, output_dir=chats_output_dir)
        print(f"\033[32m[✓] WhatsApp Chat History Reports were successfully generated!\033[0m")
    except Exception as e:
        print(f"\033[31m[✕] Failed to generate WhatsApp Chat History Reports:\033[0m {e}")

# ======================================================================================


# ======================Telegram Messenger Artefact formatting==========================

# A function which generates the General User HTML Report based on the user artefacts from the Telegram Messenger
def generate_telegram_user_report(output_path):

    # A helper function which does Base64 decode
    def decode_base64(value):
        try:
            return base64.b64decode(value).decode('utf-8', errors='ignore')
        except Exception:
            return value

    # A helper function which transforms timestamps into a real UTC+2 date
    def format_timestamp(ts):
        try:
            ts = int(ts)
            if ts in (0, -1):  # skip zero and sentinel values
                return str(ts)
            if ts > 1e12:  # convert from milliseconds to seconds if needed
                ts //= 1000
            dt = datetime.utcfromtimestamp(ts) + timedelta(hours=2)
            return f"{ts} ({dt.strftime('%Y-%m-%d %H:%M:%S')} UTC+2)"
        except Exception:
            return str(ts)

    # A Helper function which parses '.xml' files so we can extract data from them
    def parse_xml_values(xml_path, keys=None, dynamic_key_prefix=None):
        values = {}
        try:
            tree = ET.parse(xml_path)
            root = tree.getroot()
            for elem in root:
                key = elem.attrib.get("name", "")
                if not key:
                    continue
                if keys and key in keys:
                    values[key] = elem.attrib.get("value", elem.text)
                elif dynamic_key_prefix and key.startswith(dynamic_key_prefix):
                    values[key] = elem.attrib.get("value", elem.text)
        except Exception as e:
            print(f"\033[31m[✕] Failed to parse XML file\033[0m {xml_path}: {e}")
        return values

    # Delete unprintable characters in the extracted blob
    def clean_binary_data(blob):
        if isinstance(blob, bytes):
            decoded = blob.decode('utf-8', errors='ignore')
            return ''.join(c for c in decoded if c.isprintable())
        return str(blob)

    # File paths to the main artefacts
    base_path = os.path.expanduser(r"~\Downloads\DatabasExtractor\Telegram\org.telegram.messenger")
    mainconfig = os.path.join(base_path, "shared_prefs", "mainconfig.xml")
    userconfig = os.path.join(base_path, "shared_prefs", "userconfing.xml")
    db_path = os.path.join(base_path, "files", "cache4.db")

    # Begin HTML
    html = ["<html><head><title>Telegram User Report</title><style>",
            "body { font-family: Arial; margin: 20px; }",
            "table { border-collapse: collapse; width: 100%; margin-bottom: 20px; }",
            "th, td { border: 1px solid #ccc; padding: 8px; text-align: left; }",
            "th { background-color: #f2f2f2; }",
            "h2 { border-bottom: 2px solid #ccc; }",
            "</style></head><body>",
            "<h1>Telegram User Report</h1>"]

    # ========== Account Information section ==========
    html.append("<h2>Account Information</h2><table><tr><th>Key</th><th>Value</th></tr>")

    # Extract values from 'mainconfig.xml'
    main_keys = ["wifiPreset", "mobilePreset", "autologinToken", "lastReloadStatusTime", "language", "hasEmailLogin"]
    main_values = parse_xml_values(mainconfig, keys=main_keys, dynamic_key_prefix="phone_code_last_matched_")
    for key, value in main_values.items():
        if "Time" in key:
            value = format_timestamp(value)
        display_key = key
        html.append(f"<tr><td>{display_key}</td><td>{value}</td></tr>")

    # Extract values from 'userconfing.xml'
    user_keys = [
        "user", "pushAuthKey", "passcodeSalt", "loginTime", "syncContacts",
        "lastContactsSyncTime", "lastMyLocationShareTime", "selectedAccount",
        "lastSendMessageId", "passcodeHash1", "useFingerprint"
    ]
    user_values = parse_xml_values(userconfig, keys=user_keys)

    # Decode and clean base64 'user' field
    decoded_user = decode_base64(user_values.get("user", ""))
    cleaned_user = ''.join(c for c in decoded_user if c.isprintable())
    user_values["user"] = cleaned_user

    for key in user_keys:
        value = user_values.get(key, "")
        if "Time" in key or "loginTime" in key:
            value = format_timestamp(value)
        html.append(f"<tr><td>{key}</td><td>{value}</td></tr>")

    html.append("</table>")

    # ========== User Chats section ==========
    def get_chats_and_dialogs(db_path):
        # Extract chats, dialogs, and media from Telegram's 'cache4.db' database.
        chats, dialogs, media = {}, {}, {}
        try:
            conn = sqlite3.connect(db_path)
            cur = conn.cursor()

            # Chats
            cur.execute("SELECT uid, name FROM chats")
            for uid, name in cur.fetchall():
                chats[str(uid)] = {"uid": str(uid), "name": name}

            # Dialogs
            cur.execute("SELECT did, date, unread_count, pinned, folder_id, data FROM dialogs")
            for did, date, unread_count, pinned, folder_id, data in cur.fetchall():
                clean_did = str(did).lstrip("-")
                dialogs[clean_did] = {
                    "did": str(did),
                    "date": format_timestamp(date),
                    "unread_count": unread_count,
                    "pinned": pinned,
                    "folder_id": folder_id,
                    "data": data
                }

            # Media
            cur.execute("SELECT uid, data FROM media_v4")
            for uid, data in cur.fetchall():
                media[str(uid)] = data
        except Exception as e:
            print(f"\033[31m[✕] Error reading chats/media/dialogs from DB:\033[0m {e}")
        finally:
            if conn:
                conn.close()
        return chats, dialogs, media

    chats, dialogs, media = get_chats_and_dialogs(db_path)
    html.append("<h2>User Chats</h2><table><tr><th>UID</th><th>Name</th><th>Media Links</th><th>Date</th><th>Unread</th><th>Pinned</th><th>Folder ID</th><th>Dialog Data</th></tr>")
    for uid, chat in chats.items():
        dialog = dialogs.get(uid, {})
        html.append(f"<tr><td>{uid}</td><td>{chat['name']}</td>"
                    f"<td>{media.get(uid, '')}</td>"
                    f"<td>{dialog.get('date', '')}</td><td>{dialog.get('unread_count', '')}</td>"
                    f"<td>{dialog.get('pinned', '')}</td><td>{dialog.get('folder_id', '')}</td>"
                    f"<td>{dialog.get('data', '')}</td></tr>")
    html.append("</table>")

    # ========== User Contacts section ==========
    def get_contacts(db_path):
        contacts = []
        try:
            conn = sqlite3.connect(db_path)
            cur = conn.cursor()
            # Select all records from the table "users" of the database "cache4.db" to form a contact list
            cur.execute("SELECT uid, name, status, data FROM users")
            for uid, name, status, data in cur.fetchall():
                name_parts = name.split(";") if ";" in name else [name, ""]
                name, username = name_parts[0], name_parts[1]
                status_fmt = f"{format_timestamp(status)}" if isinstance(status, int) and status >= 0 else "Unknown"
                contacts.append({
                    "uid": uid,
                    "name": name,
                    "username": username,
                    "status": status_fmt,
                    "data": clean_binary_data(data)  # Cleaning this key off unprintable characters
                })
        except Exception as e:
            print(f"\033[31m[✕] Failed to fetch contacts:\033[0m {e}")
        finally:
            # Closing the connection if it still exists
            if conn:
                conn.close()
        return contacts

    contacts = get_contacts(db_path)
    html.append("<h2>User Contacts</h2><table><tr><th>UID</th><th>Name</th><th>Username</th><th>Status</th><th>Data</th></tr>")
    for contact in contacts:
        html.append(f"<tr><td>{contact['uid']}</td><td>{contact['name']}</td><td>{contact['username']}</td>"
                    f"<td>{contact['status']}</td><td>{contact['data']}</td></tr>")
    html.append("</table></body></html>")

    # Save all data to a file
    with open(output_path, "w", encoding="utf-8") as f:
        f.write('\n'.join(html))
    print(f"\033[32m[✓] Telegram User Report generated at:\033[0m {output_path}")

# A function which generates an HTML report for each user's in-messenger conversation based on the artefacts collected from the cache of the Telegram Messenger
def generate_telegram_chat_history_report():
    # Define main paths used in Telegram data extraction
    telegram_root = os.path.expanduser(r"~\Downloads\DatabasExtractor\Telegram\org.telegram.messenger")
    files_dir = os.path.join(telegram_root, "files") # Contains Telegram database files
    shared_prefs = os.path.join(telegram_root, "shared_prefs", "userconfing.xml") # XML with user configuration
    chats_output_dir = os.path.join(telegram_root, "Chats") # Output directory for HTML chat reports
    pulled_media_dir = os.path.join(telegram_root, "PulledMedia") # Directory for extracted media files

    # Ensure output directories exist
    os.makedirs(chats_output_dir, exist_ok=True)
    os.makedirs(pulled_media_dir, exist_ok=True)

    # Helper function to find the Telegram account owner UID
    def get_owner_uid(cursor):
        try:
            tree = ET.parse(shared_prefs)
            root = tree.getroot()
            for elem in root.iter("string"):
                if elem.attrib.get("name") == "user": # Extracting the value of the key "user" from the file "userconfing.xml"
                    encoded = elem.text.replace(" ", "").replace("\n", "")
                    try:
                        decoded_user_blob = base64.b64decode(encoded) # Base64 decode the value of the extracted key "user"
                    except Exception as e:
                        print(f"\033[31m[✗] Base64 decode failed:\033[0m {e}")
                        return None

                    # Search for matching user data in the database
                    for row in cursor.execute("SELECT uid, data FROM users"):
                        uid, data_blob = row
                        if isinstance(data_blob, bytes) and data_blob == decoded_user_blob: # Comparing the decoded value of the key "user" from "userconfing.xml" to
                            print(f"\033[32m[✓] Matched user config to UID:\033[0m {uid}")                 # the key "data" in the table "users" of the database "cache4.db"
                            return uid

                    print("\033[31m[✗] No match found for user blob in users table.\033[0m")
                    return None
        except Exception as e:
            print(f"\033[31m[✗] Error identifying Telegram account owner:\033[0m {e}")
        return None

    # Open the required Telegram database files
    cache_db = os.path.join(files_dir, "cache4.db") # Contains messages and user data
    path_db = os.path.join(files_dir, "file_to_path.db") # Maps message IDs to media file paths

    # Creating connections to the databases
    conn_cache = sqlite3.connect(cache_db)
    conn_path = sqlite3.connect(path_db)
    cursor_cache = conn_cache.cursor()
    cursor_path = conn_path.cursor()

    # Identify the current Telegram account's UID
    owner_uid = get_owner_uid(cursor_cache)
    if not owner_uid:
        print("\033[31m[✗] Failed to identify Telegram account owner.\033[0m")
        return

    # Build a UID-to-username mapping for displaying chat names
    users_map = {}
    try:
        for row in cursor_cache.execute("SELECT uid, name FROM users"):
            uid, name = row
            users_map[str(uid)] = name.split(";;;")[0]
    except Exception as e:
        print(f"\033[31m[✗] Error reading users:\033[0m {e}")
        return

    # Fetch and group all messages by chat type (user, group, or channel)
    cursor_cache.execute("SELECT mid, uid, read_state, send_state, date, data, is_channel, group_id FROM messages_v2")
    messages = cursor_cache.fetchall()

    conversations = {} # Keyed by chat type: user_123, group_456, or channel_789
    for msg in messages:
        mid, uid, read_state, send_state, date, data, is_channel, group_id = msg

        # Determine conversation key based on message type
        if is_channel:
            key = f"channel_{is_channel}"
        elif group_id:
            key = f"group_{group_id}"
        else:
            key = f"user_{uid}"

        # Append message to the corresponding chat context
        conversations.setdefault(key, []).append({
            "mid": mid,
            "uid": uid,
            "read_state": read_state,
            "send_state": send_state,
            "date": date,
            "data": (data or '').strip(),
            "is_channel": is_channel,
            "group_id": group_id
        })

    # Generate one HTML chat report per conversation
    for conv_key, msgs in conversations.items():
        participant_uid = None
        # Attempt to extract participant UID for naming the chat
        if conv_key.startswith("user_"):
            participant_uid = conv_key.replace("user_", "").lstrip("-")
        elif msgs:
            participant_uid = str(msgs[0]['uid']).lstrip("-")

        # Get display name from the UID mapping
        chat_name = users_map.get(participant_uid, conv_key)

        # Sanitize filename of each Chat History report for use in the filesystem
        safe_chat_name = "".join(c if c.isalnum() or c in " _-()" else "_" for c in chat_name)
        html_file = os.path.join(chats_output_dir, f"Chat_with_{safe_chat_name}.html")

        # Create HTML file with structured chat messages
        with open(html_file, "w", encoding="utf-8") as f:
            f.write("<html><head><meta charset='utf-8'><title>Chat History</title>\n")
            f.write("<style>\n")
            f.write(".msg-left { text-align: left; background-color: #e0f0ff; margin: 10px; padding: 8px; border-radius: 8px; width: 60%; }\n")
            f.write(".msg-right { text-align: right; background-color: #d0ffd0; margin: 10px auto 10px 40%; padding: 8px; border-radius: 8px; width: 60%; }\n")
            f.write("</style></head><body>\n")
            f.write(f"<h2>Chat with {html.escape(str(chat_name))}</h2>\n")

            # Sort messages chronologically
            for msg in sorted(msgs, key=lambda x: x["date"]):
                msg_uid = str(msg["uid"])
                sender_label = "Me" if msg_uid == str(owner_uid) else f"User (UID: {msg_uid})"
                css_class = "msg-right" if msg_uid == str(owner_uid) else "msg-left" # Account Owner's messages are displayed on the right and others - on the left of a Chat History report

                # Displaying the status of each message
                send_status = "Message was sent successfully" if msg["send_state"] == 0 else "Message hasn't been sent yet"
                read_status = "Read" if msg["read_state"] == 3 else "Unread"

                # Convert Unix timestamp to readable datetime in UTC+2
                try:
                    dt = datetime.utcfromtimestamp(msg["date"]) + timedelta(hours=2)
                    formatted_date = dt.strftime("Sent: %Y-%m-%d %H:%M:%S (UTC+2)")
                except:
                    formatted_date = "Unknown date"

                media_html = ""
                try:
                    # Try to find associated media using message_id
                    cursor_path.execute("SELECT path FROM paths_by_dialog_id WHERE message_id = ?", (msg["mid"],))
                    media_path_row = cursor_path.fetchone()
                    if media_path_row:
                        media_path = media_path_row[0]
                        media_path = media_path.decode() if isinstance(media_path, bytes) else media_path  # Decode if necessary
                        src_path = media_path if os.path.isabs(media_path) else os.path.join(files_dir, media_path)

                        # Copy media to output folder and include it in the HTML
                        if os.path.exists(src_path):
                            filename = os.path.basename(src_path)
                            dest_path = os.path.join(pulled_media_dir, filename)
                            shutil.copyfile(str(src_path), str(dest_path))  # Ensure paths are strings
                            media_html = f"<br><img src='../PulledMedia/{filename}' style='max-width:300px;'>"
                except:
                    pass  # Ignore media extraction errors

                f.write(f"<div class='{css_class}'>\n")
                f.write(f"<strong>{html.escape(str(sender_label))}</strong><br>\n")
                f.write(f"{html.escape(str(msg['data']))}{media_html}<br>\n")
                f.write(f"<small>{send_status} | {read_status}</small><br>\n")
                f.write(f"<small>{formatted_date}</small>\n")
                f.write("</div>\n")

            f.write("</body></html>\n")

    # Close created earlier database connections
    conn_cache.close()
    conn_path.close()

# Functions that do the process of extracting the artefacts of the Telegram Messenger and transforming them into the .html files
def extract_telegram_artefacts():
    print("\n[+] Starting Telegram artifact extraction and report generation...")

    # Define base Telegram path and target output
    report_output_path = os.path.expanduser(r"~\Downloads\DatabasExtractor\Telegram\org.telegram.messenger\Telegram_User_Report.html")

    # Generate Telegram User Report
    try:
        generate_telegram_user_report(output_path=report_output_path)
        print(f"\033[32m[✓] Telegram User Report was successfully generated!\033[0m")
    except Exception as e:
        print(f"\033[31m[✕] Failed to generate Telegram User Report:\033[0m {e}")

    # Generate Telegram Chat History Report
    try:
        generate_telegram_chat_history_report()
        print(f"\033[32m[✓] Telegram Chat History Report was successfully generated!\033[0m")
    except Exception as e:
         print(f"\033[31m[✕] Failed to generate Telegram Chat History Report:\033[0m {e}")

# ======================================================================================


# A function to check the content of the created earlier folder "DatabasExtractor" in case to define the list of the extracted Messengers
def extract_data_from_artefacts():
    base_path = r"C:\Users\dimit\Downloads\DatabasExtractor"
    if not os.path.exists(base_path):
        print("\033[31m[✕] DatabasExtractor folder not found on your system.\033[0m")
        return

    print("\n\033[34m[+] Scanning for extracted messenger data...\033[0m")
    expected_messengers = ["Viber", "WhatsApp", "Signal", "Telegram"]   # The list of the expected messengers in the folder "DatabasExtractor"
    found_messengers = [m for m in expected_messengers if os.path.isdir(os.path.join(base_path, m))]

    if not found_messengers:
        print("\033[33m[✕] No messenger folders found in the DatabasExtractor directory.\033[0m")
        return

    while True:
        print("\nFound the following messenger folders:")
        print("0 - Return to main menu")
        # Give all the found messengers a corresponding number
        for idx, name in enumerate(found_messengers, 1):
            print(f"{idx} - {name}")

        try:
            choice = int(input("Choose a messenger to process (or 0 to return): "))
            if choice == 0:
                print("\033[34m[+] Returning to main menu...\033[0m")
                return
            if 1 <= choice <= len(found_messengers):
                selected = found_messengers[choice - 1]
                print(f"\033[32m[+] You selected:\033[0m {selected}")

                # Calling a function based on the user's choice
                if selected == "Signal":
                    extract_signal_artefacts()
                elif selected == "Viber":
                    extract_viber_artefacts()
                elif selected == "WhatsApp":
                    extract_whatsapp_artefacts()
                elif selected == "Telegram":
                    extract_telegram_artefacts()
            else:
                print("\033[31m[✕] Invalid selection.\033[0m")
        except ValueError:
            print("\033[31m[✕] Invalid input. Please enter a number.\033[0m")


# Main function
def main():
    # First, check whether the mobile device is connected to the computer
    if "device" not in run_adb_command("adb devices"):
        print("\033[31m[✕] No device connected. Please connect your device and try again.\033[0m")
        return

    # Second, try to get the root access on the connected mobile device
    print("[+] Attempting to get root access...")
    time.sleep(0.5)
    if not check_root_access():
        print("\033[31m[✕] Failed to get root access. Exiting...\033[0m")
        return
    print("\033[32m[✓] Root access granted.\033[0m")

    # The main folder on the mobile device into which the messenger files will be copied
    main_folder = "/storage/emulated/0/Download/DatabasExtractor"

    # The list of available features of the DatabasExtractor
    while True:
        print("\nChoose an option:")
        print("1 - Extract Viber files")
        print("2 - Extract WhatsApp files")
        print("3 - Extract Signal files")
        print("4 - Extract Telegram files")
        print("5 - \033[37;46mExtract messenger artifacts\033[0m")
        print("6 - \033[37;41mDelete all copied files\033[0m")
        print("7 - Exit the program")

        choice = input("Enter your choice (1-7): ")

        # The list of actions
        if choice == "1":
            files_to_copy = [
                "/data/data/com.viber.voip/",
                "/data/media/0/Android/data/com.viber.voip/",
                # "/data/user/0/com.viber.voip/" - this directory holds the same data as the directory /data/data/com.viber.voip/
            ]
            folder_name = "Viber"
        elif choice == "2":
            files_to_copy = [
                "/data/data/com.whatsapp/",
                "/data/media/0/Android/data/com.whatsapp/",
                "/data/media/0/Android/media/com.whatsapp/",
                # "/data/user/0/com.whatsapp/" - this directory holds the same data as the directory /data/data/com.whatsapp/
            ]
            folder_name = "WhatsApp"
        elif choice == "3":
            files_to_copy = [
                "/data/data/org.thoughtcrime.securesms/",
                "/data/misc/keystore/persistent.sqlite"
                # "/data/user/0/org.thoughtcrime.securesms/" - this directory holds the same data as the directory /data/data/org.thoughtcrime.securesms/
            ]
            folder_name = "Signal"
        elif choice == "4":
            files_to_copy = [
                "/data/data/org.telegram.messenger/",
                "/data/media/0/Android/data/org.telegram.messenger/",
                "/data/media/0/Android/media/org.telegram.messenger/"
                # "/data/user/0/org.telegram.messenger/" - this directory holds the same data as the directory /data/data/org.telegram.messenger/
            ]
            folder_name = "Telegram"
        elif choice == "5":
            extract_data_from_artefacts()
            continue
        elif choice == "6":
            delete_database_extractor_folder(main_folder)
            continue
        elif choice == "7":
            print("\033[32m[+] Exiting the program. Goodbye!\033[0m")
            break
        else:
            print("\033[31m[✕] Invalid choice. Please try again.\033[0m")
            continue

        # If the selected action has the "folder_name" variable in it, then invoke the "copy_files_from_device" function
        if folder_name:
            copy_files_from_device(files_to_copy, main_folder, folder_name)
            print(f"\033[32m[✓] Completed file operations for:\033[0m {folder_name}")

if __name__ == "__main__":
    main()
