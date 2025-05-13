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
version = "1.4"  #

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
    result = subprocess.run(full_command, shell=True, capture_output=True, text=True)
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

        # Pull the file. If the file throws an error, then skip it
        pull_result = run_adb_command(f'adb pull "{device_file}" "{local_file_path}"')
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

            # Try to decrypt the SQLCipher key with the given HEX key and extracted AES GCM parameters
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

    # Define which fields we want to use to form the contact list
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
    # Import necessary modules
    import os
    import json
    import re
    from datetime import datetime, timezone, timedelta

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


# A function that extracts Signal Messenger artifacts into readable HTML files and decrypts all user attachments
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
    import sqlite3
    import os
    import json
    from datetime import datetime, timezone, timedelta

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
        cur.execute("SELECT id, name, category, subtitle, icon FROM public_accounts")
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
    import os
    import sqlite3
    import base64
    import json
    import re
    from datetime import datetime, timedelta, timezone

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



# Functions that do the process of extracting artefacts from the Viber Messenger and transforming them into the HTML reports
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

def extract_whatsapp_artefacts():
    print("[!] WhatsApp artifact extraction not implemented yet.")
    return

# ======================================================================================

# ======================Telegram Messenger Artefact formatting==========================

def extract_telegram_artefacts():
    print("[!] Telegram artifact extraction not implemented yet.")
    return

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
