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


# A function to copy files on the device using 'cp' command and organize them into folders
def copy_files_from_device(remote_paths, local_dir, folder_name):

    # Create a folder for the messenger in the destination directory
    messenger_folder = f"{local_dir}/{folder_name}"
    run_adb_command(f"adb shell mkdir -p {messenger_folder}")

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

    # Pulling for files from the Mobile Device
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

        try:
            os.rename(f"{windows_viber_folder}/viber_data", f"{windows_viber_folder}/viber_data.db" )
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
def generate_user_html_report(json_dir: str, output_path: str):

    # A function which automates the process of opening several JSON files
    def load_json(file_name):
        try:
            with open(os.path.join(json_dir, file_name), 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception as e:
            print(f"\033[31m[✕] Failed to load\033[0m {file_name}: {e}")
            return []

    # A list of keys that will be formatted and used in the HTML Report (new keys can be added if necessary)
    key_value_keys = [
        "account.username", "account.e164", "registration.complete", "registration.restore_method_token", "mob_payments_enabled",
        "registration.session_e164", "account.registered_at", "registration.session_id", "misc.last_profile_refresh_time",
        "storage.last_sync_time", "account.pni", "pin.last_successful_entry", "misc.last_websocket_connect_time"
        "account.pni_identity_public_key","account.pni_identity_private_key",
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

    # A list of JSON files from which the valuable "key:value" pairs are extracted
    key_value_data = load_json("key_value.json")
    sessions = load_json("sessions.json")
    contacts = load_json("recipient.json")
    groups = load_json("groups.json")
    group_memberships = load_json("group_membership.json")
    calls = load_json("call.json")
    chat_folders = load_json("chat_folder.json")
    chat_folder_memberships = load_json("chat_folder_membership.json")

    # messages = load_json("message.json")


    # HTML Settings for the Report
    html = ["<html><head><title>Signal Report</title><style>",
            "body { font-family: Arial; margin: 20px; }",
            "h2 { border-bottom: 2px solid #ccc; padding-bottom: 5px; }",
            "table { border-collapse: collapse; width: 100%; margin-bottom: 20px; }",
            "th, td { border: 1px solid #ccc; padding: 8px; text-align: left; }",
            "th { background-color: #f2f2f2; }",
            "</style></head><body>"]

    html.append("<h1>Signal Account Report</h1>")

    # The path to the avatar picture of the User. If the user avatar doesn't exist then do not add this data to the HTML Report
    avatar_path = os.path.join(json_dir, "avatar.jpg")
    if os.path.exists(avatar_path):
        html.append(f'<img src="{avatar_path}" alt="User Avatar" width="150"><br><br>')

    # Creating the "Account Information" table in the HTML Report
    html.append("<h2>Account Information</h2><table><tr><th>Key</th><th>Value</th></tr>")
    for entry in key_value_data:
        if entry.get("key") in key_value_keys:
            raw_value = entry.get("value", '')

            try:
                parsed_value = int(raw_value)     # Transforming timestamps and booleans from STRING into INTEGER
            except (ValueError, TypeError):
                parsed_value = raw_value

            # Formatting the timestamps and the booleans
            formatted_value = format_timestamp(entry['key'], parsed_value)
            formatted_value = format_boolean_flag(entry['key'], formatted_value)

            html.append(f"<tr><td>{entry['key']}</td><td>{formatted_value}</td></tr>")
    html.append("</table>")

    # Creating the "User Sessions" table in the HTML Report
    html.append("<h2>User Sessions</h2><table><tr><th>_id</th><th>account_id</th><th>address</th><th>device</th><th>record</th></tr>")
    for s in sessions:
        html.append(f"<tr><td>{s.get('_id','')}</td><td>{s.get('account_id','')}</td><td>{s.get('address','')}</td><td>{s.get('device','')}</td><td>{s.get('record','')}</td></tr>")
    html.append("</table>")

    # FULL contact list with all valuable "key:value" pairs
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

    # Creating the "Contact List" table in the HTML Report
    html.append("<h2>Contact List</h2><table><tr>")
    for header, _ in contact_fields:
        html.append(f"<th>{header}</th>")
    html.append("</tr>")

    # Define sets of keys that require formatting
    contact_timestamp_keys = {"last_profile_fetch", "mute_until", "unregistered_timestamp"}
    contact_boolean_keys = {"blocked", "hidden", "pni_signature_verified", "registered", "phone_number_discoverable"}

    for c in contacts:
        html.append("<tr>")
        for _, json_key in contact_fields:
            raw_value = c.get(json_key, 'None')

            # Attempt to cast value to int if applicable
            try:
                parsed_value = int(raw_value)
            except (ValueError, TypeError):
                parsed_value = raw_value

            # Format timestamps
            if json_key in contact_timestamp_keys:
                display_value = format_timestamp(json_key, parsed_value)
            # Format booleans
            elif json_key in contact_boolean_keys:
                display_value = format_boolean_flag(json_key, parsed_value)
            else:
                display_value = parsed_value

            html.append(f"<td>{display_value}</td>")
        html.append("</tr>")
    html.append("</table>")

    # Creating the "Group Memberships" table in the HTML Report
    html.append("<h2>Groups Membership</h2><table><tr>")
    group_fields = ["_id", "group_id", "recipient_id", "title", "avatar_key", "avatar_content_type",
                    "timestamp", "active", "distribution_id", "last_force_update_timestamp", "ID of the group member"]

    for field in group_fields:
        html.append(f"<th>{field}</th>")
    html.append("</tr>")

    # Cross-reference memberships
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

                # Formatting the specific values (Timestamps and Booleans)
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

    # Creating the "In-App Calls" table in the HTML Report
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

            # Formatting the specific values (Timestamps and Booleans)
            if field in {"timestamp", "deletion_timestamp"}:
                display_value = format_timestamp(field, parsed_value)
            elif field in {"read", "local_joined"}:
                display_value = format_boolean_flag(field, parsed_value)
            else:
                display_value = parsed_value

            html.append(f"<td>{display_value}</td>")
        html.append("</tr>")
    html.append("</table>")

    # Creating the "Chat Folders" table in the HTML Report
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
            membership_display = f"{membership_type_value} (Member)"
        else:
            membership_display = f"Unknown"

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

                # Formatting the specific values (particularly Booleans)
                if field == "is_muted":
                    display_value = format_boolean_flag(field, parsed_value)
                else:
                    display_value = parsed_value

                html.append(f"<td>{display_value}</td>")
        html.append("</tr>")
    html.append("</table>")

    html.append("</body></html>")

    # Creating the HTML Report file. The output path will be similar to that where the JSON files are stored
    with open(output_path, 'w', encoding='utf-8') as f:
        f.write('\n'.join(html))

    print(f"\033[32m[✓] HTML report generated at:\033[0m {output_path}")

# A function which generates Chat History HTML reports for each user's chat (private and group)
def generate_chat_history_report(json_dir: str, output_base_dir: str):
    os.makedirs(output_base_dir, exist_ok=True)

    def load_json(file_name):
        try:
            with open(os.path.join(json_dir, file_name), 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception as e:
            print(f"\033[31m[✕] Failed to load\033[0m {file_name}: {e}")
            return []

    def format_clean_timestamp(ts: int) -> str:
        if ts and isinstance(ts, int) and ts > 0 and ts > 1e12:
            dt = datetime.fromtimestamp(ts / 1000, tz=timezone.utc) + timedelta(hours=2)
            return dt.strftime('%Y-%m-%d at %H:%M:%S (UTC+2)')
        return None

    def format_body_with_links(text: str) -> str:
        url_pattern = re.compile(r'(https?://[^\s<>"]+)')
        return url_pattern.sub(r'<a href="\1" target="_blank">\1</a>', text)

    messages = load_json("message.json")
    recipients = load_json("recipient.json")
    attachments = load_json("attachment.json")
    key_values = load_json("key_value.json")
    groups = load_json("groups.json")
    threads = load_json("thread.json")

    owner_id = next((item.get("value") for item in key_values if item.get("key") == "account.e164"), None)
    if not owner_id:
        print("\033[31m[✕] Could not determine the owner's Signal ID (account.e164).\033[0m")
        return

    meaningful_threads = {t["_id"] for t in threads if t.get("meaningful_messages") == 1}

    # Only keep messages from meaningful threads
    messages = [m for m in messages if m.get("thread_id") in meaningful_threads]

    recipient_lookup = {}
    phone_lookup = {}
    group_title_lookup = {g.get("group_id"): g.get("title", "Unnamed Group") for g in groups}
    recipient_group_map = {}
    group_recipient_ids = set()

    for r in recipients:
        rid = r.get("_id")
        phone = r.get("e164")
        group_id = r.get("group_id")
        name = r.get("profile_joined_name") or r.get("system_joined_name") or "Unknown"

        if not phone and group_id and group_id in group_title_lookup:
            name = group_title_lookup[group_id]
            label = f"{name} (Group)"
            recipient_group_map[rid] = group_id
            group_recipient_ids.add(rid)
        else:
            label = f"{name} ({phone})" if phone else name

        recipient_lookup[rid] = label
        phone_lookup[rid] = phone

    attachment_lookup = {}
    for a in attachments:
        mid = a.get("message_id")
        path = a.get("data_file", "")
        match = re.search(r"part\d+", path)
        if match:
            attachment_lookup[mid] = match.group(0)

    attachment_base_path = os.path.expanduser(r"~\\Downloads\\DatabasExtractor\\Signal\\org.thoughtcrime.securesms\\app_parts\\decrypted")

    # Group messages by thread_id
    thread_messages = {}
    for msg in messages:
        thread_id = msg.get("thread_id")
        if thread_id:
            thread_messages.setdefault(thread_id, []).append(msg)

    for thread_id, msgs in thread_messages.items():
        # Use first message to determine recipient
        first_msg = msgs[0]
        from_id = first_msg.get("from_recipient_id")
        to_id = first_msg.get("to_recipient_id")
        from_phone = phone_lookup.get(from_id)
        to_phone = phone_lookup.get(to_id)
        partner_id = to_id if from_phone == owner_id else from_id

        if partner_id in group_recipient_ids:
            group_id = recipient_group_map.get(partner_id)
            person = group_title_lookup.get(group_id, f"Group_{group_id}")
        else:
            person = recipient_lookup.get(partner_id, f"User_{partner_id}")

        safe_name = re.sub(r'[^\w\-]', '_', person)
        output_path = os.path.join(output_base_dir, f"chat_with_{safe_name}.html")

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
                f"<h1>Chat with {person}</h1><div class='container'>"]

        for msg in msgs:
            from_id = msg.get("from_recipient_id")
            to_id = msg.get("to_recipient_id")
            mid = msg.get("_id")
            body = msg.get("body", "")
            msg_type = msg.get("type")
            from_phone = phone_lookup.get(from_id)
            direction_class = "to" if from_phone == owner_id else "from"
            sender = recipient_lookup.get(from_id, f"User {from_id}")

            raw_ts = msg.get("date_sent") if from_phone == owner_id else msg.get("receipt_timestamp")
            try:
                raw_ts = int(raw_ts)
            except (ValueError, TypeError):
                raw_ts = 0

            formatted_ts = format_clean_timestamp(raw_ts)
            label = "Send" if from_phone == owner_id else "Received"
            timestamp_html = f"<div class='timestamp'>{label}: {formatted_ts}</div>" if formatted_ts else ""

            html.append(f"<div class='message {direction_class}'>")
            html.append(f"<div class='sender'>{sender}</div>")

            if msg_type == 2:
                from_name = recipient_lookup.get(from_id, f"User {from_id}")
                to_name = recipient_lookup.get(to_id, f"User {to_id}")
                html.append(f"<div>{from_name} added {to_name} to the group</div>")
            elif msg_type == 12:
                html.append("<div><i>[Started a video or an audio call]</i></div>")
            elif body:
                html.append(f"<div>{format_body_with_links(body)}</div>")
            else:
                part_key = attachment_lookup.get(mid)
                if part_key:
                    found_file = None
                    for ext in ['.jpg', '.jpeg', '.png', '.gif', '.mp4', '.webp', '.webm', '.pdf', '.docx', '.zip', '.txt']:
                        test_path = os.path.join(attachment_base_path, part_key + ext)
                        if os.path.exists(test_path):
                            found_file = test_path
                            break

                    if found_file:
                        path_uri = found_file.replace("\\", "/")
                        filename = os.path.basename(path_uri)
                        if path_uri.lower().endswith(('.jpg', '.jpeg', '.png', '.gif', '.webp')):
                            html.append(f"<img src='file:///{path_uri}' style='max-width:200px;'>")
                            html.append(f"<div class='filename'>{filename}</div>")
                        elif path_uri.lower().endswith(('.mp4', '.webm')):
                            html.append(f"<video controls width='250'><source src='file:///{path_uri}'></video>")
                            html.append(f"<div class='filename'>{filename}</div>")
                        else:
                            html.append(f"<a href='file:///{path_uri}' download>[Attachment: {filename}]</a>")
                    else:
                        html.append("<div><i>[Missing attachment]</i></div>")
                else:
                    html.append("<div><i>[Empty message]</i></div>")

            html.append(timestamp_html)
            html.append("</div>")

        html.append("</div></body></html>")

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
    generate_user_html_report(json_dir, html_output)
    # Generate the user's Chat History HTML reports
    chat_output_dir = os.path.join(json_dir, "Chats")
    generate_chat_history_report(json_dir, chat_output_dir)

# ======================================================================================

# ======================Viber Messenger Artefact formatting=============================

# Functions that do the process of extracting the artefacts of the messengers and transforming them into the .html files
def extract_viber_artefacts():
    print("[!] Viber artifact extraction not implemented yet.")
    return

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
            files_to_copy = ["/data/data/com.viber.voip/"]
            folder_name = "Viber"
        elif choice == "2":
            files_to_copy = ["/data/data/com.whatsapp/"]
            folder_name = "WhatsApp"
        elif choice == "3":
            files_to_copy = [
                "/data/data/org.thoughtcrime.securesms/",
                "/data/misc/keystore/persistent.sqlite"
            ]
            folder_name = "Signal"
        elif choice == "4":
            files_to_copy = ["/data/data/org.telegram.messenger/"]
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
