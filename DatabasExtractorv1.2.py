import base64
import binascii
import json
import os
import shutil
import sqlite3
import subprocess
import time
import xml.etree.ElementTree as ET
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import hmac
import hashlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

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
        run_adb_command(copy_command)
        print(f"[✓] Copied {remote_path} to {destination_path}")

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
    run_adb_command(
            f"adb pull {messenger_folder} {windows_folder_path}")
    print(f"\033[32m[✓] Files pulled successfully!\033[0m")

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
                "~\\Downloads\\DatabasExtractor\\Signal\\org.thoughtcrime.securesms\\sqlcipher_decrypted_key.txt")
            with open(sqlcipher_key_file_path, 'w') as file:
                file.write(f"[+] SQLCipher decrypted key: {decrypted}\n")
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


# A function to extract Signal's crypto parameters from the .xml file
def extract_secrets_from_xml(xml_content: str, preference_name: str):
    try:
        root = ET.fromstring(xml_content)
        for elem in root.findall("string"):
            if elem.get("name") == preference_name:
                secret_json = json.loads(elem.text)
                return secret_json["data"], secret_json["iv"]
        raise ValueError(f"[✕] Preference '{preference_name}' not found in XML")
    except (ET.ParseError, json.JSONDecodeError, KeyError) as e:
        raise ValueError(f"[✕] Failed to extract secrets: {str(e)}")


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
        raise ValueError(f"[✕] Decryption failed: {str(e)}")


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
            raise ValueError("[✕] 'SignalSecret' not found in the keyentry table")

        keyentry_id = keyentry_row[0]
        print(f"[+] Found SignalSecret with ID: {keyentry_id} in the 'keyentry' table")

        # Searching for the Secret Key by using the found ID from the previous step
        cursor.execute("SELECT blob FROM blobentry WHERE keyentryid = ?", (keyentry_id,))
        blob_row = cursor.fetchone()

        if not blob_row or not blob_row[0]:
            raise ValueError(f"[✕] No blob found for ID {keyentry_id}")

        blob_data = blob_row[0]  # Copied raw bytes of the blob

        # Extract 16-byte segment (aka Secret Key) starting at byte 5 (index 5 to 21)
        if len(blob_data) < 21:
            raise ValueError("[✕] Blob is too short to extract the required segment.")

        extracted_segment = blob_data[5:21].hex() # Extracted Secret Key in HEX

        print(f"\n[✓] Extracted 16-byte segment of the Secret Key (HEX): {extracted_segment}")

        return extracted_segment

    except sqlite3.Error as e:
        print(f"[✕] Database error: {e}")
    except Exception as e:
        print(f"[✕] Error: {e}")
    finally: # Closing the connection to the database "persistent.sqlite"
        if conn:
            conn.close()


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

# A function that extracts Signal Messenger artifacts into readable HTML files and decrypts all user attachments
def extract_signal_artefacts():
    print("\n[+] Starting Signal artifact extraction and attachment decryption...")

    # Preparing all necessary paths and files
    signal_dir = os.path.expanduser("~\\Downloads\\DatabasExtractor\\Signal\\org.thoughtcrime.securesms")
    xml_path = os.path.join(signal_dir, "shared_prefs", "org.thoughtcrime.securesms_preferences.xml")
    persistent_path = os.path.expanduser("~\\Downloads\\DatabasExtractor\\Signal\\persistent.sqlite")
    app_parts_dir = os.path.join(signal_dir, "app_parts")
    decrypted_dir = os.path.join(app_parts_dir, "decrypted")

    # Ensure the directory for the decrypted attachments exists
    os.makedirs(decrypted_dir, exist_ok=True)

    # Prompt the user to input the path to the directory which containing the "attachment.json" file
    json_dir = input("Enter full path to directory containing 'attachment.json' file: ").strip()
    attachment_json_path = os.path.join(json_dir, "attachment.json")

    if not os.path.exists(attachment_json_path):
        print("\033[31m[✕] attachment.json not found. Aborting decryption.\033[0m")
        return

    try:
        # Reading the "attachment.json" file
        with open(attachment_json_path, 'r', encoding='utf-8') as aj:
            attachment_data = json.load(aj)
    except Exception as e:
        print(f"\033[31m[✕] Failed to load attachment.json: {e}\033[0m")
        return

    # Load XML content and extract enc_secret and IV of each attachment
    with open(xml_path, 'r', encoding='utf-8') as f:
        xml_content = f.read()
    enc_secret_b64, enc_secret_iv_b64 = extract_secrets_from_xml(xml_content, "pref_attachment_encrypted_secret")

    # Extract the AES GCM secret_key from the 'persistent.sqlite' database
    secret_key_hex = extract_specific_blob_segment(persistent_path)

    # Loop over '.mms' files in app_parts_dir
    for file_name in os.listdir(app_parts_dir):
        if file_name.endswith(".mms"):
            mms_path = os.path.join(app_parts_dir, file_name)

            # Find the corresponding to the chosen '.mms' file entry in the 'attachment.json' file
            matched_entry = next((entry for entry in attachment_data if entry.get("data_file", "").endswith(file_name)), None)

            if not matched_entry:
                print(f"[!] Skipping {file_name} - No matching data_file entry in attachment.json.")
                continue

            # If the corresponding to the chosen '.mms' file entry was found in the 'attachment.json' file
            try:
                # then extract related "data_random" key. The "data_random" key is used to derive the attachment decryption key via HMAC-SHA256
                data_random_b64 = matched_entry["data_random"]
                data_random_bytes = base64.b64decode(pad_base64(data_random_b64))
                data_random_hex = data_random_bytes.hex()
                # and "content_type" key. The "content_type" key is used as the correct extension for the decrypted attachment
                content_type = matched_entry.get("content_type", "application/octet-stream")
                extension = content_type.split("/")[-1]
                output_path = os.path.join(decrypted_dir, os.path.splitext(file_name)[0] + f".{extension}")
            except Exception as e:
                print(f"[✕] Failed to prepare decryption for {file_name}: {e}")
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
                print(f"[!] Failed to decrypt {file_name}: {e}")



# Functions that do the process of extracting the artefacts of the messengers and transforming them into the .html files
def extract_viber_artefacts():
    print("[!] Viber artifact extraction not implemented yet.")
    return

def extract_whatsapp_artefacts():
    print("[!] WhatsApp artifact extraction not implemented yet.")
    return

def extract_telegram_artefacts():
    print("[!] Telegram artifact extraction not implemented yet.")
    return


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
