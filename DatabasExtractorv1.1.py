import subprocess
import os
import time
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag
import base64
import binascii
import xml.etree.ElementTree as ET
import json
import re
import sqlite3


# A function to execute ADB commands
def run_adb_command(command):
    result = subprocess.run(command, shell=True, capture_output=True, text=True)
    if result.returncode != 0:
        print(f"\033[31mError executing command:\033[0m {command}")
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
        print(f"Copied {remote_path} to {destination_path}")

    # Pulling the directory 'DatabasExtractor' from Mobile Device to the local computer into the C:/Users/%username%/Downloads
    print(f"\033[34mPulling for files from\033[0m {messenger_folder} \033[34mto the local computer...\033[0m")
    windows_folder_path = os.path.join(os.path.expanduser("~\Downloads"), "DatabasExtractor")

    if not (os.path.exists(windows_folder_path) and os.path.isdir(windows_folder_path)):
        # Creating a DatabasExtractor folder in Windows OS if it isn't there
        try:
            print(f"Creating a new folder at {windows_folder_path}")
            os.mkdir(windows_folder_path)
            print(f"\033[32mFolder created at:\033[0m {windows_folder_path}")
        except Exception as e:
            print(f"\033[31mAn error occurred:\033[0m {e}")

    # Pulling for files from the Mobile Device
    run_adb_command(
            f"adb pull {messenger_folder} {windows_folder_path}")
    print(f"\033[32mFiles pulled successfully!\033[0m")

    # Renaming extracted Viber files so they have the correct database form
    if folder_name == "Viber":
        windows_viber_folder = os.path.expanduser("~\Downloads\DatabasExtractor\Viber\com.viber.voip\databases/")
        os.rename(f"{windows_viber_folder}/viber_data", f"{windows_viber_folder}/viber_data.db" )
        os.rename(f"{windows_viber_folder}/viber_messages", f"{windows_viber_folder}/viber_messages.db")
        os.rename(f"{windows_viber_folder}/viber_prefs", f"{windows_viber_folder}/viber_prefs.db")

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
            print("Signal AES GCM parameters:")
            print(f"Extracted data: {data}")
            print(f"Extracted IV: {iv}")

            # Extracting the AES GCM Secret Key from the database "persistent.sqlite"
            persistent_database_file_path = os.path.expanduser("~\Downloads\DatabasExtractor\Signal\persistent.sqlite")
            hex_key = extract_specific_blob_segment(persistent_database_file_path)                 # The correct value is: " 4d 96 ce 69 9c 1f 8d da 1b f7 55 4c 97 7d 3f 4f "

            # Try to decrypt the SQLCipher key with the given HEX key. If fails then asks the user to input another HEX key.
            try:
                decrypted = aes_gcm_decrypt(data, iv, hex_key)
                print("\033[32mDecryption successful!\033[0m")
                print(f"Decrypted key (hex/plaintext): {decrypted}")
            except ValueError as e:
                print(f"\033[31mDecryption failed:\033[0m {e}")

            # Saving the decrypted key
            sqlcipher_key_file_path = os.path.expanduser(
                "~\\Downloads\\DatabasExtractor\\Signal\\org.thoughtcrime.securesms\\sqlcipher_decrypted_key.txt")
            with open(sqlcipher_key_file_path, 'w') as file:
                file.write(f"SQLCipher decrypted key: {decrypted}\n")
                file.write(sqlcipher_settings) # Adding extra instructions for user to easily use the decrypted SQLCipher key
            print(f"Decrypted SQLCipher key was saved at: {sqlcipher_key_file_path}")

        except ValueError as e:
            print(f"\033[31mError:\033[0m {e}")

# A function to delete the "DatabasExtractor" folder and all its contents on the Mobile Device
def delete_database_extractor_folder(local_dir):
    print(f"Deleting {local_dir} and all its contents...")
    run_adb_command(f"adb shell rm -rf {local_dir}")
    print(f"\033[32mDeleted {local_dir}.\033[0m")

# A function to extract Signal's crypto parameters from the .xml file
def extract_secrets_from_xml(xml_content: str, preference_name: str):
    try:
        root = ET.fromstring(xml_content)
        for elem in root.findall("string"):
            if elem.get("name") == preference_name:
                secret_json = json.loads(elem.text)
                return secret_json["data"], secret_json["iv"]
        raise ValueError(f"Preference '{preference_name}' not found in XML")
    except (ET.ParseError, json.JSONDecodeError, KeyError) as e:
        raise ValueError(f"Failed to extract secrets: {str(e)}")

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
        raise ValueError(f"Decryption failed: {str(e)}")

# A function to extract the AES GCM Secret Key of the Signal Messenger
def extract_specific_blob_segment(database_path: str) -> str:
    conn = None
    try:
        # Connect to the database
        conn = sqlite3.connect(database_path)
        cursor = conn.cursor()

        print(f"Connected to the 'persistent.sqlite' database: {database_path}")

        # Find in the database the ID of the row which has the string "SignalSecret" in it
        cursor.execute("SELECT id FROM keyentry WHERE alias = 'SignalSecret'")
        keyentry_row = cursor.fetchone()

        if not keyentry_row:
            raise ValueError("'SignalSecret' not found in keyentry table")

        keyentry_id = keyentry_row[0]
        print(f"Found SignalSecret with ID: {keyentry_id} in the 'keyentry' table")

        # Searching for the Secret Key by using the found ID from the previous step
        cursor.execute("SELECT blob FROM blobentry WHERE keyentryid = ?", (keyentry_id,))
        blob_row = cursor.fetchone()

        if not blob_row or not blob_row[0]:
            raise ValueError(f"No blob found for ID {keyentry_id}")

        blob_data = blob_row[0]  # Copied raw bytes of the blob

        # Extract 16-byte segment (aka Secret Key) starting at byte 5 (index 5 to 21)
        if len(blob_data) < 21:
            raise ValueError("Blob is too short to extract the required segment.")

        extracted_segment = blob_data[5:21].hex() # Extracted Secret Key in HEX

        print(f"\nExtracted 16-byte segment of the Secret Key (HEX): {extracted_segment}")

        return extracted_segment

    except sqlite3.Error as e:
        print(f"Database error: {e}")
    except Exception as e:
        print(f"Error: {e}")
    finally:
        if conn:
            conn.close()


# Main function
def main():

    # Check if the device is connected
    device_status = run_adb_command("adb devices")
    if "device" not in device_status:
        print("\033[31mNo device connected. Please connect your device and try again.\033[0m")
        return

    # Get root access
    print("Attempting to get root access...")
    time.sleep(0.5)
    if not check_root_access():
        print("\033[31mFailed to get root access. Exiting...\033[0m")
        return

    print("\033[32mRoot access granted.\033[0m")
    time.sleep(0.5)

    # Main folder for all extracted data
    main_folder = "/storage/emulated/0/Download/DatabasExtractor"

    while True:
        # Ask the user to choose a messenger or delete all copied files
        print("\nChoose an option:")
        print("1 - Extract Viber files")
        print("2 - Extract WhatsApp files")
        print("3 - Extract Signal files")
        print("4 - Extract Telegram files")
        print("5 - \033[31mDelete all copied files\033[0m")
        print("6 - Exit the program")

        choice = input("Enter your choice (1-6): ")

        # Define the files to copy and folder name based on the user's choice
        if choice == "1":
            files_to_copy = [
                "/data/data/com.viber.voip/"
            ]
            folder_name = "Viber"
        elif choice == "2":
            files_to_copy = [
                "/data/data/com.whatsapp/"
            ]
            folder_name = "WhatsApp"
        elif choice == "3":
            files_to_copy = [
                "/data/data/org.thoughtcrime.securesms/",
                "/data/misc/keystore/persistent.sqlite"
            ]
            folder_name = "Signal"
        elif choice == "4":
            files_to_copy = [
                "/data/data/org.telegram.messenger/"
            ]
            folder_name = "Telegram"
        elif choice == "5":
            delete_database_extractor_folder(main_folder)
            continue
        elif choice == "6":
            print("\033[32mExiting the program. Goodbye!\033[0m")
            break
        else:
            print("\033[31mInvalid choice. Please try again.\033[0m")
            continue

        # Copy the files to the Android's /storage/emulated/0/Download/DatabasExtractor directory in a folder named after the messenger
        messenger_folder = f"{main_folder}/{folder_name}"
        copy_files_from_device(files_to_copy, main_folder, folder_name)
        print(f"\033[32mFile copying and sharing completed for\033[0m {folder_name}.")


if __name__ == "__main__":
    main()
