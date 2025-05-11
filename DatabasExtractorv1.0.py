import subprocess
import os
import time
from pathlib import Path

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


# Function to execute ADB commands
def run_adb_command(command):
    result = subprocess.run(command, shell=True, capture_output=True, text=True)
    if result.returncode != 0:
        print(f"\033[31mError executing command:\033[0m {command}")
        print(result.stderr)
        return None
    return result.stdout


# Function to check root access
def check_root_access():
    whoami_output = run_adb_command("adb shell su -c whoami")
    if whoami_output and whoami_output.strip() == "root":
        return True
    return False


# Function to copy files on the device using 'cp' command and organize them into folders
def copy_files_from_device(remote_paths, local_dir, folder_name):
    # Create a folder for the messenger in the destination directory
    messenger_folder = f"{local_dir}/{folder_name}"
    run_adb_command(f"adb shell mkdir -p {messenger_folder}")

    for remote_path in remote_paths:
        file_name = os.path.basename(remote_path)
        destination_path = f"{messenger_folder}/{file_name}"

        # Use 'cp' command to copy files on the device
        copy_command = f"adb shell su -c cp {remote_path} {destination_path}"
        run_adb_command(copy_command)
        print(f"Copied {remote_path} to {destination_path}")
        time.sleep(0.25)

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

    # Renaming extracted Viber files so they are represented in the correct database form
    if folder_name == "Viber":
        windows_viber_folder = os.path.expanduser("~\Downloads\DatabasExtractor\Viber/")
        os.rename(f"{windows_viber_folder}/viber_data", f"{windows_viber_folder}/viber_data.db" )
        os.rename(f"{windows_viber_folder}/viber_messages", f"{windows_viber_folder}/viber_messages.db")
        os.rename(f"{windows_viber_folder}/viber_prefs", f"{windows_viber_folder}/viber_prefs.db")



# Function to delete the "DatabasExtractor" folder and all its contents
def delete_database_extractor_folder(local_dir):
    print(f"Deleting {local_dir} and all its contents...")
    run_adb_command(f"adb shell rm -rf {local_dir}")
    print(f"\033[32mDeleted {local_dir}.\033[0m")


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
                "/data/data/com.viber.voip/databases/viber_data",
                "/data/data/com.viber.voip/databases/viber_messages",
                "/data/data/com.viber.voip/databases/viber_prefs"
            ]
            folder_name = "Viber"
        elif choice == "2":
            files_to_copy = [
                "/data/data/com.whatsapp/databases/axolotl.db",
                "/data/data/com.whatsapp/databases/wa.db",
                "/data/data/com.whatsapp/databases/msgstore.db",
                "/data/data/com.whatsapp/databases/media.db",
                "/data/data/com.whatsapp/databases/location.db",
                "/data/data/com.whatsapp/shared_prefs/keystore.xml"
            ]
            folder_name = "WhatsApp"
        elif choice == "3":
            files_to_copy = [
                "/data/data/org.thoughtcrime.securesms/databases/signal.db",
                "/data/data/org.thoughtcrime.securesms/shared_prefs/org.thoughtcrime.securesms_preferences.xml",
                "/data/misc/keystore/persistent.sqlite"
            ]
            folder_name = "Signal"
        elif choice == "4":
            files_to_copy = [
                "/data/data/org.telegram.messenger/files/cache4.db",
                "/data/data/org.telegram.messenger/shared_prefs/mainconfig.xml",
                "/data/data/org.telegram.messenger/shared_prefs/userconfig.xml"
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
        time.sleep(0.5)


if __name__ == "__main__":
    main()
