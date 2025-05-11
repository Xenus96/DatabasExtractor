# DatabasExtractor version 1.3
Messenger DatabasExtractor for Android devices. Was tested primarly on Android 14.

<p align="center">
  <img width="800" src="https://github.com/user-attachments/assets/d21b617d-9dd5-43c1-bbe3-f22ea835300c">
</p>

## Current DatabasExtractor features:
- Allows to extract artifacts of the following messengers: Viber, WhatsApp, Signal and Telegram;
- Extracted artifacts are automatically copied to your local computer at C:\Users\<username>\Downloads\DatabasExtractor;
- Extracted artifacts are also saved to an internal /storage/emulated/0/Download/DatabasExtractor directory of your Mobile Device;
- Allows to delete the directory /storage/emulated/0/Download/DatabasExtractor to free the Mobile Device's space;
- Automatically performs the AES GCM decryption of the SQLCipher key which is used to open the file "signal.db".

<p align="center">
  <img width="800" src="https://github.com/user-attachments/assets/f3a2cb82-ae7f-4c2b-91df-ee9f23b29412">
</p>

- Automatically decrypts all user attachments (photo, video, documents) from the "../app_parts" directory of the Signal Messenger (for detailed examples check the **"How to use the "Signal Artefact Extraction" feature"** paragraph below)
- Automatically generates HTML reports with the general info about the user and with his messaging history in the Signal Messenger (for detailed examples check the **"How to use the "Signal Artefact Extraction" feature"** paragraph below)

## How to use the "Signal Artefact Extraction" feature
#### Step 1: Launch the DatabasExtractor tool and choose the specific option from the menu.

<p align="center">
  <img width="800" src="https://github.com/user-attachments/assets/014474e8-0208-4bdf-a9bb-8ac63d2db243">
</p>

**IMPORTANT NOTE:** Before decrypting attachments and generating the HTML reports, you need to extract the Signal Messenger files from you Mobile Device with DatabasExtractor!

#### Step 2: Open the decrypted "signal.db" database in DB Browser for SQLite and export the table "attachment.json" to a new folder.

<p align="center">
  <img width="800" src="https://github.com/user-attachments/assets/15da87f3-7fe0-4826-b202-2a9e45de9ec8">
</p>

Extract the table "key_value" from the database "signal-key-value.db" in the same way into the same folder.

#### Step 3: Send the path pointing to the folder (where the “attachment.json” and other JSON files are located) to the DatabasExtractor tool.

<p align="center">
  <img width="800" src="https://github.com/user-attachments/assets/f67c5cbd-9d91-44f1-983f-118498b37bab">
</p>

All decrypted attachments will be saved at: **C:/Users/%username%/Downloads/DatabasExtractor/Signal/org.thoughtcrime.securesms/app_parts/decrypted.**\
The generated HTML report about the user will be saved at: **<path_to_the_folder_with_extracted_json_tables>/Signal_User_Report.html**\
The generated chat history HTML reports will be saved at: **<path_to_the_folder_with_extracted_json_tables>/Chats**

<p align="center">
  <img width="800" src="https://github.com/user-attachments/assets/b7c6136b-a2fb-4001-a6f9-b93a9975b4a9">
</p>


## Prerequisites:
- Your mobile device must work under the Android OS 12-14;
- Your mobile device must be rooted to use the DatabasExtractor tool;
- You need to download an Android Debug Bridge (ADB) tool on your computer;
- You need to install Python 3.10 (or newer) on your computer;
- You need to connect your mobile device to your computer with USB cable and turn on USB Debugging on the phone;
- The following Python libraries must be manually installed: cryptography.

## License

[![License: CC BY-NC-ND 4.0](https://licensebuttons.net/l/by-nc-nd/4.0/88x31.png)](http://creativecommons.org/licenses/by-nc-nd/4.0/)
This project is licensed under the [Creative Commons Attribution-NonCommercial-NoDerivatives 4.0 International License](http://creativecommons.org/licenses/by-nc-nd/4.0/).
