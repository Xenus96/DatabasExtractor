<div align="center">

# 🔎 DatabasExtractor v1.6

[![Python 3.10+](https://img.shields.io/badge/Python-3.10%2B-FFD43B?style=for-the-badge&logo=python&logoColor=blue)](https://www.python.org/)
[![Android 12-14](https://img.shields.io/badge/Android-12--14-3DDC84?style=for-the-badge&logo=android&logoColor=white)](https://www.android.com/)
[![License: CC BY-NC-ND 4.0](https://img.shields.io/badge/License-CC_BY--NC--ND_4.0-0467DF?style=for-the-badge&logo=creativecommons&logoColor=white)](http://creativecommons.org/licenses/by-nc-nd/4.0/)

**An Automated Digital Forensics Tool for Modern Android Messengers**

</div>

> [!WARNING]  
> **DISCLAIMER:** This tool was developed as a Master's Diploma project. It is strictly intended for **demonstrational, educational, and authorized digital forensics purposes only**. The author is not responsible for any misuse or illegal application of this software.

---

## 📖 About The Project

**DatabasExtractor** is a streamlined console utility designed to automate the digital forensics investigation of popular messaging applications on Android devices. Operating seamlessly via the command line (optimized for Windows Terminal but cross-platform compatible), it communicates with connected mobile devices utilizing the **Android Debug Bridge (ADB)**.

The tool systematically extracts, decrypts, and reports on user data and chat histories from **Viber, WhatsApp, Signal, and Telegram**, transforming complex database structures into readable, professional-grade reports.

<p align="center">
  <img width="800" src="https://github.com/user-attachments/assets/d21b617d-9dd5-43c1-bbe3-f22ea835300c" alt="DatabasExtractor Main Menu">
</p>

---

## ✨ Key Features

### 📱 Broad Messenger Support
Extracts artifacts from the most widely used secure messengers:
*   **Viber**
*   **WhatsApp**
*   **Signal**
*   **Telegram** (Cache data)

### 🔄 Intelligent Extraction Routing (Root Limitation Bypass)
To bypass direct ADB root pull limitations, DatabasExtractor uses a smart two-step extraction process:
1.  Copies all relevant messenger files to a temporary directory on the target device (`/storage/emulated/0/Download/DatabasExtractor`).
2.  Pulls the files securely to the investigator's PC (`C:\Users\<username>\Downloads\DatabasExtractor`).
*Includes a built-in clean-up feature to remotely delete the temporary device folder and free up storage space post-extraction.*

### 🔐 Automated Signal Decryption
*   Automatically performs **AES GCM decryption** of the SQLCipher key required to open `signal.db`, saving it directly to `sqlcipher_decrypted_key.txt`.
*   Automatically decrypts all user media attachments (photos, videos, documents) from the `../app_parts` directory, neatly organizing them into a designated `/Decrypted` folder.

### 📊 Comprehensive Forensic Reporting
Automatically queries extracted databases to build well-formatted **HTML/PDF Reports**:
*   **User Reports:** Contains global account info, contacts, and metadata of the investigated subject (e.g., `<Messenger>_User_Report`).
*   **Chat Reports:** Generates isolated, comprehensive histories for each individual conversation (e.g., `Chat_with_<phone_number>`), complete with embedded files, clickable links, and voice messages stored cleanly in a dedicated `/Chats` directory.

<details>
<summary><b>📸 Click to view Report Previews</b></summary>

<p align="center">
  <br><b>Signal Artifacts Decryption:</b><br>
  <img width="800" src="https://github.com/user-attachments/assets/f3a2cb82-ae7f-4c2b-91df-ee9f23b29412">
</p>
<p align="center">
  <br><b>Viber Report:</b><br>
  <img width="800" src="https://github.com/user-attachments/assets/d9efd946-0df8-41f6-bfaf-7bf0e4f42db4">
</p>
<p align="center">
  <br><b>WhatsApp Report:</b><br>
  <img width="800" src="https://github.com/user-attachments/assets/82103851-ea0a-438b-adf3-10c71331ea83">
</p>
<p align="center">
  <br><b>Telegram Report:</b><br>
  <img width="800" src="https://github.com/user-attachments/assets/7295acf9-967d-4a0b-a7a1-6b1ae2025ee2">
</p>
</details>

---

## 🛠️ Prerequisites

Before utilizing DatabasExtractor, ensure your environment meets the following requirements:

*   **Target Device:** Android OS 12–14.
*   **Privileges:** The target device **must be rooted** (DatabasExtractor verifies `sudo su` execution capabilities).
*   **Connection:** Device must be connected to the PC via USB cable with **USB Debugging** enabled.
*   **System Tools:** [Android Debug Bridge (ADB)](https://developer.android.com/studio/command-line/adb) installed and added to your system PATH.
*   **Python:** Python 3.10 or newer installed.
*   **Dependencies:** The `cryptography` Python library must be installed manually:
    ```bash
    pip install cryptography
    ```

---

## 🔍 How to Use the "Signal Artifact Extraction" Feature

Signal requires a specific workflow to successfully decrypt databases and generate reports. 

> [!IMPORTANT]  
> **Before starting:** You must first use the main menu to extract the Signal Messenger files from the mobile device to your PC!

### Step 1: Launch Signal Artifact Extraction
Launch the DatabasExtractor tool and choose the specific Signal extraction option from the menu.
<p align="center">
  <img width="800" src="https://github.com/user-attachments/assets/014474e8-0208-4bdf-a9bb-8ac63d2db243">
</p>

### Step 2: Export Database Tables
Open the decrypted `signal.db` database in [DB Browser for SQLite](https://sqlitebrowser.org/) and export all the tables into a new, dedicated folder.
<p align="center">
  <img width="800" src="https://github.com/user-attachments/assets/15da87f3-7fe0-4826-b202-2a9e45de9ec8">
</p>
*Note: Extract the `key_value` table from the `signal-key-value.db` database into the exact same folder.*

### Step 3: Provide Path and Generate Reports
Provide DatabasExtractor with the absolute path to the folder where your freshly exported `.json` tables (including `attachment.json`) are located.
<p align="center">
  <img width="800" src="https://github.com/user-attachments/assets/f67c5cbd-9d91-44f1-983f-118498b37bab">
</p>

**Output Locations:**
*   **Decrypted Attachments:** `C:/Users/<username>/Downloads/DatabasExtractor/Signal/org.thoughtcrime.securesms/app_parts/decrypted`
*   **Global User Report:** `<extracted_json_folder>/Signal_User_Report.[pdf/html]`
*   **Individual Chat Reports:** `<extracted_json_folder>/Chats/`

<p align="center">
  <img width="800" src="https://github.com/user-attachments/assets/b7c6136b-a2fb-4001-a6f9-b93a9975b4a9">
</p>

---

## ⚖️ License

This project is licensed under the **Creative Commons Attribution-NonCommercial-NoDerivatives 4.0 International License**.

[![License: CC BY-NC-ND 4.0](https://licensebuttons.net/l/by-nc-nd/4.0/88x31.png)](http://creativecommons.org/licenses/by-nc-nd/4.0/)

To view a copy of this license, visit [http://creativecommons.org/licenses/by-nc-nd/4.0/](http://creativecommons.org/licenses/by-nc-nd/4.0/).
