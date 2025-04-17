# DatabasExtractor
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

- Automatically decrypts all user attachments (photo, video, documents) from the "../app_parts" directory of the Signal Messenger (for detailed examples check the **"How to use the "Signal Attachment Decryption" feature"** paragraph below)

## How to use the "Signal Attachment Decryption" feature
#### Step 1:


## Prerequisites:
- Your Android device must be rooted to use the DatabasExtractor script;
- You need to download an Android Debug Bridge (ADB) tool on your computer;
- You need to install Python on your computer;
- You need to connect your Android device to your computer via USB cable and turn on USB Debugging on the phone;
- You need to start the DatabasExtractor.py script from the ADB directory (where the file abd.exe is located). This is applicable ONLY to DatabasExtractorv1.0. In DatabasExtractorv1.1 this process was automated.
- The following Python libraries must be installed: cryptography, ...
