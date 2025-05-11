# DatabasExtractor version 1.1
Messenger DatabasExtractor for Android devices.\
Was tested primarly on Android 14.

![An example of using DatabasExtractor](https://github.com/user-attachments/assets/891ab671-9f63-43a8-938b-e4aa3872d905)

## Current DatabasExtractor features:
- Allows to extract artifacts of the following messengers: Viber, WhatsApp, Signal and Telegram;
- Extracted artifacts are automatically copied to your local computer at C:\Users\<username>\Downloads\DatabasExtractor;
- Extracted artifacts are also saved to an internal /storage/emulated/0/Download/DatabasExtractor directory of your Mobile Device;
- Allows to delete the directory /storage/emulated/0/Download/DatabasExtractor to free the Mobile Device's space;
- Automatically performs the AES GCM decryption of the SQLCipher key which is used to open the file "signal.db".
![An example of using the AES GCM decryption functionality](https://github.com/user-attachments/assets/f3a2cb82-ae7f-4c2b-91df-ee9f23b29412)


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
