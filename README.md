# Unity A16 Fixer: Fix Old Unity Games Crashing on Newer Android Versions

A one-click, pure Python 3 script designed to fix old Unity games (<= 2017.x) that crash upon launch on modern Android 14, 15, and 16 devices (specifically newer arm64 phones, like recent Samsung Galaxy models).

No need to install complex dependencies or `pip` packages. The script automatically handles downloading the required tools (Apktool and Uber-APK-Signer), decompiles the game, applies the necessary binary and manifest patches, and rebuilds a ready-to-install APK.

## 📋 Requirements

* **Python 3.8** or newer.
* **Java (JRE/JDK 11+)** installed and added to your system's PATH.
* An active internet connection (only required for the **first run** to download Apktool and Uber-APK-Signer).

## 🚀 How to Use (One-Click Method)

1. Place your target game `.apk` in the **same folder** as `unity_a16_fix.py`.
2. Run the script:
   ```bash
   python unity_a16_fix.py
   ```
3. The script will ask you to select the APK file. 
4. Wait for the process to finish. The script will generate a new file named `<your_game>_fixed.apk`.
5. **Uninstall the original game** from your phone (the signatures will not match).
6. Install the new `_fixed.apk` on your device.

## 🛠️ Advanced Usage (CLI)

You can bypass the interactive menu by passing arguments directly via the command line:

```bash
python unity_a16_fix.py

python unity_a16_fix.py game.apk

# Patch an already decompiled Apktool folder in place
python unity_a16_fix.py <decoded_folder>

# Patch and automatically rebuild the folder
python unity_a16_fix.py <decoded_folder> --build
```

**Optional Flags:**
* `--dry-run` : Simulates the patching process without writing any changes.
* `--no-sign` : Rebuilds the APK without signing it.
* `--out PATH` : Specify a custom output path for the fixed APK.
* `--skip-manifest` / `--skip-lib` / `--skip-jni` : Skips specific patching steps.

## 🐛 What Exactly Does This Fix?

This script doesn't just guess offsets; it uses advanced pattern matching to apply precise fixes to the decompiled code:

1. **MTE / Heap Pointer Tagging:** Adds standard opt-outs to `AndroidManifest.xml` to prevent crashes on modern ARMv9 processors.
2. **Unity Allocator Crash:** Fixes the dreaded SIGSEGV/SIGABRT crash (`"Using memoryadresses from more that 16GB of memory"`). Older `libunity.so` files only have limited 4GB address slots. This script patches the native ARM64 assembly to force extra regions to share slot 0.
3. **Android 16 NoSuchMethodError:** Modern Android versions introduce new default interface methods (like `ServiceConnection.onServiceConnected` with 3 arguments). Older Unity JNI bridges don't know how to handle this and crash. This script injects custom Smali code to catch and safely handle these exceptions.
4. **ABI Architecture Check:** Automatically detects if the game lacks `arm64-v8a` libraries. If it's a 32-bit only game, the script will warn you, as modern 64-bit-only phones physically cannot run it, regardless of patches.
5. **Google Play Services Crash:** Fixes the IllegalStateException: A fatal developer error has occurred crash caused by older Google Play Games / Google Mobile Services clients. When a re-signed APK causes Google Play Services to return DEVELOPER_ERROR (status 10), the legacy library may throw the exception on the main thread and terminate the game. This patch intercepts the failed sign-in/developer-error path so it is handled as a normal authentication failure instead of an uncaught exception and crash.
---

## 🤝 Contributing & Anti-Plagiarism Policy

**Pull Requests are highly encouraged!** 
If you want to help improve this code, optimize the patching process, or fix bugs, please feel free to fork the repository and submit a Pull Request. Your contributions to the community are greatly appreciated.

🚫 **ZERO TOLERANCE FOR CODE THEFT** 🚫
You are strictly prohibited from taking this code, slightly modifying it (or not modifying it at all), and re-uploading it as your own original creation. 

* **Do not steal this script.**
* **Do not claim this work as yours.**
* If you use parts of this script in your own public project, you **must** provide clear, visible credit to this original repository. 

### License
This project is provided for educational and preservation purposes. While you are free to use it to fix your own legally obtained games and submit improvements back to this repository, the underlying code remains the intellectual property of its original author. Copying and rebranding this tool without permission is strictly forbidden.
