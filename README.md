# Manual Map Injector

**Manual Map Injector.exe** — A Windows console tool for advanced DLL injection using **manual mapping**. This method bypasses `LoadLibrary` for stealthier injection and greater control.

---

## ✨ Features

- **Manual Mapping:** Handles PE relocations, import table resolution, TLS callbacks, and SEH setup manually.
- **Architecture Support:** Works for both x86 and x64 target processes.
- **Privilege Management:** Checks for administrator rights and enables debug privileges automatically.
- **Clear Console Logs:** Uses color-coded output for success, info, warnings, and errors.
- **Portable Source:** Clean C++ code with minimal dependencies.

---

## ⚙️ How It Works

1. Prompts for the **target process name** and **path to the DLL**.
2. Reads the DLL into memory.
3. Allocates memory in the target process.
4. Writes PE headers and sections manually.
5. Executes custom shellcode in the remote process to finalize mapping.
6. Runs the DLL’s `DllMain` entry point directly.

---

## 🚀 Usage

1. **Run as Administrator**  
   Required to obtain necessary process access rights.
2. **Provide Inputs**  
   - **Target process name** (e.g., `notepad.exe`)
   - **Full DLL path** (e.g., `C:\Path\To\MyDLL.dll`)
3. The injector will attempt to map the DLL and log progress to the console.

**Example:**
Enter target process name: notepad.exe
Enter DLL path: C:\MyDLL.dll
---

## ⚠️ Disclaimer

This project is for **educational and research purposes only**.  
**Do not use** this tool to inject into software you do not own or without permission.  
The author is **not responsible** for any misuse.

---

## 📌 Author

Developed by [Krishna1nOnly](https://github.com/Krishna1nOnly)  
Feel free to fork, star ⭐, and contribute!

---

## ✅ License

*Add a license file if you wish to specify usage rights.*

