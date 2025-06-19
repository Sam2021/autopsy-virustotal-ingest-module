# Autopsy VirusTotal Hash Checker

This is an **Autopsy Python Ingest Module** that computes the SHA-256 hash of files and checks them against [VirusTotal](https://www.virustotal.com/) to identify potentially malicious files.

---

## 📦 Features

- Computes SHA-256 using Python and Autopsy's native file interface
- Queries VirusTotal API for hash lookups
- Displays scan results in the Autopsy interface
- Logs findings and errors clearly for analysis

---

## 🧰 Requirements

- Autopsy (tested with version X.X+)
- VirusTotal API key (free or premium)
- Internet connection for querying VirusTotal
- Python (used within Autopsy’s Jython environment)

---

## 🚀 Installation

1. Clone this repo or download the `vt_malware_scanner` directory.
2. Place the folder inside:

    ```bash
    C:\Users\<your-username>\AppData\Roaming\autopsy\python_modules\
    ```

3. Restart Autopsy.
4. In Autopsy, go to:
    ```
    Ingest Modules > Python Modules > VirusTotal Hash Checker
    ```

---

## 🔐 Configuration

Make sure you have your VirusTotal API key set in the module's configuration (modify the script or use GUI options if supported).

```python
API_KEY = "your_virustotal_api_key"
