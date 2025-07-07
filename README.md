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





5. 🚀 Run Autopsy
Open your case or create a new one.

Add data source (e.g., image or logical file set).

Ensure VirusTotal Hash Checker is selected under ingest modules.

Start ingest – malicious files will be flagged automatically.

✅ Features Implemented
🧠 File Handling
Processes all files during ingest (skips folders/0-byte files)

Computes SHA-256 of each file

Reads file content safely using Autopsy APIs

Logs hashes and file names

☁️ VirusTotal API Integration
Sends hash to VirusTotal via REST API

Parses and interprets JSON response

Extracts detection score and report URL

Uses configurable detection threshold (currently hardcoded)

🚨 Detection & Tagging
Flags suspicious/malicious files based on score

Creates Autopsy tags with:

SHA-256

Detection count

VirusTotal scan URL

Also creates blackboard artifacts with the same fields

Logs all tagged files with detailed metadata

Tag levels based on detection count (Low → High)

🧰 Developer Features
Clean modular design: tagging, ingest, blackboard separated

Logging integrated with Autopsy’s system

Easy to extend and maintain

Safe fallback behavior on errors

📅 Roadmap (Planned / In Progress)
 UI panel for API key and detection threshold

 Export to CSV/JSON report (malicious files list)

 Upload file to VirusTotal if hash not found

 Cache past queries to reduce API load

 Local/Offline result saving

 Advanced tagging (color, timeline, grouping)

🛡️ Disclaimer
This tool uses the public VirusTotal API. Please ensure you abide by VirusTotal's terms of service and use an appropriate API key. Public/free API keys may have rate limits.

📧 Feedback / Issues
Feel free to open an Issue or submit a pull request. Contributions are welcome!
