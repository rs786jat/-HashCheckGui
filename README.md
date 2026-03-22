
# HashCheckGui

## Project Overview
HashCheck is a simple file integrity verification tool designed to detect changes in files over time. It allows a user to create a baseline of cryptographic hashes for all files in a selected folder, and later verify the current state of that folder against the original baseline.

This helps identify whether files have been:
- Modified  
- Added  
- Deleted  
- Left unchanged  

HashCheck is useful for cybersecurity students and DFIR professionals, or anyone looking for a lightweight tool that will provide a clear view of how files change between two points in time.


## Platform Support
HashCheck is currently designed and tested for **Windows 10 & Windows 11**, Linux and macOS may require additional configuration and have **not been tested**.


## Features

- **Baseline Scan**  
  Generate a CSV manifest of files, including paths, sizes, last modified timestamps, and hashes.

- **Verification Scan**  
  Compare current files to a previous baseline and detect:
  - **OK** – Unchanged | No Color
  - **MISMATCH** – File modified | Red
  - **NEW FILE** – File added | Orange
  - **MISSING FILE** – File deleted | Grey
  - **ERROR** – File unreadable or hashing failed | Magenta/Purple

- **User Friendly Interface**  
  Clean & Simple interface with color-coded results.

- **Recursive Scanning**  
  Option to include all subfolders during scans.

- **CSV Export**  
  Save baseline or verification results for further analysis or documentation.


## Setup & Run Instructions

### 1. Install Python
Ensure you have **Python (3.14 is recommended)** installed on Windows. You can install Python here: https://www.python.org/downloads/

### 2. Download the Project Files
Place the following files together in the same directory:
- hashcheck.py
- hashcheck_gui.py

### 3. Run Hashcheck
Double-clicking the **hashcheck_gui.py** file will run HashCheck. You will see a command prompt window open, and shortly after that, HashCheck's user-friendly interface will appear!


## How to Use HashCheck
Creating a Baseline:
  1. Launch the application
  2. Select a target file or folder
  3. Choose where you want your scan results (manifest) to be stored
  4. Select a hashing algorithm (e.g., SHA-256)
  5. Enable recursive if you want to include subfolders
  6. Click "Run Scan"
  7. You can either review results in a CSV or within the HashCheck GUI itself


## Verifying File Integrity
1. Switch to the Verify tab
2. Select the same folder
3. Choose your previously created or most recent baseline CSV
4. Click "Run Verify"
