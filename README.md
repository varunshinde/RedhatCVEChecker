# RedhatCVEChecker

# Red Hat CVE Checker

## Overview

This Python script is designed to check whether Redhat CVEs have been fixed on a Red Hat system. It supports two formats:
1. CVEs from Red Hat Security Advisories (RHSA) with naming format RHSA-XXX-XXXX
2. Direct CVEs with naming format CVE-XXXX-XXXX

The script fetches CVE information, checks if they are fixed in the system, and categorizes them based on their fix status and severity level.

## Features

- Support for both RHSA and direct CVE formats
- Fetch CVEs from RHSA pages or directly process CVE entries
- Check if CVEs are fixed in the redhat linux image
- Categorize CVEs by their severity level (Low, Moderate, Important, Critical)
- Generate a report with the status of each CVE

## Prerequisites

- Python 3.x
- Required Python packages: `requests`, `beautifulsoup4`

## Installation

1. **Clone the Repository:**
    ```bash
    git clone https://github.com/varunshinde/RedhatCVEChecker.git
    cd RedhatCVEChecker
    ```

2. **Install Required Packages:**
    ```bash
    pip install requests beautifulsoup4
    ```

## Usage

1. **Prepare the Input File:**
    - Create a file named `RHEL8CVE.txt` in the `/tmp` directory.
    - List the RHEL advisories (RHSA) and/or direct CVEs you want to check, one per line.
    - Example formats:
        ```
        RHEL 8 : cups (RHSA-2024:4580)  # RHSA format
        RHEL 8 : git (CVE-2024-4579)    # Direct CVE format
        ```

2. **Run the Script:**
    ```bash
    python redhat_cve_checker.py
    ```

3. **View the Report:**
    - The script generates a report named `CVE_Report.txt` in the `/tmp` directory.
    - The report includes the total number of CVEs, the number of fixed CVEs, and the number of not-fixed CVEs, categorized by their severity level and further categorized by packages name.

## Example

```bash
# Clone the repository
git clone https://github.com/varunshinde/RedhatCVEChecker.git
cd RedhatCVEChecker

# Install dependencies
pip install requests beautifulsoup4 tqdm

# Prepare the input file with both RHSA and direct CVE formats
echo "RHEL 8 : cups (RHSA-2024:4580)" > /tmp/RHEL8CVE.txt
echo "RHEL 8 : git (CVE-2024-4579)" >> /tmp/RHEL8CVE.txt

# Run the script
python redhat_cve_checker.py

# Check the report
cat /tmp/CVE_Report.txt
```

An example input file with both formats is provided in `RHEL8CVE_with_CVE.txt.example`.