# RedhatCVEChecker

# Red Hat CVE Checker

## Overview

This Python script is designed to check whether Redhat CVEs which naming starts as RHSA-XXX-XXXX(Common Vulnerabilities and Exposures) have been fixed on a Red Hat system. It fetches CVEs from Red Hat Security Advisories (RHSA) and categorizes them based on their fix status.

## Features

- Fetch CVEs from RHSA pages.
- Check if CVEs are fixed in the redhat linux image.
- Categorize CVEs by their severity level (Low, Moderate, Important, Critical).
- Generate a report with the status of each CVE.

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
    pip install requests beautifulsoup4 tqdm
    ```

## Usage

1. **Prepare the Input File:**
    - Create a file named `RHEL8CVE.txt` in the `/tmp` directory.
    - List the RHEL advisories and CVEs you want to check, one per line.
    - Example:
        ```
        RHEL 8 : cups (RHSA-2024:4580)
        RHEL 8 : git (RHSA-2024:4579)
        RHEL 8 / 9 : java-17-openjdk (RHSA-2024:4568)
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

# Prepare the input file
#Usually CVE's scanner like tenable/nessus agent will generate the report from 
#where you can copy the list of CVE's mentioned in a file.
echo "RHEL 8 : cups (RHSA-2024:4580)" > /tmp/RHEL8CVE.txt
echo "RHEL 8 : git (RHSA-2024:4579)" >> /tmp/RHEL8CVE.txt

# Run the script
python redhat_cve_checker.py

# Check the report
cat /tmp/CVE_Report.txt

