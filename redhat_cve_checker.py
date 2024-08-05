import requests
import re
import subprocess
from bs4 import BeautifulSoup
from collections import defaultdict
from tqdm import tqdm

# File paths
fixes_file = '/tmp/RHEL8Fixes.txt'
report_file = '/tmp/CVE_Report.txt'

# Function to fetch Security Advisory and CVEs from RHSA entries
def fetch_security_advisory_and_cves(rhsa_id):
    url = f"https://access.redhat.com/errata/{rhsa_id}"
    response = requests.get(url)
    soup = BeautifulSoup(response.text, 'html.parser')

    # Fetch Security Advisory
    advisory_value = "unknown"
    div_tag = soup.find('div', {'id': 'type-severity'})
    if div_tag:
        p_tag = div_tag.find('p')
        if p_tag:
            advisory_value = p_tag.text.strip().split(": ")[1]

    # Fetch CVEs
    cves = list(set(re.findall(r'CVE-\d{4}-\d+', response.text)))
    
    return advisory_value, cves

# Function to check if a CVE fix is available in the kernel changelog
def check_cve(cve):
    result = subprocess.run(['rpm', '-q', '--changelog', 'kernel'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
    return cve in result.stdout

# Read fixes from the file and fetch Security Advisory and CVEs for RHSA entries
security_advisory_data = defaultdict(list)
with open(fixes_file, 'r') as file:
    lines = file.readlines()
    for line in tqdm(lines, desc="Processing lines"):
        line = line.strip()
        if 'RHSA-' in line:
            rhsa_id = re.search(r'RHSA-\d{4}:\d+', line).group()
            security_advisory, cves = fetch_security_advisory_and_cves(rhsa_id)
            security_advisory_data[security_advisory].extend(cves)
        elif 'CVE-' in line:
            security_advisory_data['unknown'].append(line)

# Check if fixes are available for the CVEs and categorize them
fixed_cves = defaultdict(list)
not_fixed_cves = defaultdict(list)

for advisory, cves in tqdm(security_advisory_data.items(), desc="Checking CVEs"):
    for cve in cves:
        if check_cve(cve):
            fixed_cves[advisory].append(cve)
        else:
            not_fixed_cves[advisory].append(cve)

# Calculate total counts
total_cves = sum(len(cves) for cves in security_advisory_data.values())
total_fixed = sum(len(cves) for cves in fixed_cves.values())
total_not_fixed = sum(len(cves) for cves in not_fixed_cves.values())

# Generate the report
with open(report_file, 'w') as report:
    report.write(f"Total CVEs: {total_cves}\n")
    report.write(f"Fixed CVEs: {total_fixed}\n")
    report.write(f"Not Fixed CVEs: {total_not_fixed}\n\n")

    report.write("Fixed CVEs:\n")
    for advisory, cves in fixed_cves.items():
        report.write(f"\n{advisory}:\n")
        for cve in cves:
            report.write(f"  - {cve}\n")

    report.write("\nNot Fixed CVEs:\n")
    for advisory, cves in not_fixed_cves.items():
        report.write(f"\n{advisory}:\n")
        for cve in cves:
            report.write(f"  - {cve}\n")

print(f"Report generated at: {report_file}")

