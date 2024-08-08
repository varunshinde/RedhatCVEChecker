import re
import subprocess
import requests
from bs4 import BeautifulSoup
import os
from collections import defaultdict

def parse_rhsa_line(line):
    """
    Parse a line from the input file to extract RHSA and package information.
    """
    match = re.match(r'RHEL \d+ : (.+) \((RHSA-\d+:\d+)\)', line)
    if match:
        package = match.group(1).strip()
        rhsa = match.group(2)
        return package, rhsa
    return None, None

def fetch_cves_and_advisory(rhsa):
    """
    Fetch CVEs and security advisory for a given RHSA.
    """
    url = f"https://access.redhat.com/errata/{rhsa}"
    print(f"Fetching data for {rhsa} from {url}")
    try:
        response = requests.get(url)
        response.raise_for_status()
    except requests.exceptions.RequestException as e:
        print(f"Error fetching {url}: {str(e)}")
        return [], "Unknown"

    soup = BeautifulSoup(response.content, 'html.parser')
    
    # Fetch Security advisory(Severity)
    advisory = "Unknown"
    div_tag = soup.find('div', {'id': 'type-severity'})
    if div_tag:
        p_tag = div_tag.find('p')
        if p_tag:
            advisory_parts = p_tag.text.strip().split(": ")
            if len(advisory_parts) > 1:
                advisory = advisory_parts[1]
    print(f"Advisory for {rhsa}: {advisory}")

    # Fetch CVEs under each RHSA Vulnerability
    cves = list(set(re.findall(r'CVE-\d{4}-\d+', response.text)))
    print(f"CVEs found for {rhsa}: {cves}")
    
    return cves, advisory

def check_cve_fixed(cve, package):
    """
    Check if a CVE is fixed in the current Linux image. Logic has been separated for the kernel and other packages.
    More optimized way will be updated later on. 
    """
    if not re.match(r'CVE-\d{4}-\d+', cve):
        print(f"Invalid CVE format: {cve}")
        return False

    if package.lower() == 'kernel':
        cmd = f"rpm -q --changelog kernel | grep {cve}"
    else:
        cmd = f"rpm -q --changelog {package} | grep {cve}"
    
    print(f"Checking if {cve} is fixed in {package}")
    try:
        process = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
        stdout, stderr = process.communicate()
        
        if process.returncode == 0:
            print(f"{cve} is fixed in {package}")
            return True
        else:
            print(f"{cve} is not fixed in {package}")
            return False
    except Exception as e:
        print(f"Error checking {cve} in {package}: {str(e)}")
        return False

def categorize_cves(rhsa_list):
    """
    Categorize CVEs as fixed or not fixed, subcategorized by security advisory and package.
    """
    fixed = defaultdict(lambda: defaultdict(list))
    not_fixed = defaultdict(lambda: defaultdict(list))
    total_cves = 0
    fixed_count = 0
    not_fixed_count = 0
    
    for package, rhsa in rhsa_list:
        print(f"\nProcessing {rhsa} for package {package}")
        try:
            cves, advisory = fetch_cves_and_advisory(rhsa)
            if not cves:
                print(f"No CVEs found for {rhsa}")
                continue
            
            total_cves += len(cves)
            for cve in cves:
                if check_cve_fixed(cve, package):
                    fixed[advisory][package].append(cve)
                    fixed_count += 1
                else:
                    not_fixed[advisory][package].append(cve)
                    not_fixed_count += 1
        except Exception as e:
            print(f"Error processing {rhsa}: {str(e)}")
    
    return fixed, not_fixed, total_cves, fixed_count, not_fixed_count

def save_results_to_file(fixed, not_fixed, total_cves, fixed_count, not_fixed_count, output_file):
    """
    Save the results to a file.
    """
    with open(output_file, 'w') as file:
        file.write("Results:\n")
        file.write(f"Total CVEs processed: {total_cves}\n")
        file.write(f"Fixed CVEs: {fixed_count}\n")
        file.write(f"Not Fixed CVEs: {not_fixed_count}\n")
        
        file.write("\nFixed CVEs:\n")
        for advisory, packages in fixed.items():
            file.write(f"  {advisory}:\n")
            for package, cves in packages.items():
                file.write(f"    {package}:\n")
                for cve in cves:
                    file.write(f"      - {cve}\n")
        
        file.write("\nNot Fixed CVEs:\n")
        for advisory, packages in not_fixed.items():
            file.write(f"  {advisory}:\n")
            for package, cves in packages.items():
                file.write(f"    {package}:\n")
                for cve in cves:
                    file.write(f"      - {cve}\n")
        
        if not fixed and not not_fixed:
            file.write("No CVEs were processed. This could be due to network issues, incorrect RHSA format, or problems with the rpm command.\n")

def main():
    input_file = '/tmp/RHEL8CVE.txt'
    output_file = '/tmp/CVE_Report.txt'
    
    if not os.path.exists(input_file):
        print(f"Error: Input file not found at {input_file}")
        return

    with open(input_file, 'r') as file:
        rhsa_list = []
        for line in file:
            package, rhsa = parse_rhsa_line(line.strip())
            if package and rhsa:
                rhsa_list.append((package, rhsa))
    
    print(f"Found {len(rhsa_list)} valid RHSA entries in the input file")
    
    fixed, not_fixed, total_cves, fixed_count, not_fixed_count = categorize_cves(rhsa_list)
    
    print("\nResults:")
    print(f"Total CVEs processed: {total_cves}")
    print(f"Fixed CVEs: {fixed_count}")
    print(f"Not Fixed CVEs: {not_fixed_count}")
    
    print("\nFixed CVEs:")
    for advisory, packages in fixed.items():
        print(f"  {advisory}:")
        for package, cves in packages.items():
            print(f"    {package}:")
            for cve in cves:
                print(f"      - {cve}")
    
    print("\nNot Fixed CVEs:")
    for advisory, packages in not_fixed.items():
        print(f"  {advisory}:")
        for package, cves in packages.items():
            print(f"    {package}:")
            for cve in cves:
                print(f"      - {cve}")
    
    if not fixed and not not_fixed:
        print("No CVEs were processed. This could be due to network issues, incorrect RHSA format, or problems with the rpm command.")
    
    # Save results to a file
    save_results_to_file(fixed, not_fixed, total_cves, fixed_count, not_fixed_count, output_file)
    print(f"\nResults saved to {output_file}")

if __name__ == "__main__":
    main()

