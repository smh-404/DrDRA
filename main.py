import requests
import zipfile
import io
import os
import base64
import re
from datetime import datetime, timedelta
import Levenshtein

def get_encoded_date_string(date_obj):
    filename = date_obj.strftime("%Y-%m-%d.zip")
    return base64.b64encode(filename.encode()).decode()

def download_and_extract(encoded_date):
    url = f"https://www.whoisds.com//whois-database/newly-registered-domains/{encoded_date}/nrd"
    print(f"Trying URL: {url}")
    response = requests.get(url)

    if response.status_code == 200 and response.content[:2] == b'PK':
        print("Valid ZIP file detected. Extracting...")
        with zipfile.ZipFile(io.BytesIO(response.content)) as zip_file:
            extract_dir = "extracted_domains_tmp"
            os.makedirs(extract_dir, exist_ok=True)
            zip_file.extractall(extract_dir)
            print(f"Files extracted to: {extract_dir}")
            return extract_dir
    else:
        print("Not a valid ZIP file or download failed.")
        print(f"Status: {response.status_code}, Content-Type: {response.headers.get('Content-Type')}")
        return None

def generate_typosquatting_domains(domain):
    base, _, tld = domain.lower().rpartition('.')
    variants = set()

    homoglyphs = {
        'a': ['@', '4'],
        'e': ['3'],
        'i': ['1', 'l'],
        'o': ['0'],
        's': ['5', '$'],
        'l': ['1', 'i'],
        'm': ['rn'],
        'c': ['k']
    }

    variants.add(domain)

    for i in range(len(base)):
        variants.add(base[:i] + base[i+1:] + '.' + tld)
        variants.add(base[:i] + base[i]*2 + base[i+1:] + '.' + tld)

    for i in range(len(base) - 1):
        swapped = list(base)
        swapped[i], swapped[i+1] = swapped[i+1], swapped[i]
        variants.add(''.join(swapped) + '.' + tld)

    for i, char in enumerate(base):
        if char in homoglyphs:
            for alt in homoglyphs[char]:
                new = base[:i] + alt + base[i+1:]
                variants.add(new + '.' + tld)

    for word in ['login', 'verify', 'update', 'secure']:
        variants.add(f"{base}-{word}.{tld}")
        variants.add(f"{base}{word}.{tld}")

    return variants

def build_regex_patterns(base_name):
    patterns = [
        rf"{base_name}[-]?[a-z0-9]*",
        rf"{base_name}[a-z0-9]*[-]?[a-z0-9]*",
        rf"[a-z0-9]*{base_name}[a-z0-9]*",
    ]
    return [re.compile(p, re.IGNORECASE) for p in patterns]

def search_domains(extract_dir, legit_domain, levenshtein_threshold=2):
    base_name = legit_domain.split('.')[0].lower()
    tld = legit_domain.split('.')[-1].lower()
    typoset = generate_typosquatting_domains(legit_domain)
    regex_patterns = build_regex_patterns(base_name)

    matched_domains = set()

    for filename in os.listdir(extract_dir):
        if filename.endswith(".txt"):
            txt_path = os.path.join(extract_dir, filename)
            with open(txt_path, "r", encoding="utf-8", errors="ignore") as file:
                for line in file:
                    domain = line.strip().lower()

                    if domain in typoset:
                        matched_domains.add(domain)
                        continue

                    if any(p.search(domain) for p in regex_patterns):
                        matched_domains.add(domain)
                        continue

                    domain_part = domain.split('.')[0]
                    distance = Levenshtein.distance(domain_part, base_name)
                    if 0 < distance <= levenshtein_threshold:
                        matched_domains.add(domain)

    if matched_domains:
        print(f"\nDetected suspicious domains related to '{legit_domain}' in '{extract_dir}':")
        for match in sorted(matched_domains):
            print("  -", match)
    else:
        print(f"No suspicious domains found for '{legit_domain}' in '{extract_dir}'.")


def banner():
    print("")
    print(" _____         _____  _____             ")
    print(" |  __ \\       |  __ \\|  __ \\     /\\    ")
    print(" | |  | |_ __  | |  | | |__) |   /  \\   ")
    print(" | |  | | '__| | |  | |  _  /   / /\\ \\  ")
    print(" | |__| | |    | |__| | | \\ \\  / ____ \\ ")
    print(" |_____/|_|    |_____/|_|  \\_\\/_/    \\_\\ ")
    print("\nCreated by smh-404")
    print("More information can be found on: https://github.com/smh-404/DrDRA")


if __name__ == '__main__':
    banner()
    base_dir = "extracted_domains"
    os.makedirs(base_dir, exist_ok=True)

    today = datetime.today()
    downloaded_days = []
    days_checked = 0

    while len(downloaded_days) < 4:
        date_obj = today - timedelta(days=days_checked)
        days_checked += 1

        encoded_date = get_encoded_date_string(date_obj)
        dated_dir = os.path.join(base_dir, date_obj.strftime("%Y-%m-%d"))

        if os.path.exists(dated_dir):
            print(f"Already downloaded for {date_obj.strftime('%Y-%m-%d')}, skipping.")
            downloaded_days.append(dated_dir)
            continue

        print(f"\nDownloading domains for {date_obj.strftime('%Y-%m-%d')}")
        extract_dir = download_and_extract(encoded_date)

        if extract_dir:
            os.rename(extract_dir, dated_dir)
            downloaded_days.append(dated_dir)
        else:
            print(f"Failed to retrieve data for {date_obj.strftime('%Y-%m-%d')}")

    if downloaded_days:
        while True:
            user_input = input("\nEnter your legitimate domain (or type 'exit' to quit): ").strip()
            if user_input.lower() == "exit":
                print("\nGoodbye.")
                break
            elif "." not in user_input:
                print("Invalid domain format (example: microsoft.com)")
                continue

            for dir_path in downloaded_days:
                print(f"\nSearching in {dir_path}...")
                search_domains(dir_path, user_input, levenshtein_threshold=1)
