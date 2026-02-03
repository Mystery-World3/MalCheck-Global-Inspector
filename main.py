import requests
import hashlib
import argparse
import base64

# Replace with VirusTotal API Key (can be obtained for free at virustotal.com)
API_KEY = 'YOUR_VIRUSTOTAL_API_KEY'

def check_hash(resource_hash):
    url = f"https://www.virustotal.com/api/v3/files/{resource_hash}"
    headers = {"x-apikey": API_KEY}
    response = requests.get(url, headers=headers)
    
    if response.status_code == 200:
        stats = response.json()['data']['attributes']['last_analysis_stats']
        print(f"\n[+] Hasil Hash: {resource_hash}")
        print(f"    Malicious: {stats['malicious']} | Harmless: {stats['harmless']}")
    else:
        print(f"[-] Error Hash: {response.json().get('error', {}).get('message')}")

def check_url(target_url):
    url_id = base64.urlsafe_b64encode(target_url.encode()).decode().strip("=")
    api_url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
    headers = {"x-apikey": API_KEY}
    response = requests.get(api_url, headers=headers)

    if response.status_code == 200:
        stats = response.json()['data']['attributes']['last_analysis_stats']
        print(f"\n[+] Hasil URL: {target_url}")
        print(f"    Malicious: {stats['malicious']} | Harmless: {stats['harmless']}")
    else:
        print(f"[-] Error URL: {response.json().get('error', {}).get('message')}")

def main():
    parser = argparse.ArgumentParser(description="Malware & URL Reputation Checker")
    parser.add_argument("-f", "--file", help="Cek file lokal")
    parser.add_argument("-s", "--hash", help="Cek SHA256 Hash")
    parser.add_argument("-u", "--url", help="Cek Link Website/URL") # Tambahan baru
    
    args = parser.parse_args()

    if args.url:
        check_url(args.url)
    elif args.file:
        pass 
    elif args.hash:
        check_hash(args.hash)

if __name__ == "__main__":
    main()