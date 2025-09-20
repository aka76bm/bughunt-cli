import requests
import json
import socket # For DNS lookups
from urllib.parse import urlparse

def get_subdomains_from_crtsh(domain):
    """
    Queries crt.sh for subdomains of a given domain.
    """
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()  # Raise an exception for HTTP errors
        data = response.json()

        subdomains = set()
        for entry in data:
            name_value = entry.get('name_value', '')
            # crt.sh returns domains with and without wildcards, and also the main domain
            # We want to extract unique subdomains
            for subdomain in name_value.split('\n'):
                subdomain = subdomain.strip()
                if subdomain.startswith('*.') :
                    subdomain = subdomain[2:]
                if subdomain.endswith(f".{domain}") and subdomain != domain:
                    subdomains.add(subdomain)
                elif subdomain == domain: # Include the main domain if it's explicitly listed
                    subdomains.add(subdomain)

        return sorted(list(subdomains))
    except requests.exceptions.RequestException as e:
        print(f"Error querying crt.sh: {e}")
        return []
    except json.JSONDecodeError:
        print("Error decoding JSON response from crt.sh")
        return []

def dns_brute_force(domain, wordlist=None):
    """
    Performs DNS brute force to discover subdomains.
    """
    if wordlist is None:
        # A small, built-in wordlist for demonstration
        wordlist = ["www", "mail", "ftp", "dev", "test", "admin", "blog", "api", "cdn"]

    found_subdomains = set()
    # print(f"[*] Starting DNS brute force for {domain} with {len(wordlist)} words...") # Rich will handle this

    for word in wordlist:
        subdomain_to_check = f"{word}.{domain}"
        try:
            # Attempt to resolve the subdomain
            ip_address = socket.gethostbyname(subdomain_to_check)
            found_subdomains.add(subdomain_to_check)
            # print(f"    [+] Found: {subdomain_to_check} ({ip_address})") # Rich will handle this
        except socket.gaierror:
            # Host not found
            pass
        except Exception as e:
            print(f"    [-] Error resolving {subdomain_to_check}: {e}")
    
    return sorted(list(found_subdomains))

def get_subdomains_from_wayback(domain):
    """
    Queries Wayback Machine for subdomains of a given domain.
    """
    url = f"http://web.archive.org/cdx/search/cdx?url=*.{domain}/*&output=json&collapse=urlkey"
    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        data = response.json()

        subdomains = set()
        # The first element in the response is usually the header, skip it
        for entry in data[1:]:
            full_url = entry[2] # The 'urlkey' field
            parsed_url = urlparse(full_url)
            hostname = parsed_url.hostname
            if hostname and hostname.endswith(f".{domain}"):
                subdomains.add(hostname)
        
        return sorted(list(subdomains))
    except requests.exceptions.RequestException as e:
        print(f"Error querying Wayback Machine: {e}")
        return []
    except json.JSONDecodeError:
        print("Error decoding JSON response from Wayback Machine")
        return []

def enumerate_subdomains(domain, dns_wordlist=None):
    """
    Enumerates subdomains using multiple sources: crt.sh, DNS brute force, and Wayback Machine.
    """
    all_subdomains = set()

    print(f"[*] Enumerating subdomains for {domain}...")

    # crt.sh
    print(f"    [*] Querying crt.sh for {domain}...")
    crtsh_subdomains = get_subdomains_from_crtsh(domain)
    if crtsh_subdomains:
        all_subdomains.update(crtsh_subdomains)
        print(f"        [+] Found {len(crtsh_subdomains)} subdomains from crt.sh")

    # DNS Brute Force
    print(f"    [*] Starting DNS brute force for {domain}...")
    dns_subdomains = dns_brute_force(domain, dns_wordlist)
    if dns_subdomains:
        all_subdomains.update(dns_subdomains)
        print(f"        [+] Found {len(dns_subdomains)} subdomains from DNS brute force")

    # Wayback Machine
    print(f"    [*] Querying Wayback Machine for {domain}...")
    wayback_subdomains = get_subdomains_from_wayback(domain)
    if wayback_subdomains:
        all_subdomains.update(wayback_subdomains)
        print(f"        [+] Found {len(wayback_subdomains)} subdomains from Wayback Machine")

    print(f"[*] Total unique subdomains found for {domain}: {len(all_subdomains)}")
    return sorted(list(all_subdomains))

if __name__ == '__main__':
    target_domain = "example.com"
    print(f"Running comprehensive subdomain enumeration for {target_domain}...")
    found_subdomains = enumerate_subdomains(target_domain)
    if found_subdomains:
        print("\n--- Discovered Subdomains ---")
        for sd in found_subdomains:
            print(sd)
    else:
        print(f"No subdomains found for {target_domain} or an error occurred.")
