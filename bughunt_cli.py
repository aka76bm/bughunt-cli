import argparse
from rich.console import Console
from rich.text import Text
from rich.padding import Padding
from rich.panel import Panel
from rich.rule import Rule

from core.recon.subdomains import get_subdomains_from_crtsh, dns_brute_force, get_subdomains_from_wayback
from core.recon.port_scanner import scan_ports
from core.recon.tech_fingerprint import get_technologies

console = Console()

def main():
    parser = argparse.ArgumentParser(description="bughunt-cli: A comprehensive bug bounty and security research tool.")
    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # Reconnaissance module
    recon_parser = subparsers.add_parser("recon", help="Perform reconnaissance tasks.")
    recon_parser.add_argument("domain", help="Target domain for reconnaissance.")
    recon_parser.add_argument("--subdomains", action="store_true", help="Discover subdomains using certificate transparency.")
    recon_parser.add_argument("--dns-brute", action="store_true", help="Discover subdomains using DNS brute force.")
    recon_parser.add_argument("--wayback", action="store_true", help="Discover subdomains using Wayback Machine.")
    recon_parser.add_argument("--ports", type=str, help="Perform port scanning on discovered subdomains (e.g., '80,443' or '1-1024').")
    recon_parser.add_argument("--tech-fingerprint", action="store_true", help="Perform technology fingerprinting on discovered subdomains.")


    args = parser.parse_args()

    if args.command == "recon":
        console.print(Rule(f"[bold blue]Reconnaissance for {args.domain}[/bold blue]"))

        all_subdomains = set()

        if args.subdomains:
            console.print(Padding(Text("[*] Discovering subdomains using certificate transparency...", style="blue"), (1, 0, 0, 4)))
            crtsh_subdomains = get_subdomains_from_crtsh(args.domain)
            if crtsh_subdomains:
                console.print(Padding(Text(f"[+] Found {len(crtsh_subdomains)} subdomains via crt.sh.", style="green"), (0, 0, 0, 4)))
                all_subdomains.update(crtsh_subdomains)
            else:
                console.print(Padding(Text("[-] No subdomains found via crt.sh or an error occurred.", style="red"), (0, 0, 0, 4)))
        
        if args.dns_brute:
            console.print(Padding(Text("[*] Discovering subdomains using DNS brute force...", style="blue"), (1, 0, 0, 4)))
            dns_subdomains = dns_brute_force(args.domain)
            if dns_subdomains:
                console.print(Padding(Text(f"[+] Found {len(dns_subdomains)} subdomains via DNS Brute Force.", style="green"), (0, 0, 0, 4)))
                all_subdomains.update(dns_subdomains)
            else:
                console.print(Padding(Text("[-] No subdomains found via DNS brute force or an error occurred.", style="red"), (0, 0, 0, 4)))

        if args.wayback:
            console.print(Padding(Text("[*] Discovering subdomains using Wayback Machine...", style="blue"), (1, 0, 0, 4)))
            wayback_subdomains = get_subdomains_from_wayback(args.domain)
            if wayback_subdomains:
                console.print(Padding(Text(f"[+] Found {len(wayback_subdomains)} subdomains via Wayback Machine.", style="green"), (0, 0, 0, 4)))
                all_subdomains.update(wayback_subdomains)
            else:
                console.print(Padding(Text("[-] No subdomains found via Wayback Machine or an error occurred.", style="red"), (0, 0, 0, 4)))

        if not args.subdomains and not args.dns_brute and not args.wayback and not args.ports and not args.tech_fingerprint:
            console.print(Padding(Text("[-] Please specify a recon task. Use --subdomains for certificate transparency, --dns-brute for DNS brute force, --wayback for Wayback Machine, --ports for port scanning, or --tech-fingerprint for technology fingerprinting.", style="red"), (0, 0, 0, 4)))
        else:
            if all_subdomains:
                console.print(Rule("[bold green]Consolidated Subdomains[/bold green]"))
                sorted_subdomains = sorted(list(all_subdomains))
                for subdomain in sorted_subdomains:
                    console.print(Padding(Text(f"    - {subdomain}", style="green"), (0, 0, 0, 4)))
                console.print(Padding(Text(f"[+] Total unique subdomains found: {len(sorted_subdomains)}", style="bold green"), (1, 0, 0, 4)))

                open_ports_results = {}
                if args.ports:
                    console.print(Rule("[bold blue]Port Scanning Discovered Subdomains[/bold blue]"))
                    open_ports_results = scan_ports(list(all_subdomains), args.ports)
                    if open_ports_results:
                        for host, ports in open_ports_results.items():
                            console.print(Padding(Text(f"[+] Open ports on {host}: {', '.join(map(str, ports))}", style="cyan"), (0, 0, 0, 4)))
                    else:
                        console.print(Padding(Text("[-] No open ports found on discovered subdomains or an error occurred during scan.", style="red"), (0, 0, 0, 4)))
                
                if args.tech_fingerprint:
                    console.print(Rule("[bold blue]Technology Fingerprinting Discovered Subdomains[/bold blue]"))
                    for subdomain in sorted_subdomains:
                        # Prioritize HTTPS if port 443 is open, otherwise HTTP if port 80 is open
                        target_url = None
                        if subdomain in open_ports_results and 443 in open_ports_results[subdomain]:
                            target_url = f"https://{subdomain}"
                        elif subdomain in open_ports_results and 80 in open_ports_results[subdomain]:
                            target_url = f"http://{subdomain}"
                        elif not args.ports: # If no port scan was performed, try HTTPS then HTTP
                            try:
                                requests.head(f"https://{subdomain}", timeout=5)
                                target_url = f"https://{subdomain}"
                            except requests.exceptions.RequestException:
                                try:
                                    requests.head(f"http://{subdomain}", timeout=5)
                                    target_url = f"http://{subdomain}"
                                except requests.exceptions.RequestException:
                                    pass

                        if target_url:
                            console.print(Padding(Text(f"[*] Fingerprinting {target_url}...", style="blue"), (0, 0, 0, 8)))
                            technologies = get_technologies(target_url)
                            if technologies:
                                console.print(Padding(Text(f"[+] Technologies for {target_url}:", style="green"), (0, 0, 0, 8)))
                                for tech in technologies:
                                    console.print(Padding(Text(f"    - {tech}", style="green"), (0, 0, 0, 8)))
                            else:
                                console.print(Padding(Text(f"[-] No technologies identified for {target_url}.", style="red"), (0, 0, 0, 8)))
                        else:
                            console.print(Padding(Text(f"[-] Skipping technology fingerprinting for {subdomain}: No accessible HTTP/S port found or specified.", style="yellow"), (0, 0, 0, 8)))

            else:
                console.print(Rule("[bold red]No Subdomains Found[/bold red]"))
                console.print(Padding(Text("[-] No unique subdomains were found using the selected methods. Port scanning and technology fingerprinting skipped.", style="red"), (1, 0, 0, 4)))

    else:
        parser.print_help()

if __name__ == "__main__":
    main()
