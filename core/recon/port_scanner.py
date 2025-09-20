import nmap

def scan_ports(targets, ports="1-1024"):
    """
    Performs a port scan on the given targets.
    Requires nmap to be installed on the system.
    """
    nm = nmap.PortScanner()
    open_ports_found = {}

    print(f"[*] Starting port scan on {len(targets)} targets for ports: {ports}...")

    for target in targets:
        try:
            nm.scan(target, ports)
            if target in nm.all_hosts():
                for proto in nm[target].all_protocols():
                    lport = nm[target][proto].keys()
                    for port in lport:
                        if nm[target][proto][port]['state'] == 'open':
                            if target not in open_ports_found:
                                open_ports_found[target] = []
                            open_ports_found[target].append(port)
                            # print(f"    [+] {target}:{port} is open ({nm[target][proto][port]['name']})") # Rich will handle this
            else:
                print(f"    [-] Host {target} is down or not responding to scan.")
        except nmap.PortScannerError as e:
            print(f"    [-] Nmap scan error for {target}: {e}")
        except Exception as e:
            print(f"    [-] An unexpected error occurred during scan for {target}: {e}")
    
    return open_ports_found

if __name__ == '__main__':
    # Example usage
    test_targets = ["scanme.nmap.org"] # Use a safe target for testing
    print(f"Scanning ports for {test_targets}...")
    results = scan_ports(test_targets, ports="22,80,443")
    if results:
        for host, ports in results.items():
            print(f"Open ports on {host}: {ports}")
    else:
        print("No open ports found or an error occurred.")
