import argparse
import requests
import os
import sys
import re
import json
from typing import Set, List

def fetch_crtsh(domain: str) -> Set[str]:
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    try:
        resp = requests.get(url, timeout=15)
        resp.raise_for_status()
        data = resp.json()
        subdomains = set()
        for entry in data:
            name = entry.get("name_value", "")
            for sub in name.split("\n"):
                if sub.endswith(domain):
                    subdomains.add(sub.strip())
        return subdomains
    except Exception as e:
        print(f"[!] crt.sh error: {e}")
        return set()

def fetch_alienvault(domain: str) -> Set[str]:
    url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns"
    try:
        resp = requests.get(url, timeout=15)
        resp.raise_for_status()
        data = resp.json()
        subdomains = set()
        for entry in data.get("passive_dns", []):
            hostname = entry.get("hostname", "")
            if hostname.endswith(domain):
                subdomains.add(hostname.strip())
        return subdomains
    except Exception as e:
        print(f"[!] AlienVault OTX error: {e}")
        return set()

def fetch_securitytrails(domain: str, api_key: str) -> Set[str]:
    url = f"https://api.securitytrails.com/v1/domain/{domain}/subdomains"
    headers = {"APIKEY": api_key}
    try:
        resp = requests.get(url, headers=headers, timeout=15)
        resp.raise_for_status()
        data = resp.json()
        subdomains = set()
        for sub in data.get("subdomains", []):
            subdomains.add(f"{sub}.{domain}")
        return subdomains
    except Exception as e:
        print(f"[!] SecurityTrails error: {e}")
        return set()

def fetch_certspotter(domain: str) -> Set[str]:
    url = f"https://api.certspotter.com/v1/issuances?domain={domain}&include_subdomains=true&expand=dns_names"
    try:
        resp = requests.get(url, timeout=15)
        resp.raise_for_status()
        data = resp.json()
        subdomains = set()
        for entry in data:
            for name in entry.get("dns_names", []):
                if name.endswith(domain):
                    subdomains.add(name.strip())
        return subdomains
    except Exception as e:
        print(f"[!] certspotter error: {e}")
        return set()

def fetch_hackertarget(domain: str) -> Set[str]:
    url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
    try:
        resp = requests.get(url, timeout=15)
        resp.raise_for_status()
        subdomains = set()
        for line in resp.text.splitlines():
            parts = line.split(",")
            if len(parts) > 0 and parts[0].endswith(domain):
                subdomains.add(parts[0].strip())
        return subdomains
    except Exception as e:
        print(f"[!] hackertarget error: {e}")
        return set()

def fetch_threatcrowd(domain: str) -> Set[str]:
    url = f"https://www.threatcrowd.org/searchApi/v2/domain/report/?domain={domain}"
    try:
        resp = requests.get(url, timeout=15)
        resp.raise_for_status()
        data = resp.json()
        subdomains = set()
        for sub in data.get("subdomains", []):
            if sub.endswith(domain):
                subdomains.add(sub.strip())
        return subdomains
    except Exception as e:
        print(f"[!] threatcrowd error: {e}")
        return set()

def fetch_wayback(domain: str) -> Set[str]:
    url = f"http://web.archive.org/cdx/search/cdx?url=*.{domain}/*&output=text&fl=original&collapse=urlkey"
    try:
        resp = requests.get(url, timeout=15)
        resp.raise_for_status()
        subdomains = set()
        for line in resp.text.splitlines():
            if domain in line:
                host = line.split("/")[2] if "/" in line else line
                if host.endswith(domain):
                    subdomains.add(host.strip())
        return subdomains
    except Exception as e:
        print(f"[!] wayback error: {e}")
        return set()

def fetch_bufferover(domain: str) -> Set[str]:
    url = f"https://dns.bufferover.run/dns?q=.{domain}"
    try:
        resp = requests.get(url, timeout=15)
        resp.raise_for_status()
        data = resp.json()
        subdomains = set()
        for entry in data.get("FDNS_A", []) + data.get("RDNS", []):
            sub = entry.split(",")[-1].strip()
            if sub.endswith(domain):
                subdomains.add(sub)
        return subdomains
    except Exception as e:
        print(f"[!] bufferover.run error: {e}")
        return set()

def fetch_virustotal(domain: str, api_key: str) -> Set[str]:
    url = f"https://www.virustotal.com/api/v3/domains/{domain}/subdomains?limit=100"
    headers = {"x-apikey": api_key}
    try:
        resp = requests.get(url, headers=headers, timeout=15)
        resp.raise_for_status()
        data = resp.json()
        subdomains = set()
        for entry in data.get("data", []):
            sub = entry.get("id", "")
            if sub.endswith(domain):
                subdomains.add(sub.strip())
        return subdomains
    except Exception as e:
        print(f"[!] virustotal error: {e}")
        return set()

def is_subdomain(sub: str, domain: str) -> bool:
    return sub != domain and sub.endswith('.' + domain)

def main():
    parser = argparse.ArgumentParser(description="Passive subdomain enumerator (enhanced)")
    parser.add_argument("domain", nargs="?", help="Target domain (e.g. example.com)")
    parser.add_argument("-o", "--output", help="Output file to save results")
    parser.add_argument("--securitytrails-key", help="SecurityTrails API key (or set SECURITYTRAILS_KEY env var)")
    parser.add_argument("--virustotal-key", help="VirusTotal API key (or set VT_API_KEY env var)")
    parser.add_argument("--subs-only", action="store_true", help="Show only subdomains, not related domains")
    parser.add_argument("--stdin", action="store_true", help="Read domains from stdin (one per line)")
    parser.add_argument("--filter", help="Regex or wildcard pattern to filter subdomains (e.g. 'dev*' or '.*test.*')")
    parser.add_argument("--json", action="store_true", help="Output results in JSON format")
    parser.add_argument("--verbose", action="store_true", help="Enable verbose output")
    parser.add_argument("--timeout", type=int, default=15, help="HTTP request timeout in seconds (default: 15)")
    args = parser.parse_args()    # Prepare filter
    filter_pattern = None
    if args.filter:
        if '*' in args.filter:
            filter_pattern = re.compile('^' + re.escape(args.filter).replace('\\*', '.*') + '$')
        else:
            filter_pattern = re.compile(args.filter)

    domains = []
    if args.stdin:
        for line in sys.stdin:
            d = line.strip()
            if d:
                domains.append(d)
    elif args.domain:
        domains = [args.domain.strip()]
    else:
        parser.error("No domain provided. Use --stdin or provide a domain argument.")

    all_results = set()
    sources = [
        ("crt.sh", fetch_crtsh),
        ("AlienVault OTX", fetch_alienvault),
        ("certspotter", fetch_certspotter),
        ("hackertarget", fetch_hackertarget),
        ("threatcrowd", fetch_threatcrowd),
        ("wayback", fetch_wayback),
        ("bufferover.run", fetch_bufferover)
    ]
    # Add API sources if keys provided
    api_key = args.securitytrails_key or os.environ.get("SECURITYTRAILS_KEY")
    vt_key = args.virustotal_key or os.environ.get("VT_API_KEY")
    if api_key:
        sources.append(("SecurityTrails", lambda domain: fetch_securitytrails(domain, api_key)))
    if vt_key:
        sources.append(("VirusTotal", lambda domain: fetch_virustotal(domain, vt_key)))

    summary = {}
    for domain in domains:
        if args.verbose:
            print(f"[*] Enumerating {domain} ...")
        subdomains = set()
        found_by_source = {}
        for src_name, src_func in sources:
            if args.verbose:
                print(f"  [>] Querying {src_name} ...", end=" ")
            try:
                result = src_func(domain)
                if args.verbose:
                    print(f"{len(result)} found.")
                subdomains |= result
                for sub in result:
                    found_by_source.setdefault(sub, []).append(src_name)
            except Exception as e:
                if args.verbose:
                    print(f"error: {e}")
        # Filter if --subs-only
        if args.subs_only:
            subdomains = {s for s in subdomains if is_subdomain(s, domain)}
        # Filter by pattern
        if filter_pattern:
            subdomains = {s for s in subdomains if filter_pattern.match(s)}
        all_results |= subdomains
        summary[domain] = {
            "count": len(subdomains),
            "sources": {src: len([s for s in found_by_source if src in found_by_source[s]]) for src, _ in sources},
            "subdomains": sorted(subdomains)
        }
        if args.verbose:
            print(f"[+] {domain}: {len(subdomains)} unique subdomains after filtering.")

    subdomains_sorted = sorted(all_results)
    if args.json:
        output_data = {
            "domains": summary,
            "total_unique": len(subdomains_sorted),
            "all_subdomains": subdomains_sorted
        }
        output_str = json.dumps(output_data, indent=2)
        print(output_str)
    else:
        print(f"\n[+] Total unique subdomains: {len(subdomains_sorted)}")
        for sub in subdomains_sorted:
            print(sub)
    if args.output:
        try:
            with open(args.output, "w", encoding="utf-8") as f:
                if args.json:
                    f.write(output_str)
                else:
                    for sub in subdomains_sorted:
                        f.write(sub + "\n")
            print(f"[+] Results saved to {args.output}")
        except Exception as e:
            print(f"[!] Error saving to file: {e}")
    # Print summary
    print("\n[=] Summary:")
    for domain, info in summary.items():
        print(f"  {domain}: {info['count']} subdomains found. Sources: " + ", ".join(f"{k}({v})" for k,v in info['sources'].items()))

if __name__ == "__main__":
    main()
