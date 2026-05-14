#!/usr/bin/env python3

import csv
import argparse
import shlex
import xml.etree.ElementTree as ET
from pathlib import Path


ART = r"""
 _   _                         ____            _     _
| \ | |_ __ ___   __ _ _ __   | __ ) _   _  __| | __| |_   _
|  \| | '_ ` _ \ / _` | '_ \  |  _ \| | | |/ _` |/ _` | | | |
| |\  | | | | | | (_| | |_) | | |_) | |_| | (_| | (_| | |_| |
|_| \_|_| |_| |_|\__,_| .__/  |____/ \__,_|\__,_|\__,_|\__, |
                      |_|                               |___/
"""


def print_banner():
    print(ART)
    print("[*] Nmap Buddy")
    print("[*] Parsing Nmap XML output into CSV")
    print()


def parse_args():
    parser = argparse.ArgumentParser(
        prog="nmap_buddy.py",
        description=(
            "Parse one or more Nmap XML files into a combined CSV.\n"
            "If the original scan did not use -sV, Nmap Buddy can suggest follow-up version scans."
        ),
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="""
Usage:

  ./nmap_buddy.py scan.xml combined.csv

  ./nmap_buddy.py *.xml combined.csv

Input:

  One or more Nmap XML files created with:

    nmap -oX scan.xml <target>
    nmap -oA scan <target>

Output CSV columns:

  Target, Resolved IP, Protocol, Port, Port Status, Service, Service Info

Column meaning:

  Target        Hostname/FQDN if present in the XML, otherwise the scanned IP.
  Resolved IP   The IP address Nmap scanned.
  Protocol      TCP or UDP.
  Port          Port number.
  Port Status   Nmap port state, such as open, closed, filtered, or open|filtered.
  Service       Service name reported by Nmap, such as http, ssh, domain, or unknown.
  Service Info  Extra service details from -sV, such as product, version, and extra info.

Example workflow:

  sudo nmap -iL targets.txt -p- -sS -Pn -n --min-rate 5000 --max-retries 2 --open -oA tcp_fast

  ./nmap_buddy.py tcp_fast.xml tcp_fast.csv
"""
    )

    parser.add_argument(
        "files",
        nargs="+",
        help="Input XML file(s), followed by output CSV."
    )

    args = parser.parse_args()

    if len(args.files) < 2:
        parser.error(
            "You need at least one input XML file and one output CSV file.\n"
            "Example: ./nmap_buddy.py *.xml combined.csv"
        )

    args.input_files = args.files[:-1]
    args.output_csv = args.files[-1]

    output_lower = args.output_csv.lower()

    if output_lower.endswith(".xml"):
        parser.error(
            "Output file cannot be .xml. You probably forgot the output CSV.\n"
            "Example: ./nmap_buddy.py *.xml combined.csv"
        )

    if not output_lower.endswith(".csv"):
        parser.error(
            "Output file must end with .csv.\n"
            "Example: ./nmap_buddy.py *.xml combined.csv"
        )

    return args


def get_host_input_and_ip(host):
    ip = ""
    fqdn = ""

    for addr in host.findall("address"):
        if addr.get("addrtype") in ("ipv4", "ipv6"):
            ip = addr.get("addr", "")
            break

    hostnames = host.find("hostnames")
    if hostnames is not None:
        for hostname in hostnames.findall("hostname"):
            name = hostname.get("name", "")
            if name:
                fqdn = name
                break

    target = fqdn if fqdn else ip
    return target, ip


def port_sort_key(port):
    try:
        return int(port)
    except ValueError:
        return port


def extract_il_wordlists_from_args(nmap_args):
    wordlists = []

    if not nmap_args:
        return wordlists

    try:
        tokens = shlex.split(nmap_args)
    except ValueError:
        tokens = nmap_args.split()

    i = 0

    while i < len(tokens):
        token = tokens[i]

        if token in ("-iL", "--input-filename"):
            if i + 1 < len(tokens):
                wordlists.append(tokens[i + 1])
                i += 2
                continue

        if token.startswith("--input-filename="):
            wordlists.append(token.split("=", 1)[1])

        i += 1

    return wordlists


def scan_used_version_detection(nmap_args):
    """
    Detect whether the original Nmap command already used version detection.

    -sV   = service/version detection
    -sCV  = default scripts + service/version detection
    -sVC  = service/version detection + default scripts
    -A    = aggressive scan, includes version detection
    """

    if not nmap_args:
        return False

    try:
        tokens = shlex.split(nmap_args)
    except ValueError:
        tokens = nmap_args.split()

    for token in tokens:
        if token in ("-sV", "-sCV", "-sVC", "-A"):
            return True

        if token in ("--version-light", "--version-all"):
            return True

        if token.startswith("--version-intensity"):
            return True

        if token.startswith("-") and "sV" in token:
            return True

    return False


def get_service_details(port):
    service_el = port.find("service")

    service = "unknown"
    service_info = ""

    if service_el is not None:
        service = service_el.get("name", "") or "unknown"

        service_info_parts = []

        for attr in ("product", "version", "extrainfo"):
            value = service_el.get(attr, "")
            if value:
                service_info_parts.append(value)

        service_info = " ".join(service_info_parts)

    return service, service_info


def parse_xml_file(xml_file, writer, discovered):
    try:
        tree = ET.parse(xml_file)
        root = tree.getroot()
    except ET.ParseError as e:
        print(f"[!] Skipping invalid XML: {xml_file} - {e}")
        return
    except Exception as e:
        print(f"[!] Failed to read: {xml_file} - {e}")
        return

    nmap_args = root.get("args", "")

    for wordlist in extract_il_wordlists_from_args(nmap_args):
        discovered["target_lists"].add(wordlist)

    if scan_used_version_detection(nmap_args):
        discovered["version_scan_detected"] = True

    for host in root.findall("host"):
        target, ip = get_host_input_and_ip(host)

        if not target and not ip:
            continue

        ports = host.find("ports")
        if ports is None:
            continue

        for port in ports.findall("port"):
            protocol = port.get("protocol", "")
            protocol_display = protocol.upper()

            port_id = port.get("portid", "")

            state_el = port.find("state")
            port_status = state_el.get("state", "") if state_el is not None else ""

            service, service_info = get_service_details(port)

            writer.writerow({
                "Target": target,
                "Resolved IP": ip,
                "Protocol": protocol_display,
                "Port": port_id,
                "Port Status": port_status,
                "Service": service,
                "Service Info": service_info
            })

            if protocol == "tcp" and port_status == "open":
                discovered["tcp_ports"].add(port_id)

            if protocol == "udp" and port_status in ("open", "open|filtered"):
                discovered["udp_ports"].add(port_id)


def print_version_scan_recommendations(base, discovered):
    tcp_ports = sorted(discovered["tcp_ports"], key=port_sort_key)
    udp_ports = sorted(discovered["udp_ports"], key=port_sort_key)
    target_lists = sorted(discovered["target_lists"])

    print()
    print("[+] Open-port summary")
    print(f"    TCP ports: {','.join(tcp_ports) if tcp_ports else 'None'}")
    print(f"    UDP ports: {','.join(udp_ports) if udp_ports else 'None'}")

    if discovered["version_scan_detected"]:
        print()
        print("[+] Version scan detected")
        print("    The XML indicates that the original Nmap scan already used version detection.")
        print("    No follow-up -sV recommendation is needed.")
        return

    print()
    print("[+] Recommended follow-up version scans")
    print("    The XML does not appear to come from a version scan.")
    print("    If you want better service/version data, run one of the commands below.")
    print("    These commands scan only the discovered open ports, not all 65535 ports again.")

    if not tcp_ports and not udp_ports:
        print()
        print("No open TCP or UDP ports were found in the XML files.")
        return

    if target_lists:
        print()
        print("[+] Original Nmap target list(s) detected:")
        for target_list in target_lists:
            print(f"    {target_list}")
    else:
        print()
        print("[!] Could not detect an original -iL target list from the XML.")
        print("    Replace <original_targets.txt> with the target list you used for the original scan.")
        target_lists = ["<original_targets.txt>"]

    for target_list in target_lists:
        if target_list == "<original_targets.txt>":
            safe_name = "targets"
        else:
            safe_name = Path(target_list).stem

        if tcp_ports:
            tcp_port_arg = ",".join(tcp_ports)

            print()
            print(f"# TCP version scan for {target_list}")
            print(
                f"sudo nmap "
                f"-iL {target_list} "
                f"-sS "
                f"-sV "
                f"-Pn "
                f"-n "
                f"-p {tcp_port_arg} "
                f"--version-intensity 5 "
                f"-oA {base}_{safe_name}_tcp_version"
            )

        if udp_ports:
            udp_port_arg = ",".join(udp_ports)

            print()
            print(f"# UDP version scan for {target_list}")
            print(
                f"sudo nmap "
                f"-iL {target_list} "
                f"-sU "
                f"-sV "
                f"-Pn "
                f"-n "
                f"-p {udp_port_arg} "
                f"--version-intensity 2 "
                f"--max-retries 2 "
                f"-oA {base}_{safe_name}_udp_version"
            )


def main():
    args = parse_args()

    print_banner()

    output_csv = Path(args.output_csv)
    input_files = args.input_files
    base = output_csv.with_suffix("")

    discovered = {
        "tcp_ports": set(),
        "udp_ports": set(),
        "target_lists": set(),
        "version_scan_detected": False
    }

    fieldnames = [
        "Target",
        "Resolved IP",
        "Protocol",
        "Port",
        "Port Status",
        "Service",
        "Service Info"
    ]

    with open(output_csv, "w", newline="", encoding="utf-8") as out_f:
        writer = csv.DictWriter(out_f, fieldnames=fieldnames)
        writer.writeheader()

        for xml_file in input_files:
            path = Path(xml_file)

            if not path.exists():
                print(f"[!] File does not exist, skipping: {xml_file}")
                continue

            if path.stat().st_size == 0:
                print(f"[!] Empty file, skipping: {xml_file}")
                continue

            print(f"[*] Processing: {xml_file}")
            parse_xml_file(str(path), writer, discovered)

    print()
    print(f"[+] CSV written to: {output_csv}")

    print_version_scan_recommendations(base, discovered)

    print()
    print("[+] Done.")


if __name__ == "__main__":
    main()
