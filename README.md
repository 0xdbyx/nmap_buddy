# Nmap Buddy

Python script that parses one or more Nmap XML files into a CSV file.

Vibe coded this to help with parsing Nmap output, especially when scanning a large number of assets. When running large all-port scans, Nmap can take a long time or get stuck if service/version detection flags are used.

Enumeration workflow:

1. Run a fast Nmap scan first to find open ports.
2. Parse one or more XML files into a combined CSV.
3. Use the suggested follow-up command to rescan only the discovered open ports for service/version detection.

## Features

- Parses Nmap XML output
- Supports multiple XML files
- Combines results into one CSV

## Usage

    ./nmap_buddy.py <input.xml> [more.xml ...] <output.csv>

Example with one XML file:

    ./nmap_buddy.py tcp_fast.xml tcp_fast.csv

Example with multiple XML files:

    ./nmap_buddy.py *.xml combined.csv

## Example Workflow

Run a fast TCP discovery scan:

    sudo nmap \
      -iL targets.txt \
      -p- \
      -sS \
      -Pn \
      -n \
      --min-rate 5000 \
      --max-retries 2 \
      --open \
      -oA tcp_fast

This creates several output files, including:

    tcp_fast.xml

Parse the XML output:

    ./nmap_buddy.py tcp_fast.xml tcp_fast.csv

Or parse multiple XML files into one combined CSV:

    ./nmap_buddy.py *.xml combined.csv

If the original scan did not use service/version detection, Nmap Buddy will print a suggested follow-up command like:

    sudo nmap -iL targets.txt -sS -sV -Pn -n -p 22,80,443 --version-intensity 5 -oA combined_targets_tcp_version

This helps avoid running `-sV` against all 65535 ports from the start.

## CSV Output

The CSV output contains these columns:

    Target, Resolved IP, Protocol, Port, Port Status, Service, Service Info

Column meaning:

| Column | Description |
|---|---|
| Target | Hostname/FQDN if present in the XML, otherwise the scanned IP |
| Resolved IP | The IP address Nmap scanned |
| Protocol | TCP or UDP |
| Port | Port number |
| Port Status | Nmap port state, such as open, closed, filtered, or open\|filtered |
| Service | Service name reported by Nmap, such as http, ssh, domain, or unknown |
| Service Info | Extra service details from version detection, such as product, version, and extra info |

Example CSV output:

    Target,Resolved IP,Protocol,Port,Port Status,Service,Service Info
    example.com,93.184.216.34,TCP,80,open,http,Apache httpd 2.4.52
    example.com,93.184.216.34,TCP,443,open,https,
    192.168.1.10,192.168.1.10,UDP,53,open|filtered,domain,
