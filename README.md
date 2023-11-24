# evilmapper

`evilmapper` is a simple, yet powerful shell script that allows you to initiate various types of `nmap` scans. It provides an easy-to-use interface for running different scan types, including scans for web applications, databases, and ICS/SCADA systems. All of the scan types were found on nmap.org and on this great cheat sheet from Security Trails : https://securitytrails.com/blog/nmap-cheat-sheet. 

This script is meant to be updated to add features, such as statistics, CVE reports...

## Table of Contents
- [Features](#features)
- [Usage](#usage)
- [Requirements](#requirements)
- [Disclaimer](#disclaimer)
- [Scanning Types](#scanning-types)
  - [ICS/SCADA Systems](#ics-scada-systems)
  - [Host Discovery and Identification](#host-discovery-and-identification)
  - [Version Detection](#version-detection)
  - [Network and Port Scanning](#network-and-port-scanning)
  - [Timing and Performance](#timing-and-performance)
  - [Nmap Scripting Engine (NSE)](#nmap-scripting-engine-nse)
  - [Scanning Web Servers](#scanning-web-servers)
  - [Scanning Mail Servers](#scanning-mail-servers)
  - [Scanning Databases](#scanning-databases)
- [Contributing](#contributing)
- [License](#license)

## Features

- Multiple scan categories: Choose from a variety of scan categories to suit your needs.
- Top commands: Run the most commonly used `nmap` commands with a single selection.
- Browser view and report saves: View your scan results in the browser for easy reading and analysis, with files saved under html and xml format.


## Usage

1. Clone the repository: `git clone https://github.com/ahasera/evilmapper.git`
2. Navigate to the `evilmapper` directory: `cd evilmapper`
3. Run the script directly: `sudo bash evilmapper.sh`
4. Follow the prompts to select your scan category and options.

## Requirements

- `nmap`: The script uses `nmap` to perform the scans. Make sure `nmap` is installed on your system.
- `xsltproc`: Used to convert the `nmap` XML output to HTML for viewing in the browser.

## Disclaimer

This tool is intended for network security research and should not be used for illegal activities. Always obtain proper authorization before performing scans.

# Scanning types

## ICS/SCADA Systems
- Detect standard (open) ports: `nmap -Pn -sT --scan-delay 1s --max-parallelism 1 -p80,102,443,502,1089,1091,2222,4000,4840,20000,34962,34964,34980,44818,47808,55000,55003 <target>`
- Control system ports (BACnet/IP): `nmap -Pn -sU -p47808 --script bacnet-info <target>`
- Ethernet/IP: `nmap -Pn -sU -p44818 --script enip-info <target>`
- Discover a Modbus device: `nmap -Pn -sT -p502 --script modbus-discover <target>`
- Discover a Niagara Fox device: `nmap -Pn -sT -p1911,4911 --script fox-info <target>`
- Discover a PCWorx device: `nmap -Pn -sT -p1962 --script pcworx-info <target>`

## Host Discovery and Identification
- Basic scanning: `nmap <target>`
- Launch a ping scan (subnet): `nmap -sn <target>`, e.g., `nmap -sn 192.168.1.0/24`
- Scan a list of targets: `nmap -iL [targets.txt]`
- Ping scan with traceroute: `nmap -sn --traceroute acme.org example.org`
- TCP SYN ping: `nmap -PS <target>`
- UDP ping: `nmap -PU <target>`
- Scan IPv6 target: `nmap -6 <target>`
- Specify NSE script: `nmap -sn --script dns-brute example.org`
- Manually assign DNS servers: `nmap --dns-servers <servers> <target>`
- ARP discovery: `nmap -PR <target>`, e.g., `nmap -PR 192.168.1.0/24`
- UDP discovery on specified port: `nmap -PU53 <target>`
- No DNS resolution: `nmap -n <target>`
- Select network interface: `nmap -e <interface> <target>`
- Skip host discovery: `nmap -Pn <target>`

## Version Detection
- Service detection: `nmap -sV <target>`, e.g., `nmap -sV scanme.nmap.org`
- OS detection: `nmap -O <target>`
- Attempt OS guessing: `nmap -O --osscan-guess <target>`
- Increasing version detection: `nmap -sV --version-intensity <0-9> <target>`
- Troubleshoot version scans: `nmap -sV --version-trace <target>`
- Aggressive detection mode: `nmap -A <target>`
- Verbose mode: `nmap -O -v <target>`

## Network and Port Scanning
- TCP SYN ping scan: `nmap -sn -PS <target>` or `nmap -sS`
- Scanning multiple ports: `nmap -sn -PS80,100-1000 <target>`
- TCP ACK ping scan: `nmap -sn -PA <target>` or `nmap -sA`
- UDP ping scan: `nmap -sn -PU <target>`
- ICMP ping scan: `nmap -sn -PE <target>`
- SCTP INIT ping scan: `nmap -sn -PY <target>` or `nmap -sY`
- IP protocol ping scan (tracing): `nmap -sn -PO --packet-trace <target>`
- Scan random number of hosts: `nmap -iR [number]`
- Broadcast ping scan: `nmap --script broadcast-ping --packet-trace`
- Xmas scan (Sets the FIN, PSH, and URG flags): `nmap -sX <target>`
- UDP scan (with verbosity): `nmap -sU -v <target>`
- Scan a firewall (split TCP header into tiny fragments): `nmap -f <target>`
- Cloak a scan with decoys: `nmap -D <decoy1>[,<decoy2>] <target>`, e.g., `nmap -D 192.168.1.101,192.168.1.102 <target>`
- Spoof source IP address: `nmap -S <IP_Address> <target>`
- Spoof MAC address: `nmap --spoof-mac [MAC_ADDRESS] <target>`
- Scan using a random MAC address: `nmap -v -sT -PN --spoof-mac 0 <target>`

## Timing and Performance
- Rate limiting: `nmap --scan-delay <time>`
- Adjust delay between probes: `nmap --scan-delay <time>; --max-scan-delay <time>`
- Paranoid timing template: `nmap -T0 <target>`
- Sneaky – ID evasion (also T0): `nmap -T1 <target>`
- Polite – Slower than normal scan: `nmap -T2 <target>`
- Normal – Default speed: `nmap -T3 <target>`
- Aggressive – Recommended mode: `nmap -T4 -n -Pn -p- <target>`
- Insane – Very fast networks: `nmap -T5 <target>`
- Host timeouts – Give up on hosts: `nmap -sV -A -p- --host-timeout 5m <target>`

## Nmap Scripting Engine (NSE)
- Safe category – Default: `nmap -sC <host>`, e.g., `nmap -sC scanme.nmap.org`
- Execute (multiple) scripts by name: `nmap --script default,safe`
- Select script by category: `nmap --script exploit <target>`
- Execute NSE script file: `nmap --script /path/to/script.nse <target>`
- Exclude a specific category: `nmap -sV --script "not exploit" <target>`
- Include two different categories: `nmap --script "broadcast and discovery" <target>`
- Combining wildcards: `nmap --script "http-*” <target>`
- Set arguments: `nmap -sV --script http-title --script-args http.useragent="Mozilla 1337"<target>`
- Load arguments from a file: `nmap --script "discovery" --script-args-file nmap-args.txt<target>`

## Scanning Web Servers
- List supported HTTP methods: `nmap -p80,443 --script http-methods --script-args httpmethods.test-all=true <target>`
- Discover interesting paths/folders: `nmap --script http-enum -sV <target>`
- Brute-forcing HTTP basic auth: `nmap -p80 --script http-brute <target>`
- Provide own user/password list: `nmap -sV --script http-brute --script-args userdb=~/usernames.txt,passdb=~/passwords.txt <target>`
- Brute-forcing common web platforms (e.g., WordPress): `nmap -sV --script http-wordpress-brute <target>`
- Detect a web application firewall: `nmap -sV --script http-waf-detect,http-waf-fingerprint<target>`
- Detect XST vulnerabilities (via HTTP TRACE method): `nmap -sV --script http-methods,http-trace --script-argshttp-methods.retest <target>`
- Detect XSS vulnerabilities: `nmap -sV --script http-unsafe-output-escaping <target>`
- Detect SQL injection vulnerabilities: `nmap -sV --script http-sql-injection <target>`
- Finding default credentials: `nmap -sV --script http-default-accounts <target>`
- Finding exposed Git repos: `nmap -sV --script http-git <target>`

## Scanning Mail Servers
- Brute-force SMTP: `nmap -p25 --script smtp-brute <target>`
- Brute-force IMAP: `nmap -p143 --script imap-brute <target>`
- Brute-force POP3: `nmap -p110 --script pop3-brute <target>`
- Enumerate users: `nmap -p 25 --script=smtp-enum-users <target>`
- SMTP running on alternate port(s): `nmap -sV --script smtp-strangeport <target>`
- Discovering open relays: `nmap -sV --script smtp-open-relay -v <target>`
- Find available SMTP commands: `nmap -p 25 --script=smtp-commands <target>`

## Scanning Databases
- Identify MS SQL servers: `nmap -p1433 --script ms-sql-info <target>`
- Brute-force MS SQL passwords: `nmap -p1433 --script ms-sql-brute <target>`
- Dump password hashes (MS SQL): `nmap -p1433 --script ms-sql-empty-password,ms-sql-dump-hashes<target>`
- List databases (MySQL): `nmap -p3306 --script mysql-databases --script-args mysqluser=[user],mysqlpass=[password] <target>`
- Brute-force MySQL passwords: `nmap -p3306 --script mysql-brute <target>`