# evilmapper

`evilmapper` is a simple, yet powerful shell script that allows you to initiate various types of `nmap` scans. It provides an easy-to-use interface for running different scan types, including scans for web applications, databases, and ICS/SCADA systems. All of the scan types were found on nmap.org and on this great cheat sheet from Security Trails : https://securitytrails.com/blog/nmap-cheat-sheet

## Features

- Multiple scan categories: Choose from a variety of scan categories to suit your needs.
- Top commands: Run the most commonly used `nmap` commands with a single selection.
- Browser view: View your scan results in the browser for easy reading and analysis.
- Skip host discovery: Option to skip the host discovery phase, useful for networks with ICMP/Ping restrictions.

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
