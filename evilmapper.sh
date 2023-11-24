#!/bin/bash
if [ -z "$EVILMAPPER_RERUN" ]; then

    echo "▄███▄      ▄   ▄█ █    █▀▄▀█ ██   █ ▄▄  █ ▄▄  ▄███▄   █▄▄▄▄ ";
    sleep 0.3
    echo "█▀   ▀      █  ██ █    █ █ █ █ █  █   █ █   █ █▀   ▀  █  ▄▀ ";
    sleep 0.3
    echo "██▄▄   █     █ ██ █    █ ▄ █ █▄▄█ █▀▀▀  █▀▀▀  ██▄▄    █▀▀▌  ";
    sleep 0.3
    echo "█▄   ▄▀ █    █ ▐█ ███▄ █   █ █  █ █     █     █▄   ▄▀ █  █  ";
    sleep 0.3
    echo "▀███▀    █  █   ▐     ▀   █     █  █     █    ▀███▀     █   ";
    sleep 0.3
    echo "          █▐             ▀     █    ▀     ▀            ▀    ";
    sleep 0.3
    echo "          ▐                   ▀                             ";

    echo -e "\e[3mWritten by ahasera\e[0m"
    # Set the variable to skip this part on subsequent runs
    export EVILMAPPER_RERUN=1
fi
sleep 1
echo

SERVER_PORT=8000
SERVER_PATH="scans/html/server/server.py"

# Check root privileges
if [ "$EUID" -ne 0 ]; then
    echo "Please run as root"
    exit 1
fi

change_ownership() {
    local directory=./
    local user=$2

    if [ -d "$directory" ]; then
        chown -R "$user" "$directory"
    else
        echo ""
    fi
}

# Check if the script is run with sudo
if [ -n "$SUDO_USER" ]; then
    # Change ownership of html and xml directories to the sudo user for further reading as files created by root
    change_ownership "scans/html" "$SUDO_USER"
    change_ownership "scans/xml" "$SUDO_USER"
else
    echo "This script was not run with sudo. Aborting chown."
fi

check_and_notify_http_server() {
    local pids=$(pgrep -f 'python.*http.server')
    if [ -n "$pids" ]; then
        echo "Python HTTP server is currently running with PID(s): $pids"
        echo "If you wish to stop it, use the following command:"
        echo "kill $pids"
        exit 1
    else
        echo "No Python HTTP server processes found. Continuing..."
    fi
}

check_and_notify_http_server


# Install required packages
install_if_not_present() {
    local pkg=$1
    if ! command -v $pkg &>/dev/null; then
        echo "$pkg not installed. Installing..."
        if command -v apt-get &>/dev/null; then
            sudo apt-get update && sudo apt-get install -y $pkg
        elif command -v yum &>/dev/null; then
            sudo yum update && sudo yum install -y $pkg
        else
            echo "Package manager not found. Exiting." >&2
            exit 1
        fi
    fi
    # Check if http.server module is available
    if ! python3 -c "import http.server" &> /dev/null; then
        echo "http.server module not found. Please ensure you have the correct version of Python installed."
        exit 1
    fi
}

install_if_not_present nmap
install_if_not_present xsltproc

# Create necessary directories
mkdir -p scans/xml scans/html

# Initialize pn_option
pn_option=""

# Function to perform Nmap scan
perform_scan() {
    local scan_type=$1
    local scan_options=$2   
    local scan_name="nmap_$(date +%Y-%m-%d_%H-%M-%S)"
    local xml_output="scans/xml/${scan_name}.xml"
    local html_output="scans/html/${scan_name}.html"
    read -p "Enter custom options (e.g., -sV -A -p- or none): " custom_opts
    echo -e "\e[32mStarting Nmap scan: $scan_type\e[0m"  
    IFS=' ' read -r -a opts_array <<< "$custom_opts"

    # Check each option in custom_opts
    for opt in "${opts_array[@]}"; do
        if grep -q "^$opt$" src/nmap_options.txt; then
            echo ""
        else
            echo "$opt is not a valid option."
            # Handle invalid option case (e.g., exit or prompt for correction)
            # exit 1
        fi
    done  
    nmap $pn_option $custom_opts $scan_options $target -oX $xml_output
    xsltproc $xml_output -o $html_output
    echo
    echo -e "\e[32mScan completed. View results at: http://localhost:8000/$scan_name.html\e[0m"
}

# Get target from user
read -p "Enter target (IP, FQDN, or network with CIDR notation): " target
if [[ ! $target =~ ^[0-9a-zA-Z\.\:/-]+$ ]]; then
    echo "Invalid target format. Exiting."
    exit 1
fi

# Asking the user if they want to skip the discovery phase
read -p "Skip host discovery phase? (Treat all hosts as online, recommended if there are ICMP/Ping requests restrictions on target) [y/N]: " skip_discovery
pn_option=""
if [[ $skip_discovery == [yY] || $skip_discovery == [yY][eE][sS] ]]; then
    pn_option="-Pn"
    echo "Skipping host discovery phase... This will override ping scans"
else
    echo "Will perform host discovery phase..."
fi



# Main menu for scan type selection
echo "Select a category:"
echo
categories=("Host Discovery" "Version Detection" "Network and Port Scanning" "Timing and Performance" "NSE Scripts" "Web Server Scanning" "Mail Server Scanning" "Database Scanning" "ICS/SCADA Systems" "Top Commands" "Custom Scan" "Quit")
select category in "${categories[@]}"; do
    case $category in
        "Host Discovery")
            echo
            echo "Select Host Discovery type:"
            echo
            options=("Ping Scan" "Scan a List of Targets" "Ping Scan with Traceroute" "TCP SYN Ping" "UDP Ping" "Scan IPv6 Target" "Specify NSE Script" "Back")
            select opt in "${options[@]}"; do
                case $opt in
                    "Ping Scan") perform_scan "Ping Scan" "-sn"; break 2;;
                    "Scan a List of Targets") perform_scan "List Scan" "-iL targets.txt"; break 2;;
                    "Ping Scan with Traceroute") perform_scan "Ping with Traceroute" "-sn --traceroute"; break 2;;
                    "TCP SYN Ping") perform_scan "TCP SYN Ping" "-PS"; break 2;;
                    "UDP Ping") perform_scan "UDP Ping" "-PU"; break 2;;
                    "Scan IPv6 Target") perform_scan "IPv6 Scan" "-6"; break 2;;
                    "Specify NSE Script") perform_scan "NSE Script" "-sn --script dns-brute"; break 2;;
                    "Back") break;;
                esac
            
            done
            ;;


        "Version Detection")
            echo "Select Version Detection type:"
            options=("Service Detection" "OS Detection" "Attempt OS Guessing" "Increasing Version Detection" "Troubleshoot Version Scans" "Aggressive Detection Mode" "Verbose Mode" "Back")
            select opt in "${options[@]}"; do
                case $opt in
                    "Service Detection")
                        perform_scan "Service Detection" "-sV "
                        break 2;;
                    "OS Detection")
                        perform_scan "OS Detection" "-O "
                        break 2;;
                    "Attempt OS Guessing")
                        perform_scan "OS Guessing" "-O --osscan-guess "
                        break 2;;
                    "Increasing Version Detection")
                        perform_scan "Version Intensity" "-sV --version-intensity 5 "
                        break 2;;
                    "Troubleshoot Version Scans")
                        perform_scan "Version Trace" "-sV --version-trace "
                        break 2;;
                    "Aggressive Detection Mode")
                        perform_scan "Aggressive Detection" "-A "
                        break 2;;
                    "Verbose Mode")
                        perform_scan "Verbose OS Detection" "-O -v "
                        break 2;;
                    "Back") break;;
                esac
            done
            ;;

        "Network and Port Scanning")
            echo
            echo "Select Network and Port Scanning type:"
            echo
            options=("TCP SYN Ping Scan" "Scanning Multiple Ports" "TCP ACK Ping Scan" "UDP Ping Scan" "ICMP Ping Scan" "SCTP INIT Ping Scan" "IP Protocol Ping Scan (Tracing)" "Scan Random Number of Hosts" "Broadcast Ping Scan" "Xmas Scan" "UDP Scan (Verbose)" "Scan a Firewall" "Cloak Scan with Decoys" "Spoof Source IP Address" "Spoof MAC Address" "Scan Using a Random MAC Address" "Back")
            select opt in "${options[@]}"; do
                case $opt in
                    "TCP SYN Ping Scan")
                        perform_scan "TCP_SYN_Ping_Scan" "-sS -v "
                        break 2;;
                    "Scanning Multiple Ports")
                        perform_scan "Multiple_Ports_Scan" "-sn -PS80,100-1000 "
                        break 2;;
                    "TCP ACK Ping Scan")
                        perform_scan "TCP_ACK_Ping_Scan" "-sA -v "
                        break 2;;
                    "UDP Ping Scan")
                        perform_scan "UDP_Ping_Scan" "-sU -v "
                        break 2;;
                    "ICMP Ping Scan")
                        perform_scan "ICMP_Ping_Scan" "-sn -PE "
                        break 2;;
                    "SCTP INIT Ping Scan")
                        perform_scan "SCTP_INIT_Ping_Scan" "-sY "
                        break 2;;
                    "IP Protocol Ping Scan (Tracing)")
                        perform_scan "IP_Protocol_Ping_Scan" "-sn -PO --packet-trace "
                        break 2;;
                    "Scan Random Number of Hosts")
                        read -p "Enter number of hosts to scan randomly: " num_hosts
                        perform_scan "Random_Hosts_Scan" "-iR $num_hosts "
                        break 2;;
                    "Broadcast Ping Scan")
                        perform_scan "Broadcast_Ping_Scan" "--script broadcast-ping --packet-trace "
                        break 2;;
                    "Xmas Scan")
                        perform_scan "Xmas_Scan" "-sX "
                        break 2;;
                    "UDP Scan (Verbose)")
                        perform_scan "UDP_Verbose_Scan" "-sU -v "
                        break 2;;
                    "Scan a Firewall")
                        perform_scan "Firewall_Scan" "-f "
                        break 2;;
                    "Cloak Scan with Decoys")
                        read -p "Enter decoy IPs (comma-separated, no spaces): " decoys
                        perform_scan "Decoy_Scan" "-D $decoys "
                        break 2;;
                    "Spoof Source IP Address")
                        read -p "Enter IP address to spoof: " spoof_ip
                        echo "Available network interfaces:"
                        ip -o link show | awk -F': ' '{print $2}'
                        read -p "Enter the network interface to use: " net_interface
                        perform_scan "Spoof_IP_Scan" "-S $spoof_ip -Pn -e $net_interface"
                        break 2;;
                    "Spoof MAC Address")
                        read -p "Enter MAC address to spoof (or 0 for random): " spoof_mac
                        echo "Available network interfaces:"
                        ip -o link show | awk -F': ' '{print $2}'
                        read -p "Enter the network interface to use: " net_interface
                        perform_scan "Spoof_MAC_Scan" "--spoof-mac $spoof_mac -e $net_interface"
                        break 2;;
                    "Scan Using a Random MAC Address")
                        perform_scan "Random_MAC_Scan" "--spoof-mac 0 "
                        break 2;;
                    "Back") break;;
                esac
            done
            ;;

        "Timing and Performance")
            echo
            echo "Select Timing and Performance type:"
            echo
            options=("Rate Limiting" "Adjust Delay Between Probes" "Host Timeouts – Give up on Hosts" "Paranoid Timing Template" "Sneaky – ID Evasion (T0)" "Polite – Slower Than Normal Scan" "Normal – Default Speed" "Aggressive – Recommended Mode" "Insane – Very Fast Networks" "Back")
            select opt in "${options[@]}"; do
                case $opt in
                    "Rate Limiting")
                        read -p "Enter rate limiting time (e.g., 0.1s): " rate_limit
                        read -p "Custom options : (e.g., -sV -A -p- or none): " custom_opts
                        perform_scan "Rate_Limiting" " --scan-delay $rate_limit"
                        break 2;;
                    "Adjust Delay Between Probes")
                        read -p "Enter initial delay time (e.g., 0.1s): " init_delay
                        read -p "Enter maximum delay time (e.g., 1s): " max_delay
                        read -p "Custom options : (e.g., -sV -A -p- or none): " custom_opts
                        perform_scan "Adjust_Delay" " --scan-delay $init_delay --max-scan-delay  $max_delay"
                        break 2;;
                    "Timing and Performance")
                        echo
                        echo "Select Timing and Performance type:"
                        echo
                        options=("Rate Limiting" "Adjust Delay Between Probes" "Host Timeouts – Give up on Hosts" "Paranoid Timing Template" "Sneaky – ID Evasion (T0)" "Polite – Slower Than Normal Scan" "Normal – Default Speed" "Aggressive – Recommended Mode" "Insane – Very Fast Networks" "Back")
                        select opt in "${options[@]}"; do
                            case $opt in
                                "Rate Limiting")
                                    read -p "Enter rate limiting time (e.g., 0.1s): " rate_limit
        
                                    perform_scan "Rate_Limiting" " --scan-delay   $rate_limit"
                                    break 2;;
                                "Adjust Delay Between Probes")
                                    read -p "Enter initial delay time (e.g., 0.1s): " init_delay
                                    read -p "Enter maximum delay time (e.g., 1s): " max_delay
        
                                    perform_scan "Adjust_Delay" " --scan-delay  $init_delay --max-scan-delay  $max_delay"
                                    break 2;;
                                "Host Timeouts – Give up on Hosts")
                                    read -p "Enter host timeout (e.g., 5m): " host_timeout
        
                                    perform_scan "Host_Timeouts" " --host-timeout   $host_timeout"
                                    break 2;;
                                "Paranoid Timing Template")
        
                                    perform_scan "Paranoid_Timing" " -T0  "
                                    break 2;;
                                "Sneaky – ID Evasion (T0)")
        
                                    perform_scan "Sneaky_ID_Evasion" " -T1  "
                                    break 2;;
                                "Polite – Slower Than Normal Scan")
        
                                    perform_scan "Polite_Slower" " -T2  "
                                    break 2;;
                                "Normal – Default Speed")
        
                                    perform_scan "Normal_Default" " -T3  "
                                    break 2;;
                                "Aggressive – Recommended Mode")
        
                                    perform_scan "Aggressive_Recommended" " -T4 -n -p-  "
                                    break 2;;
                                "Insane – Very Fast Networks")
        
                                    perform_scan "Insane_Very_Fast" " -T5  "
                                    break 2;;
                                "Back") break;;
                            esac
                        done
                        ;;
                    "Back") break;;
                esac
            done
            ;;

        "NSE Scripts")
           echo
           echo "Select NSE Script type:"
           echo
            options=("Safe Category – Default" "Execute Scripts by Name" "Select Script by Category" "Execute NSE Script File" "Exclude a Specific Category" "Include Two Different Categories" "Combining Wildcards" "Set Arguments" "Load Arguments from a File" "Back")
            select opt in "${options[@]}"; do
                case $opt in
                    "Safe Category – Default") 
                        perform_scan "Safe_Category_Default" " -sC "
                        break 2;;
                    "Execute Scripts by Name") 
                        read -p "Enter script name (Please have a look at : https://nmap.org/nsedoc/scripts/): " script_name
                        perform_scan "Scripts_by_Name" " --script $script_name "
                        break 2;;
                    "Select Script by Category")
                        read -p "Enter script category (e.g., exploit): " script_category
                        perform_scan "Script_by_Category" " --script $script_category "
                        break 2;;
                    "Execute NSE Script File")
                        read -p "Enter path to NSE script file: " script_path
                        perform_scan "NSE_Script_File" " --script $script_path "
                        break 2;;
                    "Exclude a Specific Category")
                        read -p "Enter category to exclude (e.g., exploit): " exclude_category
                        perform_scan "Exclude_Category" " -sV --script \"not $exclude_category\" "
                        break 2;;
                    "Include Two Different Categories")
                        read -p "Enter two categories to include (e.g., broadcast,discovery): " include_categories
                        perform_scan "Include_Categories" " --script \"$include_categories\" "
                        break 2;;
                   # "Combining Wildcards") 
                
                   #     perform_scan "Combining_Wildcards" " --script \"http-*\" "
                   #     break 2;;
                    "Set Arguments")
                        read -p "Enter script and arguments (e.g., http-title --script-args http.useragent='Mozilla'): " script_args
                        perform_scan "Set_Arguments" " -sV --script $script_args "
                        break 2;;
                    "Load Arguments from a File")
                        read -p "Enter script and args file path (e.g., discovery nmap-args.txt): " script_args_file
                        perform_scan "Load_Args_From_File" " --script \"$script_args_file\" "
                        break 2;;
                    "Back") break;;
                esac
            done
            ;;

        "Web Server Scanning")
            echo
            echo "Select Web Server Scanning type:"
            echo
            options=("List Supported HTTP Methods" "Discover Interesting Paths/Folders" "Brute-force HTTP Basic Auth" "Provide Own User/Password List" "Brute-force Common Web Platforms" "Detect Web Application Firewall" "Detect XST Vulnerabilities" "Detect XSS Vulnerabilities" "Detect SQL Injection Vulnerabilities" "Find Default Credentials" "Find Exposed Git Repos" "Back")
            select opt in "${options[@]}"; do
                case $opt in
                    "List Supported HTTP Methods") perform_scan "List_HTTP_Methods" "-p80,443 --script http-methods --script-args httpmethods.test-all=true"; break 2;;
                    "Discover Interesting Paths/Folders") perform_scan "Discover_Paths" "--script http-enum -sV"; break 2;;
                    "Brute-force HTTP Basic Auth") perform_scan "HTTP_Basic_Auth_Brute" "-p80 --script http-brute"; break 2;;
                    "Provide Own User/Password List")
                        read -p "Enter path to username list: " user_list
                        read -p "Enter path to password list: " pass_list
                        perform_scan "User_Pass_Brute" "-sV --script http-brute --script-args userdb=$user_list,passdb=$pass_list"
                        break 2;;
                    "Brute-force Common Web Platforms") perform_scan "Web_Platforms_Brute" "-sV --script http-wordpress-brute"; break 2;;
                    "Detect Web Application Firewall") perform_scan "Detect_WAF" "-sV --script http-waf-detect,http-waf-fingerprint"; break 2;;
                    "Detect XST Vulnerabilities") perform_scan "Detect_XST" "-sV --script http-methods,http-trace --script-args http-methods.retest"; break 2;;
                    "Detect XSS Vulnerabilities") perform_scan "Detect_XSS" "-sV --script http-unsafe-output-escaping"; break 2;;
                    "Detect SQL Injection Vulnerabilities") perform_scan "Detect_SQL_Injection" "-sV --script http-sql-injection"; break 2;;
                    "Find Default Credentials") perform_scan "Find_Default_Credentials" "-sV --script http-default-accounts"; break 2;;
                    "Find Exposed Git Repos") perform_scan "Find_Git_Repos" "-sV --script http-git"; break 2;;
                    "Back") break;;
                esac
            done
            ;;

        "Mail Server Scanning")
            echo
            echo "Select Mail Server Scanning type:"
            echo
            options=("Brute-force SMTP" "Brute-force IMAP" "Brute-force POP3" "Enumerate SMTP Users" "SMTP on Alternate Ports" "Discover Open Relays" "Find Available SMTP Commands" "Back")
            select opt in "${options[@]}"; do
                case $opt in
                    "Brute-force SMTP")
                        perform_scan "Brute_force_SMTP" "-p25  --script smtp-brute"
                        break 2;;
                    "Brute-force IMAP")
                        perform_scan "Brute_force_IMAP" "-p143  --script imap-brute"
                        break 2;;
                    "Brute-force POP3")
                        perform_scan "Brute_force_POP3" "-p110  --script pop3-brute"
                        break 2;;
                    "Enumerate SMTP Users")
                        perform_scan "Enumerate_SMTP_Users" "-p25  --script smtp-enum-users"
                        break 2;;
                    "SMTP on Alternate Ports")
                        perform_scan "SMTP_Alternate_Ports" "-sV  --script smtp-strangeport"
                        break 2;;
                    "Discover Open Relays")
                        perform_scan "Discover_Open_Relays" "-sV  --script smtp-open-relay -v"
                        break 2;;
                    "Find Available SMTP Commands")
                        perform_scan "Available_SMTP_Commands" "-p25  --script smtp-commands"
                        break 2;;
                    "Back") break;;
                esac
            done
            ;;

        "Database Scanning")
            echo
            echo "Select Database Scanning type:"
            echo
            options=("Identify MS SQL Servers" "Brute-force MS SQL Passwords" "Dump MS SQL Password Hashes" "List MySQL Databases" "Brute-force MySQL Passwords" "MySQL Root/Anonymous Empty Passwords" "Brute-force Oracle SIDs" "Identify MongoDB Servers" "List CouchDB Databases" "Identify Cassandra Databases" "Brute-force Redis Passwords" "Back")
            select opt in "${options[@]}"; do
                case $opt in
                    "Identify MS SQL Servers") perform_scan "Identify_MS_SQL" "-p1433 --script ms-sql-info"; break 2;;
                    "Brute-force MS SQL Passwords") perform_scan "Brute_force_MS_SQL" "-p1433 --script ms-sql-brute"; break 2;;
                    "Dump MS SQL Password Hashes") perform_scan "Dump_MS_SQL_Hashes" "-p1433 --script ms-sql-empty-password,ms-sql-dump-hashes"; break 2;;
                    "List MySQL Databases")
                        read -p "Enter MySQL username: " mysql_user
                        read -p "Enter MySQL password: " mysql_pass
                        perform_scan "List_MySQL_DB" "-p3306 --script mysql-databases --script-args mysqluser=$mysql_user,mysqlpass=$mysql_pass"
                        break 2;;
                    "Brute-force MySQL Passwords") perform_scan "Brute_force_MySQL" "-p3306 --script mysql-brute"; break 2;;
                    "MySQL Root/Anonymous Empty Passwords") perform_scan "MySQL_Empty_Passwords" "-p3306 --script mysql-empty-password"; break 2;;
                    "Brute-force Oracle SIDs") perform_scan "Brute_force_Oracle_SID" "-sV --script oracle-sid-brute"; break 2;;
                    "Identify MongoDB Servers") perform_scan "Identify_MongoDB" "-p27017 --script mongodb-info"; break 2;;
                    "List CouchDB Databases") perform_scan "List_CouchDB_DB" "-p5984 --script couchdb-databases"; break 2;;
                    "Identify Cassandra Databases") perform_scan "Identify_Cassandra" "-p9160 --script cassandra-brute"; break 2;;
                    "Brute-force Redis Passwords")
                        perform_scan "Brute_force_Redis" "-p6379  --script redis-brute"
                        break 2;;
                    "Back") break;;
                esac
            done
            ;;

        "ICS/SCADA Systems")
            echo
            echo "Select ICS/SCADA Systems type:"
            echo    
            options=("Detect Standard Ports" "Control System Ports (BACnet/IP)" "Ethernet/IP" "Back")
            select opt in "${options[@]}"; do
                case $opt in
                    "Detect Standard Ports") perform_scan "Standard Ports" "-Pn -sT --scan-delay 1s --max-parallelism 1"; break 2;;
                    "Control System Ports (BACnet/IP)") perform_scan "BACnet/IP" "-Pn -sU -p47808 --script bacnet-info"; break 2;;
                    "Ethernet/IP") perform_scan "Ethernet/IP" "-Pn -sU -p44818 --script enip-info"; break 2;;
                    "Back") break;;
                esac
            done
            ;;

        "Top Commands")
            echo
            echo "Select Top Command type:"
            echo
            options=("Comprehensive Scan" "Back")
            select opt in "${options[@]}"; do
                case $opt in
                    "Comprehensive Scan") perform_scan "Comprehensive_Scan" "-A -T4 -v -sS -sV -sC -O --script=all --script-args=safe=1 --open --reason"; break 2;;
                    "Back") break;;
                esac
            done
            ;;

        "Custom Scan")
            read -p "Enter custom Nmap options (eg: -sV -sS -vvv): " custom_opts
            perform_scan "Custom" ""
            break
            ;;

        "Quit")
            exit 0
            ;;

        *) echo "Invalid category. Please try again.";;
    esac
done

    # Define function to start Python server
    start_python_server() {
        # Check if server.py is moved to scans folder
        if test -f "$SERVER_PATH"; then
            echo ""
        else
            echo "Server.py not found moving it to scans folder"
            mv server.py $SERVER_PATH
        fi

        if lsof -Pi :$SERVER_PORT -sTCP:LISTEN -t >/dev/null ; then
            echo "Port 8000 is in use, killing the process to free up the port"
            kill -9 $(lsof -Pi :8000 -sTCP:LISTEN -t)
        fi

        # Start Python server
        cd scans/html/
        python3 server/server.py &
        PYTHON_SERVER_PID=$!
        cd ../../
    }

    # Define function to stop Python server
    stop_python_server() {
        # Find and kill Python server process
        ps aux | grep "python3 server.py" | awk '{print $2}' | xargs kill -9 >/dev/null 2>&1
    }

    # Start Python server
    start_python_server

    # Create a menu with options
    while true; do
        echo
        echo "1. View scan folder"
        echo "2. Run another nmap scan"
        echo "3. Quit"

        urlpath="${scan_path%\\}"        
        # Read user input
        read -p "Enter your choice: " choice


        # Handle user input
        case $choice in

            1)
                # Open scan folder
                echo "Go to http://localhost:8000" 
                ;;
            2)
                # Run another nmap scan
                bash evilmapper.sh
                ;;
            3)
                # Quit
                exit 0
                ;;
            *)
                echo "Invalid choice"
                ;;
        esac
    done

# Stop Python server
pkill "$PYTHON_SERVER_PID" > /dev/null 
trap stop_python_server EXIT
trap stop_python_server SIGINT
trap 'cleanup_function' EXIT SIGINT SIGTERM


