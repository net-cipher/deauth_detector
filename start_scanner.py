import subprocess
import time
import os
from rich.console import Console
from rich.table import Table
from rich.text import Text
from rich.panel import Panel
from datetime import datetime
import pyfiglet  # For displaying the text "CYBER-HEAT" using ASCII art

# Store the previously connected devices for comparison
previous_connected_devices = set()

# Threshold for detecting abnormal disconnections
disconnection_threshold = 5  # Number of devices disconnected in a short time
check_interval = 10  # Time interval (seconds) to check for connected devices

# Log file location
log_file = "logs.txt"

console = Console()

def display_header():
    # Display "CYBER-HEAT" using figlet
    ascii_art = pyfiglet.figlet_format("NET-CIPHER", font="slant")
    console.print(f"[bold cyan]{ascii_art}[/bold cyan]")

    print("\033[1;32m     	   A tool for detecting Deauthentication Attacks\033[0m")
    print("\033[1;33m                             	    	        - Ranjith V\033[0m")

def get_connected_devices():
    # Get connected devices using 'arp -n' (for Linux)
    try:
        # Run the arp command to get the current ARP cache
        devices = subprocess.check_output(["arp", "-n"], stderr=subprocess.STDOUT)
        devices = devices.decode("utf-8").splitlines()
        current_devices = set()

        # Parse the ARP cache output
        for line in devices:
            if line:
                parts = line.split()
                if len(parts) > 3:
                    ip = parts[0]
                    mac = parts[3]
                    current_devices.add((ip, mac))
        
        return current_devices
    except subprocess.CalledProcessError as e:
        print(f"Error occurred while getting connected devices: {e}")
        return set()

def detect_deauth_attack(previous_devices, current_devices):
    # Compare the previously connected devices with the current ones
    disconnected_devices = previous_devices - current_devices
    
    if len(disconnected_devices) > disconnection_threshold:
        log_attack("Deauthentication attack detected!")
        return True
    return False

def log_attack(message):
    # Log the attack in a file with date and time
    with open(log_file, "a") as log:
        log.write(f"{datetime.now()} - {message}\n")

def display_connected_devices(devices):
    # Display the list of connected devices in a table format using rich
    print("\033[96m | Connected devices are Displayed Below |\033[0m")  # Cyan color for text
    print("\033[96m -----------------------------------------\033[0m")  # Cyan color
    table = Table()
    table.add_column("IP", style="cyan")
    table.add_column("MAC", style="magenta")

    for ip, mac in devices:
        table.add_row(ip, mac)

    console.print(table)

def display_network_info():
    # Get network interface details (only for wlan0)
    try:
        interface_info = subprocess.check_output(["ip", "addr", "show", "wlan0"], stderr=subprocess.STDOUT)
        interface_info = interface_info.decode("utf-8")
        
        # Display in an ordered format
        lines = interface_info.splitlines()
        ordered_info = [
            lines[0],  # Interface name
            lines[1],  # IP address
            lines[2],  # Broadcast address
            lines[3],  # Network mask
            lines[5]   # MAC address
        ]
        
        console.print("\033[95mNetwork Interface Info (wlan0):\033[0m")  # Pink color for text
        for line in ordered_info:
            console.print(f"  {line}")
    except subprocess.CalledProcessError as e:
        print(f"Error getting network interface info: {e}")

def display_network_usage():
    # Display network statistics for wlan0 using 'netstat'
    try:
        netstat_info = subprocess.check_output(["netstat", "-i"], stderr=subprocess.STDOUT)
        netstat_info = netstat_info.decode("utf-8")
        
        # Filter for wlan0 only
        lines = netstat_info.splitlines()
        wlan0_stats = [line for line in lines if "wlan0" in line]

        console.print("\033[95mNetwork Usage Info (wlan0):\033[0m")  # Pink color for text
        for stat in wlan0_stats:
            print("\033[91mwlan0\033[0m", stat)  # Red color for wlan0
    except subprocess.CalledProcessError as e:
        print(f"Error getting network usage info: {e}")

def ping_gateway():
    # Ping the gateway/router to check if it's reachable
    try:
        gateway_ip = "172.20.10.1"  # Replace with your gateway IP
        ping_result = subprocess.check_output(["ping", "-c", "1", gateway_ip], stderr=subprocess.STDOUT)
        ping_result = ping_result.decode("utf-8")
        
        print("\033[95mPing to Gateway:\033[0m")  # Pink color for "Ping to Gateway"
        
        # Display the first ping statistics line in cyan
        print("\033[96m--- 172.20.10.4 ping statistics ---\033[0m")  # Cyan for the whole line
        
        # The IP address in the ping result will be shown in green
        ping_result = ping_result.replace("172.20.10.4", "\033[92m172.20.10.4\033[0m")  # Green color for the IP address
        
        # Display the ping result in white after replacing IP with green
        print("\033[97m" + ping_result + "\033[0m")  # White color for the rest of the ping result
        
    except subprocess.CalledProcessError as e:
        print(f"Error pinging gateway: {e}")

def display_attack_status():
    # Display the attack status in a bold box and yellow color using Panel
    attack_status = Text("No attacks Detected!", style="bold yellow")
    panel = Panel(attack_status, style="yellow", title="Status", border_style="bold yellow")
    console.print(panel)

def display_logs():
    # Check if log file exists and display the logs in a table format
    if os.path.exists(log_file):
        with open(log_file, "r") as log:
            logs = log.readlines()

        # Create a table
        table = Table(title="Log Entries", caption="Deauthentication Attack Logs", show_lines=True)
        table.add_column("Timestamp", style="cyan", no_wrap=True)
        table.add_column("Message", style="magenta")

        # Add rows to the table
        for line in logs:
            log_parts = line.strip().split(" - ")
            if len(log_parts) == 2:
                datetime_str, message = log_parts
                table.add_row(datetime_str, message)

        # Display the table
        console.print(table)
    else:
        console.print("[bold red]Log file does not exist.[/bold red]")

def menu():
    while True:
        display_header()
        print("\033[96m1. Start the Scan\033[0m")
        print("\033[96m2. Check Logs\033[0m")
        print("\033[96m3. Exit\033[0m")
        choice = input("\033[97mChoose an option (1-3): \033[0m")

        if choice == '1':
            
            print("\033[96m -----------------------------------------\033[0m")  # Cyan color
            print("\033[96m | Starting network monitoring...       |\033[0m")  # Cyan color
            print("\033[96m -----------------------------------------\033[0m")  # Cyan color
            monitor_network()
        elif choice == '2':
            display_logs()
        elif choice == '3':
            print("\033[96mExiting... Goodbye!\033[0m")
            break
        else:
            print("\033[91mInvalid option. Please try again.\033[0m")

def monitor_network():
    global previous_connected_devices
    while True:
        # Display the starting message with cyan color
        
        
        # Get the list of currently connected devices
        current_devices = get_connected_devices()

        # Display the connected devices
        display_connected_devices(current_devices)

        # Check for unusual disconnections (potential deauth attack)
        if detect_deauth_attack(previous_connected_devices, current_devices):
            print("\033[91mDeauthentication attack detected!\033[0m")  # Red color for attack
        else:
            # If no attack is detected, print "No attacks Detected!" in a bold box and yellow color
            display_attack_status()
        
        # Display additional network information
        display_network_info()
        display_network_usage()
        ping_gateway()

        # Update the previous connected devices list
        previous_connected_devices = current_devices

        # Wait for the next check
        time.sleep(check_interval)

if __name__ == "__main__":
    menu()
