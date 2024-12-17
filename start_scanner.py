import subprocess
import time
import os
from rich.console import Console
from rich.table import Table
from rich.text import Text
from rich.panel import Panel
from datetime import datetime
import pyfiglet 


previous_connected_devices = set()


disconnection_threshold = 5  
check_interval = 10

# Log file location
log_file = "logs.txt"

console = Console()

def display_header():

    ascii_art = pyfiglet.figlet_format("NET-CIPHER", font="slant")
    console.print(f"[bold cyan]{ascii_art}[/bold cyan]")

    print("\033[1;32m     	   A tool for detecting Deauthentication Attacks\033[0m")
    print("\033[1;33m                             	    	        - Ranjith V\033[0m")

def get_connected_devices():

    try:

        devices = subprocess.check_output(["arp", "-n"], stderr=subprocess.STDOUT)
        devices = devices.decode("utf-8").splitlines()
        current_devices = set()


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

    disconnected_devices = previous_devices - current_devices
    
    if len(disconnected_devices) > disconnection_threshold:
        log_attack("Deauthentication attack detected!")
        return True
    return False

def log_attack(message):
 
    with open(log_file, "a") as log:
        log.write(f"{datetime.now()} - {message}\n")

def display_connected_devices(devices):

    print("\033[96m | Connected devices are Displayed Below |\033[0m") 
    print("\033[96m -----------------------------------------\033[0m")  
    table = Table()
    table.add_column("IP", style="cyan")
    table.add_column("MAC", style="magenta")

    for ip, mac in devices:
        table.add_row(ip, mac)

    console.print(table)

def display_network_info():
    try:
        interface_info = subprocess.check_output(["ip", "addr", "show", "wlan0"], stderr=subprocess.STDOUT)
        interface_info = interface_info.decode("utf-8")
        
        # Displays
        lines = interface_info.splitlines()
        ordered_info = [
            lines[0],  # Interface name
            lines[1],  # IP address
            lines[2],  # Broadcast address
            lines[3],  # Network mask
            lines[5]   # MAC address
        ]
        
        console.print("\033[95mNetwork Interface Info (wlan0):\033[0m")
        for line in ordered_info:
            console.print(f"  {line}")
    except subprocess.CalledProcessError as e:
        print(f"Error getting network interface info: {e}")

def display_network_usage():
    try:
        netstat_info = subprocess.check_output(["netstat", "-i"], stderr=subprocess.STDOUT)
        netstat_info = netstat_info.decode("utf-8")
        
        lines = netstat_info.splitlines()
        wlan0_stats = [line for line in lines if "wlan0" in line]

        console.print("\033[95mNetwork Usage Info (wlan0):\033[0m")
        for stat in wlan0_stats:
            print("\033[91mwlan0\033[0m", stat)
    except subprocess.CalledProcessError as e:
        print(f"Error getting network usage info: {e}")

def ping_gateway():
    try:
        gateway_ip = "(ip_here)"   #<-----------------------------------------------------------------------------------Enter your ip here instead of (ip_here) in 1 place
        ping_result = subprocess.check_output(["ping", "-c", "1", gateway_ip], stderr=subprocess.STDOUT)
        ping_result = ping_result.decode("utf-8")
        
        print("\033[95mPing to Gateway:\033[0m") 
        
        # Display the ping statistics
        print("\033[96m--- (ip_here) ping statistics ---\033[0m")                   #<----------------------------------Enter your ip here instead of (ip_here) in 1 place
        ping_result = ping_result.replace("(ip_here)", "\033[92m(ip_here)\033[0m")  #<----------------------------------Enter your ip here instead of (ip_here) in 2 places
                                                                                                    #remove the brackets , it should looks like 127.0.0.1 , not (127.0.0.1)
        print("\033[97m" + ping_result + "\033[0m")                                                 #use your gateway ip address.
        
    except subprocess.CalledProcessError as e:
        print(f"Error pinging gateway: {e}")

def display_attack_status():
    # Display the attack status in a bold box and yellow color using Panel
    attack_status = Text("No attacks Detected!", style="bold yellow")
    panel = Panel(attack_status, style="yellow", title="Status", border_style="bold yellow")
    console.print(panel)

def display_logs():
    if os.path.exists(log_file):
        with open(log_file, "r") as log:
            logs = log.readlines()

        table = Table(title="Log Entries", caption="Deauthentication Attack Logs", show_lines=True)
        table.add_column("Timestamp", style="cyan", no_wrap=True)
        table.add_column("Message", style="magenta")

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
        current_devices = get_connected_devices()
        display_connected_devices(current_devices)
        if detect_deauth_attack(previous_connected_devices, current_devices):
            print("\033[91mDeauthentication attack detected!\033[0m") 
        else:
            # If no attack is detected, print "No attacks Detected!"
            display_attack_status()
        display_network_info()
        display_network_usage()
        ping_gateway()
        previous_connected_devices = current_devices
        time.sleep(check_interval)

if __name__ == "__main__":
    menu()
