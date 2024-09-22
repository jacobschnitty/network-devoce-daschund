import subprocess
import json
import time
import pyshark
import signal
import sys
from rich.console import Console
from rich.table import Table
from rich.prompt import Prompt
from threading import Thread
from queue import Queue
from datetime import datetime

console = Console()

# Queue for processing MAC addresses
mac_queue = Queue()

# Dictionary to store unique MAC addresses, along with their IP and timestamp
device_info = {}

class MACAddressCounter(Thread):
    '''Handles processing of MAC addresses asynchronously'''

    def __init__(self, queue):
        Thread.__init__(self)
        self.queue = queue
    
    def run(self):
        while True:
            mac_address, ip_address = self.queue.get()  # Get MAC and IP address from the queue
            self.process_mac_address(mac_address, ip_address)
            self.queue.task_done()  # Signal task completion

    def process_mac_address(self, mac_address, ip_address):
        '''Add MAC address to the device dictionary and display the table'''
        if mac_address not in device_info:
            # Store MAC address with its associated IP and timestamp
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            device_info[mac_address] = {"ip": ip_address, "timestamp": timestamp}
            console.print(f"[green]New device detected:[/] MAC {mac_address}, IP {ip_address}")

            # Display the updated table
            self.display_device_table()

    def display_device_table(self):
        '''Displays a table of all unique devices'''
        device_table = Table(title="Unique Devices Detected")

        # Add columns for MAC Address, IP Address, and Timestamp
        device_table.add_column("MAC Address", style="cyan")
        device_table.add_column("IP Address", style="magenta")
        device_table.add_column("Timestamp", style="green")

        # Add rows for each unique device
        for mac, info in device_info.items():
            device_table.add_row(mac, info['ip'], info['timestamp'])

        console.print(device_table)

def get_interface_names():
    '''Retrieve network interfaces and their status'''
    interfaces = {}
    try:
        command = 'powershell -Command "Get-NetAdapter | Select-Object Name, InterfaceGuid, Status | ConvertTo-Json"'
        result = subprocess.check_output(command, shell=True)
        interfaces_data = json.loads(result)
        for idx, iface in enumerate(interfaces_data):
            name = iface['Name']
            guid = iface['InterfaceGuid']
            status = iface['Status']
            if status == "Up":
                interfaces[idx] = {'name': name, 'guid': guid}
    except Exception as e:
        console.print(f"[bold red]Error retrieving interface names:[/bold red] {e}")
    return interfaces

def signal_handler(sig, frame):
    '''Graceful shutdown handler'''
    console.print("[yellow]Stopping packet capture and exiting...[/]")
    sys.exit(0)

def handle_packet(packet):
    '''Packet parsing logic for extracting MAC addresses and IP addresses'''
    try:
        if hasattr(packet, 'eth') and hasattr(packet, 'ip'):
            mac_address = packet.eth.src
            ip_address = packet.ip.src
            mac_queue.put((mac_address, ip_address))  # Add the MAC and IP address to the queue
    except AttributeError:
        pass  # Ignore packets that do not contain the necessary fields

def capture_packets(interface):
    '''Packet capture logic'''
    console.print(f"[green]Starting packet capture[/] on interface [bold]{interface}[/]")
    capture = pyshark.LiveCapture(interface=interface)
    
    for packet in capture.sniff_continuously():
        handle_packet(packet)

def main():
    '''Main program logic'''
    interfaces = get_interface_names()
    table = Table(title="Available Interfaces")
    table.add_column("Index", justify="right", style="cyan", no_wrap=True)
    table.add_column("Name", style="magenta")
    table.add_column("GUID", style="green")

    for i, iface in interfaces.items():
        table.add_row(str(i), iface['name'], iface['guid'])

    console.print(table)
    selected_index = Prompt.ask("Select interface number to sniff on")
    selected_index = int(selected_index.strip())

    if selected_index in interfaces:
        iface_name = interfaces[selected_index]['name']
        # Start the MACAddressCounter thread to handle incoming MAC addresses
        mac_counter_thread = MACAddressCounter(mac_queue)
        mac_counter_thread.start()
        # Start packet capture on the selected interface
        capture_packets(iface_name)
    else:
        console.print(f"[bold red]Interface index {selected_index} is not valid.[/bold red]")

if __name__ == "__main__":
    # Register signal handler for graceful shutdown
    signal.signal(signal.SIGINT, signal_handler)
    
    # Start the program
    main()17    
