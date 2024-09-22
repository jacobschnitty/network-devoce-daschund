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

console = Console()

# Queue for processing MAC addresses
mac_queue = Queue()

# Set to store unique MAC addresses
unique_mac_addresses = set()

class MACAddressCounter(Thread):
    '''Handles processing of MAC addresses asynchronously'''

    def __init__(self, queue):
        Thread.__init__(self)
        self.queue = queue
    
    def run(self):
        while True:
            mac_address = self.queue.get()  # Get MAC address from the queue
            self.process_mac_address(mac_address)
            self.queue.task_done()  # Signal task completion

    def process_mac_address(self, mac_address):
        '''Add MAC address to the set and display the count'''
        if mac_address not in unique_mac_addresses:
            unique_mac_addresses.add(mac_address)
            console.print(f"[green]New MAC address added:[/] {mac_address}")
            console.print(f"[cyan]Total unique MAC addresses:[/] {len(unique_mac_addresses)}")

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
    '''Packet parsing logic for extracting MAC addresses'''
    try:
        if hasattr(packet, 'eth'):
            mac_address = packet.eth.src
            mac_queue.put(mac_address)  # Add the MAC address to the queue
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
    main()
