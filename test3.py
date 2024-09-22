import subprocess
import json
import time
import pyshark
import socket
import signal
import sys
from rich.console import Console
from rich.table import Table
from rich.prompt import Prompt
from threading import Thread
from queue import Queue
import datetime

console = Console()

devices = {}

# Queue for processing DHCP packets
dhcp_queue = Queue()

class DHCPjobs(Thread):
    '''Handles incoming DHCP packets asynchronously'''

    def __init__(self, queue, parent=None):
        Thread.__init__(self)
        self.queue = queue
        self.parent = parent  # In this case, could be the main device list
    
    def run(self):
        while True:
            job = self.queue.get()  # Get job from queue
            self.process_incoming_dhcp(job)
            self.queue.task_done()  # Signal task completion

    def process_incoming_dhcp(self, job):
        mac_address, ip_address = job
        incoming_time = datetime.datetime.now()

        # Check for duplicate entries in the device list
        duplicate_list = [dev for dev in devices.values() if dev['mac'] == mac_address]

        if duplicate_list:
            # Update the existing device entry
            device = duplicate_list[0]
            device['ip'] = ip_address
            device['last_seen'] = incoming_time
            console.print(f"[cyan]Updated device:[/] MAC {mac_address}, IP {ip_address}")
        else:
            # Add new device
            devices[ip_address] = {
                'mac': mac_address,
                'ip': ip_address,
                'arrival_time': incoming_time
            }
            console.print(f"[green]New device added:[/] MAC {mac_address}, IP {ip_address}")

        # You could trigger additional logic here (e.g., send data to Node-RED, play sound, etc.)

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

def handle_dhcp_packet(packet):
    '''Packet parsing and queueing logic'''
    try:
        # Check if it's a DHCP ACK packet
        if packet.dhcp.option_dhcp == '5':  # DHCP ACK
            mac_address = packet.eth.src
            ip_address = packet.ip.src
            # Add the DHCP packet to the processing queue
            dhcp_queue.put((mac_address, ip_address))
    except AttributeError:
        pass  # Ignore packets that do not contain the necessary fields

def capture_dhcp_packets(interface):
    '''Packet capture logic'''
    console.print(f"[green]Starting DHCP packet capture[/] on interface [bold]{interface}[/]")
    capture = pyshark.LiveCapture(interface=interface, bpf_filter='udp port 67 or udp port 68')
    
    for packet in capture.sniff_continuously():
        handle_dhcp_packet(packet)

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
        # Start the DHCPjobs thread to handle incoming packets
        dhcp_thread = DHCPjobs(dhcp_queue)
        dhcp_thread.start()
        # Start DHCP packet capture on selected interface
        capture_dhcp_packets(iface_name)
    else:
        console.print(f"[bold red]Interface index {selected_index} is not valid.[/bold red]")

if __name__ == "__main__":
    # Register signal handler for graceful shutdown
    signal.signal(signal.SIGINT, signal_handler)
    
    # Start the program
    main()
