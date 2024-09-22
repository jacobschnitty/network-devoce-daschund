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
from rich.progress import Progress

console = Console()

devices = {}

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

def send_data_to_node_red(ip, mac, server_ip, server_port):
    '''TCP client to send data to Node-RED'''
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.connect((server_ip, server_port))
            message = f"IP: {ip}, MAC: {mac}"
            sock.sendall(message.encode('utf-8'))
            console.print(f"[green]Sent to Node-RED:[/] IP {ip}, MAC {mac}")
    except Exception as e:
        console.print(f"[red]Error sending data:[/] {e}")

def signal_handler(sig, frame):
    '''Graceful shutdown handler'''
    console.print("[yellow]Stopping packet capture and exiting...[/]")
    sys.exit(0)

def handle_dhcp_packet(packet):
    '''Packet parsing and handling logic'''
    try:
        # Check if it's a DHCP ACK packet
        if packet.dhcp.option_dhcp == '5':  # DHCP ACK
            mac_address = packet.eth.src
            ip_address = packet.ip.src
            console.print(f"[cyan]DHCP ACK detected:[/] IP [bold blue]{ip_address}[/], MAC [bold magenta]{mac_address}[/]")
            # Send the data to Node-RED
            send_data_to_node_red(ip_address, mac_address, 'node-red-server-ip', 12345)
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
        capture_dhcp_packets(iface_name)  # Start DHCP capture on selected interface
    else:
        console.print(f"[bold red]Interface index {selected_index} is not valid.[/bold red]")

if __name__ == "__main__":
    # Register signal handler for graceful shutdown
    signal.signal(signal.SIGINT, signal_handler)
    
    # Start the program
    main()
