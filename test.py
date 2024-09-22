import pyshark
import socket
import signal
import sys
from rich.console import Console
from rich.text import Text
from rich import print

# Create a Console instance for Rich output
console = Console()

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
            # Use rich to print color-coded messages
            console.print(f"[cyan]DHCP ACK detected:[/] IP [bold blue]{ip_address}[/], MAC [bold magenta]{mac_address}[/]")
            # Send the data to Node-RED
            send_data_to_node_red(ip_address, mac_address, 'node-red-server-ip', 12345)
    except AttributeError:
        pass  # Ignore packets that do not contain the necessary fields

def capture_dhcp_packets(interface='eth0'):
    '''Packet capture logic'''
    console.print(f"[green]Starting packet capture[/] on interface [bold]{interface}[/]")
    capture = pyshark.LiveCapture(interface=interface, bpf_filter='udp port 67 or udp port 68')
    
    for packet in capture.sniff_continuously():
        handle_dhcp_packet(packet)

if __name__ == "__main__":
    # Register signal handler for graceful shutdown
    signal.signal(signal.SIGINT, signal_handler)
    
    # Start the packet capture (you can change the network interface as needed)
    try:
        capture_dhcp_packets(interface='eth0')  # Replace 'eth0' with your interface
    except Exception as e:
        console.print(f"[red]Error:[/] {e}")
