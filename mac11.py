import subprocess
import json
import time
import pyshark
import socket
import signal
import sys
import asyncio
import websockets
from rich.console import Console
from rich.table import Table
from rich.prompt import Prompt
from threading import Thread
from queue import Queue
from datetime import datetime, timedelta

console = Console()

# Queue for processing MAC addresses
mac_queue = Queue()

# Dictionary to store unique MAC addresses, along with IP, hostname, and last seen time
device_info = {}

# Timeout after which devices are marked as offline (2 minutes)
DEVICE_TIMEOUT = timedelta(minutes=2)

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


class MACAddressCounter(Thread):
    '''Handles processing of MAC addresses asynchronously'''

    def __init__(self, queue, websocket):
        Thread.__init__(self)
        self.queue = queue
        self.websocket = websocket
    
    def run(self):
        while True:
            mac_address, ip_address = self.queue.get()
            asyncio.run(self.process_mac_address(mac_address, ip_address))  # Use asyncio.run to call async function
            self.queue.task_done()

    async def process_mac_address(self, mac_address, ip_address):
        '''Add MAC address to the device dictionary, display the table, and send data to Node-RED'''
        current_time = datetime.now()
        hostname = self.get_hostname(ip_address)
        is_new_device = False

        if mac_address not in device_info:
            device_info[mac_address] = {
                "ip": ip_address,
                "hostname": hostname,
                "last_seen": current_time,
                "online": True
            }
            is_new_device = True
            console.print(f"[green]New device detected:[/] MAC {mac_address}, IP {ip_address}")
            await self.send_data_to_node_red(mac_address, ip_address, hostname, "online")

        else:
            device_info[mac_address]["last_seen"] = current_time
            device_info[mac_address]["online"] = True

        if is_new_device:
            self.display_device_table()

    def display_device_table(self):
        device_table = Table(title="Unique Devices Detected")
        device_table.add_column("MAC Address", style="cyan")
        device_table.add_column("IP Address", style="magenta")
        device_table.add_column("Hostname", style="green")
        device_table.add_column("Status", style="bold yellow")

        current_time = datetime.now()
        for mac, info in device_info.items():
            time_since_last_seen = current_time - info["last_seen"]

            if time_since_last_seen > DEVICE_TIMEOUT:
                info["online"] = False
                offline_duration = int(time_since_last_seen.total_seconds()) - int(DEVICE_TIMEOUT.total_seconds())
                status = f"Offline ({offline_duration}s)"
            else:
                status = "Online" if info["online"] else "Offline"

            device_table.add_row(mac, info['ip'], info['hostname'], status)

        console.clear()
        console.print(device_table)

    def get_hostname(self, ip_address):
        try:
            return socket.gethostbyaddr(ip_address)[0]
        except (socket.herror, socket.gaierror):
            return "Unknown"

    async def send_data_to_node_red(self, mac_address, ip_address, hostname, status):
        '''Send data to Node-RED via WebSocket'''
        try:
            message = {
                "mac_address": mac_address,
                "ip_address": ip_address,
                "hostname": hostname,
                "status": status
            }
            message_json = json.dumps(message)
            await self.websocket.send(message_json)
            console.print(f"[cyan]Data sent to Node-RED:[/] {message_json}")
        except Exception as e:
            console.print(f"[red]Error sending data to Node-RED via WebSocket: {e}[/red]")


async def capture_packets(interface):
    '''Async packet capture logic'''
    console.print(f"[green]Starting packet capture[/] on interface [bold]{interface}[/]")
    capture = pyshark.LiveCapture(interface=interface)

    for packet in capture.sniff_continuously():
        if hasattr(packet, 'eth') and hasattr(packet, 'ip'):
            mac_address = packet.eth.src
            ip_address = packet.ip.src
            mac_queue.put((mac_address, ip_address))

async def create_websocket_connection():
    '''Establish a persistent WebSocket connection to Node-RED'''
    server_url = "ws://192.168.1.252:1880/ws/devices"  # Ensure this matches the WebSocket In node in Node-RED
    try:
        console.print(f"[yellow]Attempting to connect to Node-RED WebSocket server at {server_url}...[/yellow]")
        async with websockets.connect(server_url) as websocket:
            console.print(f"[green]Connection established with Node-RED WebSocket server at {server_url}[/green]")
            
            mac_counter_thread = MACAddressCounter(mac_queue, websocket)
            mac_counter_thread.start()

            await asyncio.Future()  # Keep the connection open

    except Exception as e:
        console.print(f"[red]Failed to connect to Node-RED WebSocket server: {e}[/red]")
        sys.exit(1)

async def main():
    '''Main async logic'''
    interfaces = get_interface_names()
    
    # Display available interfaces to the user
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

        # Start WebSocket connection and packet capture concurrently
        await asyncio.gather(
            create_websocket_connection(),
            capture_packets(iface_name)
        )
    else:
        console.print(f"[bold red]Interface index {selected_index} is not valid.[/bold red]")


if __name__ == "__main__":
    signal.signal(signal.SIGINT, signal_handler)
    asyncio.run(main())
