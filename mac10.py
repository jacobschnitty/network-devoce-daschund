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

# class KeepAliveThread(Thread):
#     '''Send a placeholder JSON message every 15 seconds to keep the TCP socket alive'''
#     def __init__(self, sock):
#         Thread.__init__(self)
#         self.sock = sock

#     def run(self):
#         while True:
#             try:
#                 # Construct and send a placeholder JSON message to keep the socket alive
#                 placeholder_message = {
#                     "message": "keep_alive",
#                     "timestamp": str(datetime.now())
#                 }
#                 message_json = json.dumps(placeholder_message)
#                 self.sock.sendall(message_json.encode('utf-8'))
#                 console.print(f"[cyan]Keep-alive message sent:[/] {message_json}")

#                 # Sleep for 15 seconds before sending the next keep-alive message
#                 time.sleep(15)

#             except Exception as e:
#                 console.print(f"[red]Error sending keep-alive message: {e}[/red]")
#                 break

# Create a new asynchronous function to establish a WebSocket connection
async def create_websocket_connection():
    '''Establish a persistent WebSocket connection to Node-RED'''
    server_ip, server_port, ws_path = get_node_red_server_details()
    try:
        websocket_url = f"ws://{server_ip}:{server_port}{ws_path}"
        console.print(f"[yellow]Attempting to connect to Node-RED WebSocket server at {websocket_url}...[/yellow]")
        websocket = await websockets.connect(websocket_url)
        console.print(f"[green]Connection established with Node-RED WebSocket server at {websocket_url}[/green]")
        return websocket
    except Exception as e:
        console.print(f"[red]Failed to connect to Node-RED WebSocket server: {e}[/red]")
        sys.exit(1)

# class MACAddressCounter(Thread):
#     '''Handles processing of MAC addresses asynchronously'''

#     def __init__(self, queue, sock):
#         Thread.__init__(self)
#         self.queue = queue
#         self.sock = sock  # Keep the TCP socket connection
    
#     def run(self):
#         while True:
#             mac_address, ip_address = self.queue.get()  # Get MAC and IP address from the queue
#             self.process_mac_address(mac_address, ip_address)
#             self.queue.task_done()  # Signal task completion

#     def process_mac_address(self, mac_address, ip_address):
#         '''Add MAC address to the device dictionary, display the table, and send data to Node-RED'''
#         current_time = datetime.now()
#         hostname = self.get_hostname(ip_address)
#         is_new_device = False

#         if mac_address not in device_info:
#             # Store MAC address with its associated IP, hostname, and last seen time
#             device_info[mac_address] = {
#                 "ip": ip_address,
#                 "hostname": hostname,
#                 "last_seen": current_time,
#                 "online": True
#             }
#             is_new_device = True
#             console.print(f"[green]New device detected:[/] MAC {mac_address}, IP {ip_address}")

#             # Send data to Node-RED
#             self.send_data_to_node_red(mac_address, ip_address, hostname, "online")

#         else:
#             # Update the last seen time and set the device as online
#             device_info[mac_address]["last_seen"] = current_time
#             device_info[mac_address]["online"] = True

#         # Only refresh the table if there's a new device or status change
#         if is_new_device:
#             self.display_device_table()

#     def display_device_table(self):
#         '''Displays a table of all unique devices and their online/offline status'''
#         device_table = Table(title="Unique Devices Detected")

#         # Add columns for MAC Address, IP Address, Hostname, and Status
#         device_table.add_column("MAC Address", style="cyan")
#         device_table.add_column("IP Address", style="magenta")
#         device_table.add_column("Hostname", style="green")
#         device_table.add_column("Status", style="bold yellow")

#         # Check device status (online/offline)
#         current_time = datetime.now()
#         for mac, info in device_info.items():
#             time_since_last_seen = current_time - info["last_seen"]

#             if time_since_last_seen > DEVICE_TIMEOUT:
#                 # Mark device as offline if inactive for more than 2 minutes
#                 info["online"] = False
#                 offline_duration = int(time_since_last_seen.total_seconds()) - int(DEVICE_TIMEOUT.total_seconds())
#                 status = f"Offline ({offline_duration}s)"
#             else:
#                 status = "Online" if info["online"] else "Offline"

#             # Add the device info to the table
#             device_table.add_row(mac, info['ip'], info['hostname'], status)

#         console.clear()
#         console.print(device_table)

#     def get_hostname(self, ip_address):
#         '''Get hostname via reverse DNS lookup'''
#         try:
#             return socket.gethostbyaddr(ip_address)[0]
#         except (socket.herror, socket.gaierror):
#             return "Unknown"

class MACAddressCounter(Thread):
    '''Handles processing of MAC addresses asynchronously using WebSocket'''

    def __init__(self, queue, websocket):
        Thread.__init__(self)
        self.queue = queue
        self.sock = websocket  # Keep the WebSocket connection
    
    def run(self):
        asyncio.run(self.process_mac_addresses())  # Start the async event loop

    async def process_mac_addresses(self):
        while True:
            mac_address, ip_address = self.queue.get()  # Get MAC and IP address from the queue
            await self.process_mac_address(mac_address, ip_address)
            self.queue.task_done()  # Signal task completion

    async def process_mac_address(self, mac_address, ip_address):
        '''Add MAC address to the device dictionary, display the table, and send data to Node-RED via WebSocket'''
        current_time = datetime.now()
        hostname = self.get_hostname(ip_address)
        is_new_device = False

        if mac_address not in device_info:
            # Store MAC address with its associated IP, hostname, and last seen time
            device_info[mac_address] = {
                "ip": ip_address,
                "hostname": hostname,
                "last_seen": current_time,
                "online": True
            }
            is_new_device = True
            console.print(f"[green]New device detected:[/] MAC {mac_address}, IP {ip_address}")

            # Send data to Node-RED via WebSocket
            await self.send_data_to_node_red(mac_address, ip_address, hostname, "online")

        else:
            # Update the last seen time and set the device as online
            device_info[mac_address]["last_seen"] = current_time
            device_info[mac_address]["online"] = True

        # Only refresh the table if there's a new device or status change
        if is_new_device:
            self.display_device_table()


    # def send_data_to_node_red(self, mac_address, ip_address, hostname, status):
    #     '''Send data to Node-RED via TCP (maintain open connection)'''
    #     try:
    #         # Validate input parameters
    #         if not all(isinstance(param, str) for param in [mac_address, ip_address, hostname, status]):
    #             raise ValueError("Input parameters must be strings.")
        
    #         # Create a structured message with MAC address, IP, hostname, and status
    #         message = {
    #             "mac_address": mac_address,
    #             "ip_address": ip_address,
    #             "hostname": hostname,
    #             "status": status
    #         }
    #         # Convert message to JSON
    #         message_json = json.dumps(message)

    #         # Send the message via the existing socket connection with a timeout
    #         self.sock.settimeout(5)  # Example timeout of 5 seconds
    #         self.sock.sendall(message_json.encode('utf-8'))
    #         console.print(f"[cyan]Data sent to Node-RED:[/] {message_json}")
    
    #     except ConnectionError as e:
    #         error_log = open("error_log.txt", "a")
    #         error_log.write(f"Error sending data to Node-RED: {e}\n")
    #         error_log.close()
    #         console.print(f"[red]Error sending data to Node-RED:[/] {e}")
    #         self.sock.close()

    async def send_data_to_node_red(self, mac_address, ip_address, hostname, status):
        '''Send data to Node-RED via WebSocket (maintain open connection)'''
        try:
            # Validate input parameters
            if not all(isinstance(param, str) for param in [mac_address, ip_address, hostname, status]):
                raise ValueError("Input parameters must be strings.")
        
            # Create a structured message with MAC address, IP, hostname, and status
            message = {
                "mac_address": mac_address,
                "ip_address": ip_address,
                "hostname": hostname,
                "status": status
            }
            # Convert message to JSON
            message_json = json.dumps(message)

            # Send the message via the WebSocket connection
            await self.sock.send(message_json)
            console.print(f"[cyan]Data sent to Node-RED:[/] {message_json}")
    
        except Exception as e:
            console.print(f"[red]Error sending data to Node-RED WebSocket:[/] {e}")
            await self.sock.close()


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

def get_node_red_server_details():
    '''Prompt the user for Node-RED server IP and port, with defaults'''
    default_ip = '192.168.1.252'
    default_port = '1880'
    ws_path = '/ws/devices'

    console.print(f"[yellow]Current Node-RED Server IP: {default_ip}[/yellow]")
    console.print(f"[yellow]Current Node-RED Server Port: {default_port}[/yellow]")
    console.print(f"[yellow]Current Node-RED WebSocket path: {ws_path}[/yellow]")
    
    # Prompt user for server IP, default to the existing one if enter is pressed
    server_ip = Prompt.ask("Enter Node-RED Server IP (press Enter to use the default)", default=default_ip)
    
    # Prompt user for server port, default to the existing one if enter is pressed
    server_port = Prompt.ask("Enter Node-RED Server Port (press Enter to use the default)", default=str(default_port))
    
    return server_ip, int(server_port), ws_path

# def create_tcp_connection():
#     '''Establish a persistent TCP connection to Node-RED'''
#     server_ip, server_port = get_node_red_server_details()
#     try:
#         console.print(f"[yellow]Attempting to connect to Node-RED server at {server_ip}:{server_port}...[/yellow]")
#         sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
#         sock.connect((server_ip, server_port))
#         console.print(f"[green]Connection established with Node-RED server at {server_ip}:{server_port}[/green]")
#         return sock
#     except Exception as e:
#         console.print(f"[red]Failed to connect to Node-RED server: {e}[/red]")
#         sys.exit(1)

# def main():
#     '''Main program logic'''
#     interfaces = get_interface_names()
    
#     # Display available interfaces to the user
#     table = Table(title="Available Interfaces")
#     table.add_column("Index", justify="right", style="cyan", no_wrap=True)
#     table.add_column("Name", style="magenta")
#     table.add_column("GUID", style="green")

#     for i, iface in interfaces.items():
#         table.add_row(str(i), iface['name'], iface['guid'])

#     console.print(table)
    
#     # Ask the user to select a network interface
#     selected_index = Prompt.ask("Select interface number to sniff on")
#     selected_index = int(selected_index.strip())

#     if selected_index in interfaces:
#         iface_name = interfaces[selected_index]['name']

#         # Create a persistent TCP connection to Node-RED
#         tcp_sock = create_tcp_connection()

#         # Start the MACAddressCounter thread to handle incoming MAC addresses
#         mac_counter_thread = MACAddressCounter(mac_queue, tcp_sock)
#         mac_counter_thread.start()

#         # # Start the KeepAliveThread to send keep-alive messages every 15 seconds
#         # keep_alive_thread = KeepAliveThread(tcp_sock)
#         # keep_alive_thread.start()

#         # Start packet capture on the selected interface
#         capture_packets(iface_name)
#     else:
#         console.print(f"[bold red]Interface index {selected_index} is not valid.[/bold red]")

# if __name__ == "__main__":
#     # Register signal handler for graceful shutdown
#     signal.signal(signal.SIGINT, signal_handler)
    
#     # Start the program
#     main()

async def main():
    '''Main program logic'''
    interfaces = get_interface_names()
    
    # Display available interfaces to the user
    table = Table(title="Available Interfaces")
    table.add_column("Index", justify="right", style="cyan", no_wrap=True)
    table.add_column("Name", style="magenta")
    table.add_column("GUID", style="green")

    for i, iface in interfaces.items():
        table.add_row(str(i), iface['name'], iface['guid'])

    console.print(table)
    
    # Ask the user to select a network interface
    selected_index = Prompt.ask("Select interface number to sniff on")
    selected_index = int(selected_index.strip())

    if selected_index in interfaces:
        iface_name = interfaces[selected_index]['name']

        # Create a persistent WebSocket connection to Node-RED
        websocket = await create_websocket_connection()

        # Start the MACAddressCounter thread to handle incoming MAC addresses using WebSocket
        mac_counter_thread = MACAddressCounter(mac_queue, websocket)
        mac_counter_thread.start()

        # Start packet capture on the selected interface
        capture_packets(iface_name)
    else:
        console.print(f"[bold red]Interface index {selected_index} is not valid.[/bold red]")

if __name__ == "__main__":
    # Register signal handler for graceful shutdown
    signal.signal(signal.SIGINT, signal_handler)
    
    # Start the async event loop
    asyncio.run(main())
