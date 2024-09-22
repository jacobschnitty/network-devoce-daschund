import subprocess, json, pyshark, signal, sys, asyncio, websockets
from concurrent.futures import ThreadPoolExecutor
from rich.console import Console
from rich.prompt import Prompt
from rich.table import Table
from threading import Thread
from queue import Queue
from datetime import datetime, timedelta

console         = Console()
mac_queue       = Queue() # Queue for processing MAC addresses
device_info     = {} # Dictionary to store unique MAC addresses, along with IP, hostname, and last seen time
DEVICE_TIMEOUT  = timedelta(minutes=2) # Timeout after which devices are marked as offline (2 minutes)
WS_URI          = "ws://192.168.1.252:1880/ws/devices" # WebSocket URI (Node-RED WebSocket server)

async def websocket_client():
    '''WebSocket client thread handling the WebSocket communication'''
    async with websockets.connect(WS_URI) as websocket:
        while True:
            # Get device data from the queue
            if not mac_queue.empty():
                mac_address, ip_address, hostname, status = mac_queue.get()
                # Prepare data to send
                message = {
                    "mac_address"   : mac_address,
                    "ip_address"    : ip_address,
                    "hostname"      : hostname,
                    "status"        : status,
                    "timestamp"     : str(datetime.now())
                }
                # Send the message
                await websocket.send(json.dumps(message))
                console.print(f"[cyan]Data sent to WebSocket:[/] {message}")

def handle_packet(packet):
    '''Packet parsing logic for extracting MAC addresses and IP addresses'''
    if hasattr(packet, 'eth') and hasattr(packet, 'ip'):
        mac_address = packet.eth.src
        ip_address  = packet.ip.src
        hostname    = "Unknown"  # Add your logic to retrieve hostname
        mac_queue.put((mac_address, ip_address, hostname, "online"))

def sniff_packets(interface):
    '''Packet capture logic running in a separate thread'''
    console.print(f"Starting packet capture on interface {interface}")
    
    # Create and set a new event loop for this thread
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    
    # Start packet capture using the new event loop
    capture = pyshark.LiveCapture(interface=interface)
    
    for packet in capture.sniff_continuously():
        handle_packet(packet)

def start_websocket_client():
    '''Start WebSocket client in its own thread using asyncio'''
    asyncio.run(websocket_client())

def 1interface_names():
    '''Retrieve network interfaces and their status'''
    interfaces = {}
    try:
        command = 'powershell -Command "Get-NetAdapter | Select-Object Name, InterfaceGuid, Status | ConvertTo-Json"'
        result = subprocess.check_output(command, shell=True)
        interfaces_data = json.loads(result)
        for idx, iface in enumerate(interfaces_data):
            name    = iface['Name']
            guid    = iface['InterfaceGuid']
            status  = iface['Status']
            if status == "Up":
                interfaces[idx] = {'name': name, 'guid': guid}
    except Exception as e:
        console.print(f"[bold red]Error retrieving interface names:[/bold red] {e}")
    return interfaces

def display_device_table():
    '''Displays a table of all unique devices and their online/offline status'''
    device_table = Table(title="Unique Devices Detected")

    # Add columns for MAC Address, IP Address, Hostname, and Status
    device_table.add_column("MAC Address", style    ="cyan")
    device_table.add_column("IP Address", style     ="magenta")
    device_table.add_column("Hostname", style       ="green")
    device_table.add_column("Status", style         ="bold yellow")

    # Check device status (online/offline)
    current_time = datetime.now()
    for mac, info in device_info.items():
        time_since_last_seen = current_time - info["last_seen"]

        if time_since_last_seen > DEVICE_TIMEOUT:
            # Mark device as offline if inactive for more than 2 minutes
            info["online"] = False
            offline_duration = int(time_since_last_seen.total_seconds()) - int(DEVICE_TIMEOUT.total_seconds())
            status = f"Offline ({offline_duration}s)"
        else:
            status = "Online" if info["online"] else "Offline"

        # Add the device info to the table
        device_table.add_row(mac, info['ip'], info['hostname'], status)

    console.clear()
    console.print(device_table)

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

        # Start WebSocket communication in asyncio event loop
        ws_task = asyncio.create_task(websocket_client())
        
        # Run packet sniffing in a background thread
        with ThreadPoolExecutor() as executor:
            loop = asyncio.get_running_loop()
            sniff_task = loop.run_in_executor(executor, sniff_packets, iface_name)

            await asyncio.gather(ws_task, sniff_task)
    else:
        console.print(f"[bold red]Interface index {selected_index} is not valid.[/bold red]")

# Function to manage threads
def run_threads(interface):
    '''Launch threads for sniffing, websocket, and future tasks'''
    # Thread for packet sniffing
    sniffing_thread = Thread(target=sniff_packets, args=(interface,))
    
    # Start all threads
    sniffing_thread.start()

    # Run WebSocket in the event loop
    asyncio.run(websocket_client())
    
    # Wait for threads to complete (this will block until threads finish)
    sniffing_thread.join()

# Main program logic
def main():
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

        # Start all threads (sniffing, WebSocket, and future tasks)
        run_threads(iface_name)
    else:
        console.print(f"[bold red]Interface index {selected_index} is not valid.[/bold red]")

if __name__ == "__main__":
    try:
        # Register signal handler for graceful shutdown
        signal.signal(signal.SIGINT, lambda sig, frame: sys.exit(0))
        
        # Start the program
        main()
    except KeyboardInterrupt:
        console.print("[yellow]Exiting program...[/]")
