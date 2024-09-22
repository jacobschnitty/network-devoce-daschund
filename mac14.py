import subprocess, json, pyshark, signal, sys, asyncio, websockets, socket
from concurrent.futures import ThreadPoolExecutor
from rich.console import Console
from rich.prompt import Prompt
from rich.table import Table
from threading import Thread
from queue import Queue
from datetime import datetime, timedelta

console         = Console()
mac_queue       = Queue() # Queue for processing MAC addresses
websocket_queue = Queue() # Queue for sending processed data to WebSocket
device_info     = {} # Dictionary to store unique MAC addresses, along with IP, hostname, and last seen time
DEVICE_TIMEOUT  = timedelta(minutes=2) # Timeout after which devices are marked as offline (2 minutes)
WS_URI          = "ws://192.168.1.252:1880/ws/devices" # WebSocket URI (Node-RED WebSocket server)

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

def get_hostname(self, ip_address):
    '''Get hostname via reverse DNS lookup'''
    try:
        return socket.gethostbyaddr(ip_address)[0]
    except (socket.herror, socket.gaierror):
        return "Unknown"
def run_threads(interface):
    '''Launch threads for sniffing, websocket, and future tasks'''
    # Thread for packet sniffing
    sniffing_thread = Thread(target=sniff_packets, args=(interface,))
    
    # Thread for WebSocket client
    ws_thread = Thread(target=start_websocket_client)
    
    # Start MACAddressCounter thread to process MAC addresses and pass the websocket_queue
    mac_counter_thread = MACAddressCounter(mac_queue, websocket_queue)  # Pass websocket_queue here
    
    # Start all threads
    sniffing_thread.start()
    ws_thread.start()
    mac_counter_thread.start()
    
    # Wait for threads to complete (this will block until threads finish)
    sniffing_thread.join()
    ws_thread.join()
    mac_counter_thread.join()

class MACAddressCounter(Thread):
    '''Handles processing of MAC addresses asynchronously'''

    def __init__(self, queue, websocket_queue):
        Thread.__init__(self)
        self.queue = queue
        self.websocket_queue = websocket_queue  # Accept websocket_queue

    def process_mac_address(self, mac_address, ip_address):
        '''Process MAC address and send data to WebSocket'''
        current_time = datetime.now()

        # Correctly reference the global function
        hostname = get_hostname(ip_address)
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

            # Send data to WebSocket (by adding it to the websocket queue)
            self.websocket_queue.put((mac_address, ip_address, hostname, "online"))

        else:
            # Update the last seen time and set the device as online
            device_info[mac_address]["last_seen"] = current_time
            device_info[mac_address]["online"] = True

        # Only refresh the table if there's a new device or status change
        if is_new_device:
            self.display_device_table()

        def display_device_table(self):
            '''Displays a table of all unique devices and their online/offline status'''
            current_time = datetime.now()
            console.clear()
            table_title = "Unique Devices Detected"
            console.print(f"[yellow]{table_title}[/]")

            for mac, info in device_info.items():
                time_since_last_seen = current_time - info["last_seen"]
                if time_since_last_seen > DEVICE_TIMEOUT:
                    # Mark device as offline if inactive for more than 2 minutes
                    info["online"] = False
                    offline_duration = int(time_since_last_seen.total_seconds()) - int(DEVICE_TIMEOUT.total_seconds())
                    status = f"Offline ({offline_duration}s)"
                else:
                    status = "Online" if info["online"] else "Offline"

                # Display the device info
                console.print(f"MAC: {mac} | IP: {info['ip']} | Hostname: {info['hostname']} | Status: {status}")

async def websocket_client():
    '''WebSocket client thread handling the WebSocket communication'''
    console.log("[yellow]Attempting to connect to WebSocket...[/yellow]")
    try:
        async with websockets.connect(WS_URI) as websocket:
            console.log(f"[green]Connected to WebSocket: {WS_URI}[/green]")
            
            while True:
                # Continuously get processed device data from the websocket queue
                mac_address, ip_address, hostname, status = await asyncio.get_event_loop().run_in_executor(None, websocket_queue.get)
                
                # Prepare data to send
                message = {
                    "mac_address": mac_address,
                    "ip_address": ip_address,
                    "hostname": hostname,
                    "status": status,
                    "timestamp": str(datetime.now())
                }
                
                # Send the message
                await websocket.send(json.dumps(message))
                console.log(f"[cyan]Data sent to WebSocket:[/] {message}")
                
                # Mark task as done for the queue
                websocket_queue.task_done()

    except websockets.ConnectionClosedError as e:
        console.log(f"[red]WebSocket connection closed: {e}[/red]")

    except Exception as e:
        console.error(f"[red]Error in WebSocket communication: {e}[/red]")
        
    finally:
        console.log(f"[yellow]WebSocket connection has been closed.[/yellow]")


def sniff_packets(interface):
    '''Packet capture logic running in a separate thread'''
    console.log(f"Starting packet capture on interface {interface}")

    # Create a new event loop for this thread
    asyncio.set_event_loop(asyncio.new_event_loop())
    capture = pyshark.LiveCapture(interface=interface)
    for packet in capture.sniff_continuously():
        handle_packet(packet)

def handle_packet(packet):
    '''Packet parsing logic for extracting MAC addresses and IP addresses'''
    if hasattr(packet, 'eth') and hasattr(packet, 'ip'):
        mac_address = packet.eth.src
        ip_address = packet.ip.src
        mac_queue.put((mac_address, ip_address))

def start_websocket_client():
    '''Start WebSocket client in its own thread using asyncio'''
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    loop.run_until_complete(websocket_client())


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
        console.error(f"[bold red]Interface index {selected_index} is not valid.[/bold red]")

if __name__ == "__main__":
    try:
        # Register signal handler for graceful shutdown
        signal.signal(signal.SIGINT, lambda sig, frame: sys.exit(0))
        
        # Start the program
        main()
    except KeyboardInterrupt:
        console.error("[yellow]Exiting program...[/]")
