import subprocess, json, pyshark, signal, sys, asyncio, websockets, socket, threading, queue
from concurrent.futures import ThreadPoolExecutor
from rich.console import Console
from rich.prompt import Prompt
from rich.table import Table
from threading import Thread
from queue import Queue
from datetime import datetime, timedelta

console = Console()

# Queues for processing MAC addresses, WebSocket communication, and loopback
mac_queue = Queue()
websocket_queue = Queue()


# Dictionary to store unique MAC addresses, along with IP, hostname, and last seen time
device_info = {}

# Timeout after which devices are marked as offline (2 minutes)
DEVICE_TIMEOUT = timedelta(minutes=2)

# WebSocket URI (Node-RED WebSocket server)
WS_URI = "ws://192.168.1.252:1880/ws/devices"

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

def get_hostname(ip_address):
    '''Get hostname via reverse DNS lookup'''
    try:
        return socket.gethostbyaddr(ip_address)[0]
    except (socket.herror, socket.gaierror):
        return "Unknown"

async def websocket_client():
    '''WebSocket client thread handling the WebSocket communication'''
    try:
        async with websockets.connect(WS_URI) as websocket:
            console.print(f"[green]Connection established with Node-RED WebSocket server at {WS_URI}[/green]")

            while True:
                try:
                    # Get processed data from the queue with timeout
                    mac_address, ip_address, hostname, status = await asyncio.get_event_loop().run_in_executor(
                        None, lambda: websocket_queue.get(timeout=1)
                    )

                    # Prepare data to send
                    message = {
                        "mac_address": mac_address,
                        "ip_address": ip_address,
                        "hostname": hostname,
                        "status": status,
                        "timestamp": datetime.now().isoformat()
                    }
                    await websocket.send(json.dumps(message))
                    console.log(f"Data sent to WebSocket: {json.dumps(message)}")

                    # Mark task as done for the queue
                    websocket_queue.task_done()

                except queue.Empty:  # Catching queue.Empty instead of mac_queue.Empty
                    pass  # Queue is empty, retry next loop

    except websockets.ConnectionClosedError as e:
        console.print(f"[red]WebSocket connection closed: {e}[/red]")
    except Exception as e:
        console.print(f"[red]Error in WebSocket communication: {e}[/red]")
    finally:
        console.print(f"[yellow]WebSocket connection has been closed.[/yellow]")

class MACAddressCounter(Thread):
    '''Handles processing of MAC addresses asynchronously'''

    def __init__(self, queue, websocket_queue):
        Thread.__init__(self)
        self.queue = queue
        self.websocket_queue = websocket_queue

    def run(self):
        while True:
            mac_address, ip_address = self.queue.get()
            self.process_mac_address(mac_address, ip_address)
            self.queue.task_done()

    def process_mac_address(self, mac_address, ip_address):
        '''Process MAC address and send data to WebSocket'''
        current_time = datetime.now()
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

            console.log(f"Adding MAC {mac_address} to WebSocket queue")
            self.websocket_queue.put((mac_address, ip_address, hostname, "online"))


        else:
            # Update the last seen time and set the device as online
            device_info[mac_address]["last_seen"] = current_time
            device_info[mac_address]["online"] = True

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
                info["online"] = False
                offline_duration = int(time_since_last_seen.total_seconds()) - int(DEVICE_TIMEOUT.total_seconds())
                status = f"Offline ({offline_duration}s)"
            else:
                status = "Online" if info["online"] else "Offline"

            console.print(f"MAC: {mac} | IP: {info['ip']} | Hostname: {info['hostname']} | Status: {status}")

def handle_packet(packet):
    '''Packet parsing logic for extracting MAC addresses and IP addresses'''
    try:
        if hasattr(packet, 'eth') and hasattr(packet, 'ip'):
            mac_address = packet.eth.src
            ip_address  = packet.ip.src
            # console.log(f"Packet captured - MAC: {mac_address}, IP: {ip_address}") # Log packet information            
            mac_queue.put((mac_address, ip_address))
        else:
            pass

    except Exception as e:
        console.log(f"[red]Error handling packet: {e}[/red]")

def sniff_packets(interface):
    '''Packet capture logic running in a separate thread'''
    console.log(f"Starting packet capture on interface {interface}")

    try:
        asyncio.set_event_loop(asyncio.new_event_loop())  # Create and set a new event loop for this thread     
        console.log(f"Initializing live network packet capture on {interface}") # Log tshark initialization
        capture = pyshark.LiveCapture(interface=interface)
        for packet in capture.sniff_continuously():
            handle_packet(packet)

    except Exception as e:
        console.log(f"[red]Error during packet capture: {e}[/red]")

def run_threads(interface):
    '''Launch threads for sniffing, websocket, loopback listener, and future tasks'''
    # Start WebSocket communication in its own thread
    websocket_thread = Thread(target=lambda: asyncio.run(websocket_client()))
    websocket_thread.start()

    # Start MAC address processing
    mac_processor_thread = MACAddressCounter(mac_queue, websocket_queue)
    mac_processor_thread.start()

    # Start packet sniffing in a separate thread
    sniffing_thread = Thread(target=sniff_packets, args=(interface,))
    sniffing_thread.start()

    # Wait for all threads to finish
    mac_processor_thread.join()
    sniffing_thread.join()
    websocket_thread.join()


def main():
    interfaces = get_interface_names()

    # Display available interfaces to the user
    console.print("[yellow]Available interfaces:[/]")
    for idx, iface in interfaces.items():
        console.print(f"{idx}: {iface['name']}")

    # Ask the user to select a network interface
    selected_index = int(Prompt.ask("Select interface number to sniff on"))

    if selected_index in interfaces:
        iface_name = interfaces[selected_index]['name']
        
        # Run the threads for packet sniffing, WebSocket communication, and loopback
        run_threads(iface_name)
    else:
        console.print(f"[bold red]Interface index {selected_index} is not valid.[/bold red]")

if __name__ == "__main__":
    try:
        # Graceful shutdown handling with signal
        signal.signal(signal.SIGINT, lambda sig, frame: sys.exit(0))

        # Start the main program logic
        main()
    except KeyboardInterrupt:
        console.print("[yellow]Exiting program...[/]")
