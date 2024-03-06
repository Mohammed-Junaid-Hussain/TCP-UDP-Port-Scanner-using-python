import socket
import threading
import tkinter as tk
from tkinter import ttk
from queue import Queue
from datetime import datetime
import os
import ssl

class PortScannerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Port Scanner")
        self.root.geometry("650x600")
        
        #  target IP/Domain input
        self.label_host = ttk.Label(root, text="Target IP/Domain:")
        self.label_host.grid(row=0, column=0, padx=10, pady=5, sticky="w")
        
        # Entry  target IP/Domain input
        self.entry_host = ttk.Entry(root, width=30)
        self.entry_host.grid(row=0, column=1, padx=10, pady=5)
        
        #  server ports input
        self.label_ports = ttk.Label(root, text="Server Port(s) (e.g., 80, 1:1024, or leave blank for all ports):")
        self.label_ports.grid(row=1, column=0, padx=10, pady=5, sticky="w")
        
        # Entry  server ports input
        self.entry_ports = ttk.Entry(root, width=30)
        self.entry_ports.grid(row=1, column=1, padx=10, pady=5)
        
        # Button to trigger port scanning
        self.button_scan = ttk.Button(root, text="Scan", command=self.scan_ports)
        self.button_scan.grid(row=0, column=2, padx=10, pady=5, rowspan=2, sticky="nsew")
        
        #  displaying scan results
        self.label_output = ttk.Label(root, text="Scan Results:")
        self.label_output.grid(row=2, column=0, padx=10, pady=5, sticky="w")
        
        # Text widget for displaying scan results
        self.text_output = tk.Text(root, height=10, width=70)
        self.text_output.grid(row=3, column=0, columnspan=3, padx=10, pady=5)
        
        # Scrollbar for the text widget
        self.scrolling = ttk.Scrollbar(root, orient="vertical", command=self.text_output.yview)
        self.scrolling.grid(row=3, column=3, sticky="ns")
        self.text_output.config(yscrollcommand=self.scrolling.set)
        
    def clear(self):
        # clear the terminal screen
        if os.name == 'nt':
            _ = os.system('cls')  # Windows
        else:
            _ = os.system('clear')  # Unix/Linux
                    
    def scan_ports(self):
        # initate the port scanning process
        host = self.entry_host.get()
        ports_input = self.entry_ports.get().strip()
        
        if ports_input == "":
            start_port, end_port = 1, 65535  # if port range is not specified, scan all ports
        elif ":" in ports_input:
            # If port range is specified as start:end
            try:
                start_port, end_port = map(int, ports_input.split(':'))
            except:
                self.text_output.insert("end", "Invalid port range. Please enter ports in the format 'start:end'.\n")
                return
        else:
            # If single port is specified
            try:
                start_port = end_port = int(ports_input)
            except:
                self.text_output.insert("end", "Invalid port number. Please enter a valid port number.\n")
                return
        
        if start_port > end_port:
            # Check if start port is greater than end port
            self.text_output.insert("end", "Invalid port range. Start port cannot be greater than end port.\n")
            return
        
        self.clear()  # Clear the console/terminal screen
        self.text_output.delete(1.0, "end")  # Clear previous scan results
        self.text_output.insert("end", "Port Scanner\n")
        self.text_output.insert("end", "|CN MINI  PROJECT|\n\n")  
        self.text_output.insert("end", f"Target IP: {host}\n")
        self.text_output.insert("end", f"Scanning ports {start_port} to {end_port} started at: {datetime.now()}\n\n")
        
        # Running the scanning process in a separate thread
        threading.Thread(target=self.run_scanner, args=(host, start_port, end_port), daemon=True).start()
        
    def run_scanner(self, host, start_port, end_port):
        # Function to perform port scanning
        
        threads = 1021  # Number of threads for scanning

        def scan(port, protocol):
            # Function to scan a specific port
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM if protocol == 'tcp' else socket.SOCK_DGRAM)
            s.settimeout(5)  # Timeout for socket connection
            
            if protocol == 'tcp':
                try:
                    if port == 443:  # If port is 443, use SSL/TLS
                        s = ssl.wrap_socket(s)
                    s.connect((host, port))  # Check TCP connection
                    s.close()
                    return True
                except socket.error:
                    return False
            else:
                try:
                    s.sendto(b'', (host, port))  # Check UDP connection
                    s.close()
                    return True
                except socket.error:
                    return False

        queue = Queue()  # Queue to store ports for scanning

        def get_ports():
            # Function to populate the queue with ports to scan
            for port in range(start_port, end_port + 1):
                queue.put(port)

        open_ports_tcp = []  # List to store open TCP ports
        open_ports_udp = []  # List to store open UDP ports

        def worker():
            # Worker function for each thread to scan ports
            while not queue.empty():
                port = queue.get()
                if scan(port, 'tcp'):
                    open_ports_tcp.append(port)
                    service_name = socket.getservbyport(port, 'tcp')  # Get service name corresponding to the port
                    self.text_output.insert("end", f"TCP Port {port} is open! Service: {service_name}\n")
                if scan(port, 'udp'):
                    open_ports_udp.append(port)
                    service_name = socket.getservbyport(port, 'udp')  # Get service name corresponding to the port
                    self.text_output.insert("end", f"UDP Port {port} is open! Service: {service_name}\n")

        get_ports()  # Populate the queue with ports to scan

        thread_list = []
        for _ in range(threads):
            # Create and start threads for port scanning
            thread = threading.Thread(target=worker)
            thread_list.append(thread)

        for thread in thread_list:
            thread.start()

        for thread in thread_list:
            thread.join()  # Wait for all threads to complete

        # Check if port 443 is open
        if 443 in open_ports_tcp:
            self.text_output.insert("end", "Port 443 is open!\nThe domain is secure and is using SSL.\n")
        else:
            self.text_output.insert("end", "Port 443 is not open.\n The domain may not be using SSL.\n")

        self.text_output.insert("end", f"\nScanning complete at: {datetime.now()}\n")

def main():
    root = tk.Tk()
    port_scanner_gui = PortScannerGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()
