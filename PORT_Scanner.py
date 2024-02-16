import socket
import threading
import tkinter as tk
from tkinter import ttk
from queue import Queue
from datetime import datetime
import os

class PortScannerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Port Scanner")
        self.root.geometry("600x400")
        
        self.label_host = ttk.Label(root, text="Target IP/Domain:")
        self.label_host.grid(row=0, column=0, padx=10, pady=5, sticky="w")
        
        self.entry_host = ttk.Entry(root, width=30)
        self.entry_host.grid(row=0, column=1, padx=10, pady=5)
        
        self.label_ports = ttk.Label(root, text="Server Port(s) (e.g., 80, 1:1024, or leave blank for all ports):")
        self.label_ports.grid(row=1, column=0, padx=10, pady=5, sticky="w")
        
        self.entry_ports = ttk.Entry(root, width=30)
        self.entry_ports.grid(row=1, column=1, padx=10, pady=5)
        
        self.button_scan = ttk.Button(root, text="Scan", command=self.scan_ports)
        self.button_scan.grid(row=0, column=2, padx=10, pady=5, rowspan=2, sticky="nsew")
        
        self.label_output = ttk.Label(root, text="Scan Results:")
        self.label_output.grid(row=2, column=0, padx=10, pady=5, sticky="w")
        
        self.text_output = tk.Text(root, height=10, width=70)
        self.text_output.grid(row=3, column=0, columnspan=3, padx=10, pady=5)
        
        self.scrolling = ttk.Scrollbar(root, orient="vertical", command=self.text_output.yview)
        self.scrolling.grid(row=3, column=3, sticky="ns")
        self.text_output.config(yscrollcommand=self.scrolling.set)
        
    def clear(self):
        if os.name == 'nt':
            _ = os.system('cls')
        else:
            _ = os.system('clear')
    
    def scan_ports(self):
        host = self.entry_host.get()
        ports_input = self.entry_ports.get().strip()
        
        if ports_input == "":
            start_port, end_port = 1, 65535
        elif ":" in ports_input:
            try:
                start_port, end_port = map(int, ports_input.split(':'))
            except:
                self.text_output.insert("end", "Invalid port range. Please enter ports in the format 'start:end'.\n")
                return
        else:
            try:
                start_port = end_port = int(ports_input)
            except:
                self.text_output.insert("end", "Invalid port number. Please enter a valid port number.\n")
                return
        
        if start_port > end_port:
            self.text_output.insert("end", "Invalid port range. Start port cannot be greater than end port.\n")
            return
        
        self.clear()
        self.text_output.delete(1.0, "end")
        self.text_output.insert("end", "Port Scanner\n")
        self.text_output.insert("end", "|--------------------------------------------Coded by Junaid Hussain--------------------------------------|\n\n")
        self.text_output.insert("end", f"Target IP: {host}\n")
        self.text_output.insert("end", f"Scanning ports {start_port} to {end_port} started at: {datetime.now()}\n\n")
        
        # Running the scanning process in a separate thread
        threading.Thread(target=self.run_scanner, args=(host, start_port, end_port), daemon=True).start()
        
    def run_scanner(self, host, start_port, end_port):
        threads = 1021  # Number of threads for scanning
        
        def scan(port):
            s = socket.socket()
            s.settimeout(5)
            result = s.connect_ex((host, port))
            s.close()
            return result == 0
        
        queue = Queue()
        def get_ports():
            for port in range(start_port, end_port + 1):
                queue.put(port)
        
        open_ports = []
        def worker():
            while not queue.empty():
                port = queue.get()
                if scan(port):
                    open_ports.append(port)
                    service_name = socket.getservbyport(port)
                    self.text_output.insert("end", f"Port {port} is open! Service: {service_name}\n")
        
        get_ports()
        thread_list = []
        for _ in range(threads):
            thread = threading.Thread(target=worker)
            thread_list.append(thread)
        for thread in thread_list:
            thread.start()
        for thread in thread_list:
            thread.join()
        
        self.text_output.insert("end", f"\nScanning complete at: {datetime.now()}\n")

def main():
    root = tk.Tk()
    port_scanner_gui = PortScannerGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()
