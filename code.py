# Import the required libraries for GUI creation and network scanning
import tkinter as tk                 # Basic GUI framework in Python
from tkinter import ttk, scrolledtext  # ttk for modern widgets, scrolledtext for text area with a scrollbar
import socket                        # For network-related functions
import threading                     # To handle background tasks (multithreading)
import json                          # To handle JSON data if needed
from datetime import datetime        # To work with dates and times
import nmap                          # Python wrapper for the Nmap tool to perform network scans
import csv                           # To handle CSV file creation for reports

class NetworkSecurityTool:
    # Class constructor (initialization function)
    def __init__(self, root):
        # Store the reference to the root window
        self.root = root
        # Set the window title
        self.root.title("Network Security Assessment Tool")
        # Set the dimensions of the window
        self.root.geometry("800x600")
        
        # Define NIST CSF Categories that will be assessed in this tool
        self.nist_categories = {
            "Identify": ["Network Mapping","State-Up/Down","Device response while scanning"],   # Identify phase subcategories
            "Detect": ["Port Scanning","Port accesibility and servicing check"],      # Detect phase subcategories
            "Respond": ["Vulnerability Assessment","Respond to any unuasual port"]                # Respond phase subcategories
        }
        
        # Call the method to set up the GUI
        self.setup_gui()
        
    # Method to set up the GUI components
    def setup_gui(self):
        # Create a Notebook widget to hold tabs
        notebook = ttk.Notebook(self.root)
        # Place the Notebook widget in the main window
        notebook.pack(pady=10, expand=True, fill="both")
        
        # Create the Dashboard tab
        dashboard_frame = ttk.Frame(notebook)
        # Add the Dashboard tab to the notebook with the label "Dashboard"
        notebook.add(dashboard_frame, text="Dashboard")
        
        # Create a frame to hold scan controls (IP input, buttons)
        control_frame = ttk.LabelFrame(dashboard_frame, text="Scan Controls")
        # Add padding and make it fill the width
        control_frame.pack(padx=10, pady=5, fill="x")
        
        # Add a label for the target IP input
        ttk.Label(control_frame, text="Target IP:").pack(side=tk.LEFT, padx=5)
        # Create an Entry widget for the user to input the target IP address
        self.ip_entry = ttk.Entry(control_frame)
        # Place the IP entry field in the control frame
        self.ip_entry.pack(side=tk.LEFT, padx=5)
        # Set a default IP value (localhost)
        self.ip_entry.insert(0, "127.0.0.1")
        
        # Create a button to start the scan, and assign it a command
        ttk.Button(control_frame, text="Start Scan", 
                  command=self.start_scan).pack(side=tk.LEFT, padx=5)
        
        # Create a frame to display scan results
        results_frame = ttk.LabelFrame(dashboard_frame, text="Scan Results")
        # Add padding and make it expandable
        results_frame.pack(padx=10, pady=5, fill="both", expand=True)
        
        # Add a ScrolledText widget for showing the scan results (with scrollbars)
        self.results_text = scrolledtext.ScrolledText(results_frame, height=20)
        # Place the ScrolledText widget in the results frame
        self.results_text.pack(padx=5, pady=5, fill="both", expand=True)
        
        # Create the Reports tab
        reports_frame = ttk.Frame(notebook)
        # Add the Reports tab to the notebook with the label "Reports"
        notebook.add(reports_frame, text="Reports")
        
        # Add a button in the Reports tab to generate a report
        ttk.Button(reports_frame, text="Generate Report", 
                  command=self.generate_report).pack(pady=10)
        
        # Add a ScrolledText widget for showing the generated report (with scrollbars)
        self.report_text = scrolledtext.ScrolledText(reports_frame, height=20)
        # Place the ScrolledText widget in the reports frame
        self.report_text.pack(padx=5, pady=5, fill="both", expand=True)
    
    # Method to initiate the scan process
    def start_scan(self):
        # Clear previous scan results in the text widget
        self.results_text.delete(1.0, tk.END)
        # Display a message indicating that the scan is starting
        self.results_text.insert(tk.END, "Starting security assessment...\n")
        # Retrieve the IP address entered by the user
        target_ip = self.ip_entry.get()
        
        # Start the scanning process in a separate thread to avoid freezing the GUI
        thread = threading.Thread(target=self.perform_scan, args=(target_ip,))
        # Set the thread as a daemon so it terminates when the main program exits
        thread.daemon = True
        # Start the thread
        thread.start()
    
    # Method to perform the actual scan using Nmap
    def perform_scan(self, target_ip):
        try:
            # Initialize an Nmap PortScanner object
            nm = nmap.PortScanner()
            
            # Log the start of the port scan to the results text area
            self.log_message("Performing port scan...")
            # Perform a basic port scan on the target IP, scanning ports 22 to 443
            nm.scan(target_ip, '22-443', arguments='-sV')
            
            # Iterate over all scanned hosts to analyze the results
            for host in nm.all_hosts():
                # Log the host and its state (up/down)
                self.log_message(f"\nHost: {host}")
                self.log_message(f"State: {nm[host].state()}")
                
                # Iterate over each protocol found on the host (like TCP, UDP)
                for proto in nm[host].all_protocols():
                    # Log the protocol type (TCP, UDP)
                    self.log_message(f"\nProtocol: {proto}")
                    # Get a list of all ports for the current protocol
                    ports = nm[host][proto].keys()
                    
                    # Iterate over each port to log its state and service name (if any)
                    for port in ports:
                        service = nm[host][proto][port]
                        self.log_message(
                            f"Port {port}: {service['state']} "
                            f"({service.get('name', 'unknown')})"
                        )
            
            # Store the scan results for later reporting
            self.scan_results = nm
            # Indicate that the scan completed successfully
            self.log_message("\nScan completed successfully!")
            
        except Exception as e:
            # If any error occurs during the scan, log the error message
            self.log_message(f"Error during scan: {str(e)}")
    
    # Method to log messages to the results text area
    def log_message(self, message):
        # Insert the message into the results text area and add a newline
        self.results_text.insert(tk.END, message + "\n")
        # Scroll to the end of the text area to show the latest message
        self.results_text.see(tk.END)
    
    # Method to generate a report based on the scan results
    def generate_report(self):
        # Check if scan results are available
        if not hasattr(self, 'scan_results'):
            # If no results, show an error message in the report area
            self.report_text.delete(1.0, tk.END)
            self.report_text.insert(tk.END, "No scan results available. Please run a scan first.")
            return
        
        # Create a list to hold the report content
        report = []
        # Add a header and the current date/time to the report
        report.append("Network Security Assessment Report")
        report.append(f"Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        
        # Iterate over each NIST CSF framework category to include in the report
        for category, subcategories in self.nist_categories.items():
            # Add the category to the report
            report.append(f"\n{category} Framework Category:")
            # List all subcategories under each category
            for subcategory in subcategories:
                report.append(f"- {subcategory}")
        
        # Add scan results to the report
        report.append("\nScan Results:")
        # Iterate over each scanned host
        for host in self.scan_results.all_hosts():
            # Add host information to the report
            report.append(f"\nHost: {host}")
            report.append(f"State: {self.scan_results[host].state()}")
            
            # Iterate over each protocol for the current host
            for proto in self.scan_results[host].all_protocols():
                report.append(f"\nProtocol: {proto}")
                # List each scanned port and its details
                ports = self.scan_results[host][proto].keys()
                
                for port in ports:
                    service = self.scan_results[host][proto][port]
                    report.append(
                        f"Port {port}: {service['state']} "
                        f"({service.get('name', 'unknown')})"
                    )
        
        # Clear the report area and display the generated report
        self.report_text.delete(1.0, tk.END)
        self.report_text.insert(tk.END, "\n".join(report))
        
        # Save the report to a CSV file
        self.save_report_csv()
    
    # Method to save the scan report to a CSV file
    def save_report_csv(self):
        # Generate a filename using the current date and time
        filename = f"security_assessment_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
        # Open a CSV file for writing
        with open(filename, 'w', newline='') as csvfile:
            writer = csv.writer(csvfile)
            # Write the header row to the CSV
            writer.writerow(['Category', 'Finding', 'Status'])
            
            # Iterate over each scanned host and protocol
            for host in self.scan_results.all_hosts():
                for proto in self.scan_results[host].all_protocols():
                    ports = self.scan_results[host][proto].keys()
                    # Write each port's information to the CSV
                    for port in ports:
                        service = self.scan_results[host][proto][port]
                        writer.writerow([
                            'Port Scan',
                            f'Port {port} ({service.get("name", "unknown")})',
                            service['state']
                        ])

# Main function to launch the application
def main():
    # Create the main Tkinter window
    root = tk.Tk()
    # Instantiate the NetworkSecurityTool with the root window
    app = NetworkSecurityTool(root)
    # Run the Tkinter main loop to start the GUI
    root.mainloop()

# Entry point for the script
if __name__ == "__main__":
    main()
