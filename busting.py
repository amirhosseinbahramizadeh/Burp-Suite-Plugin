from burp import IBurpExtender
from burp import ITab
from javax.swing import JPanel, JButton, JLabel, JTextField, JCheckBox
import threading
import requests
import dns.resolver
import socket

class BurpExtender(IBurpExtender, ITab):
    
    # Define the plugin name and version
    PLUGIN_NAME = "Buster | AmiRHbz"
    PLUGIN_VERSION = "1.0"
    
    def registerExtenderCallbacks(self, callbacks):
        # Save the callbacks object for later use
        self.callbacks = callbacks
        
        # Set the name of the extension
        self.callbacks.setExtensionName(self.PLUGIN_NAME)
        
        # Create the GUI components
        self.panel = JPanel()
        self.target_label = JLabel("Enter target URL:")
        self.target_field = JTextField(20)
        self.wordlist_label = JLabel("Enter wordlist file:")
        self.wordlist_field = JTextField(20)
        self.recursive_checkbox = JCheckBox("Scan subdirectories recursively")
        self.dns_checkbox = JCheckBox("DNS brute force")
        self.vhost_checkbox = JCheckBox("VHost brute force")
        self.run_button = JButton("Run Buster", actionPerformed=self.run_buster)
        
        # Add the components to the panel
        self.panel.add(self.target_label)
        self.panel.add(self.target_field)
        self.panel.add(self.wordlist_label)
        self.panel.add(self.wordlist_field)
        self.panel.add(self.recursive_checkbox)
        self.panel.add(self.dns_checkbox)
        self.panel.add(self.vhost_checkbox)
        self.panel.add(self.run_button)
        
        # Register the extension as a tab
        self.callbacks.addSuiteTab(self)
        
    def getTabCaption(self):
        # Return the name of the tab
        return self.PLUGIN_NAME
    
    def getUiComponent(self):
        # Return the GUI panel
        return self.panel
    
    def run_buster(self, event):
        # Get the target URL and wordlist file from the text fields
        target_url = self.target_field.getText()
        wordlist_file = self.wordlist_field.getText()
        
        # Check if the recursive checkbox is selected
        recursive = self.recursive_checkbox.isSelected()
        
        # Check if the DNS and VHost checkboxes are selected
        dns_brute_force = self.dns_checkbox.isSelected()
        vhost_brute_force = self.vhost_checkbox.isSelected()
        
        # Read the wordlist file into a list
        with open(wordlist_file, "r") as f:
            wordlist = [line.strip() for line in f]
        
        # Create a thread for the buster to run in
        buster_thread = threading.Thread(target=self.run_buster_threads, args=(target_url, wordlist, recursive, dns_brute_force, vhost_brute_force))
        buster_thread.start()
        
    def run_buster_threads(self, target_url, wordlist, recursive, dns_brute_force, vhost_brute_force):
        # Create a list to hold the found paths
        found_paths = []
        
        # Create a list to hold the found subdomains
        found_subdomains = []
        
        # Create a list to hold the found VHosts
        found_vhosts = []
        
        # Create a list to hold the found IPs
        found_ips = []
        
        # Create a thread for the directory/file brute force to run in
        directory_thread = threading.Thread(target=self.run_directory_buster, args=(target_url, wordlist, recursive, found_paths))
        directory_thread.start()
        
        # Create a thread for the DNS brute force to run in
        if dns_brute_force:
            dns_thread = threading.Thread(target=self.run_dns_buster, args=(target_url, wordlist, found_subdomains, found_ips))
            dns_thread.start()
        
        # Create a thread for the VHost brute force to run in
        if vhost_brute_force:
            vhost_thread = threading.Thread(target=self.run_vhost_buster, args=(target_url, wordlist, found_vhosts))
            vhost_thread.start()
        
        # Wait for all threads to finish
        directory_thread.join()
        if dns_brute_force:
            dns_thread.join()
        if vhost_brute_force:
            vhost_thread.join()
        
        # Print the found paths to the Burp Suite output tab
        for path in found_paths:
            self.callbacks.printOutput("[+] Found path: " + path)
        
        # Print the found subdomains to the Burp Suite output tab
        for subdomain in found_subdomains:
            self.callbacks.printOutput("[+] Found subdomain: " + subdomain)
        
        # Print the found VHosts to the Burp Suite output tab
        for vhost in found_vhosts:
            self.callbacks.printOutput("[+] Found VHost: " + vhost)
        
        # Print the found IPs to the Burp Suite output tab
        for ip in found_ips:
            self.callbacks.printOutput("[+] Found IP: " + ip)
    
    def run_directory_buster(self, target_url, wordlist, recursive, found_paths):
        # Loop through each path in the wordlist
        for path in wordlist:
            # Create the full URL to test
            url = target_url + "/" + path
            
            # Send a GET request to the URL
            response = requests.get(url)
            
            # Check if the response code is 200 or 401
            if response.status_code == 200 or response.status_code == 401:
                # Add the path to the found paths list
                found_paths.append(path)
                
                # Print the path to the Burp Suite output tab
                self.callbacks.printOutput("[+] Found path: " + path)
            
            # Check if the recursive checkbox is selected
            if recursive and response.status_code == 200:
                # Recursively scan subdirectories
                subwordlist = [path + "/" + subpath for subpath in wordlist]
                subpaths = self.run_directory_buster(target_url + "/" + path, subwordlist, True, found_paths)
                
                # Add the subpaths to the found paths list
                found_paths += subpaths
        
        # Return the found paths
        return found_paths
    
    def run_dns_buster(self, target_url, wordlist, found_subdomains, found_ips):
        # Loop through each subdomain in the wordlist
        for subdomain in wordlist:
            # Create the full domain name to test
            domain_name = subdomain + "." + target_url
            
            # Try to resolve the domain name to an IP address
            try:
                answers = dns.resolver.query(domain_name, "A")
                
                # Loop through each answer and add the IP to the found IPs list
                for answer in answers:
                    found_ips.append(answer.address)
                    
                    # Print the IP to the Burp Suite output tab
                    self.callbacks.printOutput("[+] Found IP: " + answer.address)
                
                # Add the subdomain to the found subdomains list
                found_subdomains.append(subdomain)
                
                # Print the subdomain to the Burp Suite output tab
                self.callbacks.printOutput("[+] Found subdomain: " + subdomain)
            
            except:
                pass
        
        # Return the found subdomains and IPs
        return found_subdomains, found_ips
    
    def run_vhost_buster(self, target_url, wordlist, found_vhosts):
        # Loop through each VHost in the wordlist
        for vhost in wordlist:
            # Create the full domain name to test
            domain_name = vhost + "." + target_url
            
            # Try to connect to the domain name
            try:
                # Create a socket connection to the domain name
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.connect((domain_name, 80))
                
                # Send a GET request to the domain name
                s.sendall(b"GET / HTTP/1.1\r\nHost: " + domain_name.encode() + b"\r\n\r\n")
                
                # Receive the response from the server
                response = s.recv(4096)
                
                # Check if the response code is 200
                if b"200 OK" in response:
                    # Add the VHost to the found VHosts list
                    found_vhosts.append(vhost)
                    
                    # Print the VHost to the Burp Suite output tab
                    self.callbacks.printOutput("[+] Found VHost: " + vhost)
                
                # Close the socket connection
                s.close()
            
            except:
                pass
        
        # Return the found VHosts
        return found_vhosts