from burp import IBurpExtender
from burp import ITab
from javax.swing import JPanel, JButton, JLabel, JTextField, JCheckBox
import threading
import requests

class BurpExtender(IBurpExtender, ITab):
    
    # Define the plugin name and version
    PLUGIN_NAME = "Web Path Scanner | AmiRHbz"
    PLUGIN_VERSION = "1.0"
    
    def registerExtenderCallbacks(self, callbacks):
        # Save the callbacks object for later use
        self.callbacks = callbacks
        
        # Set the name of the extension
        self.callbacks.setExtensionName(self.PLUGIN_NAME)
        
        # Create the GUI components
        self.panel = JPanel()
        self.label = JLabel("Enter target URL:")
        self.target_field = JTextField(20)
        self.wordlist_label = JLabel("Enter path wordlist file:")
        self.wordlist_field = JTextField(20)
        self.recursive_checkbox = JCheckBox("Scan subdirectories recursively")
        self.run_button = JButton("Run Scan", actionPerformed=self.run_scan)
        
        # Add the components to the panel
        self.panel.add(self.label)
        self.panel.add(self.target_field)
        self.panel.add(self.wordlist_label)
        self.panel.add(self.wordlist_field)
        self.panel.add(self.recursive_checkbox)
        self.panel.add(self.run_button)
        
        # Register the extension as a tab
        self.callbacks.addSuiteTab(self)
        
    def getTabCaption(self):
        # Return the name of the tab
        return self.PLUGIN_NAME
    
    def getUiComponent(self):
        # Return the GUI panel
        return self.panel
    
    def run_scan(self, event):
        # Get the target URL and wordlist file from the text fields
        target_url = self.target_field.getText()
        wordlist_file = self.wordlist_field.getText()
        
        # Check if the recursive checkbox is selected
        recursive = self.recursive_checkbox.isSelected()
        
        # Read the wordlist file into a list
        with open(wordlist_file, "r") as f:
            wordlist = [line.strip() for line in f]
        
        # Create a thread for the scan to run in
        scan_thread = threading.Thread(target=self.scan_web_paths, args=(target_url, wordlist, recursive))
        scan_thread.start()
        
    def scan_web_paths(self, target_url, wordlist, recursive):
        # Create a list to hold the found paths
        found_paths = []
        
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
                subpaths = self.scan_web_paths(target_url + "/" + path, subwordlist, True)
                
                # Add the subpaths to the found paths list
                found_paths += subpaths
        
        # Return the found paths
        return found_paths