from burp import IBurpExtender
from burp import ITab
from javax.swing import JPanel, JButton, JLabel, JTextField, JCheckBox
import subprocess
import threading

class BurpExtender(IBurpExtender, ITab):
    
    # Define the plugin name and version
    PLUGIN_NAME = "Multi Tool Subdomain Enumeration | AmiRHbz"
    PLUGIN_VERSION = "1.0"
    
    def registerExtenderCallbacks(self, callbacks):
        # Save the callbacks object for later use
        self.callbacks = callbacks
        
        # Set the name of the extension
        self.callbacks.setExtensionName(self.PLUGIN_NAME)
        
        # Create the GUI components
        self.panel = JPanel()
        self.label = JLabel("Enter target domain:")
        self.target_field = JTextField(20)
        self.amass_checkbox = JCheckBox("Use Amass")
        self.sublist3r_checkbox = JCheckBox("Use Sublist3r")
        self.run_button = JButton("Run Enumeration", actionPerformed=self.run_enumeration)
        
        # Add the components to the panel
        self.panel.add(self.label)
        self.panel.add(self.target_field)
        self.panel.add(self.amass_checkbox)
        self.panel.add(self.sublist3r_checkbox)
        self.panel.add(self.run_button)
        
        # Register the extension as a tab
        self.callbacks.addSuiteTab(self)
        
    def getTabCaption(self):
        # Return the name of the tab
        return self.PLUGIN_NAME
    
    def getUiComponent(self):
        # Return the GUI panel
        return self.panel
    
    def run_enumeration(self, event):
        # Get the target domain from the text field
        target_domain = self.target_field.getText()
        
        # Check which tools to use
        use_amass = self.amass_checkbox.isSelected()
        use_sublist3r = self.sublist3r_checkbox.isSelected()
        
        # Create a thread for the enumeration to run in
        enumeration_thread = threading.Thread(target=self.enumerate_subdomains, args=(target_domain, use_amass, use_sublist3r))
        enumeration_thread.start()
        
    def enumerate_subdomains(self, target_domain, use_amass, use_sublist3r):
        # Create a list to hold the subdomains
        subdomains = []
        
        # Run Amass if selected
        if use_amass:
            amass_cmd = "amass enum -d " + target_domain
            amass_output = subprocess.check_output(amass_cmd.split())
            amass_subdomains = amass_output.decode('utf-8').split("\n")
            subdomains += amass_subdomains
        
        # Run Sublist3r if selected
        if use_sublist3r:
            sublist3r_cmd = "python sublist3r.py -d " + target_domain
            sublist3r_output = subprocess.check_output(sublist3r_cmd.split())
            sublist3r_subdomains = sublist3r_output.decode('utf-8').split("\n")
            subdomains += sublist3r_subdomains
        
        # Remove duplicates from the subdomains list
        subdomains = list(set(subdomains))
        
        # Print the subdomains to the Burp Suite output tab
        for subdomain in subdomains:
            self.callbacks.printOutput(subdomain)