# Burp-Suite-Plugin
burp suite plugins for Recon written by Python

<h1>pathscanner.py</h1>
This plugin creates a GUI with options to enter a target URL, a wordlist file, and whether to scan subdirectories recursively, perform DNS brute force, and perform VHost brute force. When the "Run Buster" button is clicked, a new thread is started which creates separate threads for the directory/file brute force, DNS brute force, and VHost brute force. The directory/file brute force thread reads in the wordlist file and sends GET requests to each URL formed by appending a path from the wordlist to the target URL. If a response code of 200 or 401 is received, the path is added to a list of found paths and printed to the Burp Suite output tab. If the recursive checkbox is selected and a response code of 200 is received, the plugin recursively scans subdirectories by calling itself with the subdirectory URL and a subwordlist formed by appending paths from the original wordlist to the current path. The DNS brute force thread loops through each subdomain in the wordlist and attempts to resolve the subdomain to an IP address. If successful, the subdomain and IP are added to lists of found subdomains and IPs and printed to the Burp Suite output tab. The VHost brute force thread loops through each VHost in the wordlist and attempts to connect to the VHost and send a GET request. If a response code of 200 is received, the VHost is added to a list of found VHosts and printed to the Burp Suite output tab.
