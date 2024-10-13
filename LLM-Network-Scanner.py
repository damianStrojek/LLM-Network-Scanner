#
# LLM Network Scanner
# Copyright (C) 2024 Damian Strojek
#

# Imports
import openai
import subprocess
from openai import OpenAI

# Constants
TEMPERATURE = 0
MODEL = "gpt-4o-mini"
RED='\033[1;31m'
GRN='\033[1;32m'
YEL='\033[1;33m'
BLU='\033[1;34m'
MAG='\033[1;35m'
ORN='\033[38;5;208m'
CYN='\033[1;36m'
ITA='\033[3m'
NC='\033[0m'

# General class for a single host in the network
class NetworkHost:
    def __init__(self, ipAddress, openPorts=None, services=None):
        self.ipAddress = ipAddress
        self.openPorts = openPorts if openPorts else []
        self.services = services if services else []

    def add_port(self, port, service=None):
        if port not in self.openPorts:
            self.openPorts.append(port)
            if service:
                self.services[port] = service

    def remove_port(self, port):
        if port in self.openPorts:
            self.openPorts.remove(port)
            if port in self.services:
                del self.services[port]

    def list_ports(self):
        return self.openPorts

    def list_services(self):
        return self.services

    def debug(self):
        print(f"Host IP: {self.ipAddress}\nOpen Ports: {self.openPorts}\nServices: {self.services}")
        return

    def __str__(self):
        hostInfo = f"Host IP: {self.ipAddress}\nOpen Ports: {self.openPorts}\nServices: {self.services}"
        return hostInfo

# Prompt the user for their OpenAI API key (security measures)
# and Set the OpenAI API key
def set_openai_api_key():
    apiKey = input(YEL + "[?] " + BLU + "Please enter your OpenAI API key: " + NC)
    openai.api_key = apiKey
    client = OpenAI(api_key=apiKey)
    return client

# Set hosts that will be scanned
def set_hosts():
    userInput = input(YEL + "[?] " + BLU + "Please enter host or hosts (text file) to be scanned: " + NC)

    if userInput.endswith(".txt"):
        try:
            with open(userInput, 'r') as file:
                hosts = file.read()
            return hosts
        except FileNotFoundError:
            print(f"[!] File {userInput} doesn't exist.")
            exit()

    host = userInput.strip()
    print(f"Given host: {host}")
    return host

# Send request to OpenAI API and return response
# Use pre-defined systemPrompt and context
def send_request(client, userQuery, debug):
    systemPrompt = """
        You are a penetration tester for one of the biggest companies in the world."""
    context = """
        You are tasked with coming up with technical answers to given questions.
        The idea for following prompts is to prepare and execute an infrastracture penetration test on given IP address.
        When said, create only commands that can be copy-pasted into /bin/bash console on Kali Linux 2024 system.
        You are allowed to use only public tools that will not create a Denial-of-Service attack.
        When not said how to print out the results, print only the console command.
        Do not add back ticks.
        Do not add any python or bash comments when answering.
        Use sudo when you have to."""
    
    messages = [{"role": "system", "content": systemPrompt},
                {"role": "user", "content": userQuery},
                {"role": "assistant", "content": context}]
    chatCompletion = client.chat.completions.create(messages = messages, model = MODEL, temperature = TEMPERATURE)
    chatCompletion = chatCompletion.choices[0].message.content.strip()
    debug.write(chatCompletion + "\n")
    
    print(YEL + "[DEBUG] " + RED + chatCompletion + NC)
    
    return chatCompletion

# Send custom request to OpeniAI API and retun response
def send_custom_request(client, systemPrompt, context, userQuery, debug):
    messages = [{"role": "system", "content": systemPrompt},
                {"role": "user", "content": userQuery},
                {"role": "assistant", "content": context}]
    chatCompletion = client.chat.completions.create(messages = messages, model = MODEL, temperature = TEMPERATURE)
    chatCompletion = chatCompletion.choices[0].message.content.strip()
    debug.write(chatCompletion + "\n")
    return chatCompletion

# Print out welcoming banner
def create_banner(client, debug):
    systemPrompt = "Your task is to return a banner that will be shown as the first thing after running the application."
    context = """
    You should only return the text that can be instantly printed out. Not functions or anything else.
    Do not add back ticks.
    Do not add any python or bash comments when answering.
    First thing shown should be a picture created in fancy ASCII text format representing whatever you want."""
    userQuery = "Return me a banner for application called 'LLMNS'. Also, include current date, time, and geo-localization."
    
    debug.write("\n" + "#" * 50 + "\n")
    response = send_custom_request(client, systemPrompt, context, userQuery, debug)
    
    print("\n" + CYN + response + NC + "\n")
    return

# Run shell command in the background and return stdout-formatted output
def run_command(response):
    outputText = subprocess.run(response, shell=True, capture_output=True, text=True)
    output = outputText.stdout
    return output

# Main function
def main():
    debug = open('openai-log.txt', 'a')

    # Set the OpenAI API key, hosts, and print welcoming banner
    client = set_openai_api_key()
    create_banner(client, debug)
    hosts = set_hosts()
    activeHosts = []

    # --------------------------
    # 1. Test out status of defined addresses
    # --------------------------
    
    userQuery = f"""
    Print out a command to test if all of the following hosts are up or not: {hosts}
    You should use ping.
    The command should print out all of the hosts that are up, one per line.
    If some hosts are up and some hosts are down, print out only ip addresses of the active hosts.
    If all of hosts are down, output an empty string."""
    
    response = send_request(client, userQuery, debug)
    onlineHosts = run_command(response)

    if(onlineHosts == ""):
        print(YEL + "[!] " + RED + "All hosts are down" + NC)
        exit()
    else:
        print(YEL + "[*] " + MAG + "Following hosts are up: " + ORN + onlineHosts.strip().replace('\n', ', ') + NC)

    ipAddresses = onlineHosts.splitlines()

    # Create records for each online host
    for ip in ipAddresses:
        newHost = NetworkHost(ipAddress = ip)
        activeHosts.append(newHost)

    # Each host have their own set of unique challenges and thus they are scanned independently
    for currentHost in activeHosts:
        
        print(GRN + "\n###")
        print(YEL + "[*] " + MAG + "Scanning host " + ORN + currentHost.ipAddress)
        print(GRN + "###\n" + NC)

        # --------------------------
        # 2. Gather information about open ports on online hosts
        # --------------------------

        userQuery = f"""
        Scan 50 top ports (use --top-ports and don't use -oG) of host {currentHost.ipAddress}.
        Output only numbers of ports that are either open or filtered on this specific host.
        Use sed tool to filter out the port numbers."""

        response = send_request(client, userQuery, debug)

        openPorts = run_command(response)
        openPorts = openPorts.splitlines()

        if(openPorts == ""):
            print(YEL + "[!] " + RED + "No open ports." + NC)
            exit()
        else:
            for port in openPorts: currentHost.add_port(port=port)

        # --------------------------
        # 3. Aggresively scan open ports in search of vulnerabilities
        # --------------------------

        userQuery = f"""
        Take following ports that are open on host {currentHost.ipAddress} and scan them aggressively 
        gathering as much information as possible: {openPorts}
        Save this information locally into nmap-aggresive-{currentHost.ipAddress}.txt"""

        response = send_request(client, userQuery, debug)
        aggresiveScan = run_command(response)

        print(YEL + "\n[*]" + MAG + " Aggresive scan overview: " + NC)
        print(ITA + aggresiveScan + NC)

        # --------------------------
        # 4. Prepare tools for next step of discovery
        # --------------------------

        userQuery = f"""
        Take information, that will be added at the end of this query.
        Prepare one-liner that will scan each open port of {currentHost.ipAddress} with the tools that 
        are designed for this specific port and service. Do not use nmap in this step.
        Use only tools that does not need any interaction from the user.
        Information from nmap: {aggresiveScan}"""
        
        response = send_request(client, userQuery, debug)

        #scanServices = run_command(response)

        print(YEL + "[*] " + MAG + "Specific tools: " + NC)
        #print(scanServices)
        
        # --------------------------
        # 5. TBD: Visualize findings with the use of DALL-E-3
        # --------------------------
        
        

    debug.close()
    exit()

if __name__ == "__main__":
    main()
