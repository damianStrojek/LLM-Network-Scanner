#
# LLM Netowrk Scanner
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
GREEN='\033[1;32m'
YELLOW='\033[1;33m'
BLUE='\033[1;34m'
MAGENTA='\033[1;35m'
ITALIC='\033[3m'
NC='\033[0m'

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
def get_api_key():
    apiKey = input(YELLOW + "[?] " + BLUE + "Please enter your OpenAI API key: " + NC)
    return apiKey

# Set the OpenAI API key
def set_openai_api_key(apiKey):
    openai.api_key = apiKey
    client = OpenAI(api_key=apiKey)
    return client

# Set hosts that will be scanned
def set_hosts():
    user_input = input(YELLOW + "[?] " + BLUE + "Please enter host or hosts (text file) to be scanned: " + NC)

    if user_input.endswith(".txt"):
        try:
            with open(user_input, 'r') as file:
                hosts = file.read()
            return hosts
        except FileNotFoundError:
            print(f"[!] File {user_input} doesn't exist.")
            exit()

    host = user_input.strip()
    print(f"Given host: {host}")
    return host

# Print out welcoming banner
def create_banner(client, debug):
    systemPrompt = "Your task is to return a banner that will be shown as the first thing after running the application."
    context = """
    You should only return the text that can be instantly printed out. Not functions or anything else.
    Do not add back ticks.
    Do not add any python or bash comments when answering.
    First thing shown should be a picture created in fancy ASCII text format representing whatever you want.
    """
    userQuery = 'Return me a banner for application called "LLMNS". Also, include current date, time, and geo-localization.'
    
    debug.write("\n" + "#" * 50 + "\n")
    messages = [{"role": "system", "content": systemPrompt}, {"role": "user", "content": userQuery},{"role": "assistant", "content": context}]
    chatCompletion = client.chat.completions.create(messages = messages, model = MODEL, temperature = TEMPERATURE)
    chatCompletion = chatCompletion.choices[0].message.content.strip()
    debug.write(chatCompletion + "\n")
    
    print("\n" + GREEN + chatCompletion + NC + "\n")

    return

# Prepare context for future queries
def prepare_context():
    systemPrompt = """
    You are a penetration tester for one of the biggest companies in the world.
    The idea for following prompts is to prepare and execute an infrastracture penetration test on given IP address.
    """

    context = """
        You are tasked with coming up with technical answers to given questions.
        When said, create only commands that can be copy-pasted into /bin/bash console on Kali Linux 2024 system.
        You are allowed to use only public tools that will not create a Denial-of-Service attack.
        When not said how to print out the results, print only the console command.
        Do not add back ticks.
        Do not add any python or bash comments when answering.
        Use sudo when you have to.
    """

    return systemPrompt, context

# Main function
def main():
    debug = open('openai-debug.txt', 'a')

    # Set the OpenAI API key, hosts, and print welcoming banner
    apiKey = get_api_key()
    client = set_openai_api_key(apiKey)
    create_banner(client, debug)
    hosts = set_hosts()
    activeHosts = []
    
    # Set up online hosts and prepare context for later queries
    systemPrompt, context = prepare_context()

    ### Test out status of hosts
    userQuery = f"""
    Print out a command to test if all of the following hosts are up or not: {hosts}
    You should use ping.
    The command should print out all of the hosts that are up, one per line.
    If some hosts are up and some hosts are down, print out only ip addresses of the active hosts.
    If all of hosts are down, output an empty string.
    """

    messages = [{"role": "system", "content": systemPrompt}, {"role": "user", "content": userQuery},{"role": "assistant", "content": context}]
    chatCompletion = client.chat.completions.create(messages = messages, model = MODEL, temperature = TEMPERATURE)
    chatCompletion = chatCompletion.choices[0].message.content.strip()
    debug.write(chatCompletion + "\n")

    # Execute the command and capture the output
    outputText = subprocess.run(chatCompletion, shell=True, capture_output=True, text=True)
    onlineHosts = outputText.stdout

    if(onlineHosts == ""):
        print(YELLOW + "[!] " + RED + "All hosts are down" + NC)
        exit()
    else:
        print(YELLOW + "[*] " + MAGENTA + "Following hosts are up: " + onlineHosts.strip().replace('\n', ', ') + NC)

    ipAddresses = onlineHosts.splitlines()
    ipAddresses = [ip for ip in ipAddresses if ip]

    for ip in ipAddresses:
        newHost = NetworkHost(ipAddress = ip)
        activeHosts.append(newHost)

    for currentHost in activeHosts:
        
        print(GREEN + "\n###")
        print(YELLOW + "[*] " + MAGENTA + "Scanning host " + currentHost.ipAddress)
        print(GREEN + "###\n" + NC)

        ### Query for gathering information about open ports

        userQuery = f"""
        Scan 50 top ports (most common, --top-ports) of host {currentHost.ipAddress}.
        Output only numbers of ports that are 'open' or 'filtered' on this specific host.
        Remove the /tcp or /udp from the end of port output.
        """

        messages = [{"role": "system", "content": systemPrompt}, {"role": "user", "content": userQuery},{"role": "assistant", "content": context}]
        chatCompletion = client.chat.completions.create(messages = messages, model = MODEL, temperature = TEMPERATURE)
        chatCompletion = chatCompletion.choices[0].message.content.strip()
        debug.write(chatCompletion + "\n")

        print(YELLOW + "[DEBUG1] " + RED + chatCompletion + NC)

        outputText = subprocess.run(chatCompletion, shell=True, capture_output=True, text=True)
        openPorts = outputText.stdout

        hostPorts = openPorts.splitlines()
        hostPorts = [port for port in hostPorts if port]

        # Prepare individual hosts
        for port in hostPorts:
            currentHost.add_port(port=port)

        if(openPorts == ""):
            print(YELLOW + "[!] " + RED + "No open ports." + NC)
            exit()

        ### Query for aggressive scan of open ports

        userQuery = f"""
        Take following ports that are open on host {currentHost.ipAddress} and scan them aggressively gathering as much information as possible:
        {openPorts}
        Save this information locally into nmap-tcp-ports-{currentHost.ipAddress}.txt
        """

        messages = [{"role": "system", "content": systemPrompt}, {"role": "user", "content": userQuery},{"role": "assistant", "content": context}]
        chatCompletion = client.chat.completions.create(messages = messages, model = MODEL, temperature = TEMPERATURE)
        chatCompletion = chatCompletion.choices[0].message.content.strip()
        debug.write(chatCompletion + "\n")

        print(YELLOW + "[DEBUG2] " + RED + chatCompletion + NC)

        # Execute the command and capture the output
        outputText = subprocess.run(chatCompletion, shell=True, capture_output=True, text=True)
        detailedPorts = outputText.stdout

        # Output
        print(YELLOW + "\n[*]" + MAGENTA + " Aggresive Scan: " + NC)
        print(detailedPorts)

        ### Prepare tools for next step of discovery

        userQuery = f"""
        Take information, that will be added at the end of this query.
        Prepare one-liner that will scan each open port of {currentHost.ipAddress} with the tools that are designed for this specific port and service.
        Do not use nmap in this step.
        Information from nmap:
        {detailedPorts}
        """

        messages = [{"role": "system", "content": systemPrompt}, {"role": "user", "content": userQuery},{"role": "assistant", "content": context}]
        chatCompletion = client.chat.completions.create(messages = messages, model = MODEL, temperature = TEMPERATURE)
        chatCompletion = chatCompletion.choices[0].message.content.strip()
        debug.write(chatCompletion + "\n")

        print(YELLOW + "[DEBUG3] " + RED + chatCompletion + NC)

        # Execute the command and capture the output
        #outputText = subprocess.run(chatCompletion, shell=True, capture_output=True, text=True)
        #scanServices = outputText.stdout
        scanServices = "...TBD"

        #!!! Output
        print(YELLOW + "[*] " + MAGENTA + "Specific Tools: " + NC)
        print(scanServices)

    debug.close()
    exit()

if __name__ == "__main__":
    main()
