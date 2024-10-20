#
# LLM Network Scanner
# Copyright (C) 2024 Damian Strojek
#

# Imports
import openai
import subprocess
import datetime
import textwrap
from openai import OpenAI
from fpdf import FPDF

# Constants
DEBUG = 0
TEMPERATURE = 0
MODEL = "gpt-4o-mini"
IMAGE_MODEL = "dall-e-3"
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
    def __init__(self, ipAddress, openPorts=None, recommendations=None):
        self.ipAddress = ipAddress
        self.openPorts = openPorts if openPorts else []
        self.recommendations = recommendations if recommendations else []

    def add_port(self, port, service=None):
        if port not in self.openPorts:
            self.openPorts.append(port)
            if service:
                self.services[port] = service

    def add_recommendation(self, recommendation):
        self.recommendations = recommendation

    def remove_port(self, port):
        if port in self.openPorts:
            self.openPorts.remove(port)
            if port in self.services:
                del self.services[port]

    def list_ports(self):
        return self.openPorts

    def list_recommendations(self):
        return self.recommendations

    def debug(self):
        print(f"Host IP: {self.ipAddress}\nOpen Ports: {self.openPorts}\rRecommendations: {self.recommendations}")
        return

    def __str__(self):
        hostInfo = f"Host IP: {self.ipAddress}\nOpen Ports: {self.openPorts}\rRecommendations: {self.recommendations}"
        return hostInfo

# Create a class inheriting from FPDF for custom functions
class PDFReport(FPDF):
    def header(self):
        self.set_font('Arial', 'B', 16)
        self.cell(0, 10, 'Vulnerability Scan Report', ln=True, align='C')

    def footer(self):
        self.set_y(-15)
        self.set_font('Arial', 'I', 8)
        self.cell(0, 10, f'Page {self.page_no()}', 0, 0, 'C')

    def add_report_title(self):
        self.set_font('Arial', 'B', 12)
        self.cell(0, 10, f'Report generated: {datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")}', ln=True)
        self.ln(10)  # Line break

    def add_host_report(self, hostData):
        # Host details
        self.set_font('Arial', 'B', 12)
        self.cell(0, 10, f'Host: {hostData["host"]} ({hostData["status"]})', ln=True)

        # Open ports
        self.set_font('Arial', 'B', 10)
        self.cell(0, 10, 'Open Ports:', ln=True)
        self.set_font('Arial', '', 10)
        self.cell(0, 10, ', '.join(map(str, hostData['openPorts'])), ln=True)

        # Recommendations
        if hostData['recommendations']:
            self.set_font('Arial', 'B', 10)
            self.cell(0, 10, 'Recommendations:', ln=True)
            self.set_font('Arial', '', 10)
            
            # Split recommendations string by line breaks
            recommendations = hostData['recommendations'].split('\n\n')
            
            for rec in recommendations:
                # Wrap the recommendation text to fit into the PDF page
                wrappedRecommendation = wrap_text(rec)
                self.multi_cell(0, 10, wrappedRecommendation)
        else:
            self.cell(0, 10, 'No recommendations available.', ln=True)

        self.ln(10)  # Add space before next host

# Prompt the user for their OpenAI API key (security measures)
# and Set the OpenAI API key
def set_openai_api_key():
    apiKey = input(YEL + "\n[?] " + BLU + "Please enter your OpenAI API key: " + NC)
    openai.api_key = apiKey
    client = OpenAI(api_key=apiKey)
    return client

# Set hosts that will be scanned
def set_hosts():
    userInput = input(YEL + "\n[?] " + BLU + "Please enter host or hosts (text file) to be scanned: " + NC)

    if userInput == "":
        userInput = "hosts.txt"

    if userInput.endswith(".txt"):
        try:
            # First attempt: Check the current directory
            with open(userInput, 'r') as file:
                hosts = file.read()
                return hosts
        except FileNotFoundError:
            try:
                # Second attempt: Check the ./files/ directory
                with open('./files/' + userInput, 'r') as file:
                    hosts = file.read()
                    return hosts
            except FileNotFoundError:
                # If the file isn't found in either directory, raise an exception
                print(YEL + "[!] " + RED + "File doesn't exist in current directory or './files/'." + NC)
                exit()

    print(YEL + "[!] " + RED + "Source file must be a text (.txt) file." + NC)
    exit()

# Send request to OpenAI API and return response
# Use pre-defined systemPrompt and context
def send_openai_request(client, userQuery, debug):
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
    
    if(DEBUG): print(YEL + "[DEBUG] " + RED + chatCompletion + NC)
    
    return chatCompletion

# Send custom request to OpeniAI API and retun response
def send_custom_openai_request(client, systemPrompt, context, userQuery, debug):
    messages = [{"role": "system", "content": systemPrompt},
                {"role": "user", "content": userQuery},
                {"role": "assistant", "content": context}]
    chatCompletion = client.chat.completions.create(messages = messages, model = MODEL, temperature = TEMPERATURE)
    chatCompletion = chatCompletion.choices[0].message.content.strip()
    debug.write(chatCompletion + "\n")
    
    return chatCompletion

# Send request to image generation model
def send_dalle_request(client, userQuery, debug):
    response = client.images.generate(model=IMAGE_MODEL, prompt=userQuery, 
        size="1024x1024", quality="standard", n=1)
    imageUrl = response.data[0].url
    
    print(YEL + "[*] " + MAG + "Your image is located at: " + imageUrl + NC)
    debug.write("Image URL: " + imageUrl + "\n")
    
    return

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
    response = send_custom_openai_request(client, systemPrompt, context, userQuery, debug)
    
    print("\n" + CYN + response + NC + "\n")
    return

# Run shell command in the background and return stdout-formatted output
def run_command(response):
    outputText = subprocess.run(response, shell=True, capture_output=True, text=True)
    output = outputText.stdout
    return output

# Create the PDF report
def generate_pdf_report(scanResults, outputFilename='./files/Penetration-Testing-Report.pdf'):
    pdf = PDFReport()
    pdf.add_page()
    pdf.add_report_title()

    for host in scanResults:
        if host != scanResults[0]:
            pdf.add_page()
        pdf.add_host_report(host)
    
    pdf.output(outputFilename)
    print(YEL + "\n[*] " + MAG + "Report saved as " + outputFilename + "." + NC)
    return

# Helper function to wrap long recommendation text
def wrap_text(text, width=100):
    return '\n'.join(textwrap.wrap(text, width))

# Main function
def main():
    debug = open('./files/openai-log.txt', 'a')

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
    
    response = send_openai_request(client, userQuery, debug)
    onlineHosts = run_command(response)

    if(onlineHosts == ""):
        print(YEL + "\n[!] " + RED + "All hosts are down." + NC)
        exit()
    else:
        print(YEL + "\n[*] " + MAG + "Following hosts are up: " + ORN + onlineHosts.strip().replace('\n', ', ') + NC)

    ipAddresses = onlineHosts.splitlines()

    # Create records for each online host
    for ip in ipAddresses:
        newHost = NetworkHost(ipAddress = ip)
        activeHosts.append(newHost)

    # Each host have their own set of unique challenges and thus they are scanned independently
    for currentHost in activeHosts:
        
        print(GRN + "\n###")
        print(YEL + "[*] " + MAG + "Scanning host " + ORN + currentHost.ipAddress)
        print(GRN + "###" + NC)

        # --------------------------
        # 2. Gather information about open ports on online hosts
        # --------------------------

        userQuery = f"""
        Scan 50 top ports (use --top-ports and don't use -oG) of host {currentHost.ipAddress}.
        Output only numbers of ports that are either open or filtered on this specific host.
        Use sed tool to filter out the port numbers."""

        response = send_openai_request(client, userQuery, debug)
        openPorts = run_command(response)
        openPorts = openPorts.splitlines()

        if(openPorts == ""):
            print(YEL + "\n[!] " + RED + "No open ports." + NC)
            exit()
        else:
            for port in openPorts: currentHost.add_port(port=port)

        # --------------------------
        # 3. Aggresively scan open ports in search of vulnerabilities
        # --------------------------

        userQuery = f"""
        Take following ports that are open on host {currentHost.ipAddress} and scan them aggressively 
        gathering as much information as possible: {openPorts}
        Save this information locally into ./files/nmap-aggresive-{currentHost.ipAddress}.txt"""

        response = send_openai_request(client, userQuery, debug)
        aggresiveScan = run_command(response)

        print(YEL + "\n[*]" + MAG + " Aggresive scan overview:\n" + NC)
        print(ITA + aggresiveScan + NC)

        # --------------------------
        # 4. Prepare tools for next step of discovery
        # --------------------------

        userQuery = f"""
        Take information, that will be added at the end of this query.
        Prepare one-liner that will scan each open port of {currentHost.ipAddress} with the tools that 
        are designed for this specific port and service. Do not use nmap in this step.
        Use only tools that does not need any interaction from the user.
        In this one-liner everything should be done one after another.
        Information from nmap: {aggresiveScan}"""
        
        response = send_openai_request(client, userQuery, debug)
        #scanServices = run_command(response)

        print(YEL + "\n[*] " + MAG + "Specific commands that can be used to test host " + ORN + currentHost.ipAddress + MAG + ": " + NC)
        print(ITA + response + NC)
        
        # --------------------------
        # 5. Visualize findings with the use of DALL-E-3 (optional)
        # --------------------------
        
        if(input(YEL + "\n[?] " + BLU + "Do you want to generate image (yes/no)? " + NC) == "yes"):
            userQuery = f"""
            Take information, that will be added at the end of this query.
            Generate image that will visualize this information for executives in terms of risks.
            I want it to be a nice graph that I can show to the non-technical stuff.
            Information from nmap: {openPorts}"""
                    
            send_dalle_request(client, userQuery, debug)
            
        # --------------------------
        # 6. Recommendations for system administrator
        # --------------------------
        
        systemPrompt = """
        You are a penetration tester for one of the biggest companies in the world."""
        
        context = """
        You are tasked with creating a set of recommendations for a company that you are currently pentesting.
        You should write recommendations basing on informations that are provided in user query.
        You should be strict and write only the recommendations.
        Before a single recommendation, write the network port number that this recommendation applies to.
        Use text format without any formatting."""
        
        userQuery = f"""
        Take information, that will be added at the end of this query.
        Prepare cyber security recommendations based on this information.
        Information from nmap: {aggresiveScan}"""
        
        recommendations = send_custom_openai_request(client, systemPrompt, context, userQuery, debug)
        currentHost.add_recommendation(recommendations)
        
        print(YEL + "\n[*] " + MAG + "Recommendations:\n")
        print(GRN + recommendations + NC)
        
        # --------------------------
        # 7. Narrative Summary with GPT-4 (???)
        # --------------------------
        
        # ...
        
        
    # --------------------------
    # 8. PDF Report with All Hosts
    # --------------------------
    scanData = []

    for currentHost in activeHosts:
        
        hostReport = {
            "host": currentHost.ipAddress,
            "status": "online",
            "openPorts": currentHost.openPorts,
            "recommendations": currentHost.recommendations
        }
        
        scanData.append(hostReport)

    generate_pdf_report(scanData)
        
    debug.close()
    exit()

if __name__ == "__main__":
    main()
