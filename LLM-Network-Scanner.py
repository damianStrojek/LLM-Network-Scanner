#
# LLM Network Scanner
# Copyright (C) 2024 Damian Strojek, Hubert Piotroski, Marcin Szachowski 
#

# Imports
import openai
import subprocess
import datetime
import textwrap
from openai import OpenAI
from fpdf import FPDF

# Constants
DEBUG = True
TEMPERATURE = 0
MODEL = "gpt-4o"
IMAGE_MODEL = "dall-e-3"

# Color constants
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
        return

    def add_port(self, port, service=None):
        if port not in self.openPorts:
            self.openPorts.append(port)
            if service:
                self.services[port] = service
        return

    def add_recommendation(self, recommendation):
        self.recommendations = recommendation
        return

    def remove_port(self, port):
        if port in self.openPorts:
            self.openPorts.remove(port)
            if port in self.services:
                del self.services[port]
        return

    def print_open_ports(self):
        print(YEL + "\n[*] " + MAG + "Discovered open ports: " + ORN + ",".join(str(port) for port in self.openPorts))
        return

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
        Generate technical answers for the provided questions.
        Focus on preparing and executing an infrastructure penetration test for a specified IP address.
        Provide commands that can be directly executed in the /bin/bash console on a Kali Linux 2024 system.
        Only include the prepared commands in your response unless additional instructions are given.
        Use only public tools that do not cause Denial-of-Service attacks.
        Include sudo where necessary.
        Do not add Python or Bash comments, and avoid using backticks."""
    
    messages = [{"role": "system", "content": systemPrompt},
                {"role": "user", "content": userQuery},
                {"role": "assistant", "content": context}]

    chatCompletion = client.chat.completions.create(messages = messages, model = MODEL, temperature = TEMPERATURE)
    chatCompletion = chatCompletion.choices[0].message.content.strip()
    debug.write(chatCompletion + "\n")
    
    if(DEBUG): print(YEL + "\n[DEBUG] " + RED + chatCompletion + NC)
    
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
        Return only the text that can be immediately printed.
        Do not include functions or any additional code elements.
        Avoid using backticks.
        Do not add any comments.
        Start with an ASCII art image representing your choice of design."""
    userQuery = """
        Return me a banner for application called LLMNS (Large Language Models Network Scanner).
        Also, include current date, time, and geo-localization."""
    
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
        Create a command to check the status of the following hosts: {hosts}.
        Use ping to determine if each host is up.
        The output should list only the IP addresses that are up, one per line.
        If no hosts are up, the output should be empty.
        Do not include any additional text or information beyond the IP addresses of active hosts."""

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
            Scan 100 top ports (use --top-ports and don't use -oG) of host {currentHost.ipAddress}.
            Output only numbers of ports that are either open or filtered on this specific host.
            Use sed tool to filter out the port numbers."""

        response = send_openai_request(client, userQuery, debug)
        openPorts = run_command(response)
        openPorts = openPorts.splitlines()

        if(openPorts == ""):
            print(YEL + "\n[!] " + RED + "No open ports for this host." + NC)
            continue
        else:
            for port in openPorts: currentHost.add_port(port=port)

        currentHost.print_open_ports()

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
            Use the information provided to craft a one-liner that scans each open port on {currentHost.ipAddress}.
            Utilize tools specifically designed for the services on those ports.
            Do not use nmap.
            Ensure all actions are executed sequentially within the one-liner.
            Incorporate details from the {aggresiveScan} results."""
        
        response = send_openai_request(client, userQuery, debug)
        #scanServices = run_command(response)

        print(YEL + "\n[*] " + MAG + "Specific commands that can be used to test host " + ORN + currentHost.ipAddress + MAG + ": " + NC)
        print(ITA + response + NC)
        
        # --------------------------
        # 5. Visualize findings with the use of DALL-E-3 (optional)
        # --------------------------
        
        if(input(YEL + "\n[?] " + BLU + "Do you want to generate image (yes/no)? " + NC) == "yes"):
            userQuery = f"""
                Create an image that visualizes the risks associated with the information provided.
                Use a clear and visually appealing graph suitable for presentation to non-technical executives.
                Base the visualization on the data from the nmap scan: {openPorts}"""
                    
            send_dalle_request(client, userQuery, debug)
            
        # --------------------------
        # 6. Recommendations for system administrator
        # --------------------------
        
        systemPrompt = """
            You are a penetration tester for one of the biggest companies in the world."""
        
        context = """
            Your task is to create a set of recommendations for the company you are currently pentesting.
            Base your recommendations strictly on the information provided in the user's query.
            Each recommendation should be preceded by the applicable network port number.
            Use plain text without any additional formatting."""
        
        userQuery = f"""
            Take information that will be added at the end of this query.
            Prepare cybersecurity recommendations based on this information.
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
        
    print(YEL + "\n[*] " + MAG + "The application is terminating .\n")

    debug.close()
    exit()

if __name__ == "__main__":
    main()
