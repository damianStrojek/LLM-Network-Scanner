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
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
ITALIC='\033[3m'
BOLD='\033[1m'
NC='\033[0m'

# Prompt the user for their OpenAI API key (security measures)
def get_api_key():
    apiKey = input(BLUE + BOLD + "Please enter your OpenAI API key: " + NC)
    return apiKey

# Set the OpenAI API key
def set_openai_api_key(apiKey):
    openai.api_key = apiKey
    client = OpenAI(api_key=apiKey)
    return client

# Set hosts that will be scanned
def set_hosts():
    user_input = input(BLUE + BOLD + "Please enter host or hosts (text file) to be scanned: " + NC)

    if user_input.endswith(".txt"):
        try:
            with open(user_input, 'r') as file:
                hosts = file.read()
            print(f"Hosts from the file:\n{hosts}")
            return hosts
        except FileNotFoundError:
            print(f"File {user_input} doesn't exist.")

    host = user_input.strip()
    print(f"Given host: {host}")
    return host

# Print out welcoming banner
def create_banner(client):
    systemPrompt = "Your task is to return a banner that will be shown as the first thing after running the application."
    context = """
    You should only return the text that can be instantly printed out. Not functions or anything else.
    Do not add back ticks.
    Do not add any python or bash comments when answering.
    First thing shown should be a picture created in fancy ASCII text format representing whatever you want.
    """
    userQuery = 'Return me a banner for application called "LLMNS". Also, include current date, time, and geo-localization.'
    
    messages = [{"role": "system", "content": systemPrompt}, {"role": "user", "content": userQuery},{"role": "assistant", "content": context}]
    chatCompletion = client.chat.completions.create(messages = messages, model = MODEL, temperature = TEMPERATURE)
    chatCompletion = chatCompletion.choices[0].message.content.strip()
    

    print("\n" + GREEN + BOLD + chatCompletion + NC + "\n")

    return

# Prepare context for future queries
def prepare_context(hosts):
    systemPrompt = "You are a penetration tester for one of the biggest companies in the world."

    context = """
        You are tasked with coming up with technical answers to given questions.
        When said, create only commands that can be copy-pasted into /bin/bash console on Kali Linux 2024 system.
        The idea for following prompts is to prepare and execute an infrastracture penetration test on given IP address.
        You are allowed to use only public tools that will not create a Denial-of-Service attack.
        When not said how to print out the results, print only the console command. Do not add back ticks.
        Do not add any python or bash comments when answering.
        Use sudo when you have to (for example, nmap -sS).
        Current hosts to scan: 
    """

    context += hosts

    return systemPrompt, context

# Main function
def main():
    # Gather, set the OpenAI API key, hosts, and print welcoming banner
    apiKey = get_api_key()
    client = set_openai_api_key(apiKey)
    create_banner(client)
    hosts = set_hosts()

    # Set up online hosts and prepare context for later queries
    systemPrompt, context = prepare_context(hosts)

    ### Test out status of hosts
    userQuery = """
    Print out a command to test if all of the defined hosts are up or not. You should use ping.
    The command should print out all of the hosts that are up, one per line. If all of them are down, print out 'False'."
    """

    messages = [{"role": "system", "content": systemPrompt}, {"role": "user", "content": userQuery},{"role": "assistant", "content": context}]
    chatCompletion = client.chat.completions.create(messages = messages, model = MODEL, temperature = TEMPERATURE)
    chatCompletion = chatCompletion.choices[0].message.content.strip()

    # Command
    print(RED + BOLD + chatCompletion + NC)

    # Execute the command and capture the output
    outputText = subprocess.run(chatCompletion, shell=True, capture_output=True, text=True)
    onlineHosts = outputText.stdout

    if(onlineHosts == 'False'):
        print(RED + BOLD + "All hosts are down" + NC)
        exit()
    else:
        systemPrompt, context = prepare_context(onlineHosts)

    ### Query for gathering information about open ports

    userQuery = """
    Scan all ports of defined hosts. Output only numbers of ports that are open on these hosts.
    Remove the /tcp or /udp from the end of port output.
    """

    messages = [{"role": "system", "content": systemPrompt}, {"role": "user", "content": userQuery},{"role": "assistant", "content": context}]
    chatCompletion = client.chat.completions.create(messages = messages, model = MODEL, temperature = TEMPERATURE)
    chatCompletion = chatCompletion.choices[0].message.content.strip()

    # Command
    print(RED + BOLD + chatCompletion + NC)

    # Execute the command and capture the output
    outputText = subprocess.run(chatCompletion, shell=True, capture_output=True, text=True)
    openPorts = outputText.stdout

    # Output
    print(RED + BOLD + "Open Ports: " + NC)
    print(openPorts)

    ### Query for aggressive scan of open ports

    userQuery = """
    Take open ports, that will be added at the end of this query, and scan them aggressively gathering as much information as possible. 
    Save this information into nmap-tcp-ports.txt
    Ports: 
    """
    userQuery += openPorts

    messages = [{"role": "system", "content": systemPrompt}, {"role": "user", "content": userQuery},{"role": "assistant", "content": context}]
    chatCompletion = client.chat.completions.create(messages = messages, model = MODEL, temperature = TEMPERATURE)
    chatCompletion = chatCompletion.choices[0].message.content.strip()

    # Command
    print(RED + BOLD + chatCompletion + NC)

    # Execute the command and capture the output
    outputText = subprocess.run(chatCompletion, shell=True, capture_output=True, text=True)
    detailedPorts = outputText.stdout

    # Output
    print(RED + BOLD + "\nAggresive Scan: " + NC)
    print(detailedPorts)

    ### Prepare tools for next step of discovery

    userQuery = """
    Take information, that will be added at the end of this query, and prepare one-liner that will scan each port with the tools that are designed 
    for this specific port and service. Do not use nmap in this step.
    Information from nmap:
    """
    userQuery += detailedPorts

    messages = [{"role": "system", "content": systemPrompt}, {"role": "user", "content": userQuery},{"role": "assistant", "content": context}]
    chatCompletion = client.chat.completions.create(messages = messages, model = MODEL, temperature = TEMPERATURE)
    chatCompletion = chatCompletion.choices[0].message.content.strip()

    # Command
    print(RED + BOLD + chatCompletion + NC)

    # Execute the command and capture the output
    outputText = subprocess.run(chatCompletion, shell=True, capture_output=True, text=True)
    scanServices = outputText.stdout

    # Output
    print(RED + BOLD + "Specific Tools: " + NC)
    print(scanServices)


if __name__ == "__main__":
    main()
