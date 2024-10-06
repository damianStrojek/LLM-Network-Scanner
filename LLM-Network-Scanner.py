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

# Function to prompt the user for their OpenAI API key (security measures)
def get_api_key():
    apiKey = input(BLUE + BOLD + "Please enter your OpenAI API key: " + NC)
    return apiKey

# Function to set the OpenAI API key
def set_openai_api_key(apiKey):
    openai.api_key = apiKey
    client = OpenAI(api_key=apiKey)
    return client

def set_host():
    host = input(BLUE + BOLD + "Please enter host to be scanned: " + NC)
    return host

def prepare_context(host):
    systemPrompt = "You are a penetration tester for one of the biggest companies in the world."

    context = """
        You are tasked with coming up with technical answers to given questions.
        When said, create only commands that can be copy-pasted into /bin/bash console on Kali Linux 2024 system.
        The idea for following prompts is to prepare and execute an infrastracture penetration test on given IP address.
        You are allowed to use only public tools that will not create a Denial-of-Service attack.
        When not said how to print out the results, print only the console command. Do not add back ticks.
        Do not add any python or bash comments when answering.
        Use sudo when you have to (for example, nmap -sS).
        Current host to scan: 
    """

    context += host

    return systemPrompt, context

def main():
    # Get and set the API key
    apiKey = get_api_key()
    client = set_openai_api_key(apiKey)
    host = set_host()

    systemPrompt, context = prepare_context(host)

    userQuery = """
    Scan all ports of defined hosts. Output only numbers of ports that are open on these hosts.
    Remove the /tcp or /udp from the end of port output.
    """

    messages = [{"role": "system", "content": systemPrompt}, {"role": "user", "content": userQuery},{"role": "assistant", "content": context}]

    chatCompletion = client.chat.completions.create(messages = messages, model = MODEL, temperature = TEMPERATURE)
    chatCompletion = chatCompletion.choices[0].message.content.strip()

    # Execute the command and capture the output
    outputText = subprocess.run(chatCompletion, shell=True, capture_output=True, text=True)
    openPorts = outputText.stdout

    userQuery = """
    Take open ports that I will add at the end and scan them aggressively gathering as much information as possible. 
    Save this information into nmap-tcp-ports.txt
    Ports: 
    """
    userQuery += openPorts

    messages = [{"role": "system", "content": systemPrompt}, {"role": "user", "content": userQuery},{"role": "assistant", "content": context}]

    chatCompletion = client.chat.completions.create(messages = messages, model = MODEL, temperature = TEMPERATURE)
    chatCompletion = chatCompletion.choices[0].message.content.strip()

    ### DEBUG
    print(RED + BOLD + "Command: " + chatCompletion + NC)

    # Execute the command and capture the output
    outputText = subprocess.run(chatCompletion, shell=True, capture_output=True, text=True)
    detailsPorts = outputText.stdout

    ### DEBUG
    print(RED + BOLD + "outputText: " + outputText + NC)


if __name__ == "__main__":
    main()
