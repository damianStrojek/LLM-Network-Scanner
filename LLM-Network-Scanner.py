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

# Function to prompt the user for their OpenAI API key (security measures)
def get_api_key():
    apiKey = input("Please enter your OpenAI API key: ")
    return apiKey

# Function to set the OpenAI API key
def set_openai_api_key(apiKey):
    openai.api_key = apiKey
    client = OpenAI(api_key=apiKey)
    return client

def set_host():
    host = input("Please enter host to be scanned: ")
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

    userQuery = "Scan ports of defined host and print out only open ones."

    messages=[
        {"role": "system", "content": systemPrompt},
        {"role": "user", "content": userQuery},
        {"role": "assistant", "content": context}
    ]

    #chatCompletion = client.chat.completions.create(messages = messages, model = MODEL, temperature = TEMPERATURE)
    #chatCompletion = chatCompletion.choices[0].message.content.strip()
    chatCompletion = "nmap -p- 127.0.0.1 | grep 'open' | awk '{print $1}'"

    ### DEBUG
    print("Command: ", chatCompletion)

    # Execute the command and capture the output
    outputText = subprocess.run(chatCompletion, shell=True, capture_output=True, text=True)
    print("Output: ", outputText)

    openPorts = outputText.stdout

    ### DEBUG
    print("Output: ", openPorts)

if __name__ == "__main__":
    main()
