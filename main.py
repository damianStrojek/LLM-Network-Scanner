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
    api_key = input("Please enter your OpenAI API key: ")
    return api_key

# Function to set the OpenAI API key
def set_openai_api_key(ApiKey):
    openai.api_key = ApiKey

    client = OpenAI(api_key=ApiKey)

    return client

def prepare_context():
    system_prompt = "You are a penetration tester for one of the biggest companies in the world."

    context = """
        You are tasked with coming up with technical answers to given questions.
        When said, create only commands that can be copy-pasted into /bin/bash console on Kali Linux 2024 system.
        The idea for following prompts is to prepare and execute an infrastracture penetration test on given IP address.
        You are allowed to use only public tools that will not create a Denial-of-Service attack.
        When not said how to print out the results, print only the console command. Do not add back ticks.
        Do not add any python or bash comments when answering.
        Current host to scan: 192.168.0.1
    """

    return system_prompt, context

def main():
    # Get and set the API key
    api_key = get_api_key()
    client = set_openai_api_key(api_key)

    system_prompt, context = prepare_context()

    user_query = "Scan ports and save open ports into a local variable of $OPEN_PORTS"

    messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_query},
                {"role": "assistant", "content": context}
    ]

    chat_completion = client.chat.completions.create(messages = messages, model = MODEL, temperature = TEMPERATURE)
    
    ### DEBUG
    print(chat_completion.choices[0].message.content.strip())


    # Command you want to run (as a string)
    command = "ls -l"

    # Execute the command and capture the output
    result = subprocess.run(command, shell=True, capture_output=True, text=True)

    # The result is stored in the `stdout` attribute
    output = result.stdout

    # Print or use the captured output
    print("Command output:")
    print(output)




if __name__ == "__main__":
    main()
