#
# LLM Network Scanner
# Copyright (C) 2024 Damian Strojek
#
# This file is an addition to LLM-Network-Scanner.py used to test out future ideas
#

# Imports
import openai
from openai import OpenAI

# Constants
YELLOW='\033[1;33m'
MAGENTA='\033[1;35m'
RED='\033[1;31m'
NC='\033[0m'
BLUE='\033[1;34m'

# Prompt the user for their OpenAI API key (security measures)
# and Set the OpenAI API key
def set_openai_api_key():
    apiKey = input(YEL + "[?] " + BLU + "Please enter your OpenAI API key: " + NC)
    openai.api_key = apiKey
    client = OpenAI(api_key=apiKey)
    return client

# Main function
def main():
    
    # Warning
    input(YELLOW + "[!] " + RED + "Be careful!!! Each query costs around 0.04$!" + NC)
    
    # Set the OpenAI API key
    client = set_openai_api_key()
    
    promptText = input(YELLOW + "[?] " + BLUE + "Please enter your query: " + NC)
    
    response = client.images.generate(
        model="dall-e-3",
        prompt=promptText,
        size="1024x1024",
        quality="standard",
        n=1,
    )
    
    imageUrl = response.data[0].url
    print(YELLOW + "[*] " + MAGENTA + "Your image is located at: " + imageUrl + NC)
    
    exit()
    
if __name__ == "__main__":
    main()