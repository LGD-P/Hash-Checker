import requests
from dotenv import load_dotenv
import os
import json
from const import VIRUS_TOTAL_URL
from rich.console import Console




class VirusTotal:
    def __init__(self, hash_input):
        self.hash_input = hash_input
        self.c = Console(record=True)


    def ask_virus_total(self):
        load_dotenv()
        api_key = os.getenv("VT_API_KEY")
        url = VIRUS_TOTAL_URL + self.hash_input
        headers = {
            "accept": "application/json",
            "x-apikey": api_key
        }
        response = requests.get(url, headers=headers)
        response_json = response.json()
        #result = json.dumps(response_json, indent=4)
        return response_json







