#!/usr/bin/python3

# --- Konfigurace ---
PROXY_CONFIG = {
    'proxy_host': 'localhost',     # Adresa proxy serveru
    'proxy_port': 9999,           # Port proxy serveru
    'zabbix_server': 'localhost',  # Adresa Zabbix serveru
    'max_attempts': 3,            # Maximální počet pokusů
    'retry_delay': 2             # Prodleva mezi pokusy (v sekundách)
}

import socket
import json
import sys
import time
from subprocess import Popen, PIPE
import argparse
from typing import Tuple  # Pro Python 3.6 kompatibilitu

def send_to_proxy(host: str, command: str) -> dict:
    """Pošle příkaz proxy serveru"""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.connect((PROXY_CONFIG['proxy_host'], PROXY_CONFIG['proxy_port']))
        request = json.dumps({
            "host": host,
            "command": command
        })
        sock.send(request.encode())
        
        response = sock.recv(4096).decode()
        return json.loads(response)
    finally:
        sock.close()

def send_to_zabbix(host: str, key: str, value: str) -> bool:
    """Odešle data do Zabbixu"""
    try:
        cmd = [
            "zabbix_sender",
            "-z", PROXY_CONFIG['zabbix_server'],
            "-s", host,
            "-k", key,
            "-o", str(value)
        ]
        
        process = Popen(cmd, stdout=PIPE, stderr=PIPE)
        stdout, stderr = process.communicate()
        
        if process.returncode != 0:
            print(f"Chyba při odesílání do Zabbixu: {stderr.decode()}")
            return False
        return True
    except Exception as e:
        print(f"Chyba při volání zabbix_sender: {e}")
        return False

def check_dhcp_alerts(host: str) -> Tuple[bool, int]:  # Upravená typu anotace
    """Kontrola DHCP alertů s opakováním při prázdném výstupu"""
    command = 'ip dhcp-server alert print count-only where unknown-server'
    
    for attempt in range(PROXY_CONFIG['max_attempts']):
        print(f"Pokus {attempt + 1}/{PROXY_CONFIG['max_attempts']}")
        response = send_to_proxy(host, command)
        
        if "error" in response and response["error"]:
            print(f"Chyba: {response['error']}")
            if attempt < PROXY_CONFIG['max_attempts'] - 1:
                print(f"Čekám {PROXY_CONFIG['retry_delay']} sekund před dalším pokusem...")
                time.sleep(PROXY_CONFIG['retry_delay'])
                continue
            return False, 0
            
        try:
            alert_count = int(response["output"])
            return True, alert_count
        except (ValueError, KeyError) as e:
            print(f"Neplatný výstup z proxy: {response}")
            if attempt < PROXY_CONFIG['max_attempts'] - 1:
                print(f"Čekám {PROXY_CONFIG['retry_delay']} sekund před dalším pokusem...")
                time.sleep(PROXY_CONFIG['retry_delay'])
                continue
            return False, 0
    
    return False, 0

def main():
    parser = argparse.ArgumentParser(description='Check DHCP alerts via proxy')
    parser.add_argument('host', help='Target router IP address')
    parser.add_argument('zabbix_hostname', help='Hostname in Zabbix')
    
    args = parser.parse_args()
    
    success, alert_count = check_dhcp_alerts(args.host)
    
    if success:
        if send_to_zabbix(args.zabbix_hostname, "dhcpalert", alert_count):
            print(f"Data úspěšně odeslána do Zabbixu: {alert_count}")
            sys.exit(0)
        else:
            print("Nepodařilo se odeslat data do Zabbixu")
            sys.exit(1)
    else:
        print("Nepodařilo se získat počet DHCP alertů")
        sys.exit(1)

if __name__ == "__main__":
    main()