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
from typing import Dict, Tuple, Optional

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

def execute_command(host: str, command: str) -> Tuple[bool, str]:
    """Vykoná příkaz na zařízení pomocí proxy s opakováním při chybě"""
    for attempt in range(PROXY_CONFIG['max_attempts']):
        print(f"Pokus {attempt + 1}/{PROXY_CONFIG['max_attempts']} - příkaz: {command}")
        response = send_to_proxy(host, command)
        
        if "error" in response and response["error"]:
            print(f"Chyba: {response['error']}")
            if attempt < PROXY_CONFIG['max_attempts'] - 1:
                print(f"Čekám {PROXY_CONFIG['retry_delay']} sekund před dalším pokusem...")
                time.sleep(PROXY_CONFIG['retry_delay'])
                continue
            return False, ""
            
        try:
            output = response["output"]
            return True, output
        except KeyError as e:
            print(f"Neplatný výstup z proxy: {response}")
            if attempt < PROXY_CONFIG['max_attempts'] - 1:
                print(f"Čekám {PROXY_CONFIG['retry_delay']} sekund před dalším pokusem...")
                time.sleep(PROXY_CONFIG['retry_delay'])
                continue
            return False, ""
    
    return False, ""

def check_ros_version(host: str) -> Optional[int]:
    """Zjistí verzi RouterOS"""
    success, output = execute_command(host, '/system resource print')
    if not success:
        return None
    
    if '7.' in output:
        return 7
    else:
        return 6

def check_bgp_status_ros7(host: str) -> Optional[Dict[str, int]]:
    """Kontrola BGP stavu pro RouterOS 7"""
    try:
        # RR spojení
        success, output = execute_command(host, 'routing/bgp/connection/print count-only where (remote.address=31.170.178.220/32 or remote.address=31.170.178.221/32) and disabled=no')
        if not success:
            return None
        rr_connections = int(output.strip())
        
        success, output = execute_command(host, 'routing/bgp/session/print count-only where (remote.address=31.170.178.220 or remote.address=31.170.178.221) and established=yes')
        if not success:
            return None
        rr_sessions = int(output.strip())
        
        # Ostatní spojení
        success, output = execute_command(host, 'routing/bgp/connection/print count-only where (remote.address!=31.170.178.220/32 and remote.address!=31.170.178.221/32) and disabled=no')
        if not success:
            return None
        other_connections = int(output.strip())
        
        success, output = execute_command(host, 'routing/bgp/session/print count-only where (remote.address!=31.170.178.220 and remote.address!=31.170.178.221) and established=yes')
        if not success:
            return None
        other_sessions = int(output.strip())
        
        return {
            'disconnbgprr': rr_connections - rr_sessions,
            'disconnbgp': other_connections - other_sessions
        }
    except Exception as e:
        print(f"Chyba při kontrole BGP ROS7: {e}")
        return None

def check_bgp_status_ros6(host: str) -> Optional[Dict[str, int]]:
    """Kontrola BGP stavu pro RouterOS 6"""
    try:
        # RR spojení
        command_rr = 'routing bgp peer print count-only where state!=established and disabled=no and (remote-address=31.170.178.220 or remote-address=31.170.178.221)'
        success, output = execute_command(host, command_rr)
        if not success:
            return None
        disconn_rr = int(output.strip())
        
        # Ostatní spojení
        command_other = 'routing bgp peer print count-only where state!=established and disabled=no and (remote-address!=31.170.178.220 and remote-address!=31.170.178.221)'
        success, output = execute_command(host, command_other)
        if not success:
            return None
        disconn_other = int(output.strip())
        
        return {
            'disconnbgprr': disconn_rr,
            'disconnbgp': disconn_other
        }
    except Exception as e:
        print(f"Chyba při kontrole BGP ROS6: {e}")
        return None

def main():
    parser = argparse.ArgumentParser(description='RouterOS BGP status checker via proxy')
    parser.add_argument('host', help='Target router IP address')
    parser.add_argument('zabbix_hostname', help='Hostname in Zabbix')
    
    args = parser.parse_args()
    
    # Zjištění verze RouterOS
    ros_version = check_ros_version(args.host)
    if ros_version is None:
        print("Chyba při zjišťování verze RouterOS")
        sys.exit(1)
    
    # Kontrola BGP podle verze RouterOS
    if ros_version == 7:
        print("Detekován RouterOS verze 7, použití příslušných příkazů")
        bgp_status = check_bgp_status_ros7(args.host)
    else:
        print("Detekován RouterOS verze 6, použití příslušných příkazů")
        bgp_status = check_bgp_status_ros6(args.host)
    
    if bgp_status is None:
        print("Nepodařilo se získat BGP status")
        sys.exit(1)
    
    # Odeslání dat do Zabbixu
    success = True
    for key, value in bgp_status.items():
        if send_to_zabbix(args.zabbix_hostname, key, value):
            print(f"Data úspěšně odeslána do Zabbixu: {key}={value}")
        else:
            print(f"Chyba při odesílání dat do Zabbixu pro {key}")
            success = False
    
    if not success:
        sys.exit(1)
    
    sys.exit(0)

if __name__ == "__main__":
    main()