#!/usr/bin/python3

import paramiko
import socket
import sys
import logging
from subprocess import Popen, PIPE
import argparse

def send_to_zabbix(host, key, value):
    """Odeslání dat do Zabbixu pomocí zabbix_sender"""
    try:
        cmd = [
            "zabbix_sender",
            "-z", "localhost",
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

def check_bgp_status_ros7(client):
    """Kontrola BGP stavu pro RouterOS 7"""
    try:
        # RR spojení
        stdin, stdout, stderr = client.exec_command('routing/bgp/connection/print count-only where (remote.address=31.170.178.220/32 or remote.address=31.170.178.221/32) and disabled=no')
        rr_connections = int(stdout.read().decode().strip())
        
        stdin, stdout, stderr = client.exec_command('routing/bgp/session/print count-only where (remote.address=31.170.178.220 or remote.address=31.170.178.221) and established=yes')
        rr_sessions = int(stdout.read().decode().strip())
        
        # Ostatní spojení
        stdin, stdout, stderr = client.exec_command('routing/bgp/connection/print count-only where (remote.address!=31.170.178.220/32 and remote.address!=31.170.178.221/32) and disabled=no')
        other_connections = int(stdout.read().decode().strip())
        
        stdin, stdout, stderr = client.exec_command('routing/bgp/session/print count-only where (remote.address!=31.170.178.220 and remote.address!=31.170.178.221) and established=yes')
        other_sessions = int(stdout.read().decode().strip())
        
        return {
            'disconnbgprr': rr_connections - rr_sessions,
            'disconnbgp': other_connections - other_sessions
        }
    except Exception as e:
        print(f"Chyba při kontrole BGP ROS7: {e}")
        return None

def check_bgp_status_ros6(client):
    """Kontrola BGP stavu pro RouterOS 6"""
    try:
        # RR spojení
        command_rr = ('routing bgp peer print count-only where state!=established and disabled=no and (remote-address=31.170.178.220 or remote-address=31.170.178.221)')
        stdin, stdout, stderr = client.exec_command(command_rr)
        disconn_rr = int(stdout.read().decode().strip())
        
        # Ostatní spojení
        command_other = ('routing bgp peer print count-only where state!=established and disabled=no and (remote-address!=31.170.178.220 and remote-address!=31.170.178.221)')
        stdin, stdout, stderr = client.exec_command(command_other)
        disconn_other = int(stdout.read().decode().strip())
        
        return {
            'disconnbgprr': disconn_rr,
            'disconnbgp': disconn_other
        }
    except Exception as e:
        print(f"Chyba při kontrole BGP ROS6: {e}")
        return None

def connect_router(host, username, password, source_ip, port=10002):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.bind((source_ip, 0))
        sock.connect((host, port))
        
        transport = paramiko.Transport(sock)
        transport.local_version = "SSH-2.0-Paramiko_" + paramiko.__version__
        transport.start_client(timeout=10)
        transport.auth_password(username=username, password=password)
        
        client = paramiko.SSHClient()
        client._transport = transport
        
        return client
    except Exception as e:
        print(f"Chyba při připojení: {e}")
        return None

def main():
    parser = argparse.ArgumentParser(description='RouterOS BGP status checker')
    parser.add_argument('ip', help='IP adresa routeru')
    parser.add_argument('hostname', help='Hostname pro Zabbix')
    args = parser.parse_args()

    USERNAME = "user"
    PASSWORD = "xxxxxxxxxxx"
    SOURCE_IP = "100.64.1.66"
    PORT = 10002
    
    client = connect_router(args.ip, USERNAME, PASSWORD, SOURCE_IP, PORT)
    if client:
        try:
            # Zjištění verze ROS
            stdin, stdout, stderr = client.exec_command('/system resource print')
            version_output = stdout.read().decode()
            
            # Kontrola BGP podle verze
            if '7.' in version_output:
                bgp_status = check_bgp_status_ros7(client)
            else:
                bgp_status = check_bgp_status_ros6(client)
            
            if bgp_status is None:
                print("Chyba při získávání BGP stavu")
                sys.exit(1)
            
            # Odeslání dat do Zabbixu
            for key, value in bgp_status.items():
                if send_to_zabbix(args.hostname, key, value):
                    print(f"Data úspěšně odeslána do Zabbixu: {key}={value}")
                else:
                    print(f"Chyba při odesílání dat do Zabbixu pro {key}")
                    sys.exit(1)
            
        finally:
            client.close()
    else:
        print("Nepodařilo se připojit k routeru")
        sys.exit(1)

if __name__ == "__main__":
    main()