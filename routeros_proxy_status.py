#!/usr/bin/python3

# --- Konfigurace ---
PROXY_CONFIG = {
    'proxy_host': 'localhost',
    'proxy_port': 9999,
    'buffer_size': 16384
}

import socket
import json
import sys
import argparse

def receive_all(sock):
    """Přijme kompletní data ze socketu"""
    data = []
    while True:
        chunk = sock.recv(PROXY_CONFIG['buffer_size'])
        if not chunk:
            break
        data.append(chunk)
        if len(chunk) < PROXY_CONFIG['buffer_size']:
            break
    return b''.join(data).decode()

def get_proxy_status():
    """Získá status proxy serveru"""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.connect((PROXY_CONFIG['proxy_host'], PROXY_CONFIG['proxy_port']))
        request = json.dumps({
            "command": "status"
        })
        sock.send(request.encode())
        
        response = receive_all(sock)
        return json.loads(response)
    finally:
        sock.close()

def main():
    parser = argparse.ArgumentParser(description='RouterOS Proxy Status')
    parser.add_argument('-d', '--detail', action='store_true', help='Zobrazit detailní výpis')
    args = parser.parse_args()

    try:
        status = get_proxy_status()
        print("\nStatus RouterOS Proxy:")
        print("-" * 40)
        print(f"Aktivní spojení: {status['active_connections']}")
        
        if args.detail:
            print(f"\nPřipojené routery:")
            sorted_connections = sorted(
                status['connections'].items(),
                key=lambda x: x[1]['last_used'],
                reverse=True
            )
            for host, info in sorted_connections:
                print(f"\n  - {host}")
                print(f"    Poslední aktivita: {info['last_used']}")
                print(f"    Stav spojení: {'Aktivní' if info['connected'] else 'Neaktivní'}")
        print("-" * 40)
    except Exception as e:
        print(f"Chyba při získávání statusu: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()