#!/usr/bin/python3

# Import všech potřebných knihoven
import os
import socket
import threading
import paramiko
import json
import time
import signal
import sys
import logging
import logging.handlers
import argparse
from datetime import datetime, timedelta
from typing import Dict

# --- Konfigurace ---
ROUTER_CONFIG = {
    'source_ip': '100.64.1.67',    # IP adresa, ze které se připojujeme
    'username': 'oxibak',          # SSH uživatel pro RouterOS
    'password': 'xxxxxxxxxxxxxx',           # SSH heslo
    'port': 10002,                 # SSH port na RouterOS
    'listen_port': 9999,           # Port na kterém poslouchá proxy
    'connection_timeout': 3600,    # Timeout pro neaktivní spojení (v sekundách)
    'reconnect_attempts': 3,       # Počet pokusů o obnovení spojení
    'reconnect_delay': 5,          # Prodleva mezi pokusy (v sekundách)
    'command_timeout': 30          # Timeout pro vykonání příkazu (v sekundách)
}

def setup_logging(verbose=False):
    """Nastavení logování s možností verbose módu a podporou reopen"""
    # Potlačení Paramiko logů
    logging.getLogger("paramiko").setLevel(logging.ERROR)

    # Vytvoření a konfigurace loggeru
    logger = logging.getLogger('routeros_proxy')
    logger.setLevel(logging.INFO if verbose else logging.WARNING)

    # Odstranění existujících handlerů
    for handler in logger.handlers[:]:
        logger.removeHandler(handler)

    # Přidání WatchedFileHandler místo StreamHandler
    handler = logging.handlers.WatchedFileHandler('/var/log/routeros-proxy/daemon.log')
    formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
    handler.setFormatter(formatter)
    logger.addHandler(handler)

    # Vypnutí propagace logů do root loggeru
    logger.propagate = False
    
    return logger

def handle_sighup(signum, frame):
    """Handler pro SIGHUP signál"""
    logger = logging.getLogger('routeros_proxy')
    logger.info("Received SIGHUP, reopening log file")
    
    # WatchedFileHandler automaticky znovu otevře soubor
    for handler in logger.handlers:
        if isinstance(handler, logging.handlers.WatchedFileHandler):
            handler.reopenIfNeeded()

class RouterConnection:
    def __init__(self, host: str, username: str, password: str, source_ip: str, port: int = 10002):
        self.host = host
        self.username = username
        self.password = password
        self.source_ip = source_ip
        self.port = port
        self.ssh_client = None
        self.last_used = datetime.now()
        self.lock = threading.Lock()
        self.reconnect_attempts = ROUTER_CONFIG['reconnect_attempts']
        self.reconnect_delay = ROUTER_CONFIG['reconnect_delay']
        self.logger = logging.getLogger('routeros_proxy')

    def wait_for_completion(self, channel, timeout=30):
        """Čeká na dokončení příkazu s timeoutem"""
        end_time = time.time() + timeout
        while not channel.exit_status_ready():
            if time.time() > end_time:
                raise socket.timeout("Command timeout")
            time.sleep(0.1)
        return channel.recv_exit_status()

    def check_connection(self) -> bool:
        """Kontrola aktivního spojení"""
        if not self.ssh_client:
            return False
        try:
            transport = self.ssh_client.get_transport()
            if transport is None:
                return False
            transport.send_ignore()
            return True
        except Exception:
            return False

    def connect(self) -> bool:
        """Vytvoření SSH spojení s routerem"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10)
            sock.bind((self.source_ip, 0))
            sock.connect((self.host, self.port))
            
            transport = paramiko.Transport(sock)
            transport.local_version = "SSH-2.0-Paramiko_" + paramiko.__version__
            transport.start_client(timeout=10)
            transport.auth_password(username=self.username, password=self.password)
            transport.set_keepalive(30)
            
            client = paramiko.SSHClient()
            client._transport = transport
            
            self.ssh_client = client
            return True
        except Exception as e:
            self.logger.error(f"Chyba při připojení k routeru {self.host}: {e}")
            if sock:
                try:
                    sock.close()
                except:
                    pass
            return False

    def ensure_connection(self) -> bool:
        """Zajistí aktivní spojení s opakovanými pokusy"""
        if self.check_connection():
            return True
            
        for attempt in range(self.reconnect_attempts):
            self.logger.info(f"Pokus o obnovení spojení k {self.host} ({attempt + 1}/{self.reconnect_attempts})")
            if self.ssh_client:
                try:
                    self.ssh_client.close()
                except:
                    pass
                self.ssh_client = None
            
            if self.connect():
                self.logger.info(f"Spojení k {self.host} úspěšně obnoveno")
                return True
                
            if attempt < self.reconnect_attempts - 1:
                time.sleep(self.reconnect_delay)
        return False

    def execute(self, command: str) -> Dict:
        """Vykoná příkaz na routeru s kontrolou spojení"""
        with self.lock:
            try:
                if not self.ensure_connection():
                    return {"error": f"Nelze se připojit k routeru {self.host}"}

                self.last_used = datetime.now()
                stdin, stdout, stderr = self.ssh_client.exec_command(command)
                
                # Použijeme vlastní implementaci čekání s timeoutem
                exit_status = self.wait_for_completion(stdout.channel, ROUTER_CONFIG['command_timeout'])
                
                if exit_status == 0:
                    if stdout.channel.recv_ready():
                        output = stdout.read().decode().strip()
                        error = stderr.read().decode().strip()
                        
                        if not output:
                            self.logger.warning(f"Prázdný výstup od {self.host}")
                            return {"error": "Prázdný výstup od routeru"}
                        
                        if error:
                            self.logger.warning(f"STDERR při vykonávání příkazu na {self.host}: {error}")
                        
                        return {
                            "output": output,
                            "error": error if error else None
                        }
                    else:
                        self.logger.warning(f"Žádná data nejsou k dispozici od {self.host}")
                        return {"error": "Žádná data nejsou k dispozici"}
                else:
                    return {"error": "Příkaz selhal s nenulovým návratovým kódem"}

            except socket.timeout:
                self.logger.error(f"Timeout při vykonávání příkazu na {self.host}")
                return {"error": "Timeout při vykonávání příkazu"}
            except Exception as e:
                self.logger.error(f"Chyba při vykonávání příkazu na {self.host}: {e}")
                if self.ssh_client:
                    try:
                        self.ssh_client.close()
                    except:
                        pass
                self.ssh_client = None
                return {"error": str(e)}

    def close(self):
        """Uzavře spojení"""
        if self.ssh_client:
            try:
                self.ssh_client.close()
            except:
                pass
            self.ssh_client = None

class RouterProxyDaemon:
    def __init__(self):
        self.source_ip = ROUTER_CONFIG['source_ip']
        self.username = ROUTER_CONFIG['username']
        self.password = ROUTER_CONFIG['password']
        self.listen_port = ROUTER_CONFIG['listen_port']
        self.connection_timeout = ROUTER_CONFIG['connection_timeout']
        self.connections: Dict[str, RouterConnection] = {}
        self.connections_lock = threading.Lock()
        self.running = True
        self.logger = logging.getLogger('routeros_proxy')

    def get_status(self):
        """Vrátí aktuální status proxy"""
        with self.connections_lock:
            status = {
                'active_connections': len(self.connections),
                'connections': {}
            }
            for host, conn in self.connections.items():
                status['connections'][host] = {
                    'last_used': conn.last_used.strftime('%Y-%m-%d %H:%M:%S'),
                    'connected': conn.check_connection()
                }
            return status

    def cleanup_old_connections(self):
        """Čištění starých spojení"""
        while self.running:
            time.sleep(60)  # Kontrola každou minutu
            with self.connections_lock:
                current_time = datetime.now()
                hosts_to_remove = []
                
                for host, conn in self.connections.items():
                    if (current_time - conn.last_used).total_seconds() > self.connection_timeout:
                        self.logger.info(f"Uzavírám neaktivní spojení k {host}")
                        conn.close()
                        hosts_to_remove.append(host)
                
                for host in hosts_to_remove:
                    del self.connections[host]

    def get_connection(self, host: str) -> RouterConnection:
        """Získá nebo vytvoří spojení pro daného hosta"""
        with self.connections_lock:
            if host not in self.connections:
                self.logger.info(f"Vytvářím nové spojení k {host}")
                self.connections[host] = RouterConnection(
                    host=host,
                    username=self.username,
                    password=self.password,
                    source_ip=self.source_ip
                )
            return self.connections[host]

    def handle_client(self, client_sock: socket.socket):
        """Obsluha požadavku od klienta"""
        try:
            data = client_sock.recv(1024).decode()
            request = json.loads(data)
            
            if request.get("command") == "status":
                response = self.get_status()
            else:
                host = request.get("host")
                command = request.get("command")
                
                if not host or not command:
                    response = {"error": "Chybí host nebo příkaz"}
                else:
                    conn = self.get_connection(host)
                    response = conn.execute(command)
            
            client_sock.send(json.dumps(response).encode())
        except Exception as e:
            self.logger.error(f"Chyba při obsluze klienta: {e}")
        finally:
            client_sock.close()

    def run(self):
        """Spustí proxy server"""
        # Zapíšeme PID do souboru
        with open('/var/run/routeros-proxy/pid', 'w') as f:
            f.write(str(os.getpid()))

        # Spustit thread pro čištění starých spojení
        cleanup_thread = threading.Thread(target=self.cleanup_old_connections)
        cleanup_thread.daemon = True
        cleanup_thread.start()
        
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind(('localhost', self.listen_port))
        server.listen(5)
        
        self.logger.info(f"Proxy server naslouchá na portu {self.listen_port}")
        
        while self.running:
            try:
                client_sock, addr = server.accept()
                thread = threading.Thread(target=self.handle_client, args=(client_sock,))
                thread.daemon = True
                thread.start()
            except Exception as e:
                if self.running:
                    self.logger.error(f"Chyba při přijímání spojení: {e}")
        
        server.close()
        with self.connections_lock:
            for conn in self.connections.values():
                conn.close()

    def stop(self):
        """Zastaví proxy server"""
        self.running = False
        # Odstraníme PID soubor
        try:
            os.remove('/var/run/routeros-proxy/pid')
        except:
            pass

def handle_sigterm(proxy, logger):
    """Handler pro SIGTERM signál"""
    logger.info("\nZastavuji proxy server...")
    proxy.stop()
    sys.exit(0)

def main():
    # Zpracování argumentů
    parser = argparse.ArgumentParser(description='RouterOS Proxy Daemon')
    parser.add_argument('-v', '--verbose', action='store_true', 
                      help='Zobrazit všechny log zprávy včetně informačních')
    args = parser.parse_args()
    
    # Nastavení loggeru podle parametrů
    logger = setup_logging(args.verbose)
    
    proxy = RouterProxyDaemon()
    
    # Registrace signal handlerů
    signal.signal(signal.SIGHUP, handle_sighup)
    signal.signal(signal.SIGTERM, lambda signum, frame: handle_sigterm(proxy, logger))
    signal.signal(signal.SIGINT, lambda signum, frame: handle_sigterm(proxy, logger))
    
    proxy.run()

if __name__ == "__main__":
    main()