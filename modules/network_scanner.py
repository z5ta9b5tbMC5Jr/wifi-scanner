#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import socket
import ipaddress
import logging
import time
from concurrent.futures import ThreadPoolExecutor
from tqdm import tqdm
from colorama import Fore, Style

try:
    import nmap
    NMAP_AVAILABLE = True
except ImportError:
    NMAP_AVAILABLE = False

class NetworkScanner:
    """Classe para escaneamento de redes e detecção de serviços.
    
    Attributes:
        target (str): Alvo para escaneamento (IP ou range CIDR)
        ports (list): Lista de portas para verificar
        timeout (int): Timeout para conexões em segundos
        logger (logging.Logger): Logger para registro de eventos
    """
    
    def __init__(self, target, ports, timeout=5, logger=None):
        """Inicializa o scanner de rede.
        
        Args:
            target (str): Alvo do escaneamento (IP ou range CIDR)
            ports (list): Lista de portas para verificar
            timeout (int, optional): Timeout em segundos. Default é 5
            logger (logging.Logger, optional): Logger para registro
        """
        self.target = target
        self.ports = [int(port.strip()) for port in ports]
        self.timeout = timeout
        self.logger = logger or logging.getLogger('wifi_scanner')
        
        # Mapear portas comuns para serviços
        self.port_map = {
            21: 'ftp',
            22: 'ssh',
            23: 'telnet',
            25: 'smtp',
            53: 'dns',
            80: 'http',
            110: 'pop3',
            143: 'imap',
            443: 'https',
            445: 'smb',
            3306: 'mysql',
            3389: 'rdp',
            5432: 'postgresql',
            8080: 'http-alt'
        }
    
    def _get_hosts(self):
        """Converte o alvo em uma lista de hosts para escanear.
        
        Returns:
            list: Lista de endereços IP para escanear
        """
        if '/' in self.target:  # CIDR notation
            try:
                network = ipaddress.ip_network(self.target, strict=False)
                return [str(ip) for ip in network.hosts()]
            except ValueError as e:
                self.logger.error(f"Erro ao processar range CIDR: {str(e)}")
                return []
        else:  # Single IP
            return [self.target]
    
    def _scan_port(self, host, port):
        """Verifica se uma porta específica está aberta em um host.
        
        Args:
            host (str): Endereço IP do host
            port (int): Número da porta
            
        Returns:
            tuple: (port, service_name) se a porta estiver aberta, None caso contrário
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((host, port))
            sock.close()
            
            if result == 0:
                service = self.port_map.get(port, 'unknown')
                return (port, service)
            return None
        except Exception as e:
            self.logger.debug(f"Erro ao escanear {host}:{port} - {str(e)}")
            return None
    
    def _scan_host(self, host):
        """Escaneia todas as portas especificadas em um host.
        
        Args:
            host (str): Endereço IP do host
            
        Returns:
            tuple: (host, {port: service}) se alguma porta estiver aberta, None caso contrário
        """
        open_ports = {}
        
        for port in self.ports:
            result = self._scan_port(host, port)
            if result:
                port, service = result
                open_ports[port] = service
        
        if open_ports:
            return (host, open_ports)
        return None
    
    def _scan_with_socket(self):
        """Realiza o escaneamento usando sockets Python.
        
        Returns:
            dict: Dicionário de hosts com portas abertas {host: {port: service}}
        """
        hosts = self._get_hosts()
        self.logger.info(f"Escaneando {len(hosts)} hosts em {len(self.ports)} portas...")
        
        results = {}
        
        with ThreadPoolExecutor(max_workers=50) as executor:
            futures = [executor.submit(self._scan_host, host) for host in hosts]
            
            with tqdm(total=len(futures), desc="Progresso", unit="host") as progress:
                for future in futures:
                    result = future.result()
                    if result:
                        host, services = result
                        results[host] = services
                    progress.update(1)
        
        return results
    
    def _scan_with_nmap(self):
        """Realiza o escaneamento usando a biblioteca python-nmap.
        
        Returns:
            dict: Dicionário de hosts com portas abertas {host: {port: service}}
        """
        results = {}
        nm = nmap.PortScanner()
        
        ports_str = ','.join(map(str, self.ports))
        self.logger.info(f"Escaneando com Nmap: {self.target} (portas: {ports_str})")
        
        try:
            nm.scan(hosts=self.target, ports=ports_str, timeout=self.timeout)
            
            for host in nm.all_hosts():
                if host not in results:
                    results[host] = {}
                
                for proto in nm[host].all_protocols():
                    ports = sorted(nm[host][proto].keys())
                    
                    for port in ports:
                        if nm[host][proto][port]['state'] == 'open':
                            service = nm[host][proto][port]['name']
                            results[host][port] = service
            
        except Exception as e:
            self.logger.error(f"Erro durante o escaneamento com Nmap: {str(e)}")
            self.logger.info("Alternando para escaneamento básico...")
            return self._scan_with_socket()
        
        return results
    
    def scan(self):
        """Realiza o escaneamento de rede escolhendo o melhor método disponível.
        
        Returns:
            dict: Resultados do escaneamento {host: {port: service}}
        """
        start_time = time.time()
        self.logger.debug(f"Iniciando escaneamento em {self.target}")
        
        # Usar Nmap se disponível, senão usar sockets
        if NMAP_AVAILABLE:
            self.logger.debug("Usando Nmap para escaneamento")
            results = self._scan_with_nmap()
        else:
            self.logger.debug("Nmap não disponível, usando sockets para escaneamento")
            self.logger.info("Para melhor detecção de serviços, instale python-nmap e nmap")
            results = self._scan_with_socket()
        
        duration = time.time() - start_time
        self.logger.debug(f"Escaneamento concluído em {duration:.2f} segundos")
        
        # Colorir a saída no terminal
        if results:
            print(f"\n{Fore.GREEN}[+] Hosts com portas abertas encontrados:{Style.RESET_ALL}")
            for host, services in results.items():
                print(f"\n{Fore.CYAN}[*] Host: {host}{Style.RESET_ALL}")
                for port, service in services.items():
                    print(f"  {Fore.YELLOW}Porta {port}: {service}{Style.RESET_ALL}")
        
        return results