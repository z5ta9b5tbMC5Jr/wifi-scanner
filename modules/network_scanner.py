#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import socket
import ipaddress
import logging
import time
from concurrent.futures import ThreadPoolExecutor, as_completed, Future
from tqdm import tqdm
from colorama import Fore, Style
import sys
import re

try:
    import nmap
    NMAP_AVAILABLE = True
except ImportError:
    NMAP_AVAILABLE = False

class NetworkScanner:
    """
    Realiza escaneamento de rede para descobrir hosts ativos e portas abertas.

    Pode usar Nmap (se disponível) para detecção mais precisa ou sockets Python como fallback.
    Utiliza ThreadPoolExecutor para paralelizar o escaneamento de portas/hosts.
    Mostra o progresso usando tqdm.

    Attributes:
        targets (list): Lista de alvos para escaneamento (IPs, CIDRs ou nomes de host).
        ports (list): Lista de portas (int) para verificar.
        timeout (float): Timeout para conexões de socket em segundos.
        logger (logging.Logger): Objeto logger para registro de eventos.
        max_workers (int): Número máximo de threads paralelas para o escaneamento.
        use_nmap (bool): Flag para forçar ou não o uso do Nmap.
        nmap_args (str): Argumentos adicionais para passar ao Nmap.
    """

    def __init__(self, targets, ports, timeout=1.0, max_workers=50, use_nmap=True, nmap_args="-sV -T4", logger=None):
        """
        Inicializa o NetworkScanner.

        Args:
            targets (list): Lista de alvos (IPs, CIDRs, nomes de host).
            ports (list): Lista de portas (int) a escanear.
            timeout (float, optional): Timeout de socket em segundos. Padrão: 1.0.
            max_workers (int, optional): Número de threads paralelas. Padrão: 50.
            use_nmap (bool, optional): Tentar usar Nmap se disponível. Padrão: True.
            nmap_args (str, optional): Argumentos para Nmap (ex: "-sV -T4"). Padrão: "-sV -T4".
            logger (logging.Logger, optional): Instância do logger.
        """
        self.targets = targets # Recebe a lista já validada (pode conter nomes)
        self.ports = sorted(list(set(ports))) # Remove duplicados e ordena
        self.timeout = float(timeout)
        self.max_workers = int(max_workers)
        self.use_nmap_flag = use_nmap
        self.nmap_args = nmap_args
        self.logger = logger or logging.getLogger('wifi_scanner')
        self.should_stop = False # Flag para interrupção

        # Determinar se Nmap será realmente usado
        self.nmap_is_available = NMAP_AVAILABLE
        self.actually_use_nmap = self.use_nmap_flag and self.nmap_is_available

        # Mapeamento básico, Nmap -sV é mais preciso
        self.port_map = {
            21: 'ftp', 22: 'ssh', 23: 'telnet', 25: 'smtp', 53: 'dns',
            80: 'http', 110: 'pop3', 143: 'imap', 443: 'https', 445: 'smb',
            135: 'msrpc', 139: 'netbios-ssn', 5900: 'vnc',
            3306: 'mysql', 3389: 'rdp', 5432: 'postgresql', 8080: 'http-alt'
        }

    def _resolve_targets_to_ips(self):
        """
        Expande alvos (CIDRs, nomes de host) para uma lista plana de IPs únicos.
        Loga erros de resolução de nomes.

        Retorna:
            list: Lista de strings de endereços IP únicos e válidos.
        """
        all_ips = set()
        self.logger.debug(f"Resolvendo alvos: {self.targets}")
        for target in self.targets:
            if self.should_stop: break
            try:
                if '/' in target: # É um CIDR
                    network = ipaddress.ip_network(target, strict=False)
                    count = 0
                    # Iterar com cuidado em redes grandes
                    max_hosts_per_cidr = 65536 # Limite razoável para evitar exaustão
                    for ip in network.hosts():
                        if self.should_stop: break
                        all_ips.add(str(ip))
                        count += 1
                        if count >= max_hosts_per_cidr:
                             self.logger.warning(f"Limite de {max_hosts_per_cidr} hosts atingido para o CIDR {target}. Parando expansão.")
                             break
                    if count > 0:
                         self.logger.debug(f"Expandido CIDR {target} para {count} hosts.")

                elif re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", target):
                    # Validar IP antes de adicionar
                    ipaddress.ip_address(target)
                    all_ips.add(target)
                else: # Assume que é um nome de host
                    try:
                        ip = socket.gethostbyname(target)
                        self.logger.debug(f"Resolvido nome '{target}' para IP: {ip}")
                        all_ips.add(ip)
                    except socket.gaierror:
                        self.logger.error(f"Falha ao resolver nome de host: '{target}'")
                    except Exception as e:
                         self.logger.error(f"Erro inesperado ao resolver '{target}': {e}")

            except ValueError as e:
                # Erro ao processar CIDR ou IP inválido (já validado antes, mas segurança extra)
                self.logger.error(f"Erro ao processar alvo '{target}': {e}")
            except Exception as e:
                 self.logger.error(f"Erro inesperado ao processar alvo '{target}': {e}")

        if self.should_stop:
             self.logger.warning("Resolução de alvos interrompida.")

        sorted_ips = sorted(list(all_ips), key=ipaddress.ip_address)
        self.logger.info(f"Total de {len(sorted_ips)} IPs únicos a serem escaneados.")
        return sorted_ips

    def _scan_port_socket(self, host, port):
        """
        Verifica uma única porta em um host usando socket.
        Retorna (host, port, service_name) ou None.
        """
        if self.should_stop: return None
        service_name = self.port_map.get(port, 'unknown')
        addr = (host, port)
        sock = None
        try:
            # Criar e configurar socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            # Tentar conectar
            result = sock.connect_ex(addr)
            if result == 0:
                self.logger.debug(f"Porta aberta (socket): {host}:{port} ({service_name})")
                return (host, port, service_name)
            else:
                # Logar erro de conexão apenas em debug
                # error_reason = os.strerror(result) if hasattr(os, 'strerror') else f"Error code {result}"
                # self.logger.debug(f"Porta fechada/filtrada (socket): {host}:{port} - {error_reason}")
                return None
        except socket.timeout:
             self.logger.debug(f"Timeout ao conectar (socket) {host}:{port}")
             return None
        except socket.gaierror:
            # Isso não deveria acontecer aqui se a resolução foi feita antes, mas por segurança
            self.logger.error(f"Erro de resolução de nome (inesperado) para {host}")
            return None
        except socket.error as e:
             # Outros erros de socket (ex: permissão, rede inacessível, conexão recusada agressivamente)
             self.logger.debug(f"Erro de socket ao conectar {host}:{port} - {e}")
             return None
        except Exception as e:
             self.logger.error(f"Erro inesperado ao escanear {host}:{port} (socket): {e}")
             return None
        finally:
            if sock:
                sock.close()

    def _scan_with_socket(self, hosts_to_scan):
        """
        Realiza o escaneamento de portas usando sockets Python em paralelo.
        Retorna dict {host: {port: service_details}}.
        """
        results = {}
        if not hosts_to_scan:
             self.logger.warning("Scan por socket: Nenhum host para escanear.")
             return {}
             
        total_tasks = len(hosts_to_scan) * len(self.ports)
        self.logger.info(f"Iniciando escaneamento com sockets em {len(hosts_to_scan)} hosts e {len(self.ports)} portas ({total_tasks} tentativas)...)")

        # Usar um dicionário para armazenar resultados temporários por host
        # Isso simplifica a adição concorrente
        temp_results = {host: {} for host in hosts_to_scan}

        with tqdm(total=total_tasks, desc="Socket Scan", unit="port", ncols=100, disable=not sys.stdout.isatty()) as pbar:
            with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
                # Mapeia future para (host, port) para facilitar o processamento
                futures = {executor.submit(self._scan_port_socket, host, port): (host, port)
                           for host in hosts_to_scan for port in self.ports}

                try:
                    for future in as_completed(futures):
                        if self.should_stop:
                             # Tentar cancelar futuras pendentes rapidamente
                             for f in futures: f.cancel()
                             break # Sai do loop de as_completed
                             
                        host, port = futures[future]
                        try:
                            result_data = future.result()
                            if result_data:
                                _, res_port, res_service = result_data
                                # Adiciona ao dicionário temporário do host
                                temp_results[host][res_port] = {
                                    'name': res_service,
                                    'state': 'open',
                                    'product': '', # Socket não detecta produto/versão
                                    'version': '',
                                    'extrainfo': 'scanned via socket',
                                    'cpe': ''
                                }
                        except Exception as exc:
                            self.logger.error(f"Erro na tarefa de scan {host}:{port}: {exc}")
                        finally:
                            pbar.update(1)
                except KeyboardInterrupt:
                     self.logger.warning("\nInterrupção (CTRL+C) detectada durante o scan socket.")
                     self.stop() # Sinaliza para parar outras threads
                     # Cancela futuras que ainda não iniciaram
                     for f in futures: f.cancel()

        # Filtra hosts que não tiveram portas abertas encontradas
        final_results = {host: ports for host, ports in temp_results.items() if ports}
        return final_results

    def _scan_with_nmap(self, hosts_to_scan):
        """
        Realiza o escaneamento usando python-nmap.
        Retorna dict {host: {port: {service_details}}} ou None em caso de erro fatal.
        """
        if not hosts_to_scan:
             self.logger.warning("Scan Nmap: Nenhum host para escanear.")
             return {}
             
        results = {}
        nm = None
        try:
            # Usar PortScannerAsync pode ser complexo para integrar com tqdm
            nm = nmap.PortScanner()
        except nmap.nmap.PortScannerError as e:
             self.logger.error(f"Erro ao inicializar Nmap: {e}. Verifique se Nmap está instalado e no PATH.")
             return None # Falha crítica

        ports_str = ','.join(map(str, self.ports))
        # Nmap aceita múltiplos hosts separados por espaço
        target_string = ' '.join(hosts_to_scan)
        
        nmap_command_line = f"nmap {self.nmap_args} -p {ports_str} {target_string}"
        self.logger.info(f"Iniciando Nmap... Comando estimado: {nmap_command_line}")
        # TODO: Adicionar estimativa de tempo ou barra de progresso para Nmap?
        # Poderia usar nm.scan_async com callback, mas aumenta complexidade.

        try:
            # Nota: O timeout do Nmap é complexo (--host-timeout, -T<0-5>)
            # O argumento 'timeout' do scan() do python-nmap pode não funcionar como esperado.
            scan_output = nm.scan(hosts=target_string, ports=ports_str, arguments=self.nmap_args)
            
            # Verificar se foi interrompido durante o scan Nmap (difícil de detectar precisamente)
            if self.should_stop:
                 self.logger.warning("Sinal de interrupção recebido durante ou após execução do Nmap.")
                 # Retorna o que Nmap conseguiu processar até então
                 # Pode estar incompleto

            self.logger.debug(f"Comando Nmap real executado: {nm.command_line()}")

            if not nm.all_hosts():
                self.logger.info("Nmap: Nenhum host encontrado/ativo nos alvos escaneados.")
                return {}

            # Processar resultados
            for host in nm.all_hosts():
                if host not in results:
                    results[host] = {}
                # Verificar protocolos (geralmente TCP)
                if nm[host].all_protocols():
                     proto = nm[host].all_protocols()[0] # Assume TCP na maioria dos casos
                     if proto in nm[host]:
                          lports = nm[host][proto].keys()
                          for port in lports:
                              port_info = nm[host][proto][port]
                              if port_info['state'] == 'open':
                                  service_details = {
                                      'state': port_info['state'],
                                      'name': port_info.get('name', self.port_map.get(port, 'unknown')),
                                      'product': port_info.get('product', ''),
                                      'version': port_info.get('version', ''),
                                      'extrainfo': port_info.get('extrainfo', ''),
                                      'cpe': port_info.get('cpe', '')
                                  }
                                  results[host][port] = service_details
                                  self.logger.debug(f"Porta aberta (Nmap): {host}:{port} - {service_details}")
                else:
                     self.logger.debug(f"Nenhum protocolo TCP/UDP encontrado para o host {host} nos resultados do Nmap.")

            # Logar estatísticas do Nmap
            scan_stats = scan_output.get('scanstats', {})
            elapsed = scan_stats.get('elapsed', '?')
            uphosts = scan_stats.get('uphosts', '?')
            # totalhosts = scan_stats.get('totalhosts', '?') # Pode ser útil
            self.logger.info(f"Nmap concluído em {elapsed}s. Hosts ativos encontrados: {uphosts}.")

        except nmap.nmap.PortScannerError as e:
            # Erros específicos do Nmap (ex: permissão, argumento inválido)
            self.logger.error(f"Erro durante execução do Nmap: {e}")
            return None # Indica falha no Nmap
        except Exception as e:
            self.logger.exception(f"Erro inesperado durante o escaneamento Nmap: {e}")
            return None # Indica falha inesperada

        return results

    def scan(self):
        """
        Executa o escaneamento de rede, resolvendo nomes, escolhendo Nmap ou Socket.
        Retorna dict {host: {port: {details}}}.
        """
        scan_overall_start_time = time.time()
        self.should_stop = False # Reseta flag de parada
        
        # 1. Resolver todos os alvos para IPs
        resolved_ips = self._resolve_targets_to_ips()
        if not resolved_ips:
            self.logger.warning("Nenhum IP válido para escanear após resolução de alvos.")
            return {}
        if self.should_stop: # Verifica se a resolução foi interrompida
             self.logger.warning("Escaneamento cancelado durante a resolução de alvos.")
             return {}

        # 2. Decidir método de scan e executar
        results = None
        scan_method = "Nmap" if self.actually_use_nmap else "Socket"
        self.logger.info(f"Usando método de escaneamento: {scan_method}")

        if self.actually_use_nmap:
            nmap_results = self._scan_with_nmap(resolved_ips)
            if nmap_results is not None: # Nmap executou (mesmo que sem resultados)
                 results = nmap_results
            else:
                 self.logger.warning("Falha crítica ao executar Nmap. Tentando fallback para escaneamento com sockets...")
                 # Fallback para socket scan apenas se Nmap falhou catastroficamente
                 results = self._scan_with_socket(resolved_ips)
        else:
            if self.nmap_is_available and not self.use_nmap_flag:
                 self.logger.info("Nmap está disponível, mas --no-nmap foi especificado. Usando escaneamento com sockets.")
            elif not self.nmap_is_available:
                 self.logger.info("Nmap não disponível. Usando escaneamento com sockets.")
            results = self._scan_with_socket(resolved_ips)

        if self.should_stop: # Verifica se o scan foi interrompido
             self.logger.warning("Escaneamento interrompido durante a execução.")
             # Retorna o que foi coletado até o momento

        scan_overall_duration = time.time() - scan_overall_start_time
        self.logger.info(f"Fase completa de escaneamento de rede ({scan_method}) concluída em {format_time(scan_overall_duration)}.")

        # 3. Exibir resumo no console (apenas se não interrompido e houver resultados)
        if not self.should_stop and results:
            print(f"\n{Fore.GREEN}[+] Resultados do Escaneamento ({scan_method}):{Style.RESET_ALL}")
            found_hosts_count = len(results)
            print(f"    {Fore.CYAN}Hosts com portas abertas encontrados: {found_hosts_count}{Style.RESET_ALL}")
            # Limitar a exibição no console para não ficar muito longo?
            max_hosts_to_print = 20
            hosts_printed = 0
            for host, services in results.items():
                 if hosts_printed >= max_hosts_to_print:
                     print(f"    {Fore.YELLOW}... (mais {found_hosts_count - hosts_printed} hosts encontrados, veja o log/arquivo para detalhes){Style.RESET_ALL}")
                     break
                 print(f"    {Fore.YELLOW}Host: {host}{Style.RESET_ALL}")
                 for port, details in services.items():
                     service_name = details.get('name', '?')
                     product = details.get('product', '')
                     version = details.get('version', '')
                     info_str = f"{product} {version}".strip()
                     display_name = f"{service_name} ({info_str})" if info_str else service_name
                     print(f"        {Fore.MAGENTA}Porta {port}:{Style.RESET_ALL} {display_name}")
                 hosts_printed += 1
        elif not self.should_stop:
            print(f"\n{Fore.YELLOW}[-] Nenhum host com as portas especificadas abertas foi encontrado.{Style.RESET_ALL}")

        return results if results is not None else {}

    def stop(self):
        """ Sinaliza para parar o escaneamento. """
        self.logger.warning("Recebido sinal para interromper o escaneamento...")
        self.should_stop = True
        # TODO: Tentar interromper processo Nmap se estiver rodando? (Complexo)
