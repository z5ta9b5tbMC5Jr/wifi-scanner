#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import time
import argparse
import logging
import json # Para output JSON
import csv  # Para output CSV
from datetime import datetime
from colorama import Fore, Style # Importar Fore e Style aqui

# Importando módulos personalizados
try:
    from modules.network_scanner import NetworkScanner
    from modules.brute_force import BruteForceAttacker
    # Agora importamos a função de validação que retorna lista
    from modules.utils import setup_logger, print_banner, validate_target, format_time
except ImportError as e:
    print(f"[!] Erro fatal ao importar módulos: {e}\n" 
          "Verifique se os módulos estão na pasta 'modules' e se as dependências estão instaladas.")
    sys.exit(1)

def parse_arguments():
    """Parseia os argumentos da linha de comando usando argparse."""
    parser = argparse.ArgumentParser(
        description="Ferramenta de Escaneamento Wi-Fi e Brute Force",
        epilog="Exemplo: python wifi_scanner.py -t 192.168.1.0/24 --brute-force -v --output-format json"
    )

    # Alvo(s)
    target_group = parser.add_mutually_exclusive_group(required=True)
    target_group.add_argument("-t", "--target", help="Alvo(s) (IP, CIDR, múltiplos separados por vírgula)")
    target_group.add_argument("--target-file", help="Arquivo contendo alvos (um por linha)")

    # Escaneamento
    scan_group = parser.add_argument_group("Opções de Escaneamento")
    scan_group.add_argument("-p", "--ports", default="22,80,443,21,23,3389",
                            help="Portas para escanear (separadas por vírgula, padrão: 22,80,443,21,23,3389)")
    scan_group.add_argument("--scan-timeout", type=float, default=1.0,
                            help="Timeout para conexão de socket no scan (segundos, padrão: 1.0)")
    scan_group.add_argument("--scan-workers", type=int, default=50,
                            help="Número de threads para o scan de portas (padrão: 50)")
    scan_group.add_argument("--nmap-args", default="-sV -T4",
                           help='Argumentos Nmap (padrão: \"-sV -T4\", use \"\" para desabilitar args extras)')
    scan_group.add_argument("--no-nmap", action="store_true",
                             help="Forçar o uso de escaneamento por socket mesmo se Nmap estiver disponível")

    # Brute Force
    brute_group = parser.add_argument_group("Opções de Brute Force")
    brute_group.add_argument("--brute-force", action="store_true",
                             help="Ativar módulo de brute force após o escaneamento")
    brute_group.add_argument("-U", "--userlist", default="wordlists/users.txt",
                             help="Caminho para a lista de usuários (padrão: wordlists/users.txt)")
    brute_group.add_argument("-P", "--passlist", default="wordlists/passwords.txt",
                             help="Caminho para a lista de senhas (padrão: wordlists/passwords.txt)")
    brute_group.add_argument("--brute-timeout", type=float, default=3.0,
                             help="Timeout para tentativas de login no brute force (segundos, padrão: 3.0)")
    brute_group.add_argument("--brute-workers", type=int, default=10,
                             help="Número de threads para o brute force (padrão: 10)")

    # Saída e Logging
    output_group = parser.add_argument_group("Opções de Saída")
    output_group.add_argument("-o", "--output", default=f"logs/scan_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
                              help="Nome base do arquivo de saída (sem extensão)")
    output_group.add_argument("--output-format", choices=['log', 'json', 'csv'], default='log',
                              help="Formato do arquivo de saída (log, json, csv)")
    output_group.add_argument("-v", "--verbose", action="store_true",
                              help="Modo verbose (exibe logs DEBUG no console)")

    if len(sys.argv) == 1:
        parser.print_help(sys.stderr)
        sys.exit(1)

    return parser.parse_args()

def save_results(output_base, format_type, scan_results, found_credentials, logger):
    """Salva os resultados do scan e brute force no formato especificado."""
    output_file = f"{output_base}.{format_type}"
    logger.info(f"Salvando resultados no formato '{format_type}' em: {output_file}")

    try:
        if format_type == 'json':
            data_to_save = {
                "scan_results": scan_results,
                "found_credentials": found_credentials
            }
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(data_to_save, f, indent=4, ensure_ascii=False)

        elif format_type == 'csv':
            with open(output_file, 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                # Cabeçalho Scan
                writer.writerow(['Tipo', 'Host', 'Porta', 'Servico', 'Produto', 'Versao'])
                if scan_results:
                     for host, ports in scan_results.items():
                         for port, details in ports.items():
                             writer.writerow([
                                 'Scan',
                                 host,
                                 port,
                                 details.get('name', 'N/A'),
                                 details.get('product', 'N/A'),
                                 details.get('version', 'N/A')
                             ])
                # Separador (opcional)
                writer.writerow([])
                # Cabeçalho Brute Force
                writer.writerow(['Tipo', 'Host', 'ServicoPorta', 'Usuario', 'Senha'])
                if found_credentials:
                    for host, services in found_credentials.items():
                        for service, creds in services.items():
                            for user, password in creds:
                                writer.writerow([
                                    'BruteForce',
                                    host,
                                    service, # O nome do serviço já inclui a porta no brute_force.py
                                    user,
                                    password
                                ])

        elif format_type == 'log':
            # O formato log já é tratado pelo logger, mas podemos adicionar um resumo
            # Garante que o arquivo de log principal exista antes de anexar
            log_file_path = args.output + ".log" if args.output_format == 'log' else f"logs/wifi_scanner_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
            if not os.path.exists(log_file_path):
                 logger.warning(f"Arquivo de log principal {log_file_path} não encontrado para anexar resumo. Criando/usando arquivo de saída {output_file}.")
                 target_log_file = output_file # Salva o resumo no arquivo -o se o log principal não existir
            else:
                 target_log_file = log_file_path
            
            try:
                with open(target_log_file, 'a', encoding='utf-8') as f:
                    f.write("\n" + "="*40 + " RESUMO DOS RESULTADOS " + "="*40 + "\n")
                    f.write("\n--- Resultados do Escaneamento ---\n")
                    if scan_results:
                        for host, ports in scan_results.items():
                            f.write(f"Host: {host}\n")
                            for port, details in ports.items():
                                service_name = details.get('name', 'unknown')
                                product = details.get('product', '')
                                version = details.get('version', '')
                                info_str = f"{product} {version}".strip()
                                display_name = f"{service_name} ({info_str})" if info_str else service_name
                                f.write(f"  Porta {port}: {display_name}\n")
                    else:
                        f.write("Nenhum host com portas abertas encontrado.\n")

                    f.write("\n--- Credenciais Encontradas (Brute Force) ---\n")
                    if found_credentials:
                        for host, services in found_credentials.items():
                            for service, creds in services.items():
                                f.write(f"Host: {host}, Serviço: {service}\n")
                                for user, password in creds:
                                    f.write(f"  [+] Usuario: {user}, Senha: {password}\n")
                    else:
                        f.write("Nenhuma credencial encontrada.\n")
                    f.write("\n" + "="*100 + "\n")
                if target_log_file == log_file_path:
                     logger.info(f"Resumo dos resultados adicionado ao final do log principal: {log_file_path}")
            except IOError as e:
                 logger.error(f"Erro de I/O ao anexar resumo ao log '{target_log_file}': {e}")


        logger.info(f"Resultados salvos com sucesso em {output_file}")

    except IOError as e:
        logger.error(f"Erro de I/O ao salvar resultados em '{output_file}': {e}")
    except Exception as e:
        logger.error(f"Erro inesperado ao salvar resultados em '{output_file}': {e}")

def load_targets_from_file(filepath):
    """Carrega alvos de um arquivo, um por linha."""
    targets = []
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            targets = [line.strip() for line in f if line.strip() and not line.startswith('#')]
        if not targets:
            print(f"{Fore.YELLOW}Aviso: Arquivo de alvos '{filepath}' está vazio ou contém apenas comentários.{Style.RESET_ALL}")
    except FileNotFoundError:
        print(f"{Fore.RED}Erro: Arquivo de alvos não encontrado: '{filepath}'{Style.RESET_ALL}")
        return None # Indica erro
    except IOError as e:
        print(f"{Fore.RED}Erro ao ler arquivo de alvos '{filepath}': {e}{Style.RESET_ALL}")
        return None # Indica erro
    return targets

def main():
    """Função principal: Parseia args, configura logging, executa scan e brute force."""
    args = parse_arguments()
    script_start_time = time.time() # Tempo inicial para cálculo da duração total

    # Configuração inicial de diretórios
    os.makedirs("logs", exist_ok=True)
    os.makedirs("wordlists", exist_ok=True)

    # Configuração de logging (agora depende do verbose)
    # Garante um log principal sempre, mesmo se a saída for json/csv
    log_file_base = args.output if args.output_format == 'log' else f"logs/run_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    log_file_path = f"{log_file_base}.log"
    logger = setup_logger(log_file_path, level=logging.INFO, verbose=args.verbose)

    print_banner()

    # --- Processamento de Alvos ---
    targets = []
    if args.target_file:
        logger.info(f"Carregando alvos do arquivo: {args.target_file}")
        loaded_targets = load_targets_from_file(args.target_file)
        if loaded_targets is None: # Erro ao carregar arquivo
            sys.exit(1)
        targets = loaded_targets
    elif args.target:
        # Validação básica aqui, refinar em validate_target
        targets = [t.strip() for t in args.target.split(',') if t.strip()]

    if not targets:
         logger.critical("Nenhum alvo especificado ou carregado. Encerrando.")
         sys.exit(1)

    # Validar e normalizar alvos usando a função de utils
    validated_targets = validate_target(",".join(targets)) # Re-join para a função que espera string
    if not validated_targets:
        logger.error("Nenhum alvo válido encontrado após validação. Verifique os IPs/CIDRs/Arquivo fornecidos.")
        sys.exit(1)
    logger.info(f"Alvos validados para escaneamento: {validated_targets}")

    # --- Processamento de Portas ---
    try:
        ports_list = [int(p.strip()) for p in args.ports.split(',') if p.strip().isdigit()]
        if not ports_list:
            raise ValueError("Nenhuma porta numérica válida fornecida.")
        ports_list = sorted(list(set(ports_list))) # Garante unique e ordenado
        logger.info(f"Portas a serem escaneadas: {ports_list}")
    except ValueError as e:
        logger.error(f"Erro ao processar a lista de portas ('{args.ports}'): {e}. Use números separados por vírgula.")
        sys.exit(1)

    scan_results = {}
    found_credentials = {}
    scanner = None
    attacker = None

    try:
        # --- Escaneamento de Rede ---
        scan_start_time = time.time()
        logger.info(f"Iniciando escaneamento de rede... (Use CTRL+C para interromper)")
        scanner = NetworkScanner(
            targets=validated_targets,
            ports=ports_list,
            timeout=args.scan_timeout,
            max_workers=args.scan_workers,
            use_nmap=not args.no_nmap,
            nmap_args=args.nmap_args,
            logger=logger
        )
        scan_results = scanner.scan() # Este método agora exibe seu próprio resumo
        scan_duration = time.time() - scan_start_time
        logger.info(f"Fase de escaneamento concluída em {format_time(scan_duration)}.")

        # --- Brute Force (se ativado e houver resultados) ---
        if args.brute_force:
            if not scan_results:
                logger.warning("Brute force ativado, mas nenhum host com portas abertas encontrado no escaneamento. Pulando brute force.")
            else:
                logger.info("Iniciando fase de Brute Force... (Use CTRL+C para interromper)")

                # Verificar existência das wordlists
                userlist_ok = os.path.exists(args.userlist)
                passlist_ok = os.path.exists(args.passlist)

                if not userlist_ok:
                     logger.error(f"Lista de usuários não encontrada: '{args.userlist}'. Pulando brute force.")
                elif not passlist_ok:
                     logger.error(f"Lista de senhas não encontrada: '{args.passlist}'. Pulando brute force.")
                else:
                    # Carregar usuários (senhas são carregadas dentro do attacker)
                    users = []
                    try:
                        with open(args.userlist, 'r', errors='ignore') as f:
                            users = [line.strip() for line in f if line.strip()]
                        if not users:
                            logger.warning(f"Lista de usuários '{args.userlist}' está vazia. Pulando brute force.")
                        else:
                             logger.info(f"Carregados {len(users)} usuários de '{args.userlist}'")
                    except IOError as e:
                         logger.error(f"Erro ao ler lista de usuários '{args.userlist}': {e}. Pulando brute force.")
                         users = [] # Garante que não prossiga

                    if users: # Procede apenas se usuários foram carregados
                        brute_start_time = time.time()
                        attacker = BruteForceAttacker(
                            scan_results=scan_results,
                            users=users,
                            wordlist_path=args.passlist,
                            timeout=args.brute_timeout,
                            max_workers=args.brute_workers,
                            logger=logger
                        )
                        found_credentials = attacker.attack() # O ataque agora usa tqdm interno e loga sucessos
                        brute_duration = time.time() - brute_start_time
                        logger.info(f"Fase de Brute Force concluída em {format_time(brute_duration)}.")

                        # Contagem final de credenciais
                        total_creds_found = sum(len(creds) for service in found_credentials.values() for creds in service.values())
                        if total_creds_found > 0:
                            logger.info(f"{Fore.GREEN}Total de {total_creds_found} credenciais encontradas! Ver detalhes no log/arquivo de saída.{Style.RESET_ALL}")
                        else:
                            logger.info(f"{Fore.YELLOW}Nenhuma credencial encontrada durante o brute force.{Style.RESET_ALL}")

    except KeyboardInterrupt:
        logger.warning("\n[!] Operação interrompida pelo usuário (CTRL+C).")
        # Tenta parar os processos filhos/threads gracefully
        if hasattr(scanner, 'stop') and callable(scanner.stop):
             logger.info("Tentando interromper o escaneamento...")
             scanner.stop()
        if attacker:
             logger.info("Tentando interromper o brute force...")
             attacker.stop()
        print("Aguarde um momento para finalizar...")
        # Espera um pouco para permitir que as threads/processos terminem
        time.sleep(2)
    except Exception as e:
        logger.exception(f"Erro fatal durante a execução: {e}") # Usa logger.exception para incluir traceback
        # Considerar adicionar mais detalhes dependendo do erro
    finally:
        # --- Salvando Resultados ---
        # Salva em JSON/CSV se solicitado E se houver resultados
        if args.output_format != 'log' and (scan_results or found_credentials):
             output_file_base = args.output # Usa o -o como base para json/csv
             save_results(output_file_base, args.output_format, scan_results, found_credentials, logger)
        elif not scan_results and not found_credentials:
             logger.info("Nenhum resultado de scan ou brute force para salvar.")
        else:
            # Se o formato for log, o resumo já foi adicionado (ou será, se erro ocorreu antes)
            # Mas podemos garantir que um resumo seja adicionado se a execução foi interrompida
            if args.output_format == 'log':
                 save_results(log_file_base, 'log', scan_results, found_credentials, logger)


        total_duration = time.time() - script_start_time # Recalcula duração total
        logger.info(f"Execução total finalizada em {format_time(total_duration)}.")
        print(f"\n{Fore.CYAN}Log detalhado disponível em: {log_file_path}{Style.RESET_ALL}")
        if args.output_format != 'log' and (scan_results or found_credentials):
             output_path = f"{args.output}.{args.output_format}"
             print(f"{Fore.CYAN}Resultados formatados salvos em: {output_path}{Style.RESET_ALL}")

if __name__ == "__main__":
    main()
