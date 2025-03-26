#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import time
import argparse
import logging
from datetime import datetime

# Importando módulos personalizados
try:
    from modules.network_scanner import NetworkScanner
    from modules.brute_force import BruteForceAttacker
    from modules.utils import setup_logger, print_banner, validate_target
except ImportError:
    print("[!] Erro ao importar módulos. Verifique se estão instalados corretamente.")
    sys.exit(1)

def parse_arguments():
    """Parse os argumentos da linha de comando."""
    parser = argparse.ArgumentParser(description="Ferramenta de escaneamento Wi-Fi e brute force")
    
    parser.add_argument("-t", "--target", help="Alvo (IP único ou range CIDR, ex: 192.168.1.0/24)")
    parser.add_argument("-p", "--ports", default="22,21,80,443,3389,23", 
                        help="Portas para escanear (separadas por vírgula, padrão: 22,21,80,443,3389,23)")
    parser.add_argument("-u", "--userlist", default="wordlists/users.txt", 
                        help="Caminho para a lista de usuários")
    parser.add_argument("-w", "--wordlist", default="wordlists/passwords.txt", 
                        help="Caminho para a lista de senhas")
    parser.add_argument("-o", "--output", default=f"logs/scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log", 
                        help="Arquivo de saída para salvar os resultados")
    parser.add_argument("--timeout", type=int, default=5, 
                        help="Timeout para conexões (segundos)")
    parser.add_argument("--brute-force", action="store_true", 
                        help="Realizar brute force após o escaneamento")
    parser.add_argument("-v", "--verbose", action="store_true", 
                        help="Modo verbose (mais detalhes)")
    
    return parser.parse_args()

def main():
    """Função principal do programa."""
    args = parse_arguments()
    
    # Configuração de diretórios necessários
    os.makedirs("logs", exist_ok=True)
    os.makedirs("wordlists", exist_ok=True)
    
    # Configuração de logging
    log_level = logging.DEBUG if args.verbose else logging.INFO
    logger = setup_logger(args.output, log_level)
    
    # Exibir banner
    print_banner()
    
    # Validar alvo
    if not args.target:
        logger.error("É necessário especificar um alvo com -t/--target")
        sys.exit(1)
    
    if not validate_target(args.target):
        logger.error(f"Alvo inválido: {args.target}")
        sys.exit(1)
    
    # Iniciando o escaneamento de rede
    logger.info(f"Iniciando escaneamento de rede em: {args.target}")
    
    try:
        # Criar instância do scanner
        scanner = NetworkScanner(args.target, args.ports.split(','), args.timeout, logger)
        
        # Iniciar escaneamento
        start_time = time.time()
        scan_results = scanner.scan()
        scan_duration = time.time() - start_time
        
        logger.info(f"Escaneamento concluído em {scan_duration:.2f} segundos")
        
        # Exibir resultados do escaneamento
        if scan_results:
            logger.info(f"Encontrados {len(scan_results)} hosts com serviços abertos")
            for host, services in scan_results.items():
                logger.info(f"Host: {host}")
                for port, service in services.items():
                    logger.info(f"  Porta {port}: {service}")
        else:
            logger.info("Nenhum host ou serviço encontrado")
        
        # Realizar brute force se solicitado
        if args.brute_force and scan_results:
            logger.info("Iniciando tentativas de brute force...")
            
            # Verificar se os arquivos de wordlist existem
            if not os.path.exists(args.userlist):
                logger.error(f"Lista de usuários não encontrada: {args.userlist}")
                sys.exit(1)
            
            if not os.path.exists(args.wordlist):
                logger.error(f"Lista de senhas não encontrada: {args.wordlist}")
                sys.exit(1)
            
            # Carregar listas
            with open(args.userlist, 'r', errors='ignore') as f:
                users = [line.strip() for line in f if line.strip()]
            
            logger.info(f"Carregados {len(users)} usuários para teste")
            
            # Iniciar brute force
            attacker = BruteForceAttacker(scan_results, users, args.wordlist, args.timeout, logger)
            credentials = attacker.attack()
            
            # Salvar credenciais encontradas
            if credentials:
                logger.info(f"Encontradas {len(credentials)} credenciais válidas:")
                for host, creds in credentials.items():
                    for service, user_pass in creds.items():
                        for user, password in user_pass:
                            logger.info(f"[+] {host}:{service} - {user}:{password}")
            else:
                logger.info("Nenhuma credencial encontrada")
                
    except KeyboardInterrupt:
        logger.info("\n[!] Operação cancelada pelo usuário")
    except Exception as e:
        logger.error(f"Erro durante a execução: {str(e)}")
    
    logger.info("Escaneamento finalizado. Resultados salvos em: " + args.output)

if __name__ == "__main__":
    main()