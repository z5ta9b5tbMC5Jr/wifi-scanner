#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import re
import sys
import logging
import ipaddress
from colorama import init, Fore, Style
from logging.handlers import RotatingFileHandler

# Inicializar colorama para formatação no terminal
init(autoreset=True)

# Tamanho máximo do log e número de backups
LOG_MAX_BYTES = 5 * 1024 * 1024  # 5 MB
LOG_BACKUP_COUNT = 3

def setup_logger(log_file, level=logging.INFO, verbose=False):
    """
    Configura o logger principal da aplicação com handlers para console e arquivo.

    Inclui formatação colorida para o console e rotação de arquivos de log.

    Args:
        log_file (str): Caminho base para o arquivo de log.
        level (int, optional): Nível de logging base para o console (se não verbose).
                               Padrão: logging.INFO.
        verbose (bool, optional): Se True, define o nível do console para DEBUG.
                                Padrão: False.

    Returns:
        logging.Logger: Objeto logger configurado.
    """
    # Criar diretório de logs se não existir
    log_dir = os.path.dirname(log_file)
    if log_dir and not os.path.exists(log_dir):
        try:
            os.makedirs(log_dir)
            print(f"Diretório de logs criado: {log_dir}") # Feedback no console
        except OSError as e:
            print(f"{Fore.RED}Erro ao criar diretório de logs '{log_dir}': {e}{Style.RESET_ALL}")
            # Prosseguir sem log em arquivo se não conseguir criar diretório
            log_file = None

    logger = logging.getLogger('wifi_scanner')
    # Define o nível CAPTURA do logger como DEBUG para pegar tudo
    # O nível de cada HANDLER definirá o que realmente é mostrado/salvo
    logger.setLevel(logging.DEBUG)
    logger.propagate = False # Evita duplicação se root logger estiver configurado

    # Remover handlers existentes para evitar duplicação em re-configurações
    if logger.hasHandlers():
        logger.handlers.clear()

    # Formatter base
    log_format = '%(asctime)s - %(levelname)s - %(message)s'
    date_format = '%Y-%m-%d %H:%M:%S'
    base_formatter = logging.Formatter(log_format, datefmt=date_format)

    # --- Handler para Arquivo --- 
    if log_file:
        try:
            # Usar RotatingFileHandler para controle de tamanho
            file_handler = RotatingFileHandler(
                log_file, 
                maxBytes=LOG_MAX_BYTES, 
                backupCount=LOG_BACKUP_COUNT,
                encoding='utf-8' # Especificar encoding
            )
            file_handler.setFormatter(base_formatter)
            # O nível do ARQUIVO geralmente captura mais detalhes (DEBUG)
            file_handler.setLevel(logging.DEBUG)
            logger.addHandler(file_handler)
        except Exception as e:
            # Logar erro no console se falhar ao configurar o handler de arquivo
            print(f"{Fore.RED}Erro crítico ao configurar log em arquivo '{log_file}': {e}{Style.RESET_ALL}")

    # --- Handler para Console --- 
    try:
        console_formatter = ColoredFormatter(log_format, datefmt=date_format)
        console_handler = logging.StreamHandler(sys.stdout) # Usar sys.stdout explicitamente
        console_handler.setFormatter(console_formatter)
        # Nível do CONSOLE depende do modo verbose
        console_handler.setLevel(logging.DEBUG if verbose else level)
        logger.addHandler(console_handler)
    except Exception as e:
         # Em caso extremo de falha ao configurar console log, printar erro
         print(f"{Fore.RED}Erro crítico ao configurar logger do console: {e}{Style.RESET_ALL}")

    return logger


# Classe para adicionar cores ao logging no console
class ColoredFormatter(logging.Formatter):
    """Formatter customizado para adicionar cores aos logs do console."""
    LEVEL_COLORS = {
        logging.DEBUG: Fore.CYAN,
        logging.INFO: Fore.GREEN,
        logging.WARNING: Fore.YELLOW,
        logging.ERROR: Fore.RED,
        logging.CRITICAL: Fore.MAGENTA + Style.BRIGHT # Destacar Critical
    }

    def format(self, record):
        # Armazenar o nome original do nível
        level_original_name = record.levelname 
        # Pegar a cor ou default
        color = self.LEVEL_COLORS.get(record.levelno, Fore.WHITE)
        # Colorir o nome do nível para o output formatado
        record.levelname = f"{color}{level_original_name}{Style.RESET_ALL}"
        # Formatar a mensagem usando o Formatter pai
        formatted_message = super().format(record)
        # Restaurar o nome original para não afetar outros handlers (se houver)
        record.levelname = level_original_name 
        # Adiciona cor à mensagem inteira se for WARNING ou superior (opcional)
        # if record.levelno >= logging.WARNING:
        #      formatted_message = f"{color}{formatted_message}{Style.RESET_ALL}"
        return formatted_message

def print_banner():
    """
    Exibe o banner da aplicação no terminal usando Colorama.
    Inclui um aviso sobre o uso ético.
    """
    # Gerador de banner simples (pode ser substituído por arte ASCII mais elaborada)
    banner = f"""
{Fore.BLUE}=============================================================={Style.RESET_ALL}
{Fore.CYAN}          WiFi Scanner & Brute Force Tool {Style.RESET_ALL}
{Fore.BLUE}=============================================================={Style.RESET_ALL}
 {Fore.WHITE}Version: 1.1.0 (Improved){Style.RESET_ALL}
 {Fore.WHITE}Author: Bypass{Style.RESET_ALL}
{Fore.YELLOW}--------------------------------------------------------------{Style.RESET_ALL}
{Fore.RED}      *** USO ESTRITAMENTE EDUCACIONAL E ÉTICO ***{Style.RESET_ALL}
{Fore.RED}   NÃO utilize esta ferramenta em redes sem permissão.{Style.RESET_ALL}
{Fore.RED} O uso indevido pode violar leis e causar problemas.{Style.RESET_ALL}
{Fore.YELLOW}--------------------------------------------------------------{Style.RESET_ALL}
    """
    print(banner) # Usar print direto, pois o logger pode não estar pronto ou ter nível diferente

def validate_target(target_input):
    """
    Valida e normaliza a entrada de alvos.

    Aceita:
    - IP único (ex: "192.168.1.1")
    - Range CIDR (ex: "192.168.1.0/24")
    - Múltiplos IPs/CIDRs separados por vírgula (ex: "192.168.1.1,10.0.0.0/8")
    - Nomes de host (DNS será resolvido posteriormente)

    Args:
        target_input (str): String contendo os alvos.

    Returns:
        list: Lista de strings de alvos validados e normalizados (IPs, CIDRs, ou nomes).
              Retorna lista vazia se nenhum alvo válido for encontrado.
    """
    validated_targets = []
    # Lidar com possíveis espaços extras antes/depois da vírgula
    potential_targets = [t.strip() for t in target_input.split(',') if t.strip()]

    if not potential_targets:
        # Não loga aqui, a verificação é feita no main
        return []

    logger = logging.getLogger('wifi_scanner') # Obter logger para warnings

    for target in potential_targets:
        is_valid = False
        try:
            # Tenta validar como IP ou Rede
            if '/' in target:
                ipaddress.ip_network(target, strict=False)
                validated_targets.append(target)
                is_valid = True
            else:
                ipaddress.ip_address(target)
                validated_targets.append(target)
                is_valid = True
        except ValueError:
            # Se não for IP/Rede, verifica se parece um nome de host razoável
            # Regex simples para nomes de host (permite domínios e subdomínios)
            # Permite hífen, mas não no início ou fim de um componente.
            # Não valida TLDs específicos.
            if re.match(r"^(([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9])\.)*([A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9\-]*[A-Za-z0-9])$", target):
                 logger.warning(f"Alvo '{target}' parece ser um nome de host. Será usado, mas a resolução DNS ocorrerá durante o scan.")
                 validated_targets.append(target)
                 is_valid = True
            else:
                # Se não for IP, Rede ou Hostname válido, loga como erro
                logger.error(f"Alvo inválido ou formato não reconhecido: '{target}'. Ignorando.")

    return validated_targets

def format_time(seconds):
    """
    Formata um tempo em segundos para uma string legível (h, m, s).

    Args:
        seconds (float): Duração em segundos.

    Returns:
        str: String formatada representando a duração.
    """
    if not isinstance(seconds, (int, float)) or seconds < 0:
        return "tempo inválido"
    if seconds < 1:
        return f"{seconds * 1000:.1f} ms"
    if seconds < 60:
        return f"{seconds:.2f} s"

    minutes, sec = divmod(seconds, 60)
    hours, minutes = divmod(minutes, 60)

    parts = []
    if hours >= 1:
        parts.append(f"{int(hours)}h")
    if minutes >= 1:
        parts.append(f"{int(minutes)}m")
    # Mostrar segundos apenas se a duração for menor que 1 minuto ou se houver horas/minutos
    if seconds < 60 or sec > 0:
         parts.append(f"{sec:.2f}s")

    return " ".join(parts)
