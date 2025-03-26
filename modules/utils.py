#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import re
import sys
import logging
import ipaddress
from colorama import init, Fore, Style

# Inicializar colorama para formatação no terminal
init(autoreset=True)

def setup_logger(log_file, level=logging.INFO):
    """Configura o logger para o programa.
    
    Args:
        log_file (str): Caminho para o arquivo de log
        level (int, optional): Nível de logging. Default é logging.INFO
        
    Returns:
        logging.Logger: Objeto logger configurado
    """
    # Criar o diretório de logs se não existir
    os.makedirs(os.path.dirname(log_file), exist_ok=True)
    
    # Configurar o logger
    logger = logging.getLogger('wifi_scanner')
    logger.setLevel(level)
    
    # Criando formatador para os logs
    formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s', 
                                 datefmt='%Y-%m-%d %H:%M:%S')
    
    # Handler para arquivo
    file_handler = logging.FileHandler(log_file)
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)
    
    # Handler para terminal
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)
    
    return logger

def print_banner():
    """Exibe o banner da aplicação no terminal."""
    banner = f"""
{Fore.BLUE}╔══════════════════════════════════════════════════╗
{Fore.BLUE}║  {Fore.YELLOW}__          ___  ______ _       {Fore.CYAN}  _____                                {Fore.BLUE}║
{Fore.BLUE}║  {Fore.YELLOW}\ \        / (_)/ ____(_)      {Fore.CYAN}  / ____|                               {Fore.BLUE}║
{Fore.BLUE}║  {Fore.YELLOW} \ \  /\  / / _| |     _       {Fore.CYAN} | (___   ___ __ _ _ __  _ __   ___ _ __ {Fore.BLUE}║
{Fore.BLUE}║  {Fore.YELLOW}  \ \/  \/ / | | |    | |      {Fore.CYAN}  \___ \ / __/ _` | '_ \| '_ \ / _ \ '__|{Fore.BLUE}║
{Fore.BLUE}║  {Fore.YELLOW}   \  /\  /  | | |    | |      {Fore.CYAN}  ____) | (_| (_| | | | | | | |  __/ |   {Fore.BLUE}║
{Fore.BLUE}║  {Fore.YELLOW}    \/  \/   |_|_|    |_|      {Fore.CYAN} |_____/ \___\__,_|_| |_|_| |_|\___|_|   {Fore.BLUE}║
{Fore.BLUE}╠══════════════════════════════════════════════════╣
{Fore.BLUE}║ {Fore.WHITE}Versão: 1.0.0{Style.RESET_ALL}                                    {Fore.BLUE}║
{Fore.BLUE}║ {Fore.WHITE}Autor: Security Engineer{Style.RESET_ALL}                        {Fore.BLUE}║
{Fore.BLUE}║ {Fore.RED}APENAS PARA FINS EDUCACIONAIS E TESTES AUTORIZADOS{Style.RESET_ALL} {Fore.BLUE}║
{Fore.BLUE}╚══════════════════════════════════════════════════╝
    """
    print(banner)

def validate_target(target):
    """Valida se o alvo é um IP ou range CIDR válido.
    
    Args:
        target (str): IP único ou range CIDR (ex: 192.168.1.1 ou 192.168.1.0/24)
        
    Returns:
        bool: True se válido, False caso contrário
    """
    try:
        # Verificar se é um range CIDR
        if '/' in target:
            ipaddress.ip_network(target, strict=False)
            return True
        # Verificar se é um IP único
        else:
            ipaddress.ip_address(target)
            return True
    except ValueError:
        return False

def format_time(seconds):
    """Formata o tempo em segundos para uma string legível.
    
    Args:
        seconds (float): Tempo em segundos
        
    Returns:
        str: Tempo formatado
    """
    if seconds < 60:
        return f"{seconds:.2f} segundos"
    elif seconds < 3600:
        minutes = int(seconds // 60)
        sec = seconds % 60
        return f"{minutes} minutos e {sec:.2f} segundos"
    else:
        hours = int(seconds // 3600)
        minutes = int((seconds % 3600) // 60)
        sec = seconds % 60
        return f"{hours} horas, {minutes} minutos e {sec:.2f} segundos"