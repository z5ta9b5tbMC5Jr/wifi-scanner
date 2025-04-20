# WiFi Scanner & Brute Force Tool (Versão 1.1.0+)

Ferramenta de linha de comando para escaneamento de redes e testes de força bruta em serviços comuns (SSH, FTP, Telnet, HTTP Basic Auth). Desenvolvida com Python.

**AVISO IMPORTANTE: USO ÉTICO**

> Esta ferramenta foi criada para fins **estritamente educacionais** e para **testes de segurança em redes e sistemas onde você possui autorização explícita**.
>
> O uso desta ferramenta em redes ou sistemas sem permissão é **ilegal** e **antiético**. O autor não se responsabiliza pelo mau uso desta ferramenta. Utilize com responsabilidade.

## Funcionalidades Principais

*   **Escaneamento de Rede:**
    *   Descoberta de hosts ativos em redes locais (IPs únicos ou ranges CIDR).
    *   Verificação de portas TCP abertas.
    *   Utiliza **Nmap** (via `python-nmap`) para detecção de serviços e versões (`-sV`) quando disponível, com fallback para escaneamento por **socket** Python.
    *   Paralelização usando `ThreadPoolExecutor` para acelerar o scan.
    *   Barra de progresso (`tqdm`) para feedback visual.
*   **Ataque de Força Bruta:**
    *   Tentativas de login em serviços descobertos (SSH, FTP, Telnet, HTTP Basic).
    *   Utiliza listas de usuários e senhas fornecidas.
    *   Paralelização usando `ThreadPoolExecutor`.
    *   Barra de progresso (`tqdm`).
    *   Verifica a disponibilidade das bibliotecas necessárias (`paramiko`, `ftplib`, `telnetlib`).
*   **Entrada Flexível:**
    *   Aceita múltiplos alvos (IPs, CIDRs) via linha de comando (separados por vírgula).
    *   Aceita lista de alvos de um arquivo (`--target-file`).
*   **Saída Configurável:**
    *   Logs detalhados em arquivo com rotação automática.
    *   Resultados podem ser salvos em formatos estruturados: **JSON** ou **CSV**.
    *   Feedback colorido no console.

## Instalação

1.  **Clone o repositório:**
    ```bash
    git clone <URL_DO_SEU_REPOSITÓRIO>
    cd wifi-scanner
    ```
2.  **Instale as dependências:**
    *   **Nmap:** É **altamente recomendável** instalar o Nmap no seu sistema operacional, pois ele melhora significativamente a detecção de serviços. Consulte a documentação oficial do Nmap para sua plataforma (Linux, macOS, Windows).
    *   **Dependências Python:**
        ```bash
        pip install -r requirements.txt
        ```

## Uso

A ferramenta é executada via linha de comando.

```bash
python wifi_scanner.py [OPÇÕES]
```

**Exemplos:**

*   **Scan simples em uma rede, salvando em JSON:**
    ```bash
    python wifi_scanner.py -t 192.168.1.0/24 -p 21,22,80,443 -o resultados_scan --output-format json -v
    ```
*   **Scan usando Nmap com argumentos customizados e brute force com listas padrão:**
    ```bash
    python wifi_scanner.py -t 192.168.1.10,192.168.1.20 --nmap-args="-sV -T5 --top-ports 100" --brute-force -U users.txt -P common_pass.txt -o ataque_log --verbose
    ```
*   **Scan lendo alvos de um arquivo e forçando scan por socket:**
    ```bash
    python wifi_scanner.py --target-file lista_alvos.txt --no-nmap --brute-force --brute-workers 20 -o scan_socket
    ```
*   **Apenas scan, sem brute force, salvando em CSV:**
    ```bash
    python wifi_scanner.py -t 10.0.0.5 -p 1-1000 -o scan_rapido --output-format csv
    ```

**Opções Principais (use `python wifi_scanner.py -h` para ver todas):**

*   **Alvo:**
    *   `-t`, `--target IP[,IP,...]`: Especifica um ou mais alvos (IP, CIDR).
    *   `--target-file ARQUIVO`: Lê alvos de um arquivo (um por linha).
*   **Scan:**
    *   `-p`, `--ports PORTAS`: Portas a escanear (ex: `22,80` ou `1-1024`).
    *   `--scan-timeout SEGUNDOS`: Timeout para conexão socket (padrão: 1.0).
    *   `--scan-workers NUM`: Threads para scan (padrão: 50).
    *   `--nmap-args 'ARGS'`: Argumentos para Nmap (padrão: `"-sV -T4"`).
    *   `--no-nmap`: Força o uso de sockets.
*   **Brute Force:**
    *   `--brute-force`: Ativa o módulo.
    *   `-U`, `--userlist ARQUIVO`: Lista de usuários.
    *   `-P`, `--passlist ARQUIVO`: Lista de senhas.
    *   `--brute-timeout SEGUNDOS`: Timeout para login (padrão: 3.0).
    *   `--brute-workers NUM`: Threads para brute force (padrão: 10).
*   **Saída:**
    *   `-o`, `--output NOME_BASE`: Nome base para arquivos de saída.
    *   `--output-format {log,json,csv}`: Formato do arquivo de resultados (padrão: log).
    *   `-v`, `--verbose`: Aumenta o nível de detalhes no console (DEBUG).

## Estrutura do Projeto

*   `wifi_scanner.py`: Script principal.
*   `modules/`: Contém os módulos da aplicação:
    *   `network_scanner.py`: Classe `NetworkScanner`.
    *   `brute_force.py`: Classe `BruteForceAttacker`.
    *   `utils.py`: Funções utilitárias (logging, banner, validação, etc.).
*   `wordlists/`: Diretório para armazenar listas de usuários/senhas (arquivos de exemplo podem ser incluídos).
*   `logs/`: Diretório onde os arquivos de log e resultados são salvos por padrão.
*   `requirements.txt`: Dependências Python.
*   `README.md`: Esta documentação.
*   `LICENSE`: Licença do projeto (ex: MIT).

## TODO / Melhorias Futuras

*   Adicionar suporte a mais protocolos no brute force (ex: SMB, RDP, VNC, etc.).
*   Melhorar a detecção de prompts Telnet.
*   Opção para salvar apenas credenciais encontradas.
*   Interface gráfica (GUI) opcional.
*   Testes unitários e de integração.

## Licença

MIT License

Copyright (c) 2025 Security Engineer

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

LEGAL NOTICE:
THIS TOOL WAS DEVELOPED SOLELY FOR EDUCATIONAL AND SECURITY TESTING PURPOSES.
USING THIS TOOL TO ACCESS SYSTEMS UNAUTHORIZED IS ILLEGAL AND UNETHICAL.
THE AUTHOR DOES NOT ASSUME ANY RESPONSIBILITY FOR THE MISUSE OF THIS TOOL.

## Contribuições

Contribuições são bem-vindas! Sinta-se à vontade para abrir *Issues* ou *Pull Requests*.
