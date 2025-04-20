# WiFi Scanner e Brute Force Tool

Uma ferramenta para escaneamento de redes Wi-Fi e tentativa de brute force em serviços encontrados.

## ⚠️ Aviso Legal

Esta ferramenta foi desenvolvida **APENAS PARA FINS EDUCACIONAIS E DE TESTE DE SEGURANÇA** em redes e sistemas AUTORIZADOS. O uso desta ferramenta para acesso não autorizado a sistemas é ilegal e antiético. O autor não assume qualquer responsabilidade pelo uso indevido desta ferramenta.

## 📋 Funcionalidades

- Escaneamento de redes para identificar hosts ativos
- Detecção de serviços e portas abertas
- Tentativas de brute force em serviços comuns:
  - SSH
  - FTP
  - HTTP/HTTPS (Basic Auth)
  - Telnet
- Log detalhado de atividades e resultados
- Interface de linha de comando completa e flexível

## 🔧 Requisitos

- Python 3.6+
- Nmap instalado no sistema (opcional, mas recomendado para melhores resultados)
- Acesso a privilégios de administrador (necessário para algumas operações de escaneamento)
- Bibliotecas Python:
  - python-nmap
  - paramiko (para SSH)
  - requests (para HTTP)
  - colorama (para formatação do terminal)
  - tqdm (para barras de progresso)

## 🔨 Instalação

1. Clone o repositório:
```bash
git clone https://github.com/z5ta9b5tbMC5Jr/wifi-scanner.git
cd wifi-scanner
```

2. Instale as dependências:
```bash
pip install -r requirements.txt
```

3. Certifique-se de que o Nmap está instalado:
   - No Windows: Baixe e instale do [site oficial](https://nmap.org/download.html)
   - No Linux (Debian/Ubuntu): `sudo apt install nmap`
   - No Linux (CentOS/RHEL): `sudo yum install nmap`
   - No macOS: `brew install nmap`

4. Verificando a instalação:
```bash
python wifi_scanner.py --help
```
Se tudo estiver configurado corretamente, você deverá ver a mensagem de ajuda com todas as opções disponíveis.

## 🚀 Uso Básico

A ferramenta WiFi Scanner opera através de linha de comando com uma sintaxe simples e intuitiva:

### Comando Padrão:

```bash
python wifi_scanner.py -t <alvo>
```
Onde `<alvo>` pode ser um endereço IP único (ex: 192.168.1.1) ou uma faixa de IPs usando notação CIDR (ex: 192.168.1.0/24).

### Obtendo Ajuda:

```bash
python wifi_scanner.py --help
```

### Estrutura Básica de Comando:

```bash
python wifi_scanner.py [opções] -t <alvo>
```
As opções são parâmetros que modificam o comportamento da ferramenta e são precedidas por um ou dois traços (- ou --).

## 🔄 Modos de Operação

### 1. Escaneamento de Rede

O modo de escaneamento de rede é o comportamento padrão da ferramenta. Ele detecta hosts ativos na rede especificada e identifica serviços em execução em portas abertas.

#### Opções de Escaneamento:

| Opção | Descrição | Exemplo |
|-------|-----------|---------|
| `-t, --target` | Define o alvo do escaneamento | `-t 192.168.1.0/24` |
| `-p, --ports` | Define as portas a serem escaneadas (separadas por vírgula) | `-p 22,80,443,3389` |
| `--timeout` | Define o timeout para conexões em segundos | `--timeout 10` |
| `-v, --verbose` | Ativa o modo verbose (mais detalhes) | `-v` |

#### Exemplo de Escaneamento:

```bash
python wifi_scanner.py -t 192.168.1.0/24 -p 22,80,443 -v
```
Este comando escaneará toda a rede 192.168.1.0/24 procurando por hosts com as portas 22 (SSH), 80 (HTTP) e 443 (HTTPS) abertas, com saída detalhada.

### 2. Brute Force

O modo de brute force tenta acessar serviços descobertos usando combinações de usuário/senha de wordlists predefinidas.

> **Nota:** O modo de brute force só é ativado com a opção `--brute-force` e opera nos serviços descobertos durante o escaneamento.

#### Opções de Brute Force:

| Opção | Descrição | Exemplo |
|-------|-----------|---------|
| `--brute-force` | Ativa o modo de brute force | `--brute-force` |
| `-u, --userlist` | Caminho para a lista de usuários | `-u wordlists/users.txt` |
| `-w, --wordlist` | Caminho para a lista de senhas | `-w wordlists/passwords.txt` |

#### Exemplo de Brute Force:

```bash
python wifi_scanner.py -t 192.168.1.10 -p 22 --brute-force -u wordlists/users.txt -w wordlists/passwords.txt
```
Este comando escaneará o host 192.168.1.10 procurando pela porta 22 (SSH) e, se encontrada, tentará acessá-la usando as combinações de usuário/senha das wordlists especificadas.

## 🔍 Opções Avançadas

A ferramenta WiFi Scanner possui diversas opções avançadas que permitem um controle mais fino sobre seu comportamento:

| Opção | Descrição | Valor Padrão |
|-------|-----------|------------|
| `-o, --output` | Arquivo de saída para salvar os resultados | `logs/scan_YYYYMMDD_HHMMSS.log` |
| `--timeout` | Timeout para conexões em segundos | 5 |
| `-p, --ports` | Portas para escanear | 22,21,80,443,3389,23 |
| `-u, --userlist` | Caminho para a lista de usuários | wordlists/users.txt |
| `-w, --wordlist` | Caminho para a lista de senhas | wordlists/passwords.txt |
| `-v, --verbose` | Ativa o modo verbose (mais detalhes) | Desativado |

### Configurando Wordlists Personalizadas:

```bash
python wifi_scanner.py -t 192.168.1.0/24 --brute-force -u minha_lista_usuarios.txt -w minha_lista_senhas.txt
```

### Redirecionando Saída:

```bash
python wifi_scanner.py -t 192.168.1.0/24 -o relatorio_seguranca.log
```

## 📝 Exemplos de Uso

### Escaneamento Rápido de Rede Local:

```bash
python wifi_scanner.py -t 192.168.1.0/24
```
Escaneia toda a rede 192.168.1.0/24 usando as portas padrão.

### Escaneamento Específico de Portas HTTP:

```bash
python wifi_scanner.py -t 192.168.1.0/24 -p 80,443,8080
```
Escaneia a rede em busca de servidores web nas portas HTTP e HTTPS comuns.

### Brute Force em um Servidor SSH Específico:

```bash
python wifi_scanner.py -t 192.168.1.10 -p 22 --brute-force
```
Verifica se o host 192.168.1.10 tem o serviço SSH rodando e tenta fazer brute force com as wordlists padrão.

### Escaneamento Detalhado com Timeout Aumentado:

```bash
python wifi_scanner.py -t 192.168.1.0/24 -v --timeout 10
```
Realiza um escaneamento detalhado da rede com um timeout maior para conexões mais lentas.

### Escaneamento Completo com Brute Force:

```bash
python wifi_scanner.py -t 192.168.1.0/24 -p 21,22,23,25,80,443,3389 --brute-force -v
```
Realiza um escaneamento detalhado de múltiplos serviços e tenta brute force em todos eles.

## 📊 Interpretando a Saída

### Formato do Log:

Os logs seguem o formato:
```
YYYY-MM-DD HH:MM:SS - LEVEL - MESSAGE
```

### Níveis de Log:

- **INFO:** Informações gerais sobre o processo
- **DEBUG:** Informações detalhadas para depuração (apenas no modo verbose)
- **WARNING:** Avisos que não interrompem a execução
- **ERROR:** Erros que podem afetar os resultados

### Exemplos de Saída:

#### Escaneamento:
```
2025-03-26 15:32:10 - INFO - Iniciando escaneamento de rede em: 192.168.1.0/24
2025-03-26 15:32:45 - INFO - Escaneamento concluído em 35.25 segundos
2025-03-26 15:32:45 - INFO - Encontrados 5 hosts com serviços abertos
2025-03-26 15:32:45 - INFO - Host: 192.168.1.1
2025-03-26 15:32:45 - INFO -   Porta 80: http
2025-03-26 15:32:45 - INFO -   Porta 443: https
2025-03-26 15:32:45 - INFO - Host: 192.168.1.10
2025-03-26 15:32:45 - INFO -   Porta 22: ssh
```

#### Brute Force:
```
2025-03-26 15:33:10 - INFO - Iniciando tentativas de brute force...
2025-03-26 15:33:10 - INFO - Carregados 28 usuários para teste
2025-03-26 15:33:10 - INFO - Iniciando brute force em 3 serviços...
2025-03-26 15:35:22 - INFO - Credenciais encontradas - 192.168.1.10:22 (ssh) - admin:admin123
2025-03-26 15:36:45 - INFO - Encontradas 1 credenciais válidas
```

## ⚠️ Solução de Problemas

### Problemas Comuns e Soluções:

| Problema | Possível Causa | Solução |
|----------|----------------|---------|
| "Nmap não está instalado" | Nmap não está instalado ou não está no PATH | Instale o Nmap seguindo as instruções da seção de instalação |
| "Erro ao importar módulos" | Dependências Python não instaladas | Execute `pip install -r requirements.txt` |
| "Permissão negada" | Falta de privilégios de administrador | Execute como administrador/root |
| "Nenhum host encontrado" | Rede incorreta ou hosts inativos | Verifique o alvo e tente aumentar o timeout |
| "Lista de usuários não encontrada" | Arquivo de wordlist não existe | Verifique o caminho para as wordlists |

### Executando em Modo Verbose para Depuração:

```bash
python wifi_scanner.py -t 192.168.1.0/24 -v
```
O modo verbose exibe mensagens de depuração que podem ajudar a identificar problemas.

## 🛡️ Melhores Práticas

### Segurança:

- Sempre obtenha autorização por escrito antes de realizar escaneamentos em qualquer rede
- Use a ferramenta apenas em ambientes controlados ou em suas próprias redes
- Evite fazer escaneamentos frequentes em curtos períodos de tempo
- Não compartilhe logs ou resultados de escaneamento publicamente

### Desempenho:

- Limite o número de portas escaneadas para melhorar a velocidade
- Use timeouts maiores para redes mais lentas ou com muitos dispositivos
- Divida redes grandes em subredes menores para escaneamentos mais eficientes
- Evite brute force em múltiplos serviços simultaneamente em redes de produção

### Wordlists:

- Mantenha suas wordlists atualizadas com senhas comuns recentes
- Adapte as wordlists ao contexto do ambiente que está sendo testado
- Comece com listas menores e mais direcionadas antes de usar listas grandes

> **Dica:** Para melhores resultados, use o Nmap instalado no sistema em vez do escaneamento básico com sockets. As versões mais recentes do Nmap oferecem detecção de serviços mais precisa.

## 📜 Documentação Completa

Para uma documentação completa e detalhada sobre a ferramenta, visite nossa [página de documentação online](https://github.com/z5ta9b5tbMC5Jr/wifi-scanner) ou abra o arquivo `documentacao.html` incluído neste repositório.

**Nota:** A versão completa da documentação HTML pode necessitar de pequenos ajustes. A documentação neste README contém todas as informações essenciais para uso da ferramenta.

## 🤝 Contribuições

Contribuições são bem-vindas! Sinta-se à vontade para abrir issues ou enviar pull requests com melhorias.

## 📄 Licença

Este projeto está licenciado sob a Licença MIT - veja o arquivo [LICENSE](LICENSE) para detalhes.

---

WiFi Scanner e Brute Force Tool © 2025 - Documentação v1.0

Esta ferramenta é fornecida apenas para fins educacionais e de teste de segurança. Use com responsabilidade.
