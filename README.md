# Monitor de Diretórios v2

Este é um aplicativo em Rust que monitora um diretório específico em busca de novos arquivos com extensões configuradas, registrando informações sobre eles em um banco de dados MySQL. Ele também oferece uma interface via ícone na bandeja do sistema (system tray) para iniciar, parar ou reiniciar o monitoramento.

## Funcionalidades
- Monitora um diretório configurado recursivamente para novos arquivos.
- Filtra arquivos por extensões definidas (ex.: `.pdf`, `.jpg`, `.mp3`).
- Registra no banco de dados MySQL informações como nome, data de criação, tamanho e caminho do arquivo.
- Interface simples via bandeja do sistema com opções de Start, Stop e Restart.
- Gera logs de atividades e erros em um arquivo `monitor_erros.log`.

## Como Usar
1. **Pré-requisitos**:
   - Rust instalado (recomenda-se a versão mais recente).
   - MySQL rodando localmente (banco `rust_test` deve existir ou será criado).
   - Dependências do sistema para o tray icon (como `libayatana-appindicator` no Linux).

2. **Configuração**:
   - Crie um arquivo `env.txt` na raiz do projeto com as seguintes variáveis:

`CONEXAO=usuario:senha`

`EXTENSOES=pdf,jpg,mp3,xlsx`

`PASTA=C:\caminho\para\diretório`


- Se o arquivo não existir, o programa criará um com valores padrão.

3. **Execução**:
- Clone o repositório:


- Navegue até o diretório e compile/executed:

`cd monitor_de_diretorios_v2`
`cargo build --release`



- O executar o arquivo exe o aplicativo iniciará o monitoramento e exibirá um ícone na bandeja do sistema.

4. **Controle**:
- Clique no ícone da bandeja para:
- **Start**: Iniciar o monitoramento.
- **Stop**: Pausar o monitoramento.
- **Restart**: Reiniciar com novas configurações.
- **Sair**: Encerrar o aplicativo.

## Estrutura do Banco de Dados
O programa cria automaticamente uma tabela `arquivos` no banco MySQL com o DDL:

`CREATE TABLE arquivos (
	id BIGINT PRIMARY KEY AUTO_INCREMENT,
	nome_arquivo VARCHAR(255),
	data_recebimento DATETIME,
	data_criacao DATETIME,
	extensao VARCHAR(10),
	tamanho BIGINT,
	path VARCHAR(512),
	created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);`

## Dependências Principais
- `notify`: Para monitoramento de diretórios.
- `mysql`: Para conexão com o banco de dados.
- `tray-icon` e `winit`: Para o ícone na bandeja e loop de eventos.

## Contribuição
Sinta-se à vontade para abrir issues ou enviar pull requests no repositório [github.com/tiesco7/monitor_de_diretorios_v2](https://github.com/tiesco7/monitor_de_diretorios_v2).

## Licença
Este projeto é de código aberto e está sob a licença MIT (a ser adicionada).