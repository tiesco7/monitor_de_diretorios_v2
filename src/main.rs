#![windows_subsystem = "windows"]

use notify::{RecursiveMode, Watcher, EventKind};
use std::sync::mpsc::{channel, Sender, Receiver};
use std::path::{Path, PathBuf};
use mysql::prelude::Queryable;
use mysql::{Pool, Opts, PooledConn};
use chrono::{DateTime, Utc, Local};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::fs::{self, OpenOptions};
use std::io::Write;
use tray_icon::{
    menu::{Menu, MenuItem, PredefinedMenuItem, MenuEvent},
    TrayIconBuilder, Icon, TrayIcon,
};
use std::sync::{Arc, Mutex};
use std::env;
use winit::event_loop::{EventLoop, ControlFlow};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    log_error("✅ ************** APLICAÇÃO INICIADA ************** ");

    let current_dir = env::current_dir()?;
    log_error(&format!("ℹ️ Diretório atual da aplicação: {} ", current_dir.display()));

    // configuração inicial
    let (diretorio, extensoes, mysql_url) = load_config(&current_dir)?;
    
    // variáveis compartilhadas entre threads
    let running = Arc::new(Mutex::new(true));
    let watcher_tx = Arc::new(Mutex::new(None::<Sender<notify::Event>>));
    let extensoes = Arc::new(Mutex::new(extensoes));
    let diretorio = Arc::new(Mutex::new(diretorio));
    let mysql_url = Arc::new(Mutex::new(mysql_url));
    let current_dir = Arc::new(current_dir);
    
    // tooltip inicial
    let tooltip = format!("ℹ️ Diretório monitorado: \n{}", diretorio.lock().unwrap().display());

    // configurar menu do tray icon
    let tray_menu = Menu::new();
    let start_item = MenuItem::new("Start", false, None);
    let stop_item = MenuItem::new("Stop", true, None);
    let restart_item = MenuItem::new("Restart", true, None);
    let quit_item = MenuItem::new("Sair", true, None);

    tray_menu.append(&start_item)?;
    tray_menu.append(&stop_item)?;
    tray_menu.append(&restart_item)?;
    tray_menu.append(&PredefinedMenuItem::separator())?;
    tray_menu.append(&quit_item)?;

    let icon = create_tray_icon(true)?;
    let tray_icon = TrayIconBuilder::new()
        .with_menu(Box::new(tray_menu))
        .with_tooltip(&tooltip)
        .with_icon(icon)
        .build()?;

    log_error("ℹ️ menu do tray icon configurado ");

    // conexão inicial  banco de dados
    let pool = connect_to_database(&mysql_url.lock().unwrap())?;
    let conn = Arc::new(Mutex::new(pool.get_conn()?));

    ensure_table_exists(&mut conn.lock().unwrap())?;

    // configuração inicial do watcher
    let (tx, rx) = channel();
    let watcher = setup_watcher(diretorio.lock().unwrap().to_str().unwrap(), tx.clone())?;
    *watcher_tx.lock().unwrap() = Some(tx);

    // thread de monitoramento
    let running_clone = running.clone();
    let conn_clone = conn.clone();
    let extensoes_clone = extensoes.clone();
    let rx_arc = Arc::new(Mutex::new(rx));
    let rx_clone = rx_arc.clone();

    std::thread::spawn(move || {
        let counter = AtomicUsize::new(1);
        monitor_files(rx_clone, conn_clone, counter, extensoes_clone, running_clone);
    });

    let event_loop = EventLoop::new()?;
    let menu_channel = MenuEvent::receiver();
    let mut watcher = Some(watcher);

    // Clones para o loop de eventos
    let running_for_event = running.clone();
    let watcher_tx_for_event = watcher_tx.clone();
    let diretorio_for_event = diretorio.clone();
    let current_dir_for_event = current_dir.clone();
    let mysql_url_for_event = mysql_url.clone();
    let extensoes_for_event = extensoes.clone();
    let conn_for_event = conn.clone();
    let rx_for_event = rx_arc.clone();

    log_error("✅ ************** Iniciando monitoramento ************** ");
    let _ = event_loop.run(move |_event, elwt| {
        elwt.set_control_flow(ControlFlow::Wait);
        
        // processar eventos do menu
        if let Ok(menu_event) = menu_channel.try_recv() {
            if menu_event.id == start_item.id() {
                log_error(&format!("🟢 ************** Solicitação de Start pelo tray icon"));
                // iniciar monitoramento
                if !*running_for_event.lock().unwrap() {
                    // reler configuração
                    let reconfig_result = reload_configuration(
                        &current_dir_for_event,
                        &diretorio_for_event,
                        &extensoes_for_event,
                        &mysql_url_for_event,
                        &conn_for_event
                    );
                    
                    match reconfig_result {
                        Ok(()) => {
                            // atualizar tooltip com o novo diretório
                            let new_tooltip = format!(
                                "ℹ️ Diretório monitorado: \n{}", 
                                diretorio_for_event.lock().unwrap().display()
                            );
                            let _ = tray_icon.set_tooltip(Some(&new_tooltip));
                            
                            // reiniciar monitoramento
                            *running_for_event.lock().unwrap() = true;
                            
                            // atualizar estado dos itens do menu
                            start_item.set_enabled(false);
                            stop_item.set_enabled(true);
                            restart_item.set_enabled(true);
                            
                            // atualizar ícone
                            if let Ok(icon) = create_tray_icon(true) {
                                let _ = tray_icon.set_icon(Some(icon));
                            }
                            
                            // reiniciar watcher com as novas configurações
                            if let Some(sender) = &*watcher_tx_for_event.lock().unwrap() {
                                if let Ok(new_watcher) = setup_watcher(
                                    diretorio_for_event.lock().unwrap().to_str().unwrap(), 
                                    sender.clone()
                                ) {
                                    watcher = Some(new_watcher);
                                    log_error("✅ Watcher reiniciado com nova configuração ");
                                }
                            }
                        },
                        Err(e) => {
                            log_error(&format!("⛔️ Erro ao recarregar configuração: {:?}", e));
                        }
                    }
                }
            } else if menu_event.id == stop_item.id() {
                // parar monitoramento
                if *running_for_event.lock().unwrap() {
                    *running_for_event.lock().unwrap() = false;
                    
                    // atualizar estado dos itens do menu
                    start_item.set_enabled(true);
                    stop_item.set_enabled(false);
                    restart_item.set_enabled(false);
                    
                    // atualizar ícone
                    if let Ok(icon) = create_tray_icon(false) {
                        let _ = tray_icon.set_icon(Some(icon));
                    }
                    log_error(&format!("🔴 ************** Solicitação de parada pelo tray Icon"));
                }
            } else if menu_event.id == restart_item.id() {
                log_error("🔵 ************** Solicitação de restart pelo tray Icon");
                // reiniciar monitoramento
                if *running_for_event.lock().unwrap() {
                    // parar temporariamente
                    *running_for_event.lock().unwrap() = false;
                    
                    // parar watcher atual
                    watcher = None;
                    log_error("ℹ️ Watcher parado para reinício");
                    
                    // reler configuração
                    let reconfig_result = reload_configuration(
                        &current_dir_for_event,
                        &diretorio_for_event,
                        &extensoes_for_event,
                        &mysql_url_for_event,
                        &conn_for_event
                    );
                    
                    match reconfig_result {
                        Ok(()) => {
                            // atualizar tooltip com o novo diretório
                            let new_tooltip = format!(
                                "ℹ️ Diretório monitorado: \n{}", 
                                diretorio_for_event.lock().unwrap().display()
                            );
                            let _ = tray_icon.set_tooltip(Some(&new_tooltip));
                            
                            // retomar monitoramento
                            *running_for_event.lock().unwrap() = true;
                            
                            // criar novo watcher com a nova configuração
                            if let Some(sender) = &*watcher_tx_for_event.lock().unwrap() {
                                if let Ok(new_watcher) = setup_watcher(
                                    diretorio_for_event.lock().unwrap().to_str().unwrap(), 
                                    sender.clone()
                                ) {
                                    watcher = Some(new_watcher);
                                    log_error("ℹ️ Watcher reiniciado com nova configuração ");
                                }
                            }
                            
                            // atualizar ícone (garantir que está verde)
                            if let Ok(icon) = create_tray_icon(true) {
                                let _ = tray_icon.set_icon(Some(icon));
                            }
                        },
                        Err(e) => {
                            log_error(&format!("⛔️ Erro ao recarregar configuração: {:?}", e));
                            
                            // tentar restaurar o watcher com a configuração antiga
                            if let Some(sender) = &*watcher_tx_for_event.lock().unwrap() {
                                if let Ok(new_watcher) = setup_watcher(
                                    diretorio_for_event.lock().unwrap().to_str().unwrap(), 
                                    sender.clone()
                                ) {
                                    watcher = Some(new_watcher);
                                    *running_for_event.lock().unwrap() = true;
                                    log_error("⚠️ Watcher restaurado com configuração anterior");
                                }
                            }
                        }
                    }
                }
            } else if menu_event.id == quit_item.id() {
                // encerrar aplicação
                log_error("🟥 ************** Solicitação de saída recebida ************** ");
                *running_for_event.lock().unwrap() = false;
                watcher = None;
                elwt.exit();
            }
        }
    });

    log_error("🟥 ************** Finalizando aplicação ************** ");
    Ok(())
}

fn reload_configuration(
    current_dir: &Arc<PathBuf>,
    diretorio: &Arc<Mutex<PathBuf>>,
    extensoes: &Arc<Mutex<Vec<String>>>,
    mysql_url: &Arc<Mutex<String>>,
    conn: &Arc<Mutex<PooledConn>>
) -> Result<(), Box<dyn std::error::Error>> {
    log_error("ℹ️ ************** Recarregando configuração...");
    
    // carregar configuração atualizada
    let (nova_diretorio, novas_extensoes, nova_mysql_url) = load_config(current_dir)?;
    
    // verificar se a URL do banco de dados mudou
    let url_mudou = {
        let url_atual = mysql_url.lock().unwrap();
        *url_atual != nova_mysql_url
    };
    
    // atualizar configurações
    {
        let mut dir_lock = diretorio.lock().unwrap();
        *dir_lock = nova_diretorio;
        log_error(&format!("ℹ️ ************** Novo diretório: {}", dir_lock.display()));
    }
    
    {
        let mut ext_lock = extensoes.lock().unwrap();
        *ext_lock = novas_extensoes;
        log_error(&format!("ℹ️ ************** Novas extensões: {:?}", ext_lock));
    }
    
    // se a URL do banco de dados mudou, reconectar
    if url_mudou {
        log_error("ℹ️ ************** URL do banco de dados mudou, reconectando...");
        
        // atualizar URL
        {
            let mut url_lock = mysql_url.lock().unwrap();
            *url_lock = nova_mysql_url.clone();
        }
        
        // reconectar ao banco de dados
        let pool = connect_to_database(&nova_mysql_url)?;
        let mut nova_conn = pool.get_conn()?;
        
        // tabela existe?    se nao existirt criar
        ensure_table_exists(&mut nova_conn)?;
        
        // atualizar conexão
        let mut conn_lock = conn.lock().unwrap();
        *conn_lock = nova_conn;
        
        log_error("✅ ************** conexão com banco de dados atualizada");
    }
    
    log_error("✅ ************** Configuração recarregada com sucesso ");
    Ok(())
}

fn load_config(current_dir: &Path) -> Result<(PathBuf, Vec<String>, String), Box<dyn std::error::Error>> {
    let env_file = current_dir.join("env.txt");
    let mut diretorio = PathBuf::from("C:\\pasta");
    let mut extensoes = vec!["pdf".to_string(), "mp3".to_string(), "jpg".to_string(), "xlsx".to_string()];
    let mut mysql_host = "localhost".to_string();
    let mut mysql_user = "root".to_string();
    let mut mysql_password = "senha".to_string();

    if env_file.exists() {
        let content = fs::read_to_string(&env_file)?;
        for line in content.lines() {
            let parts: Vec<&str> = line.split('=').collect();
            if parts.len() == 2 {
                match parts[0].trim() {
                    "MYSQL_HOST" => mysql_host = parts[1].trim().to_string(),
                    "MYSQL_USER" => mysql_user = parts[1].trim().to_string(),
                    "MYSQL_PASSWORD" => mysql_password = parts[1].trim().to_string(),
                    "EXTENSOES" => {
                        extensoes = parts[1].split(',').map(|s| s.trim().to_lowercase()).collect();
                    }
                    "PASTA" => {
                        diretorio = PathBuf::from(parts[1].trim());
                    }
                    _ => {}
                }
            }
        }
    } else {
        log_error("⚠️ Arquivo env.txt não encontrado, usando padrões e criando um");
        fs::write(&env_file, "MYSQL_HOST=localhost\nMYSQL_USER=root\nMYSQL_PASSWORD=senha\nEXTENSOES=pdf,jpg,txt\nPASTA=C:\\pasta")?;
    }

    let mysql_url = format!("mysql://{}:{}@{}/rust_test", mysql_user, mysql_password, mysql_host);

    if !diretorio.exists() {
        fs::create_dir_all(&diretorio)?;
        log_error(&format!("✅ Diretório criado: {} ", diretorio.display()));
    }

    Ok((diretorio, extensoes, mysql_url))
}

fn connect_to_database(mysql_url: &str) -> Result<Pool, Box<dyn std::error::Error>> {
    log_error(&format!("✅ ************** Tentando conectar ao banco de dados: {}", mysql_url));

    let opts = Opts::from_url(mysql_url).map_err(|e| {
        let msg = format!("❌ Erro na URL do banco de dados: {}", e);
        log_error(&msg);
        msg
    })?;

    let pool = Pool::new(opts).map_err(|e| {
        let msg = format!("❌ Falha ao conectar com o banco: {}", e);
        log_error(&msg);
        msg
    })?;

    log_error("✅ ************** Conexão com banco de dados OK ");
    Ok(pool)
}


fn create_tray_icon(running: bool) -> Result<Icon, Box<dyn std::error::Error>> {
    let mut icon_data = Vec::with_capacity(16 * 16 * 4);
    for _ in 0..(16 * 16) {
        if running {
            // Verde (0, 255,0,255)
            icon_data.push(0);   // R
            icon_data.push(255); // G
            icon_data.push(0);   // B
            icon_data.push(255); // a
        } else {
            // VERMELHO (255, 0, 0, 255)
            icon_data.push(255); // R
            icon_data.push(0);   // G
            icon_data.push(0);   // B
            icon_data.push(255); // a
        }
    }
    let icon = Icon::from_rgba(icon_data, 16, 16)?;
    Ok(icon)
}

fn ensure_table_exists(conn: &mut PooledConn) -> Result<(), Box<dyn std::error::Error>> {
    log_error("✅ ************** Verificando se a tabela 'arquivos' existe");

    // cria a bagaça da tabela se não existir
    let create_table_query = "
        CREATE TABLE IF NOT EXISTS arquivos (
            id BIGINT AUTO_INCREMENT PRIMARY KEY,
            nome_arquivo VARCHAR(255),
            data_recebimento DATETIME,
            data_criacao DATETIME,
            extensao VARCHAR(10),
            tamanho VARCHAR(20),
            path VARCHAR(1000),
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ";

    conn.query_drop(create_table_query)?;
    log_error("✅ Tabela 'arquivos' verificada/criada com sucesso ");
    Ok(())
}

fn setup_watcher(diretorio: &str, tx: Sender<notify::Event>) -> Result<notify::RecommendedWatcher, notify::Error> {
    log_error(&format!("✅ Configurando watcher para diretório: {}", diretorio));

    let mut watcher = notify::recommended_watcher(move |res| {
        match res {
            Ok(event) => {
                if let Err(e) = tx.send(event) {
                    log_error(&format!(" ⛔️ Erro ao enviar evento: {:?}", e));
                }
            }
            Err(e) => log_error(&format!(" ⛔️ Erro no watcher: {:?}", e)),
        }
    })?;

    watcher.watch(Path::new(diretorio), RecursiveMode::Recursive)?;
    log_error(&format!("✅ Watcher configurado com sucesso para: {} ", diretorio));
    Ok(watcher)
}

fn monitor_files(
    rx: Arc<Mutex<Receiver<notify::Event>>>,
    conn: Arc<Mutex<PooledConn>>,
    counter: AtomicUsize,
    extensoes: Arc<Mutex<Vec<String>>>,
    running: Arc<Mutex<bool>>,
) {
    log_error("✅ Thread de monitoramento iniciado");

    loop {
        if !*running.lock().unwrap() {
            std::thread::sleep(std::time::Duration::from_millis(100));
            continue;
        }

        let recv_result = {
            let rx_guard = rx.lock().unwrap();
            rx_guard.recv_timeout(std::time::Duration::from_secs(1))
        };

        match recv_result {
            Ok(event) => {
                if let EventKind::Create(_) = event.kind {
                    for path in event.paths {
                        if let Some(extension) = path.extension() {
                            let ext = extension.to_string_lossy().to_lowercase();
                            let extensoes_guard = extensoes.lock().unwrap();
                            if extensoes_guard.contains(&ext) {
                                // log_error(&format!("Arquivo detectado: {}", path.display()));
                                let number = counter.fetch_add(1, Ordering::SeqCst);

                                match conn.lock() {
                                    Ok(mut conn_guard) => {
                                        inserir(&mut conn_guard, &path, number, &ext);
                                    }
                                    Err(e) => {
                                        log_error(&format!("⛔️ Erro ao obter lock da conexão: {:?}", e));
                                    }
                                }
                            }
                        }
                    }
                }
            }
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
            Err(e) => {
                log_error(&format!("⛔️ Erro ao receber evento: {:?}", e));
                std::thread::sleep(std::time::Duration::from_secs(1));
            }
        }
    }
}

fn log_error(message: &str) {
    let timestamp = Local::now().format("%Y-%m-%d %H:%M:%S").to_string();
    let log_line = format!("[{}] {}\n", timestamp, message);

    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open("monitor_erros.log")
        .unwrap_or_else(|e| {
            eprintln!("Erro ao abrir arquivo de log: {:?}", e);
            panic!("⛔️ Não foi possível abrir o log - TOMAAA");
        });

    if let Err(e) = file.write_all(log_line.as_bytes()) {
        eprintln!("⛔️ Erro ao escrever no arquivo de log: {:?}", e);
    }

    println!("{}", log_line.trim());
}

fn inserir(conn: &mut PooledConn, path: &Path, id: usize, extensao: &str) {
    let path_str = path.to_string_lossy().to_string();
    let nome_arquivo = path.file_name()
        .map(|name| name.to_string_lossy().to_string())
        .unwrap_or_default();

    let metadata = match fs::metadata(path) {
        Ok(m) => m,
        Err(e) => {
            log_error(&format!("⛔️ Erro ao obter metadata (ID {}): {:?}", id, e));
            return;
        }
    };

    let tamanho = metadata.len();
    /*
    log_error(&format!("📁 Tamanho do arquivo (ID {}): {} bytes", id, tamanho));
    log_error(&format!("📁 Permissões (ID {}): {:?}", id, metadata.permissions()));

    if let Ok(modified) = metadata.modified() {
        log_error(&format!("📁 Modificado em (ID {}): {:?}", id, modified));
    }

    if let Ok(accessed) = metadata.accessed() {
        log_error(&format!("📁 Acessado em (ID {}): {:?}", id, accessed));
    }

    #[cfg(target_family = "unix")]
    {
        use std::os::unix::fs::MetadataExt;
        log_error(&format!("📁 UID (ID {}): {}", id, metadata.uid()));
        log_error(&format!("📁 GID (ID {}): {}", id, metadata.gid()));
    }

    #[cfg(target_os = "windows")]
    {
        if let Ok(created) = metadata.created() {
            log_error(&format!("📁 Criado em (ID {}): {:?}", id, created));
        }
    }
    */

    let data_criacao = metadata.created().ok().and_then(|t| {
        t.duration_since(std::time::UNIX_EPOCH)
            .ok()
            .and_then(|d| DateTime::<Utc>::from_timestamp(d.as_secs() as i64, 0))
            .map(|dt| dt.format("%Y-%m-%d %H:%M:%S").to_string())
    });

    let data_recebimento = metadata.modified().ok().and_then(|t| {
        t.duration_since(std::time::UNIX_EPOCH)
            .ok()
            .and_then(|d| DateTime::<Utc>::from_timestamp(d.as_secs() as i64, 0))
            .map(|dt| dt.format("%Y-%m-%d %H:%M:%S").to_string())
    });

    // retirado porque só precisamos saber se iniciou ou saber erros no log...
    //log_error(&format!("Inserindo arquivo no banco: {} ({})", nome_arquivo, extensao));

    let query = "INSERT INTO arquivos (nome_arquivo, data_recebimento, data_criacao, extensao, tamanho, path) VALUES (?, ?, ?, ?, ?, ?)";
    match conn.exec_drop(
        query,
        (
            &nome_arquivo,
            data_recebimento.as_deref(),
            data_criacao.as_deref(),
            extensao,
            tamanho,
            &path_str,
        ),
    ) {
        Ok(_) => {},
        Err(e) => log_error(&format!("⛔️ Erro ao inserir (ID {}): {:?}", id, e)),
    }
}