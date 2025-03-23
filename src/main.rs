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
    log_error("Aplicação iniciada");

    let current_dir = env::current_dir()?;
    log_error(&format!("Diretório atual: {}", current_dir.display()));

    let (diretorio, extensoes, usuario, senha) = load_config(&current_dir)?;
    let running = Arc::new(Mutex::new(true));
    let watcher_tx = Arc::new(Mutex::new(None::<Sender<notify::Event>>));
    let extensoes = Arc::new(Mutex::new(extensoes));
    let tooltip = format!("Monitor de Arquivos\nDiretório: {}", diretorio.display());

    // o tray menu
    let (mut tray_icon, start_item, stop_item, restart_item) = setup_tray_menu(&tooltip, true)?;
    let _tray_icon = Arc::new(Mutex::new(tray_icon.clone())); // Para manter o tray_icon vivo

    // BD
    let pool = connect_to_database(&usuario, &senha)?;
    let conn = Arc::new(Mutex::new(pool.get_conn()?));

    ensure_table_exists(&mut conn.lock().unwrap())?;

    let (tx, rx) = channel();
    let watcher = setup_watcher(diretorio.to_str().unwrap(), tx.clone())?;
    *watcher_tx.lock().unwrap() = Some(tx);

    let running_clone = running.clone();
    let conn_clone = conn.clone();
    let extensoes_clone = extensoes.clone();

    std::thread::spawn(move || {
        let counter = AtomicUsize::new(1);
        monitor_files(rx, conn_clone, counter, extensoes_clone, running_clone);
    });

    // evento winit
    let event_loop = EventLoop::new()?;
    let menu_channel = MenuEvent::receiver();
    let mut watcher = Some(watcher);

    log_error("Iniciando loop de eventos com winit");
    event_loop.run(move |_event, elwt| {
        elwt.set_control_flow(ControlFlow::Wait);

        if let Ok(event) = menu_channel.try_recv() {
            match event.id {
                id if id == start_item.id() => {
                    let mut running_guard = running.lock().unwrap();
                    if !*running_guard {
                        *running_guard = true;
                        log_error("Monitor iniciado pelo tray");

                        // reler configurações
                        let (new_diretorio, new_extensoes, new_usuario, new_senha) = load_config(&current_dir).unwrap_or_else(|e| {
                            log_error(&format!("Erro ao recarregar config: {:?}", e));
                            (diretorio.clone(), extensoes.lock().unwrap().clone(), usuario.clone(), senha.clone())
                        });
                        *extensoes.lock().unwrap() = new_extensoes;

                        // reconectar banco de dados
                        let new_pool = connect_to_database(&new_usuario, &new_senha).unwrap_or_else(|e| {
                            log_error(&format!("Erro ao reconectar ao banco: {:?}", e));
                            pool.clone()
                        });
                        *conn.lock().unwrap() = new_pool.get_conn().unwrap_or_else(|e| {
                            log_error(&format!("Erro ao obter nova conexão: {:?}", e));
                            pool.get_conn().unwrap()
                        });

                        if let Ok(icon) = create_tray_icon(true) {
                            tray_icon.set_icon(Some(icon)).ok();
                        }
                        start_item.set_enabled(false);
                        stop_item.set_enabled(true);
                        restart_item.set_enabled(true);
                    }
                }
                id if id == stop_item.id() => {
                    let mut running_guard = running.lock().unwrap();
                    if *running_guard {
                        *running_guard = false;
                        log_error("Monitor parado pelo tray");

                        let (new_diretorio, new_extensoes, new_usuario, new_senha) = load_config(&current_dir).unwrap_or_else(|e| {
                            log_error(&format!("Erro ao recarregar config: {:?}", e));
                            (diretorio.clone(), extensoes.lock().unwrap().clone(), usuario.clone(), senha.clone())
                        });
                        *extensoes.lock().unwrap() = new_extensoes;

                        // ícone para vermelho
                        if let Ok(icon) = create_tray_icon(false) {
                            tray_icon.set_icon(Some(icon)).ok();
                        }
                        //estado dos itens do menu
                        start_item.set_enabled(true);
                        stop_item.set_enabled(false);
                        restart_item.set_enabled(false);
                    }
                }
                id if id == restart_item.id() => {
                    log_error("Tentando reiniciar o monitor");
                    let mut running_guard = running.lock().unwrap();
                    let mut tx_guard = watcher_tx.lock().unwrap();
                    *running_guard = false;
                    *tx_guard = None;

                    // drop o watcher antigo
                    watcher = None;

                    //  reler configurações
                    let (new_diretorio, new_extensoes, new_usuario, new_senha) = load_config(&current_dir).unwrap_or_else(|e| {
                        log_error(&format!("Erro ao recarregar config: {:?}", e));
                        (diretorio.clone(), extensoes.lock().unwrap().clone(), usuario.clone(), senha.clone())
                    });
                    *extensoes.lock().unwrap() = new_extensoes;

                    let new_pool = connect_to_database(&new_usuario, &new_senha).unwrap_or_else(|e| {
                        log_error(&format!("Erro ao reconectar ao banco: {:?}", e));
                        pool.clone()
                    });
                    *conn.lock().unwrap() = new_pool.get_conn().unwrap_or_else(|e| {
                        log_error(&format!("Erro ao obter nova conexão: {:?}", e));
                        pool.get_conn().unwrap()
                    });

                    let (new_tx, new_rx) = channel();
                    match setup_watcher(new_diretorio.to_str().unwrap(), new_tx.clone()) {
                        Ok(new_watcher) => {
                            watcher = Some(new_watcher);
                            *tx_guard = Some(new_tx);
                            *running_guard = true;

                            let conn_clone = conn.clone();
                            let running_clone = running.clone();
                            let extensoes_clone = extensoes.clone();

                            std::thread::spawn(move || {
                                let counter = AtomicUsize::new(1);
                                monitor_files(new_rx, conn_clone, counter, extensoes_clone, running_clone);
                            });

                            log_error("Monitor reiniciado pelo tray");

                            //ícone para verde
                            if let Ok(icon) = create_tray_icon(true) {
                                tray_icon.set_icon(Some(icon)).ok();
                            }
                            // tooltip com o novo diretório
                            let new_tooltip = format!("Monitor de Arquivos\nDiretório: {}", new_diretorio.display());
                            tray_icon.set_tooltip(Some(new_tooltip));
                            // estado dos itens do menu
                            start_item.set_enabled(false);
                            stop_item.set_enabled(true);
                            restart_item.set_enabled(true);
                        }
                        Err(e) => {
                            log_error(&format!("Erro ao reiniciar watcher: {:?}", e));
                        }
                    }
                }
                _ => {
                    log_error("Aplicação finalizada usuário (tray menu)");
                    elwt.exit();
                }
            }
        }
    });

    log_error("Finalizando aplicação");
    Ok(())
}

fn load_config(current_dir: &Path) -> Result<(PathBuf, Vec<String>, String, String), Box<dyn std::error::Error>> {
    let env_file = current_dir.join("env.txt");
    let mut diretorio = PathBuf::from(r"C:\pasta");
    let mut extensoes = vec!["pdf".to_string(), "mp3".to_string(), "jpg".to_string(), "xlsx".to_string()];
    let mut usuario = "root".to_string();
    let mut senha = "senha".to_string();

    if env_file.exists() {
        let content = fs::read_to_string(&env_file)?;
        for line in content.lines() {
            let parts: Vec<&str> = line.split('=').collect();
            if parts.len() == 2 {
                match parts[0].trim() {
                    "CONEXAO" => {
                        let conn_parts: Vec<&str> = parts[1].split(':').collect();
                        if conn_parts.len() == 2 {
                            usuario = conn_parts[0].to_string();
                            senha = conn_parts[1].to_string();
                        }
                    }
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
        log_error("Arquivo env.txt não encontrado, usando padrões e criando um");
        fs::write(&env_file, "CONEXAO=root:senha\nEXTENSOES=pdf,jpg,txt\nPASTA=C:\\pasta")?;
    }

    if !diretorio.exists() {
        fs::create_dir_all(&diretorio)?;
        log_error(&format!("Diretório criado: {}", diretorio.display()));
    }

    Ok((diretorio, extensoes, usuario, senha))
}

fn connect_to_database(usuario: &str, senha: &str) -> Result<Pool, Box<dyn std::error::Error>> {
    let url = format!("mysql://{}:{}@127.0.0.1:3306/rust_test", usuario, senha);
    log_error(&format!("Tentando conectar ao banco de dados: {}", url));

    let pool = Pool::new(Opts::from_url(&url)?)?;
    log_error("Conexão com banco de dados ok");

    Ok(pool)
}

fn setup_tray_menu(tooltip: &str, running: bool) -> Result<(TrayIcon, MenuItem, MenuItem, MenuItem), Box<dyn std::error::Error>> {
    log_error("Configurando o menu do tray");

    let tray_menu = Menu::new();
    let start_item = MenuItem::new("Start", !running, None);
    let stop_item = MenuItem::new("Stop", running, None);
    let restart_item = MenuItem::new("Restart", running, None);
    let quit_item = MenuItem::new("Sair", true, None);

    tray_menu.append(&start_item)?;
    tray_menu.append(&stop_item)?;
    tray_menu.append(&restart_item)?;
    tray_menu.append(&PredefinedMenuItem::separator())?;
    tray_menu.append(&quit_item)?;

    let icon = create_tray_icon(running)?;
    let tray_icon = TrayIconBuilder::new()
        .with_menu(Box::new(tray_menu))
        .with_tooltip(tooltip)
        .with_icon(icon)
        .build()?;

    log_error("Menu do tray icon configurado com sucesso");
    Ok((tray_icon, start_item, stop_item, restart_item))
}

fn create_tray_icon(running: bool) -> Result<Icon, Box<dyn std::error::Error>> {
    let mut icon_data = Vec::with_capacity(16 * 16 * 4);
    for _ in 0..(16 * 16) {
        if running {
            // Verde (0, 255, 0, 255)
            icon_data.push(0);   // R
            icon_data.push(255); // G
            icon_data.push(0);   // B
            icon_data.push(255); // A
        } else {
            // Vermelho (255, 0, 0, 255)
            icon_data.push(255); // R
            icon_data.push(0);   // G
            icon_data.push(0);   // B
            icon_data.push(255); // A
        }
    }
    let icon = Icon::from_rgba(icon_data, 16, 16)?;
    Ok(icon)
}

fn ensure_table_exists(conn: &mut PooledConn) -> Result<(), Box<dyn std::error::Error>> {
    log_error("Verificando se a tabela 'arquivos' existe");

    let create_table_query = "
        CREATE TABLE IF NOT EXISTS arquivos (
            id INT AUTO_INCREMENT PRIMARY KEY,
            nome_arquivo VARCHAR(255) NOT NULL,
            data_recebimento VARCHAR(20),
            data_criacao VARCHAR(20),
            extensao VARCHAR(10),
            tamanho BIGINT,
            path VARCHAR(1000)
        )
    ";

    conn.query_drop(create_table_query)?;
    log_error("Tabela 'arquivos' verificada/criada com sucesso");
    Ok(())
}

fn setup_watcher(diretorio: &str, tx: Sender<notify::Event>) -> Result<notify::RecommendedWatcher, notify::Error> {
    log_error(&format!("Configurando watcher para diretório: {}", diretorio));

    let mut watcher = notify::recommended_watcher(move |res| {
        match res {
            Ok(event) => {
                if let Err(e) = tx.send(event) {
                    log_error(&format!("Erro ao enviar evento: {:?}", e));
                }
            }
            Err(e) => log_error(&format!("Erro no watcher: {:?}", e)),
        }
    })?;

    watcher.watch(Path::new(diretorio), RecursiveMode::Recursive)?;
    log_error(&format!("Watcher configurado com sucesso para: {}", diretorio));
    Ok(watcher)
}

fn monitor_files(
    rx: Receiver<notify::Event>,
    conn: Arc<Mutex<PooledConn>>,
    counter: AtomicUsize,
    extensoes: Arc<Mutex<Vec<String>>>,
    running: Arc<Mutex<bool>>,
) {
    log_error("Thread de monitoramento iniciado");

    loop {
        if !*running.lock().unwrap() {
            std::thread::sleep(std::time::Duration::from_millis(100));
            continue;
        }

        match rx.recv_timeout(std::time::Duration::from_secs(1)) {
            Ok(event) => {
                if let EventKind::Create(_) = event.kind {
                    for path in event.paths {
                        if let Some(extension) = path.extension() {
                            let ext = extension.to_string_lossy().to_lowercase();
                            let extensoes_guard = extensoes.lock().unwrap();
                            if extensoes_guard.contains(&ext) {
                                log_error(&format!("Arquivo detectado: {}", path.display()));
                                let number = counter.fetch_add(1, Ordering::SeqCst);

                                match conn.lock() {
                                    Ok(mut conn_guard) => {
                                        inserir(&mut conn_guard, &path, number, &ext);
                                    }
                                    Err(e) => {
                                        log_error(&format!("Erro ao obter lock da conexão: {:?}", e));
                                    }
                                }
                            }
                        }
                    }
                }
            }
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
            Err(e) => {
                log_error(&format!("Erro ao receber evento: {:?}", e));
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
            panic!("Não foi possível abrir o log");
        });

    if let Err(e) = file.write_all(log_line.as_bytes()) {
        eprintln!("Erro ao escrever no arquivo de log: {:?}", e);
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
            log_error(&format!("Erro ao obter metadata (ID {}): {:?}", id, e));
            return;
        }
    };

    let tamanho = metadata.len();

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

    log_error(&format!("Inserindo arquivo no banco: {} ({})", nome_arquivo, extensao));

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
        Ok(_) => log_error(&format!("Arquivo inserido com sucesso (ID {}): {}", id, nome_arquivo)),
        Err(e) => log_error(&format!("Erro ao inserir (ID {}): {:?}", id, e)),
    }
}