#![allow(dead_code)]

use std::{
    collections::HashMap,
    io::Read,
    sync::mpsc::{channel, Receiver, Sender},
};

use crate::config::{Config, Task, When, CONFIG_FILE_NAME};
use crate::process::Process;
use cron::Schedule;
use eyre::{Context, Result};
use log::{debug, error, info};
use notify::{RecommendedWatcher, RecursiveMode, Watcher};
use std::str::FromStr;

pub struct TaskRunner {
    config: Config,
    // config_tx: Sender<Result<notify::Event, notify::Error>>,
    config_rx: Receiver<Result<notify::Event, notify::Error>>,
    trigger_tx: Sender<()>,
    trigger_rx: Receiver<()>,
    watcher: RecommendedWatcher,
    start_ts: std::time::SystemTime,
    task_ts: HashMap<String, std::time::SystemTime>,
    children: Vec<(String, Task, Process)>,
    counter: u64,
}

impl TaskRunner {
    pub fn new() -> Self {
        let config = Config {
            ..Default::default()
        };
        let (config_tx, config_rx) = channel();
        let (trigger_tx, trigger_rx) = channel();
        TaskRunner {
            config,
            config_rx,
            trigger_tx,
            trigger_rx,
            watcher: RecommendedWatcher::new(config_tx, notify::Config::default()).unwrap(),
            start_ts: std::time::SystemTime::now(),
            task_ts: HashMap::<String, std::time::SystemTime>::new(),
            children: Vec::<(String, Task, Process)>::new(),
            counter: 0u64,
        }
    }

    pub fn load_config(&mut self, s: &str) -> Result<()> {
        self.config = toml::from_str(&s)?;
        // info!("taskserv.conf has reloaded.\n\n{:#?}\n", self.config);
        info!("taskserv.conf has reloaded.");
        Ok(())
    }

    pub fn initialize(&mut self) -> Result<()> {
        let path = std::env::current_exe()?.with_file_name(CONFIG_FILE_NAME);
        let mut file = std::fs::File::open(&path).wrap_err(format!(
            "failed to open taskserv.conf ({:?})",
            path.to_str()
        ))?;
        let mut buf = String::new();
        let _ = file.read_to_string(&mut buf)?;
        self.load_config(&buf)?;

        let _ = self.watcher.watch(
            &std::env::current_exe()?.with_file_name(CONFIG_FILE_NAME),
            RecursiveMode::NonRecursive,
        )?;
        Ok(())
    }

    pub fn tick(&mut self) -> Result<()> {
        match self
            .config_rx
            .recv_timeout(std::time::Duration::from_millis(0))
        {
            Ok(_) => {
                let mut file =
                    std::fs::File::open(std::env::current_exe()?.with_file_name(CONFIG_FILE_NAME))?;
                let mut buf = String::new();
                let _ = file.read_to_string(&mut buf)?;
                self.load_config(&buf)?;
            }
            _ => (),
        };

        // startup
        if self.counter == 0 {
            self.process_startup_tasks()?;
        }

        // trigger
        match self
            .trigger_rx
            .recv_timeout(std::time::Duration::from_millis(0))
        {
            Ok(_) => self.process_triggerable_tasks()?,
            _ => (),
        }

        // cron
        self.process_scheduled_tasks()?;

        self.counter += 1;

        Ok(())
    }

    fn process_scheduled_tasks(&mut self) -> Result<()> {
        let mut tasks: Vec<String> = Vec::<String>::new();
        let now = chrono::Utc::now();
        for (key, task) in &self.config.tasks {
            for when in &task.when {
                match when {
                    When::Cron(cron) => {
                        let schedule = Schedule::from_str(cron)?;
                        let prev_ts = self.task_ts.get(key).unwrap_or(&self.start_ts);
                        let prev_dt = chrono::DateTime::<chrono::Utc>::from(*prev_ts);
                        for next_dt in schedule.after(&prev_dt) {
                            if next_dt > now {
                                break;
                            }
                            if prev_dt < next_dt && next_dt <= now {
                                tasks.push(key.clone());
                                self.task_ts.insert(key.clone(), next_dt.into());
                            }
                        }
                    }
                    _ => (),
                }
            }
        }
        for task in tasks {
            self.start_task(&task)?;
        }

        self.start_ts = now.into();
        Ok(())
    }

    fn process_triggerable_tasks(&mut self) -> Result<()> {
        let mut tasks: Vec<String> = Vec::<String>::new();
        for (key, task) in &self.config.tasks {
            for when in &task.when {
                match when {
                    When::Trigger => tasks.push(key.clone()),
                    _ => (),
                }
            }
        }
        for task in tasks {
            self.start_task(&task)?;
        }
        Ok(())
    }

    fn process_startup_tasks(&mut self) -> Result<()> {
        let mut tasks: Vec<String> = Vec::<String>::new();
        for (key, task) in &self.config.tasks {
            for when in &task.when {
                match when {
                    When::Startup => tasks.push(key.clone()),
                    _ => (),
                }
            }
        }
        for task in tasks {
            self.start_task(&task)?;
        }
        Ok(())
    }

    fn start_task(&mut self, key: &str) -> Result<()> {
        let task = self.config.tasks.get(key).unwrap();
        let msg = format!(
            "\"{}\" started. path={} args=[{}]",
            key,
            task.path,
            match &task.args {
                Some(args) => args.join(", "),
                None => String::new(),
            },
        );
        if self.config.dry_run.unwrap_or_default() {
            info!("{} (dry_run)", msg);
            return Ok(());
        }

        let count = self.children.iter().filter(|(k, _, _)| k == key).count() as i32;
        if let Some(max_instances) = task.max_instances {
            if count >= max_instances {
                info!("{} (skipped due to max_instances)", msg);
                return Ok(());
            }
        }

        info!("{}", msg);

        const DETACHED_PROCESS: u32 = 0x00000008u32;
        const CREATE_NEW_CONSOLE: u32 = 0x00000010u32;
        const CREATE_NEW_PROCESS_GROUP: u32 = 0x00000200u32;
        const INHERIT_PARENT_AFFINITY: u32 = 0x00010000u32;

        match crate::process::start_process(
            &task.path,
            task.cwd.clone().unwrap_or_default().as_ref(),
            task.args.clone().unwrap_or_default(),
        ) {
            Ok(p) => {
                info!(
                    "\"{}\" process successfully spawned. pid={}",
                    key, p.process_information.dwProcessId
                );
                self.children.push((key.to_string(), task.clone(), p));
            }
            Err(e) => error!("\"{}\" failed to run. reason={:?}", key, e),
        }

        Ok(())
    }

    fn evict_dead_processes(&mut self) {
        self.children.retain_mut(|(key, _, p)| match p.try_wait() {
            Ok(Some(status)) => {
                debug!("\"{}\" exited with code {}", key, status.to_string());
                false
            }
            _ => true,
        });
    }

    pub fn terminate_all_tasks(&mut self) {
        self.evict_dead_processes();
        debug!("terminating {} tasks ...", self.children.len());
        for (key, _, p) in &mut self.children {
            debug!("\"{}\" pid={:?}", key, p.process_information.dwProcessId);
            let err = p.kill();
            if let Err(e) = err {
                info!("failed to kill process. reason={:?}", e.to_string());
            }
        }
    }

    pub fn count_active_tasks(&mut self) -> usize {
        self.evict_dead_processes();
        self.children.len()
    }

    pub fn show_active_tasks(&mut self) {
        self.evict_dead_processes();
        for (key, task, p) in &self.children {
            info!(
                "\"{}\" path=\"{}\" args=[{}] pid={:?}",
                key,
                task.path,
                match &task.args {
                    Some(args) => args.join(", "),
                    None => String::new(),
                },
                p.process_information.dwProcessId
            );
        }
    }

    pub fn show_scheduled_tasks(&self) -> Result<()> {
        let mut pq = std::collections::BinaryHeap::new();

        for (key, task) in &self.config.tasks {
            for when in &task.when {
                match when {
                    When::Cron(cron) => {
                        let schedule = Schedule::from_str(&cron)?;
                        for dt in schedule.upcoming(chrono::Local).take(10) {
                            pq.push(std::cmp::Reverse((dt, key, &task.path, &task.args)));
                        }
                    }
                    _ => (),
                }
            }
        }

        info!("{} scheduled tasks.", std::cmp::min(10, pq.len()));
        for _ in 1..10 {
            if let Some(el) = pq.pop() {
                let t = el.0;
                info!(
                    "({}) [{}] path=\"{}\" args=[{}]",
                    t.0,
                    t.1,
                    t.2,
                    match t.3 {
                        Some(args) => args.join(", "),
                        None => String::new(),
                    },
                );
            }
        }

        Ok(())
    }

    pub fn trigger(&mut self) -> Result<()> {
        self.trigger_tx.send(())?;
        Ok(())
    }
}

fn count_processes(path: &str) -> Result<usize> {
    use sysinfo::SystemExt;

    let mut sys = sysinfo::System::new();
    sys.refresh_processes();

    let path = std::path::PathBuf::from_str(path)?;
    let name = path.file_name().unwrap().to_str().unwrap();

    let processes = sys.processes_by_exact_name(name);
    Ok(processes.count())
}
