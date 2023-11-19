#[cfg(test)]
mod tests {
    use crate::task_runner::TaskRunner;
    use std::sync::Once;

    fn init(cfg: &str) -> TaskRunner {
        static ONCE: Once = Once::new();
        ONCE.call_once(|| {
            fern::Dispatch::new()
                .level(log::LevelFilter::Debug)
                .format(|out, message, record| {
                    out.finish(format_args!(
                        "[{} {} {}] {}",
                        humantime::format_rfc3339(std::time::SystemTime::now()),
                        record.level(),
                        record.target(),
                        message
                    ))
                })
                .chain(std::io::stdout())
                .apply()
                .expect("failed to initialize logger.");
        });

        let mut app = crate::task_runner::TaskRunner::new();
        app.load_config(cfg).unwrap();
        return app;
    }

    fn enum_processes(name: &str) -> Vec<u32> {
        use sysinfo::{Pid, PidExt, ProcessExt, System, SystemExt};
        let mut sys = System::new();
        sys.refresh_processes();

        let c: Vec<u32> = sys
            .processes_by_name(name)
            .map(|p| p.pid().as_u32())
            .collect();
        return c;
    }

    #[test]
    fn test_startup() {
        let cfg: &str = r#"
[notepad]
when = "startup"
path = "notepad.exe"
"#;
        let mut app = init(cfg);
        app.tick();
        assert_eq!(app.count_active_tasks(), 1);
    }

    #[test]
    fn test_trigger() {
        let cfg: &str = r#"
[notepad]
when = "trigger"
path = "notepad.exe"
"#;
        let mut app = init(cfg);
        app.trigger();
        app.tick();
        assert_eq!(app.count_active_tasks(), 1);
    }

    #[test]
    fn test_cron() {
        let cfg: &str = r#"
[notepad]
when = { cron = "0/1 * * * * * * " }
path = "notepad.exe"
max_instances = 1
"#;
        let mut app = init(cfg);
        let now = std::time::SystemTime::now();
        while now.elapsed().unwrap() < std::time::Duration::from_millis(3500) {
            app.tick().unwrap();
        }
        assert_eq!(app.count_active_tasks(), 1);
    }

    #[test]
    fn test_dry_run() {
        let cfg: &str = r#"
dry_run = true
[notepad]
when = { cron = "0/1 * * * * * * " }
path = "notepad.exe"
max_instances = 1
"#;
        let mut app = init(cfg);
        let now = std::time::SystemTime::now();
        while now.elapsed().unwrap() < std::time::Duration::from_millis(3500) {
            app.tick().unwrap();
        }
        assert_eq!(app.count_active_tasks(), 0);
    }
}
