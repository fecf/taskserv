#[macro_use(defer)]
extern crate scopeguard;

mod config;
mod process;
mod service;
mod task_runner;
mod task_runner_test;

use log::*;
use std::os::windows::fs::OpenOptionsExt;
use windows::Win32::{Foundation::*, Security::*, System::Threading::*};

const LOG_FILE_NAME: &str = "taskserv.log";

fn main() -> eyre::Result<()> {
    // initialize logger
    fern::Dispatch::new()
        .level(log::LevelFilter::Info)
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
        .chain(
            std::fs::OpenOptions::new()
                .write(true)
                .create(true)
                .append(true)
                .share_mode(0x01 | 0x02)
                .open(std::env::current_exe()?.with_file_name(LOG_FILE_NAME))
                .unwrap(),
        )
        .apply()
        .expect("failed to initialize logger.");

    // get first argument
    let args: Vec<String> = std::env::args().collect();
    if args.len() <= 1 {
        usage();
        return Ok(());
    }
    let arg: &str = args[1].as_str();

    // service mode
    if arg == "/service" {
        if let Err(e) = service::run() {
            error!("{:?}", e);
        }
        return Ok(());
    }

    // console mode
    info!(
        "TaskServ {} ({})",
        env!("CARGO_PKG_VERSION"),
        env!("CARGO_PKG_HOMEPAGE")
    );
    match arg {
        "install" => {
            if is_elevated() {
                service::install()?;
                info!("Install completed.");
                Ok(())
            } else {
                info!("\"install\" requires administrator privileges.");
                Ok(())
            }
        }
        "uninstall" => {
            if is_elevated() {
                service::uninstall()?;
                info!("Uninstall completed.");
                Ok(())
            } else {
                info!("\"uninstall\" requires administrator privileges.");
                Ok(())
            }
        }
        "restart" => service::restart(),
        "trigger" => service::trigger(),
        "run" => service::run_without_service(),
        _ => {
            info!("unknown command \"{}\".", arg);
            Ok(())
        }
    }?;
    Ok(())
}

fn usage() {
    const MSG: &str = "\
TaskServ (https://github.com/fecf/taskserv)

TaskServ runs specified actions as written in taskserv.conf. 
taskserv.conf will be automatically reloaded when modified.

Usage:
  taskserv              Show usage
  taskserv install      Install and start the service
  taskserv uninstall    Uninstall the service
  taskserv trigger      Run triggerable tasks
  taskserv run          Start taskserv without service
";
    println!("{}", &MSG);
}

fn is_elevated() -> bool {
    // ref. https://users.rust-lang.org/t/how-do-i-determine-if-i-have-admin-rights-on-windows/35710/8
    unsafe {
        let mut handle = HANDLE(0);
        OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut handle).unwrap();

        let mut elevation = TOKEN_ELEVATION::default();
        let size = std::mem::size_of::<TOKEN_ELEVATION>() as u32;
        let mut ret_size = size;
        let _ = GetTokenInformation(
            handle,
            TokenElevation,
            Some(&mut elevation as *mut _ as *mut _),
            size,
            &mut ret_size,
        )
        .unwrap();
        return elevation.TokenIsElevated != 0;
    }
}
