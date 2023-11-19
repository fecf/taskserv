use crate::task_runner::*;
use eyre::Result;
use log::*;
use std::{ffi::OsString, time::Duration};
use windows_service::{
    define_windows_service,
    service::{
        ServiceAccess, ServiceControl, ServiceControlAccept, ServiceErrorControl, ServiceExitCode,
        ServiceInfo, ServiceStartType, ServiceState, ServiceStatus, ServiceType, UserEventCode,
    },
    service_control_handler::{self, ServiceControlHandlerResult},
    service_dispatcher,
    service_manager::{ServiceManager, ServiceManagerAccess},
};

const SERVICE_NAME: &str = "TaskServ";
const UPDATE_INTERVAL_MS: u64 = 1000;

enum Notify {
    Shutdown,
    UserEvent,
}

pub fn run() -> Result<()> {
    service_dispatcher::start(SERVICE_NAME, ffi_service_main)?;
    Ok(())
}

define_windows_service!(ffi_service_main, taskserv_service_main);

pub fn taskserv_service_main(_arguments: Vec<OsString>) {
    if let Err(_e) = run_service() {
        error!("{}", _e);
    }
}

pub fn run_service() -> Result<()> {
    let (notify_tx, notify_rx) = std::sync::mpsc::channel();

    let event_handler = move |control_event| -> ServiceControlHandlerResult {
        match control_event {
            ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
            ServiceControl::Stop => {
                notify_tx.send(Notify::Shutdown).unwrap();
                ServiceControlHandlerResult::NoError
            }
            ServiceControl::UserEvent(_) => {
                notify_tx.send(Notify::UserEvent).unwrap();
                ServiceControlHandlerResult::NoError
            }
            _ => ServiceControlHandlerResult::NotImplemented,
        }
    };

    let status_handle = service_control_handler::register(SERVICE_NAME, event_handler)?;
    status_handle.set_service_status(ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: ServiceState::Running,
        controls_accepted: ServiceControlAccept::STOP,
        exit_code: ServiceExitCode::Win32(0),
        checkpoint: 0,
        wait_hint: std::time::Duration::default(),
        process_id: None,
    })?;

    let mut task_runner: TaskRunner = TaskRunner::new();
    task_runner.initialize()?;
    loop {
        std::thread::sleep(std::time::Duration::from_millis(UPDATE_INTERVAL_MS));
        match notify_rx.recv_timeout(Duration::from_secs(0)) {
            Ok(Notify::Shutdown) => break,
            Ok(Notify::UserEvent) => task_runner.trigger(),
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => break,
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => Ok(()),
        }?;
        match task_runner.tick() {
            Ok(()) => (),
            Err(e) => error!("{:#?}", e),
        }
    }

    status_handle.set_service_status(ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: ServiceState::Stopped,
        controls_accepted: ServiceControlAccept::empty(),
        exit_code: ServiceExitCode::Win32(0),
        checkpoint: 0,
        wait_hint: std::time::Duration::default(),
        process_id: None,
    })?;

    Ok(())
}

pub fn run_without_service() -> Result<()> {
    let mut task_runner: TaskRunner = TaskRunner::new();
    task_runner.initialize()?;
    loop {
        std::thread::sleep(std::time::Duration::from_millis(UPDATE_INTERVAL_MS));
        match task_runner.tick() {
            Ok(()) => (),
            Err(e) => error!("{:#?}", e),
        }
    }
}

pub fn install() -> Result<()> {
    let service_binary_path = std::env::current_exe().unwrap();
    let service_info = ServiceInfo {
        name: OsString::from(SERVICE_NAME),
        display_name: OsString::from("TaskServ Service"),
        service_type: ServiceType::OWN_PROCESS,
        start_type: ServiceStartType::AutoStart,
        error_control: ServiceErrorControl::Normal,
        executable_path: service_binary_path,
        dependencies: vec![],
        account_name: None, // None: LocalSystem
        account_password: None,
        launch_arguments: Vec::from([OsString::from("/service")]),
    };
    let service_manager = ServiceManager::local_computer(
        None::<&str>,
        ServiceManagerAccess::CREATE_SERVICE | ServiceManagerAccess::CONNECT,
    )?;

    let service = service_manager.create_service(
        &service_info,
        ServiceAccess::CHANGE_CONFIG | ServiceAccess::START,
    )?;
    service.set_description("TaskServ https://github.com/fecf/taskserv")?;
    restart()
}

pub fn uninstall() -> Result<()> {
    let service_manager =
        ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)?;
    let service = service_manager.open_service(
        SERVICE_NAME,
        ServiceAccess::STOP | ServiceAccess::DELETE | ServiceAccess::QUERY_STATUS,
    )?;
    if service.query_status()?.current_state != ServiceState::Stopped {
        let _ = service.stop();
    }
    service.delete()?;
    Ok(())
}

pub fn restart() -> Result<()> {
    let service_manager =
        ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)?;
    let service = service_manager.open_service(
        SERVICE_NAME,
        ServiceAccess::QUERY_STATUS | ServiceAccess::STOP | ServiceAccess::START,
    )?;
    if service.query_status()?.current_state == ServiceState::Running {
        let _ = service.stop();
    }
    service.start(&[std::ffi::OsStr::new("/service")])?;
    Ok(())
}

pub fn trigger() -> Result<()> {
    let service_manager =
        ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)?;
    let service =
        service_manager.open_service(SERVICE_NAME, ServiceAccess::USER_DEFINED_CONTROL)?;
    service.notify(UserEventCode::from_raw(128).unwrap())?;
    Ok(())
}
