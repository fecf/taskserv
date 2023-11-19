// ref. https://github.com/murrayju/CreateProcessAsUser

#![allow(dead_code)]

use eyre::{Context, Result};
use log::{debug, info};
use scopeguard::guard;
use std::ptr::{null, null_mut};
use windows::{
    core::{w, PCWSTR, PWSTR},
    Win32::{
        Foundation::*,
        Security::*,
        System::{Environment::*, RemoteDesktop::*, Threading::*},
    },
};

pub struct Process {
    pub startup_info: STARTUPINFOW,
    pub process_information: PROCESS_INFORMATION,
}

impl Process {
    pub fn try_wait(&self) -> Result<Option<u32>> {
        let mut exit_code: u32 = 0;
        unsafe {
            GetExitCodeProcess(self.process_information.hProcess, &mut exit_code)
                .wrap_err("failed to GetExitCodeProcess().")?;
        }
        if exit_code == 259 {
            // STILL_ACTIVE
            return Ok(None);
        }
        Ok(Some(exit_code))
    }
    pub fn kill(&mut self) -> Result<()> {
        unsafe {
            CloseHandle(self.process_information.hProcess).wrap_err("failed to CloseHandle().")?;
        }
        Ok(())
    }
}

pub fn get_session_user_token() -> Result<HANDLE> {
    let mut active_session_id: u32 = u32::MAX;
    let mut psi: *mut WTS_SESSION_INFOW = null_mut();
    let mut pc: u32 = 0;

    let mut impersonation_token: HANDLE = HANDLE::default();
    let mut linked_token: HANDLE = HANDLE::default();

    let _ = scopeguard::guard(impersonation_token, |mut handle| unsafe {
        let _ = CloseHandle(handle);
    });
    let _ = scopeguard::guard(linked_token, |mut handle| unsafe {
        let _ = CloseHandle(handle);
    });

    if let Ok(_) =
        unsafe { WTSEnumerateSessionsW(WTS_CURRENT_SERVER_HANDLE, 0, 1, &mut psi, &mut pc) }
    {
        let sessions = unsafe { Vec::from_raw_parts(psi, pc as usize, pc as usize) };
        for session in sessions {
            if session.State == WTSActive {
                active_session_id = session.SessionId;
                if let Ok(_) =
                    unsafe { WTSQueryUserToken(active_session_id, &mut impersonation_token) }
                {
                    break;
                }
            }
        }
    }
    if active_session_id == u32::MAX {
        active_session_id = unsafe { WTSGetActiveConsoleSessionId() };
    }

    unsafe {
        WTSQueryUserToken(active_session_id, &mut impersonation_token)
            .wrap_err("failed to WTSQueryUserToken().")?
    };

    let mut buffer = Vec::<u8>::new();
    let mut buffer_length: u32 = std::mem::size_of::<TOKEN_ELEVATION_TYPE>() as u32;
    let mut return_length: u32 = 0;
    buffer.resize(buffer_length as usize, 0);
    unsafe {
        GetTokenInformation(
            impersonation_token,
            TokenElevationType,
            Some(buffer.as_mut_ptr() as *mut std::ffi::c_void),
            buffer_length,
            &mut return_length,
        )
        .wrap_err("failed to GetTokenInformation() 1.")?;
    }

    let token_elevation_type_ptr = buffer.as_ptr() as *const TOKEN_ELEVATION_TYPE;
    let token_elevation_type = unsafe { token_elevation_type_ptr.read().0 };
    if token_elevation_type == TokenElevationTypeLimited.0 {
        buffer_length = std::mem::size_of::<TOKEN_LINKED_TOKEN>() as u32;
        buffer.resize(buffer_length as usize, 0);
        unsafe {
            GetTokenInformation(
                impersonation_token,
                TokenLinkedToken,
                Some(buffer.as_mut_ptr() as *mut std::ffi::c_void),
                buffer_length,
                &mut return_length,
            )
            .wrap_err("failed to GetTokenInformation() 2.")?;
        }
        linked_token = HANDLE(unsafe { (buffer.as_ptr() as *const HANDLE).read().0 });
        assert!(!linked_token.is_invalid());
    }

    let mut duplicated_token: HANDLE = HANDLE::default();
    unsafe {
        DuplicateTokenEx(
            if linked_token.is_invalid() {
                impersonation_token
            } else {
                linked_token
            },
            TOKEN_ALL_ACCESS,
            None,
            SecurityImpersonation,
            TokenPrimary,
            &mut duplicated_token,
        )
        .wrap_err("failed to DuplicateTokenEx().")?;
    }
    return Ok(duplicated_token);
}

pub fn start_process(path: &str, cwd: &str, args: Vec<String>) -> Result<Process> {
    let mut ret: Process = Process {
        startup_info: STARTUPINFOW::default(),
        process_information: PROCESS_INFORMATION::default(),
    };
    ret.startup_info.cb = std::mem::size_of::<STARTUPINFOW>() as u32;

    let flags = PROCESS_CREATION_FLAGS::default();

    let cmd = format!("\"{}\" {}", path, args.join(" "));
    let cmd_utf16: Vec<u16> = cmd.encode_utf16().chain(Some(0)).collect();
    let cmd_pwstr = PWSTR(cmd_utf16.as_ptr() as *mut u16);

    let cwd_utf16: Vec<u16> = cwd.encode_utf16().chain(Some(0)).collect();
    let mut cwd_pcwstr = PCWSTR(null());
    if !cwd.is_empty() {
        cwd_pcwstr = PCWSTR(cwd_utf16.as_ptr() as *const u16);
    }

    let mut sid: u32 = 0xffffffff;
    unsafe {
        ProcessIdToSessionId(GetCurrentProcessId(), &mut sid).wrap_err_with(|| {
            format!(
                "failed to ProcessIdToSessionId(). err={:?}",
                GetLastError().err()
            )
        })?;
    }

    if sid == 0 {
        // service
        let user_token = get_session_user_token()?;
        let mut environment_block: *mut std::ffi::c_void = std::ptr::null_mut();
        unsafe {
            CreateEnvironmentBlock(&mut environment_block, user_token, false).wrap_err_with(
                || {
                    format!(
                        "failed to CreateEnvironmentBlock(). err={:?}",
                        GetLastError().err()
                    )
                },
            )?;
        }

        unsafe {
            ImpersonateLoggedOnUser(user_token).wrap_err_with(|| {
                format!(
                    "failed to ImpersonateLoggedOnUser(). err={:?}",
                    GetLastError().err()
                )
            })?;
        }
        defer! {
          unsafe { let _ = RevertToSelf(); }
        }

        ret.startup_info.lpDesktop = PWSTR(w!("winsta0\\default").as_ptr() as *mut u16);
        unsafe {
            CreateProcessAsUserW(
                user_token,
                PCWSTR(null()),
                cmd_pwstr,
                None,
                None,
                false,
                CREATE_UNICODE_ENVIRONMENT | NORMAL_PRIORITY_CLASS,
                Some(environment_block),
                cwd_pcwstr,
                &mut ret.startup_info,
                &mut ret.process_information,
            )
            .wrap_err_with(|| {
                format!(
                    "failed to CreateProcessAsUserW(). err={:?}",
                    GetLastError().err()
                )
            })?;
        }
    } else {
        // debug!("CreateProcessW() path={} cmd={} cwd={} flags={}", path, cmd, cwd, flags.0);
        unsafe {
            CreateProcessW(
                PCWSTR(null()),
                cmd_pwstr,
                None,
                None,
                false,
                flags,
                None,
                cwd_pcwstr,
                &mut ret.startup_info,
                &mut ret.process_information,
            )
            .wrap_err_with(|| {
                format!("failed to CreateProcessW. err={:?}", GetLastError().err())
            })?;
        }
    }
    return Ok(ret);
}
