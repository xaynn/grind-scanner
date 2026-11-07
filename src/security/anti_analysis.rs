use std::ffi::c_void;
use std::mem::zeroed;
use windows_sys::Win32::Foundation::{FALSE, HANDLE, LUID};
use windows_sys::Win32::Security::{
    AdjustTokenPrivileges, LookupPrivilegeValueW, LUID_AND_ATTRIBUTES, SE_PRIVILEGE_ENABLED,
    TOKEN_ADJUST_PRIVILEGES, TOKEN_PRIVILEGES, TOKEN_QUERY,
};
use windows_sys::Win32::System::Diagnostics::Debug::{
    CheckRemoteDebuggerPresent, GetThreadContext, IsDebuggerPresent, CONTEXT,
};
use windows_sys::Win32::System::LibraryLoader::{GetModuleHandleA, GetProcAddress};
use windows_sys::Win32::System::Threading::{GetCurrentProcess, GetCurrentThread, OpenProcessToken};

type NtQueryInformationProcessFn = unsafe extern "system" fn(
    process_handle: HANDLE,
    process_information_class: u32,
    process_information: *mut c_void,
    process_information_length: u32,
    return_length: *mut u32,
) -> i32;

/// Checks if current process is running with Administrator privileges
pub fn is_elevated() -> bool {
    unsafe {
        let mut token: HANDLE = std::ptr::null_mut();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
            return false;
        }
        // Check elevation token
        use windows_sys::Win32::Security::{GetTokenInformation, TokenElevation, TOKEN_ELEVATION};
        let mut elevation: TOKEN_ELEVATION = zeroed();
        let mut size = std::mem::size_of::<TOKEN_ELEVATION>() as u32;
        let success = GetTokenInformation(
            token,
            TokenElevation,
            &mut elevation as *mut _ as *mut c_void,
            size,
            &mut size,
        );
        windows_sys::Win32::Foundation::CloseHandle(token);
        success != 0 && elevation.TokenIsElevated != 0
    }
}

/// Enables SeDebugPrivilege so the scanner can inspect javaw.exe and service memory
pub fn enable_debug_privilege() -> bool {
    unsafe {
        let mut token: HANDLE = std::ptr::null_mut();
        if OpenProcessToken(
            GetCurrentProcess(),
            TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
            &mut token,
        ) == 0
        {
            return false;
        }

        let priv_name: Vec<u16> = "SeDebugPrivilege\0".encode_utf16().collect();
        let mut luid: LUID = zeroed();

        if LookupPrivilegeValueW(std::ptr::null(), priv_name.as_ptr(), &mut luid) == 0 {
            windows_sys::Win32::Foundation::CloseHandle(token);
            return false;
        }

        let mut tp: TOKEN_PRIVILEGES = zeroed();
        tp.PrivilegeCount = 1;
        tp.Privileges[0] = LUID_AND_ATTRIBUTES {
            Luid: luid,
            Attributes: SE_PRIVILEGE_ENABLED,
        };

        let result = AdjustTokenPrivileges(
            token,
            FALSE,
            &tp,
            std::mem::size_of::<TOKEN_PRIVILEGES>() as u32,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        );

        windows_sys::Win32::Foundation::CloseHandle(token);
        result != 0
    }
}

/// Natychmiastowe ubicie procesu skanera w sposób uniemożliwiający przechwycenie
/// przez debugery i hooki SEH/VEH (Kernel FastFail / Invalid Opcode / Memory Fault).
#[inline(never)]
pub fn crash_process() -> ! {
    #[cfg(target_arch = "x86_64")]
    unsafe {
        // FAST_FAIL_FATAL_APP_EXIT (0x7) za pomocą instrukcji int 0x29
        core::arch::asm!(
            "int 0x29",
            in("ecx") 7u32,
            options(noreturn)
        );
    }

    #[cfg(not(target_arch = "x86_64"))]
    {
        std::process::abort();
    }
}

/// Jeśli wykryto jakikolwiek ślad debugera lub analizatora, natychmiast ubij proces skanera.
pub fn crash_if_debugged() {
    if is_being_debugged() {
        crash_process();
    }
}

/// Zaawansowana, wielowarstwowa detekcja debugerów (WinAPI, Direct PEB, NtQueryInformationProcess, Hardware Breakpoints).
pub fn is_being_debugged() -> bool {
    unsafe {
        // 1. Standardowe WinAPI
        if IsDebuggerPresent() != 0 {
            return true;
        }

        let mut remote_debugger: i32 = 0;
        if CheckRemoteDebuggerPresent(GetCurrentProcess(), &mut remote_debugger) != 0
            && remote_debugger != 0
        {
            return true;
        }

        // 2. Bezpośrednia inspekcja PEB (omija user-mode hooki na IsDebuggerPresent)
        #[cfg(target_arch = "x86_64")]
        if check_peb_debug_flags() {
            return true;
        }

        // 3. Niskopoziomowe zapytania jądra NT (NtQueryInformationProcess)
        if check_nt_query_process_debug() {
            return true;
        }

        // 4. Sprzętowe pułapki procesora (Hardware Breakpoints DR0-DR3)
        #[cfg(target_arch = "x86_64")]
        if check_hardware_breakpoints() {
            return true;
        }
    }
    false
}

#[cfg(target_arch = "x86_64")]
unsafe fn check_peb_debug_flags() -> bool {
    unsafe {
        let peb: *const u8;
        core::arch::asm!(
            "mov {}, gs:[0x60]",
            out(reg) peb,
            options(nostack, readonly, preserves_flags)
        );
        if !peb.is_null() {
            // BeingDebugged flaga na offsecie +0x02
            let being_debugged = *peb.add(0x02);
            if being_debugged != 0 {
                return true;
            }

            // NtGlobalFlag na offsecie +0xBC (DWORD)
            // FLG_HEAP_ENABLE_TAIL_CHECK (0x10) | FLG_HEAP_ENABLE_FREE_CHECK (0x20) | FLG_HEAP_VALIDATE_PARAMETERS (0x40) = 0x70
            let nt_global_flag = *(peb.add(0xBC) as *const u32);
            if (nt_global_flag & 0x70) == 0x70 {
                return true;
            }
        }
        false
    }
}

unsafe fn check_nt_query_process_debug() -> bool {
    unsafe {
        let ntdll = GetModuleHandleA(b"ntdll.dll\0".as_ptr());
        if ntdll.is_null() {
            return false;
        }

        let proc_addr = GetProcAddress(ntdll, b"NtQueryInformationProcess\0".as_ptr());
        if let Some(proc) = proc_addr {
            let nt_query_info: NtQueryInformationProcessFn = std::mem::transmute(proc);

            // A. ProcessDebugPort (klasa 7)
            let mut debug_port: usize = 0;
            let status1 = nt_query_info(
                GetCurrentProcess(),
                7, // ProcessDebugPort
                &mut debug_port as *mut _ as *mut c_void,
                std::mem::size_of::<usize>() as u32,
                std::ptr::null_mut(),
            );
            if status1 == 0 && debug_port != 0 {
                return true;
            }

            // B. ProcessDebugObjectHandle (klasa 30 / 0x1E)
            let mut debug_object: HANDLE = std::ptr::null_mut();
            let status2 = nt_query_info(
                GetCurrentProcess(),
                30, // ProcessDebugObjectHandle
                &mut debug_object as *mut _ as *mut c_void,
                std::mem::size_of::<HANDLE>() as u32,
                std::ptr::null_mut(),
            );
            if status2 == 0 && !debug_object.is_null() {
                return true;
            }

            // C. ProcessDebugFlags (klasa 31 / 0x1F)
            let mut debug_flags: u32 = 0;
            let status3 = nt_query_info(
                GetCurrentProcess(),
                31, // ProcessDebugFlags
                &mut debug_flags as *mut _ as *mut c_void,
                std::mem::size_of::<u32>() as u32,
                std::ptr::null_mut(),
            );
            if status3 == 0 && debug_flags == 0 {
                return true;
            }
        }
        false
    }
}

#[cfg(target_arch = "x86_64")]
unsafe fn check_hardware_breakpoints() -> bool {
    unsafe {
        const CONTEXT_AMD64: u32 = 0x00100000;
        const CONTEXT_DEBUG_REGISTERS: u32 = CONTEXT_AMD64 | 0x00000010;

        let mut ctx: CONTEXT = zeroed();
        ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;

        if GetThreadContext(GetCurrentThread(), &mut ctx) != 0 {
            if ctx.Dr0 != 0 || ctx.Dr1 != 0 || ctx.Dr2 != 0 || ctx.Dr3 != 0 {
                return true;
            }
        }
        false
    }
}

/// Uruchamia wątek monitorujący w tle, który co 200ms weryfikuje obecność debugera
/// i natychmiast ubija aplikację, jeśli ktoś spróbuje podpiąć debugger w trakcie działania programu.
pub fn start_anti_debug_watchdog() {
    std::thread::Builder::new()
        .name("integrity-guard".to_string())
        .spawn(move || {
            crate::security::hardening::hide_current_thread_from_debugger();
            loop {
                std::thread::sleep(std::time::Duration::from_millis(200));
                crash_if_debugged();
            }
        })
        .ok();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_being_debugged_safe_execution() {
        // W normalnym środowisku testowym (bez aktywnego debugera) funkcja powinna się wykonać bez błędów
        let _ = is_being_debugged();
    }
}
