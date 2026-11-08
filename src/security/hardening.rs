use std::ffi::c_void;
use windows_sys::Win32::Foundation::HANDLE;
use windows_sys::Win32::System::LibraryLoader::{GetModuleHandleA, GetProcAddress};
use windows_sys::Win32::System::Threading::GetCurrentThread;

type NtSetInformationThreadFn = unsafe extern "system" fn(
    thread_handle: HANDLE,
    thread_information_class: u32,
    thread_information: *const c_void,
    thread_information_length: u32,
) -> i32;

type SetProcessMitigationPolicyFn = unsafe extern "system" fn(
    mitigation_policy: i32,
    lp_buffer: *const c_void,
    dw_length: usize,
) -> i32;

const THREAD_HIDE_FROM_DEBUGGER: u32 = 0x11;
const PROCESS_SIGNATURE_POLICY: i32 = 8;

#[repr(C)]
struct ProcessMitigationBinarySignaturePolicy {
    flags: u32,
}

/// Activates anti-tampering and anti-bypass protections for the scanner process
pub fn apply_all_hardening() {
    // 0. Immediate debugger check (crash immediately if detected)
    crate::security::anti_analysis::crash_if_debugged();

    // 1. Hide the current thread from kernel and usermode debuggers
    hide_current_thread_from_debugger();

    // 2. Anti-Attach Trap: patch DbgUiRemoteBreakin and DbgBreakPoint with UD2 (crashes if a debugger tries to attach)
    neutralize_debugger_attach();

    // 3. Enable process mitigation policy (block unverified DLL injection)
    enable_process_mitigation();

    // 4. Start watchdog thread checking for debugger presence every 200ms
    crate::security::anti_analysis::start_anti_debug_watchdog();
}

/// Neutralizes attempts to attach external debuggers (x64dbg, Cheat Engine, Visual Studio).
/// When a debugger invokes DebugActiveProcess, the Windows kernel injects a thread
/// executing ntdll!DbgUiRemoteBreakin / ntdll!DbgBreakPoint into the target process.
/// We patch the prologue of these functions with the UD2 instruction (0x0F 0x0B - Invalid Opcode),
/// causing any attach attempt to instantly crash with STATUS_ILLEGAL_INSTRUCTION.
pub fn neutralize_debugger_attach() {
    unsafe {
        let ntdll = GetModuleHandleA(b"ntdll.dll\0".as_ptr());
        if ntdll.is_null() {
            return;
        }

        let targets = [
            b"DbgUiRemoteBreakin\0".as_ptr(),
            b"DbgBreakPoint\0".as_ptr(),
        ];

        for &target in &targets {
            let func_ptr = GetProcAddress(ntdll, target);
            if let Some(proc) = func_ptr {
                let mut old_protect = 0u32;
                if windows_sys::Win32::System::Memory::VirtualProtect(
                    proc as *const c_void,
                    2,
                    windows_sys::Win32::System::Memory::PAGE_EXECUTE_READWRITE,
                    &mut old_protect,
                ) != 0
                {
                    let code = proc as *mut u8;
                    // UD2: 0x0F 0x0B (invalid processor opcode on x86/x64 -> unrecoverable crash)
                    *code = 0x0F;
                    *code.add(1) = 0x0B;

                    let mut dummy = 0u32;
                    windows_sys::Win32::System::Memory::VirtualProtect(
                        proc as *const c_void,
                        2,
                        old_protect,
                        &mut dummy,
                    );
                }
            }
        }
    }
}

/// Calls undocumented NtSetInformationThread(ThreadHideFromDebugger),
/// preventing debuggers from intercepting scanner worker threads.
pub fn hide_current_thread_from_debugger() -> bool {
    unsafe {
        let ntdll = GetModuleHandleA(b"ntdll.dll\0".as_ptr());
        if ntdll.is_null() {
            return false;
        }

        let func_ptr = GetProcAddress(ntdll, b"NtSetInformationThread\0".as_ptr());
        if let Some(func) = func_ptr {
            let nt_set_info: NtSetInformationThreadFn = std::mem::transmute(func);
            let status = nt_set_info(
                GetCurrentThread(),
                THREAD_HIDE_FROM_DEBUGGER,
                std::ptr::null(),
                0,
            );
            status == 0
        } else {
            false
        }
    }
}

/// Enforces binary signature policy (MicrosoftSignedOnly),
/// preventing rogue DLL injection into the scanner process.
pub fn enable_process_mitigation() -> bool {
    unsafe {
        let kernel32 = GetModuleHandleA(b"kernel32.dll\0".as_ptr());
        if kernel32.is_null() {
            return false;
        }

        let func_ptr = GetProcAddress(kernel32, b"SetProcessMitigationPolicy\0".as_ptr());
        if let Some(func) = func_ptr {
            let set_policy: SetProcessMitigationPolicyFn = std::mem::transmute(func);

            // MicrosoftSignedOnly = 1 (bit 0)
            let policy = ProcessMitigationBinarySignaturePolicy { flags: 1 };
            let result = set_policy(
                PROCESS_SIGNATURE_POLICY,
                &policy as *const _ as *const c_void,
                std::mem::size_of::<ProcessMitigationBinarySignaturePolicy>(),
            );
            result != 0
        } else {
            false
        }
    }
}

/// Checks whether a function in process memory has been patched with a JMP instruction (0xE9)
/// or a breakpoint trap (0xCC INT 3).
#[allow(dead_code)]
pub fn is_function_hooked(func_ptr: *const ()) -> bool {
    if func_ptr.is_null() {
        return false;
    }
    unsafe {
        let byte = *(func_ptr as *const u8);
        byte == 0xCC || byte == 0xE9
    }
}
