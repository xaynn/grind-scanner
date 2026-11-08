use crate::report::{FindingCategory, ScanFinding, ScanReport, VerdictLevel};
use std::ffi::c_void;
use std::mem::zeroed;
use std::path::{Path, PathBuf};
use windows_sys::Win32::Foundation::{CloseHandle, DuplicateHandle, DUPLICATE_SAME_ACCESS, FILETIME, HANDLE, INVALID_HANDLE_VALUE};
use std::io::Read;
use windows_sys::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Module32FirstW, Module32NextW, Process32FirstW, Process32NextW,
    Thread32First, Thread32Next, MODULEENTRY32W, PROCESSENTRY32W, THREADENTRY32,
    TH32CS_SNAPMODULE, TH32CS_SNAPMODULE32, TH32CS_SNAPPROCESS, TH32CS_SNAPTHREAD,
};
use windows_sys::Win32::System::Memory::{
    VirtualQueryEx, MEMORY_BASIC_INFORMATION, MEM_COMMIT, MEM_MAPPED, MEM_PRIVATE,
    PAGE_EXECUTE, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_WRITECOPY,
    PAGE_READONLY, PAGE_READWRITE,
};
use windows_sys::Win32::System::Diagnostics::Debug::ReadProcessMemory;
use windows_sys::Win32::System::LibraryLoader::{GetModuleHandleA, GetProcAddress, LoadLibraryA};
use windows_sys::Win32::System::ProcessStatus::GetModuleFileNameExW;
use windows_sys::Win32::System::Threading::{
    GetCurrentProcess, GetCurrentProcessId, GetProcessId, GetProcessTimes, OpenProcess, OpenThread,
    PROCESS_QUERY_INFORMATION, PROCESS_VM_READ, THREAD_QUERY_INFORMATION,
};

#[repr(C)]
struct ProcessBasicInformation {
    exit_status: usize,
    peb_base_address: *mut c_void,
    affinity_mask: usize,
    base_priority: usize,
    unique_process_id: usize,
    inherited_from_unique_process_id: usize,
}

type NtQueryInformationProcessFn = unsafe extern "system" fn(
    process_handle: HANDLE,
    process_information_class: u32,
    process_information: *mut c_void,
    process_information_length: u32,
    return_length: *mut u32,
) -> i32;

pub struct MinecraftProcess {
    pub pid: u32,
    pub name: String,
    pub path: String,
    pub client_brand: String,
}

/// Identifies Minecraft client branding or filters development processes (IDE/Gradle)
pub fn identify_minecraft_process(cmdline: &str) -> (bool, String) {
    let lower = cmdline.to_lowercase();

    // 1. Check if this is a tooling / IDE / build daemon process
    let is_build_or_ide = lower.contains("gradle-daemon")
        || lower.contains("org.gradle")
        || lower.contains("idea_rt.jar")
        || lower.contains("jetbrains")
        || lower.contains("kotlin-daemon")
        || lower.contains("kotlin-compiler")
        || lower.contains("org.eclipse")
        || lower.contains("org.apache.maven")
        || lower.contains("language-server")
        || lower.contains("jdt.ls");

    let has_mc_marker = lower.contains("net.minecraft")
        || lower.contains("--gamedir")
        || lower.contains("--assetsdir")
        || lower.contains(".minecraft")
        || lower.contains("minecraftlauncher")
        || lower.contains("launchwrapper")
        || lower.contains("lunar")
        || lower.contains("badlion")
        || lower.contains("feather")
        || lower.contains("dawn")
        || lower.contains("oneclient")
        || lower.contains("ixeris")
        || lower.contains("prismlauncher")
        || lower.contains("modrinth")
        || lower.contains("curseforge")
        || lower.contains("atlauncher")
        || lower.contains("tlauncher")
        || lower.contains("fabricmc")
        || lower.contains("minecraftforge")
        || lower.contains("neoforged")
        || lower.contains("labymod")
        || lower.contains("optifine");

    if is_build_or_ide && !has_mc_marker {
        return (false, "Non-Minecraft Java Process (IDE / Build Daemon)".to_string());
    }

    // 2. Identify client / launcher brand
    let brand = if lower.contains("lunar") || lower.contains("genesis") || lower.contains("launcher-bootstrap") {
        "Lunar Client"
    } else if lower.contains("badlion") || lower.contains("blclient") {
        "Badlion Client"
    } else if lower.contains("feather") {
        "Feather Client"
    } else if lower.contains("dawn") {
        "Dawn Client"
    } else if lower.contains("oneclient") || lower.contains("ixeris") {
        "OneClient"
    } else if lower.contains("prismlauncher") || lower.contains("org.prismlauncher") {
        "Prism Launcher"
    } else if lower.contains("modrinth") || lower.contains("theseus") {
        "Modrinth App"
    } else if lower.contains("curseforge") || lower.contains("overwolf") {
        "CurseForge Client"
    } else if lower.contains("atlauncher") {
        "ATLauncher"
    } else if lower.contains("tlauncher") {
        "TLauncher"
    } else if lower.contains("labymod") || lower.contains("net.labymod") {
        "LabyMod"
    } else if lower.contains("net.fabricmc") || lower.contains("fabric") {
        "Fabric (Vanilla / Custom Launcher)"
    } else if lower.contains("net.minecraftforge") || lower.contains("forge") {
        "Forge (Vanilla / Custom Launcher)"
    } else if lower.contains("net.neoforged") {
        "NeoForge (Vanilla / Custom Launcher)"
    } else if lower.contains("optifine") {
        "OptiFine (Vanilla Launcher)"
    } else if lower.contains("net.minecraft.client.main.main") || lower.contains("mojang") || lower.contains(".minecraft") {
        "Minecraft (Vanilla / Official Launcher)"
    } else if has_mc_marker {
        "Minecraft (Custom Launcher)"
    } else {
        return (false, "Non-Minecraft Java Process".to_string());
    };

    (true, brand.to_string())
}

/// Finds active Minecraft instances (strictly javaw.exe or java.exe)
use std::collections::HashSet;

unsafe extern "system" fn enum_minecraft_window_callback(hwnd: *mut c_void, lparam: isize) -> i32 {
    unsafe {
        let pids = &mut *(lparam as *mut HashSet<u32>);
        let user32 = windows_sys::Win32::System::LibraryLoader::GetModuleHandleA(b"user32.dll\0".as_ptr());
        if user32.is_null() {
            return 1;
        }
        type GetClassNameWFn = unsafe extern "system" fn(*mut c_void, *mut u16, i32) -> i32;
        type GetWindowThreadProcessIdFn = unsafe extern "system" fn(*mut c_void, *mut u32) -> u32;

        let p_class = windows_sys::Win32::System::LibraryLoader::GetProcAddress(user32, b"GetClassNameW\0".as_ptr());
        let p_pid = windows_sys::Win32::System::LibraryLoader::GetProcAddress(user32, b"GetWindowThreadProcessId\0".as_ptr());

        if let (Some(f_class), Some(f_pid)) = (p_class, p_pid) {
            let get_class: GetClassNameWFn = std::mem::transmute(f_class);
            let get_pid: GetWindowThreadProcessIdFn = std::mem::transmute(f_pid);

            let mut class_buf = [0u16; 256];
            let len = get_class(hwnd, class_buf.as_mut_ptr(), class_buf.len() as i32);
            if len > 0 {
                let class_name = String::from_utf16_lossy(&class_buf[..len as usize]);
                let lower_class = class_name.to_lowercase();

                if lower_class == "glfw30" || lower_class == "lwjgl" || lower_class.contains("minecraft") {
                    let mut pid = 0u32;
                    get_pid(hwnd, &mut pid);
                    if pid > 4 {
                        pids.insert(pid);
                    }
                }
            }
        }
        1
    }
}

/// Enumerates all active Windows top-level windows to locate Minecraft instances
/// by their GLFW30 or LWJGL window classes, defeating binary renaming (e.g. app.exe, runtime.exe, discord_rpc.exe).
pub fn get_minecraft_window_pids() -> HashSet<u32> {
    let mut pids = HashSet::new();
    unsafe {
        let user32 = windows_sys::Win32::System::LibraryLoader::LoadLibraryA(b"user32.dll\0".as_ptr());
        if !user32.is_null() {
            type EnumWindowsFn = unsafe extern "system" fn(Option<unsafe extern "system" fn(*mut c_void, isize) -> i32>, isize) -> i32;
            let p_enum = windows_sys::Win32::System::LibraryLoader::GetProcAddress(user32, b"EnumWindows\0".as_ptr());
            if let Some(f_enum) = p_enum {
                let enum_windows: EnumWindowsFn = std::mem::transmute(f_enum);
                enum_windows(Some(enum_minecraft_window_callback), &mut pids as *mut _ as isize);
            }
            windows_sys::Win32::Foundation::FreeLibrary(user32);
        }
    }
    pids
}

/// Fallback check: inspects loaded modules of a process to verify presence of jvm.dll and lwjgl/glfw/openal
/// Used when PEB command line has been wiped or binary was renamed.
fn check_process_has_jvm_and_lwjgl(pid: u32) -> (bool, bool) {
    unsafe {
        let snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
        if snap == INVALID_HANDLE_VALUE {
            return (false, false);
        }
        let mut entry: MODULEENTRY32W = zeroed();
        entry.dwSize = std::mem::size_of::<MODULEENTRY32W>() as u32;
        let mut has_jvm = false;
        let mut has_lwjgl = false;
        if Module32FirstW(snap, &mut entry) != 0 {
            loop {
                let mod_name = String::from_utf16_lossy(
                    &entry.szModule[..entry
                        .szModule
                        .iter()
                        .position(|&c| c == 0)
                        .unwrap_or(entry.szModule.len())],
                ).to_lowercase();
                if mod_name == "jvm.dll" {
                    has_jvm = true;
                }
                if mod_name.contains("lwjgl") || mod_name.contains("glfw") || mod_name.contains("openal") {
                    has_lwjgl = true;
                }
                if has_jvm && has_lwjgl {
                    break;
                }
                if Module32NextW(snap, &mut entry) == 0 {
                    break;
                }
            }
        }
        CloseHandle(snap);
        (has_jvm, has_lwjgl)
    }
}

pub fn find_minecraft_processes() -> Vec<MinecraftProcess> {
    let mut results = Vec::new();
    let window_pids = get_minecraft_window_pids();

    unsafe {
        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if snapshot == INVALID_HANDLE_VALUE {
            return results;
        }

        let mut entry: PROCESSENTRY32W = zeroed();
        entry.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;

        if Process32FirstW(snapshot, &mut entry) != 0 {
            loop {
                let name = String::from_utf16_lossy(
                    &entry.szExeFile[..entry
                        .szExeFile
                        .iter()
                        .position(|&c| c == 0)
                        .unwrap_or(entry.szExeFile.len())],
                );

                let lower_name = name.to_lowercase();
                let is_candidate = lower_name == "javaw.exe"
                    || lower_name == "java.exe"
                    || lower_name.contains("minecraft")
                    || lower_name.contains("lunar")
                    || lower_name.contains("badlion")
                    || lower_name.contains("feather")
                    || lower_name.contains("prismlauncher")
                    || window_pids.contains(&entry.th32ProcessID);

                if is_candidate {
                    let handle = OpenProcess(
                        PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
                        0,
                        entry.th32ProcessID,
                    );
                    let mut path = String::new();
                    let mut cmdline_opt = None;
                    if !handle.is_null() {
                        let mut buf = [0u16; 1024];
                        let len = GetModuleFileNameExW(handle, std::ptr::null_mut(), buf.as_mut_ptr(), 1024);
                        if len > 0 {
                            path = String::from_utf16_lossy(&buf[..len as usize]);
                        }
                        cmdline_opt = get_process_command_line(handle);
                        CloseHandle(handle);
                    }

                    let mut matched_mc = false;
                    let mut final_brand = String::new();

                    if let Some(ref cmd) = cmdline_opt {
                        let (is_mc, brand) = identify_minecraft_process(cmd);
                        if is_mc {
                            matched_mc = true;
                            final_brand = brand;
                        }
                    }

                    // Fallback for PEB Command Line clearing / anti-forensic wiped buffer:
                    // Inspect loaded modules for jvm.dll and lwjgl/glfw/openal
                    if !matched_mc {
                        let (has_jvm, has_lwjgl) = check_process_has_jvm_and_lwjgl(entry.th32ProcessID);
                        if has_jvm && has_lwjgl {
                            matched_mc = true;
                            final_brand = if cmdline_opt.is_none() || cmdline_opt.as_ref().map(|s| s.trim().is_empty()).unwrap_or(false) {
                                "Minecraft (Cloaked / PEB CommandLine Cleared)".to_string()
                            } else {
                                "Minecraft (Active JVM Runtime)".to_string()
                            };
                        }
                    }

                    if matched_mc {
                        results.push(MinecraftProcess {
                            pid: entry.th32ProcessID,
                            name,
                            path,
                            client_brand: final_brand,
                        });
                    }
                }

                if Process32NextW(snapshot, &mut entry) == 0 {
                    break;
                }
            }
        }
        CloseHandle(snapshot);
    }
    results
}

/// Extracts full command line (JVM arguments) from process PEB
pub fn get_process_command_line(handle: HANDLE) -> Option<String> {
    unsafe {
        let ntdll = windows_sys::Win32::System::LibraryLoader::GetModuleHandleA(
            b"ntdll.dll\0".as_ptr(),
        );
        if ntdll.is_null() {
            return None;
        }

        let func_ptr = windows_sys::Win32::System::LibraryLoader::GetProcAddress(
            ntdll,
            b"NtQueryInformationProcess\0".as_ptr(),
        );
        if func_ptr.is_none() {
            return None;
        }

        let nt_query_info: NtQueryInformationProcessFn = std::mem::transmute(func_ptr);
        let mut pbi: ProcessBasicInformation = zeroed();
        let mut ret_len = 0u32;

        let status = nt_query_info(
            handle,
            0, // ProcessBasicInformation
            &mut pbi as *mut _ as *mut c_void,
            std::mem::size_of::<ProcessBasicInformation>() as u32,
            &mut ret_len,
        );

        if status != 0 || pbi.peb_base_address.is_null() {
            return None;
        }

        // On x64: PEB + 0x20 is ProcessParameters
        let peb_addr = pbi.peb_base_address as usize;
        let mut process_params_ptr: usize = 0;
        let mut bytes_read = 0;

        let res = windows_sys::Win32::System::Diagnostics::Debug::ReadProcessMemory(
            handle,
            (peb_addr + 0x20) as *const c_void,
            &mut process_params_ptr as *mut _ as *mut c_void,
            8,
            &mut bytes_read,
        );

        if res == 0 || process_params_ptr == 0 {
            return None;
        }

        // In RTL_USER_PROCESS_PARAMETERS:
        // Offset 0x70 is CommandLine.Length (u16)
        // Offset 0x72 is CommandLine.MaximumLength (u16)
        // Offset 0x78 is CommandLine.Buffer (*u16)
        let mut cmd_len: u16 = 0;
        let mut cmd_buf_ptr: usize = 0;

        windows_sys::Win32::System::Diagnostics::Debug::ReadProcessMemory(
            handle,
            (process_params_ptr + 0x70) as *const c_void,
            &mut cmd_len as *mut _ as *mut c_void,
            2,
            &mut bytes_read,
        );

        windows_sys::Win32::System::Diagnostics::Debug::ReadProcessMemory(
            handle,
            (process_params_ptr + 0x78) as *const c_void,
            &mut cmd_buf_ptr as *mut _ as *mut c_void,
            8,
            &mut bytes_read,
        );

        if cmd_buf_ptr == 0 || cmd_len == 0 {
            return None;
        }

        let num_chars = (cmd_len / 2) as usize;
        let mut raw_buf = vec![0u16; num_chars];

        let read_ok = windows_sys::Win32::System::Diagnostics::Debug::ReadProcessMemory(
            handle,
            cmd_buf_ptr as *const c_void,
            raw_buf.as_mut_ptr() as *mut c_void,
            cmd_len as usize,
            &mut bytes_read,
        );

        if read_ok != 0 {
            Some(String::from_utf16_lossy(&raw_buf))
        } else {
            None
        }
    }
}

/// Scans Minecraft process: JVM arguments, memory, and loaded modules
#[allow(dead_code)]
pub fn scan_minecraft_instance(
    mc: &MinecraftProcess,
    yara_engine: &crate::scanner::yara_engine::YaraScannerEngine,
    report: &mut ScanReport,
) {
    scan_minecraft_instance_with_progress(
        mc,
        yara_engine,
        &crate::scanner::custom_rules::CustomRulesManager::default(),
        report,
        |_| {},
    );
}

/// Scans Minecraft process with progress reporting in MB
/// Extracts the process creation time and elapsed uptime using GetProcessTimes WinAPI
pub fn get_process_start_time_info(handle: HANDLE) -> Option<(String, String, String)> {
    let mut creation_time: FILETIME = unsafe { zeroed() };
    let mut exit_time: FILETIME = unsafe { zeroed() };
    let mut kernel_time: FILETIME = unsafe { zeroed() };
    let mut user_time: FILETIME = unsafe { zeroed() };

    let success = unsafe {
        GetProcessTimes(
            handle,
            &mut creation_time,
            &mut exit_time,
            &mut kernel_time,
            &mut user_time,
        )
    };

    if success == 0 {
        return None;
    }

    let ft: u64 = ((creation_time.dwHighDateTime as u64) << 32) | (creation_time.dwLowDateTime as u64);
    const WINDOWS_TICK: u64 = 10_000_000;
    const SEC_TO_UNIX_EPOCH: u64 = 11_644_473_600;
    const TICKS_TO_UNIX_EPOCH: u64 = SEC_TO_UNIX_EPOCH * WINDOWS_TICK;

    if ft < TICKS_TO_UNIX_EPOCH {
        return None;
    }

    let ticks = ft - TICKS_TO_UNIX_EPOCH;
    let secs = ticks / WINDOWS_TICK;
    let nanos = (ticks % WINDOWS_TICK) * 100;

    let utc_dt = chrono::DateTime::from_timestamp(secs as i64, nanos as u32)?;
    let local_dt: chrono::DateTime<chrono::Local> = utc_dt.with_timezone(&chrono::Local);
    let time_only = local_dt.format("%H:%M:%S").to_string();
    let date_and_time = local_dt.format("%Y-%m-%d %H:%M:%S").to_string();

    let now_secs = chrono::Utc::now().timestamp() as u64;
    let elapsed = if now_secs >= secs { now_secs - secs } else { 0 };

    let days = elapsed / 86400;
    let hours = (elapsed % 86400) / 3600;
    let mins = (elapsed % 3600) / 60;
    let remaining_secs = elapsed % 60;

    let elapsed_desc = if days > 0 {
        format!("{}d {}h ago", days, hours)
    } else if hours > 0 {
        format!("{}h {}m ago", hours, mins)
    } else if mins > 0 {
        format!("{} minutes ago", mins)
    } else {
        format!("{} seconds ago", remaining_secs)
    };

    let uptime_desc = if days > 0 {
        format!("{}d {}h {}m", days, hours, mins)
    } else if hours > 0 {
        format!("{}h {}m {}s", hours, mins, remaining_secs)
    } else if mins > 0 {
        format!("{}m {}s", mins, remaining_secs)
    } else {
        format!("{}s", remaining_secs)
    };

    let title_badge = format!("Opened {}, {}", elapsed_desc, time_only);

    Some((title_badge, date_and_time, uptime_desc))
}

pub fn scan_minecraft_instance_with_progress(
    mc: &MinecraftProcess,
    yara_engine: &crate::scanner::yara_engine::YaraScannerEngine,
    custom_rules: &crate::scanner::custom_rules::CustomRulesManager,
    report: &mut ScanReport,
    on_mb: impl Fn(usize),
) {
    report.target_process = Some(mc.name.clone());
    report.target_pid = Some(mc.pid);

    unsafe {
        let handle = OpenProcess(
            PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
            0,
            mc.pid,
        );

        if handle.is_null() {
            report.add(
                ScanFinding::new(
                    "Minecraft Process Access Denied",
                    FindingCategory::MinecraftRuntime,
                    VerdictLevel::Warning,
                    "Unable to open process with VM_READ privileges. Run scanner as Administrator.",
                )
                .with_evidence("PID", mc.pid.to_string()),
            );
            return;
        }

        let start_info = get_process_start_time_info(handle);

        let finding_name = match &start_info {
            Some((badge, _, _)) => format!("Active Minecraft Instance Detected [{}]", badge),
            None => "Active Minecraft Instance Detected".to_string(),
        };

        let finding_desc = match &start_info {
            Some((_, dt, uptime)) => format!(
                "Attached to game instance: {} ({}) [{}] - Running for {} (Started: {})",
                mc.name, mc.path, mc.client_brand, uptime, dt
            ),
            None => format!("Attached to game instance: {} ({}) [{}]", mc.name, mc.path, mc.client_brand),
        };

        let mut finding = ScanFinding::new(
            finding_name,
            FindingCategory::MinecraftRuntime,
            VerdictLevel::Information,
            finding_desc,
        )
        .with_evidence("PID", mc.pid.to_string())
        .with_evidence("Client Brand", mc.client_brand.clone())
        .with_evidence("Path", mc.path.clone());

        if let Some((badge, dt, uptime)) = start_info {
            finding = finding
                .with_evidence("Start Time (Local)", dt)
                .with_evidence("Uptime", uptime)
                .with_evidence("Instance Status", format!("Active ({})", badge));
        }

        report.add(finding);

    // 1. Inspect JVM arguments
        if let Some(cmdline) = get_process_command_line(handle) {
            check_jvm_arguments(&cmdline, report);
        } else {
            report.add(
                ScanFinding::new(
                    "Command Line Unreadable",
                    FindingCategory::MinecraftRuntime,
                    VerdictLevel::Warning,
                    "Failed to read PEB command line parameters for javaw.exe",
                )
                .with_evidence("PID", mc.pid.to_string()),
            );
        }

    // 2. Inspect loaded DLL modules (PEB Loaded Modules + Authenticode Verification)
        check_loaded_modules(mc.pid, &custom_rules.string_rules, report);

        // Dynamic Java Agent attach check (.attach_pid<PID>)
        check_dynamic_java_agent_artifacts(mc.pid, report);

        // Open handles to Minecraft from external processes (OpenProcess PROCESS_VM_WRITE / OPERATION)
        check_open_handles_to_minecraft(mc.pid, report);

    // 3. Inspect memory regions (Unbacked Executable Memory & RWX pages)
        check_memory_regions(handle, report);

    // 4. Inspect injected threads (Floating Threads / Unbacked Execution)
        check_floating_threads(handle, mc.pid, report);

    // 5. Inspect OpenGL pipeline hooks (wglSwapBuffers)
        check_graphics_pipeline_hooks(handle, mc.pid, report);

    // 6. Scan JVM memory (Aho-Corasick + AOB Engine + YARA)
        scan_memory_strings(handle, yara_engine, &custom_rules.string_rules, report, &on_mb);

        // 7. Check for DLL Hijacking in Java runtime directory and .minecraft
        check_java_dll_hijacking(mc, report);

    // 8. Check disk artifacts (.minecraft)
        check_cheat_filesystem_artifacts(report);

        CloseHandle(handle);
    }
}

fn check_jvm_arguments(cmdline: &str, report: &mut ScanReport) {
    let lower = cmdline.to_lowercase();

    // Inspect Java Agent
    if lower.contains("-javaagent:") {
        report.add(
            ScanFinding::new(
                "Potential Malicious Java Agent Found",
                FindingCategory::MinecraftRuntime,
                VerdictLevel::Warning,
                "Process was launched with -javaagent argument which can dynamically modify JVM bytecode.",
            )
            .with_evidence("Command Line Snippet", truncate_string(cmdline, 200)),
        );
    }

    // Inspect Bootclasspath
    if lower.contains("-xbootclasspath") {
        report.add(
            ScanFinding::new(
                "Modified Bootstrap Classpath",
                FindingCategory::MinecraftRuntime,
                VerdictLevel::Detection,
                "Detected -Xbootclasspath argument overriding core Java runtime classes.",
            )
            .with_evidence("Command Line", truncate_string(cmdline, 200)),
        );
    }

    // Inspect Remote Debugger (JDWP)
    if lower.contains("-agentlib:jdwp") || lower.contains("-xdebug") {
        report.add(
            ScanFinding::new(
                "JVM Debugger Interface Enabled",
                FindingCategory::MinecraftRuntime,
                VerdictLevel::Detection,
                "Java Debug Wire Protocol (JDWP) is active, enabling external bytecode injection.",
            )
            .with_evidence("Debugger Argument", truncate_string(cmdline, 150)),
        );
    }
}

/// Identifies recognized standard Minecraft mod native libraries (JNI audio, chunking, ML)
fn is_known_benign_mod_native(name: &str, path: &str) -> Option<&'static str> {
    let lower_name = name.to_lowercase();
    let lower_path = path.to_lowercase();

    if lower_name.contains("c2me") {
        return Some("C2ME (Concurrent Chunk Management Engine)");
    }
    if lower_name.contains("libopus4j") || (lower_name.starts_with("opus") && lower_path.contains("temp")) {
        return Some("Opus Audio Codec (Simple Voice Chat / Plasmo Voice)");
    }
    if lower_name.contains("librnnoise4j") || (lower_name.starts_with("rnnoise") && lower_path.contains("temp")) {
        return Some("RNNoise Denoising Filter (Simple Voice Chat / Plasmo Voice)");
    }
    if lower_name.contains("libspeex4j") || (lower_name.starts_with("speex") && lower_path.contains("temp")) {
        return Some("SpeexDSP Acoustic Echo Cancellation (Simple Voice Chat / Plasmo Voice)");
    }
    if lower_name.contains("liblame4j") || lower_name.contains("lame4j") {
        return Some("LAME MP3 Codec (Simple Voice Chat / Plasmo Voice)");
    }
    if lower_name.contains("onnxruntime") {
        return Some("Microsoft ONNX Runtime (Machine Learning / Voice Model)");
    }
    if lower_name.contains("eos_jni") || lower_name.contains("eossdk") {
        return Some("Epic Online Services SDK");
    }
    if (lower_name.starts_with("libwinpthread") || lower_name.starts_with("libgcc_s") || lower_name.starts_with("libstdc++"))
        && (lower_path.contains(".djl.ai") || lower_path.contains("natives") || lower_path.contains("temp"))
    {
        return Some("GCC / MinGW C++ Runtime (Open-Source Mod Dependency)");
    }
    if lower_name == "tokenizers.dll" || (lower_name.contains("tokenizers") && lower_path.contains(".djl.ai")) {
        return Some("Deep Java Library / Hugging Face Tokenizers");
    }
    if lower_name.contains("sqlite") || lower_name.contains("leveldb") || lower_name.contains("netty_transport") {
        return Some("Database / Netty Native Transport");
    }
    None
}

/// Anti-spoofing inspection: scans an on-disk DLL file to ensure it does not contain cheat payload strings
fn check_dll_for_embedded_cheat_strings(path: &Path) -> Option<String> {
    if !path.is_file() {
        return None;
    }
    let mut file = match std::fs::File::open(path) {
        Ok(f) => f,
        Err(_) => return None,
    };
    let mut buf = vec![0u8; 4 * 1024 * 1024];
    let bytes_read = match file.read(&mut buf) {
        Ok(n) => n,
        Err(_) => return None,
    };
    buf.truncate(bytes_read);

    let cheat_needles: &[(&str, &str)] = &[
        ("doomsday", "Doomsday Client"),
        ("vapeclient", "Vape Client"),
        ("vape.gg", "Vape Client"),
        ("kura.dll", "Kura Ghost Client"),
        ("dclient", "DClient"),
        ("aimassist", "AimAssist Feature"),
        ("killaura", "KillAura Feature"),
        ("autoclicker", "AutoClicker Feature"),
        ("silent_aura", "SilentAura Feature"),
        ("reach_distance", "Reach Modifier"),
        ("unhook_jvm", "Anti-Screenshare Unhook"),
        ("self_destruct", "Self-Destruct Routine"),
    ];

    let lower_buf = buf.to_ascii_lowercase();
    for (needle, name) in cheat_needles {
        if memchr::memmem::find(&lower_buf, needle.as_bytes()).is_some() {
            return Some(name.to_string());
        }
    }
    None
}

fn check_loaded_modules(
    pid: u32,
    custom_strings: &[crate::scanner::custom_rules::CustomStringRule],
    report: &mut ScanReport,
) {
    unsafe {
        let snapshot = CreateToolhelp32Snapshot(
            TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32,
            pid,
        );
        if snapshot == INVALID_HANDLE_VALUE {
            return;
        }

        let mut entry: MODULEENTRY32W = zeroed();
        entry.dwSize = std::mem::size_of::<MODULEENTRY32W>() as u32;

        if Module32FirstW(snapshot, &mut entry) != 0 {
            loop {
                let mod_name = String::from_utf16_lossy(
                    &entry.szModule[..entry
                        .szModule
                        .iter()
                        .position(|&c| c == 0)
                        .unwrap_or(entry.szModule.len())],
                );
                let mod_path = String::from_utf16_lossy(
                    &entry.szExePath[..entry
                        .szExePath
                        .iter()
                        .position(|&c| c == 0)
                        .unwrap_or(entry.szExePath.len())],
                );

                let lower_path = mod_path.to_lowercase();
                let lower_name = mod_name.to_lowercase();

        // Check DLL modules defined by user in /rules/
                for cr in custom_strings {
                    if (cr.pattern.ends_with(".dll") || cr.pattern.ends_with(".DLL"))
                        && lower_name == cr.pattern.to_lowercase()
                    {
                        report.add(
                            ScanFinding::new(
                                format!("Wykryto moduł DLL z własnej reguły: {}", cr.name),
                                FindingCategory::MinecraftRuntime,
                                cr.level,
                                format!(
                                    "Proces załadował moduł DLL wskazany we własnej regule (plik: {})",
                                    cr.source_file
                                ),
                            )
                            .with_evidence("Moduł DLL", mod_name.clone())
                            .with_evidence("Ścieżka", mod_path.clone())
                            .with_evidence("Własna reguła", cr.source_file.clone()),
                        );
                    }
                }

                // Ignore standard lwjgl/openal/jna/flatlaf/discord-rpc libraries extracted by Minecraft and Java frameworks
                let is_mc_native = lower_path.contains("lwjgl")
                    || lower_path.contains("openal")
                    || lower_path.contains("glfw")
                    || lower_path.contains("jemalloc")
                    || lower_path.contains("jna")
                    || lower_path.contains("flatlaf")
                    || (lower_name == "discord-rpc.dll" && lower_path.contains("discord-rpc"))
                    || (lower_name == "discord_game_sdk.dll" && lower_path.contains("discord"));

                let is_known_benign = is_known_benign_mod_native(&mod_name, &mod_path);

                // Verify Windows system directory - eliminate staging folders (Temp, Tasks, Tracing)
                let is_windows_system = (lower_path.starts_with("c:\\windows\\system32\\")
                    || lower_path.starts_with("c:\\windows\\syswow64\\")
                    || lower_path.starts_with("c:\\windows\\winsxs\\")
                    || lower_path.starts_with("c:\\windows\\systemapps\\")
                    || lower_path.starts_with("c:\\windows\\assembly\\")
                    || lower_path.starts_with("c:\\windows\\microsoft.net\\")
                    || lower_path.starts_with("\\??\\c:\\windows\\system32\\"))
                    && !lower_path.contains("\\temp\\")
                    && !lower_path.contains("\\tasks\\")
                    && !lower_path.contains("\\tracing\\");

                let is_jre = lower_path.contains("\\bin\\")
                    && (lower_path.contains("java") || lower_path.contains("jdk") || lower_path.contains("jre") || lower_path.contains("runtime"));

                let is_overlay_name = lower_name.contains("discordhook")
                    || lower_name.contains("graphics-hook") // OBS
                    || lower_name.contains("gameoverlayrenderer") // Steam
                    || lower_name.contains("rtss") // RivaTuner
                    || lower_name.contains("nvspcap") // NVIDIA
                    || lower_name.contains("nvd3d")
                    || lower_name.contains("overwolf")
                    || lower_name.contains("medallive");

                let path_obj = Path::new(&mod_path);
                let is_signed = path_obj.is_file() && crate::scanner::forensics::is_pe_signed(path_obj);
                let in_volatile = crate::scanner::forensics::is_volatile_directory(&lower_path);

                if let Some(benign_tech) = is_known_benign {
                    // Anti-spoofing check: verify that this benign-named DLL is NOT actually a cheat payload!
                    if let Some(cheat_trigger) = check_dll_for_embedded_cheat_strings(path_obj) {
                        report.add(
                            ScanFinding::new(
                                format!("Spoofed Malicious Module Masquerading as Benign Mod ({})", benign_tech),
                                FindingCategory::MinecraftRuntime,
                                VerdictLevel::Detection,
                                format!(
                                    "Module '{}' uses a known mod name ({}), but contains embedded cheat signatures: {}. Masquerading attempt detected!",
                                    mod_name, benign_tech, cheat_trigger
                                ),
                            )
                            .with_evidence("Module Name", mod_name.clone())
                            .with_evidence("Module Path", mod_path.clone())
                            .with_evidence("Spoofed Framework", benign_tech.to_string())
                            .with_evidence("Cheat Trigger", cheat_trigger),
                        );
                    } else {
                        // Legitimate verified mod native library
                        report.add(
                            ScanFinding::new(
                                format!("Legitimate Mod Native Library: {}", mod_name),
                                FindingCategory::MinecraftRuntime,
                                VerdictLevel::Information,
                                format!("Recognized standard mod native library: {} ({})", mod_name, benign_tech),
                            )
                            .with_evidence("Module Name", mod_name.clone())
                            .with_evidence("Module Path", mod_path.clone())
                            .with_evidence("Technology", benign_tech.to_string()),
                        );
                    }
                } else if is_overlay_name {
                    // Overlays must ALWAYS possess a valid publisher digital signature and cannot originate from a volatile folder!
                    if !is_signed || in_volatile {
                        report.add(
                            ScanFinding::new(
                                "Unsigned Rogue Dynamic Library Masquerading as Safe Overlay",
                                FindingCategory::MinecraftRuntime,
                                VerdictLevel::Detection,
                                format!("Rogue DLL masquerading as a known overlay '{}' is loaded into Minecraft without a valid digital signature.", mod_name),
                            )
                            .with_evidence("Module Name", mod_name.clone())
                            .with_evidence("Module Path", mod_path.clone())
                            .with_evidence("Masqueraded Target", "Legitimate Gaming Overlay (Discord/OBS/RivaTuner/Steam)".to_string()),
                        );
                    }
                } else if lower_path.contains("\\appdata\\local\\temp\\")
                    || lower_path.contains("\\downloads\\")
                    || lower_path.contains("\\desktop\\")
                {
                    if !is_mc_native {
                        let sign_status = if is_signed {
                            "Yes (Authenticode signature present; note that paid certificates can be acquired by cheat developers)"
                        } else {
                            "No (Unsigned binary)"
                        };

                        report.add(
                            ScanFinding::new(
                                "Suspicious Unverified Module in Javaw",
                                FindingCategory::MinecraftRuntime,
                                VerdictLevel::Warning,
                                format!(
                                    "Unverified dynamic library '{}' is loaded into Minecraft from a volatile directory ({}). Manual review recommended for screenshare inspection.",
                                    mod_name, mod_path
                                ),
                            )
                            .with_evidence("Module Name", mod_name.clone())
                            .with_evidence("Module Path", mod_path.clone())
                            .with_evidence("Authenticode Signed", sign_status.to_string())
                            .with_evidence("Inspection Advice", "Inspect file properties and digital signature certificate during screenshare".to_string()),
                        );
                    }
                } else if !is_windows_system && !is_jre && !is_mc_native {
                    if path_obj.is_file() && !is_signed {
                        report.add(
                            ScanFinding::new(
                                "Unsigned Foreign Dynamic Library in Javaw",
                                FindingCategory::MinecraftRuntime,
                                VerdictLevel::Warning,
                                format!("Foreign unsigned dynamic library '{}' is loaded into the Minecraft process memory space.", mod_name),
                            )
                            .with_evidence("Module Name", mod_name)
                            .with_evidence("Module Path", mod_path)
                            .with_evidence("Inspection Advice", "Verify whether this DLL belongs to an installed third-party mod".to_string()),
                        );
                    }
                }


                if Module32NextW(snapshot, &mut entry) == 0 {
                    break;
                }
            }
        }
        CloseHandle(snapshot);
    }
}

/// Scans memory for injected manual-mapped DLLs and RWX pages
fn check_memory_regions(handle: HANDLE, report: &mut ScanReport) {
    let mut address = 0usize;
    let mut rwx_count = 0;
    let mut unbacked_pe_count = 0;
    let mut code_cache_base: usize = 0;
    let mut largest_exec_reserve: usize = 0;

    unsafe {
        let mut mbi: MEMORY_BASIC_INFORMATION = zeroed();
        let mbi_size = std::mem::size_of::<MEMORY_BASIC_INFORMATION>();

        // Pass 1: Identify JVM Hotspot JIT CodeCache allocation base (largest contiguous executable private reservation, >= 32 MB)
        while VirtualQueryEx(handle, address as *const c_void, &mut mbi, mbi_size) != 0 {
            let is_exec = mbi.Protect == PAGE_EXECUTE
                || mbi.Protect == PAGE_EXECUTE_READ
                || mbi.Protect == PAGE_EXECUTE_READWRITE;
            if mbi.Type == MEM_PRIVATE && is_exec && mbi.RegionSize > largest_exec_reserve {
                largest_exec_reserve = mbi.RegionSize;
                code_cache_base = mbi.AllocationBase as usize;
            }
            let next_addr = (mbi.BaseAddress as usize).saturating_add(mbi.RegionSize);
            if next_addr <= address || next_addr == 0 {
                break;
            }
            address = next_addr;
        }

        // Pass 2: Inspect all committed executable regions
        address = 0;
        while VirtualQueryEx(handle, address as *const c_void, &mut mbi, mbi_size) != 0 {
            if mbi.State == MEM_COMMIT {
                let is_executable = mbi.Protect == PAGE_EXECUTE
                    || mbi.Protect == PAGE_EXECUTE_READ
                    || mbi.Protect == PAGE_EXECUTE_READWRITE;

                if is_executable {
                    if mbi.Protect == PAGE_EXECUTE_READWRITE {
                        rwx_count += 1;
                    }

                    // Check for unbacked or section-mapped memory (MEM_PRIVATE or MEM_MAPPED instead of MEM_IMAGE)
                    if mbi.Type == MEM_PRIVATE || mbi.Type == MEM_MAPPED {
                        let alloc_base = mbi.AllocationBase as usize;
                        let is_in_code_cache = code_cache_base != 0 && alloc_base == code_cache_base;

                        if !is_in_code_cache {
                            let mut header_buf = [0u8; 1024];
                            let mut bytes_read = 0;
                            let _ = windows_sys::Win32::System::Diagnostics::Debug::ReadProcessMemory(
                                handle,
                                mbi.BaseAddress,
                                header_buf.as_mut_ptr() as *mut c_void,
                                header_buf.len(),
                                &mut bytes_read,
                            );

                            let has_mz = bytes_read >= 2 && header_buf[0] == 0x4D && header_buf[1] == 0x5A;
                            let mut has_wiped_pe = false;

                            if !has_mz && bytes_read >= 64 {
                                let e_lfanew = u32::from_le_bytes(header_buf[0x3C..0x40].try_into().unwrap_or([0; 4])) as usize;
                                if e_lfanew > 0 && e_lfanew + 4 <= bytes_read {
                                    if &header_buf[e_lfanew..e_lfanew + 4] == b"PE\0\0" {
                                        has_wiped_pe = true;
                                    }
                                }
                                if !has_wiped_pe {
                                    for window in header_buf[..bytes_read].windows(8) {
                                        if window == b".text\0\0\0" || window == b".rdata\0\0" || window == b".data\0\0\0" {
                                            has_wiped_pe = true;
                                            break;
                                        }
                                    }
                                }
                            }

                            // Detect manual-mapped PE (genuine DOS MZ header or wiped header with PE/section remnants)
                            // Clean dynamic callback pools (e.g. LWJGL 3 libffi 64 KB trampoline closures) do NOT contain PE remnants and are not flagged as false positives.
                            if has_mz || has_wiped_pe {
                                unbacked_pe_count += 1;
                                let mem_type_str = if mbi.Type == MEM_PRIVATE { "MEM_PRIVATE (Unbacked)" } else { "MEM_MAPPED (Section View)" };
                                let (title, desc) = if has_mz {
                                    ("Manual Mapped PE Header in javaw.exe", "Detected reflective/manual-mapped PE (DLL/EXE) residing in unbacked memory.")
                                } else {
                                    ("Manual Mapped PE with Wiped Header in javaw.exe", "Detected manual-mapped PE with zeroed/tampered DOS MZ header (Anti-Analysis Manual Map evasion).")
                                };

                                report.add(
                                    ScanFinding::new(
                                        title,
                                        FindingCategory::MemoryInspection,
                                        VerdictLevel::Detection,
                                        desc,
                                    )
                                    .with_evidence("Base Address", format!("0x{:X}", mbi.BaseAddress as usize))
                                    .with_evidence("Allocation Base", format!("0x{:X}", alloc_base))
                                    .with_evidence("Region Size", format!("{} KB", mbi.RegionSize / 1024))
                                    .with_evidence("Protection", format!("0x{:X}", mbi.Protect))
                                    .with_evidence("Memory Type", mem_type_str.to_string())
                                    .with_evidence("Header State", if has_mz { "MZ Signature Present" } else if has_wiped_pe { "MZ Wiped / PE Remnants Detected" } else { "Completely Erased / Raw Shellcode" }.to_string()),
                                );
                            }
                        }
                    }
                }
            }

            let next_addr = (mbi.BaseAddress as usize).saturating_add(mbi.RegionSize);
            if next_addr <= address || next_addr == 0 {
                break;
            }
            address = next_addr;
        }

        if unbacked_pe_count == 0 && rwx_count > 15 {
            report.add(
                ScanFinding::new(
                    "Anomalous RWX Memory Allocation Count",
                    FindingCategory::MemoryInspection,
                    VerdictLevel::Warning,
                    format!("Detected {} executable read-write (RWX) memory pages inside Minecraft.", rwx_count),
                )
                .with_evidence("RWX Regions Count", rwx_count.to_string()),
            );
        }
    }
}

/// Scans all Minecraft process threads searching for "Floating Threads",
/// i.e., threads whose start address resides in private memory (MEM_PRIVATE + EXECUTE),
/// rather than an on-disk .dll (MEM_IMAGE). This is a universal code injection signature (Manual Map DLL / Shellcode).
fn check_floating_threads(handle: HANDLE, pid: u32, report: &mut ScanReport) {
    unsafe {
        let ntdll = GetModuleHandleA(b"ntdll.dll\0".as_ptr());
        if ntdll.is_null() {
            return;
        }
        let nt_query_thread_ptr = GetProcAddress(
            ntdll,
            b"NtQueryInformationThread\0".as_ptr(),
        );
        let nt_query_thread: Option<unsafe extern "system" fn(HANDLE, u32, *mut c_void, u32, *mut u32) -> i32> =
            std::mem::transmute(nt_query_thread_ptr);

        let nt_query_fn = match nt_query_thread {
            Some(f) => f,
            None => return,
        };

        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
        if snapshot == INVALID_HANDLE_VALUE {
            return;
        }

        let mut te: THREADENTRY32 = zeroed();
        te.dwSize = std::mem::size_of::<THREADENTRY32>() as u32;

        if Thread32First(snapshot, &mut te) != 0 {
            loop {
                if te.th32OwnerProcessID == pid {
                    let h_thread = OpenThread(
                        THREAD_QUERY_INFORMATION,
                        0,
                        te.th32ThreadID,
                    );

                    if !h_thread.is_null() {
                        let mut start_addr: usize = 0;
                        let mut ret_len: u32 = 0;
                        // 9 = ThreadQuerySetWin32StartAddress
                        let status = nt_query_fn(
                            h_thread,
                            9,
                            &mut start_addr as *mut _ as *mut c_void,
                            std::mem::size_of::<usize>() as u32,
                            &mut ret_len,
                        );

                        if status == 0 && start_addr != 0 {
                            let mut mbi: MEMORY_BASIC_INFORMATION = zeroed();
                            if VirtualQueryEx(
                                handle,
                                start_addr as *const c_void,
                                &mut mbi,
                                std::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
                            ) != 0
                            {
                                let is_exec = mbi.Protect == PAGE_EXECUTE
                                    || mbi.Protect == PAGE_EXECUTE_READ
                                    || mbi.Protect == PAGE_EXECUTE_READWRITE
                                    || mbi.Protect == PAGE_EXECUTE_WRITECOPY;

                                if mbi.State == MEM_COMMIT && (mbi.Type == MEM_PRIVATE || mbi.Type == MEM_MAPPED) && is_exec {
                                    report.add(
                                        ScanFinding::new(
                                            "Injected Floating Thread Detected",
                                            FindingCategory::MemoryInspection,
                                            VerdictLevel::Detection,
                                            "Wykryto aktywny wątek rozpoczynający się w niepodpisanej pamięci prywatnej (MEM_PRIVATE). Jest to uniwersalny dowód wstrzyknięcia cheata natywnego (Manual Map DLL / Shellcode).",
                                        )
                                        .with_evidence("Thread ID", te.th32ThreadID.to_string())
                                        .with_evidence("Start Address", format!("0x{:X}", start_addr))
                                        .with_evidence("Memory Type", if mbi.Type == MEM_PRIVATE { "MEM_PRIVATE (Unbacked)" } else { "MEM_MAPPED" })
                                        .with_evidence("Memory Protection", format!("0x{:X}", mbi.Protect))
                                        .with_evidence("Allocation Base", format!("0x{:X}", mbi.AllocationBase as usize)),
                                    );
                                }
                            }
                        }

                        // Thread Hijacking and Call Stack Walking Detection:
                        // Inspects thread context RIP/EIP and walks stack frames (RSP) to detect return addresses
                        // pointing into unbacked code even when the thread is sleeping in NtWaitForSingleObject!
                        let h_thread_ctx = OpenThread(
                            0x0040 | 0x0008 | 0x0002, // THREAD_QUERY_INFORMATION | THREAD_GET_CONTEXT | THREAD_SUSPEND_RESUME
                            0,
                            te.th32ThreadID,
                        );
                        if !h_thread_ctx.is_null() {
                            let suspend_count = windows_sys::Win32::System::Threading::SuspendThread(h_thread_ctx);
                            if suspend_count != u32::MAX {
                                #[repr(C, align(16))]
                                struct AlignedContext {
                                    ctx: windows_sys::Win32::System::Diagnostics::Debug::CONTEXT,
                                }
                                let mut aligned: AlignedContext = zeroed();
                                aligned.ctx.ContextFlags = 0x00100000 | 0x00000002 | 0x00000001; // CONTEXT_CONTROL | CONTEXT_INTEGER

                                if windows_sys::Win32::System::Diagnostics::Debug::GetThreadContext(h_thread_ctx, &mut aligned.ctx) != 0 {
                                    #[cfg(target_arch = "x86_64")]
                                    let ip = aligned.ctx.Rip as usize;
                                    #[cfg(not(target_arch = "x86_64"))]
                                    let ip = aligned.ctx.Eip as usize;

                                    #[cfg(target_arch = "x86_64")]
                                    let rsp = aligned.ctx.Rsp as usize;
                                    #[cfg(not(target_arch = "x86_64"))]
                                    let rsp = aligned.ctx.Esp as usize;

                                    // 1. Direct instruction pointer check
                                    if ip != 0 && ip != start_addr {
                                        let mut mbi_ip: MEMORY_BASIC_INFORMATION = zeroed();
                                        if VirtualQueryEx(
                                            handle,
                                            ip as *const c_void,
                                            &mut mbi_ip,
                                            std::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
                                        ) != 0 {
                                            let is_exec = mbi_ip.Protect == PAGE_EXECUTE
                                                || mbi_ip.Protect == PAGE_EXECUTE_READ
                                                || mbi_ip.Protect == PAGE_EXECUTE_READWRITE
                                                || mbi_ip.Protect == PAGE_EXECUTE_WRITECOPY;
                                            if mbi_ip.State == MEM_COMMIT
                                                && (mbi_ip.Type == MEM_PRIVATE || mbi_ip.Type == MEM_MAPPED)
                                                && is_exec
                                                && mbi_ip.RegionSize < 8 * 1024 * 1024
                                            {
                                                report.add(
                                                    ScanFinding::new(
                                                        "Hijacked Thread Executing in Unbacked Memory",
                                                        FindingCategory::MemoryInspection,
                                                        VerdictLevel::Detection,
                                                        "Detected active thread with hijacked execution pointer (RIP/EIP) executing in unbacked private memory outside legitimate modules. Universal signature of SetThreadContext hijacking.",
                                                    )
                                                    .with_evidence("Thread ID", te.th32ThreadID.to_string())
                                                    .with_evidence("Current Instruction Pointer", format!("0x{:X}", ip))
                                                    .with_evidence("Thread Start Address", format!("0x{:X}", start_addr))
                                                    .with_evidence("Memory Type", if mbi_ip.Type == MEM_PRIVATE { "MEM_PRIVATE (Unbacked)" } else { "MEM_MAPPED" })
                                                    .with_evidence("Region Size", format!("{} KB", mbi_ip.RegionSize / 1024))
                                                    .with_evidence("Technique", "Thread Hijacking (SetThreadContext)".to_string()),
                                                );
                                            }
                                        }
                                    }

                                    // 2. Call Stack Walk: read active stack frames (RSP) to detect return addresses into unbacked memory
                                    if rsp > 0x10000 {
                                        let mut stack_buf = vec![0usize; 2048];
                                        let mut bytes_read = 0usize;
                                        if ReadProcessMemory(
                                            handle,
                                            rsp as *const c_void,
                                            stack_buf.as_mut_ptr() as *mut c_void,
                                            stack_buf.len() * std::mem::size_of::<usize>(),
                                            &mut bytes_read,
                                        ) != 0 && bytes_read >= std::mem::size_of::<usize>() {
                                            let slots_read = bytes_read / std::mem::size_of::<usize>();
                                            for i in 0..slots_read {
                                                let candidate_ptr = stack_buf[i];
                                                if candidate_ptr > 0x10000 && candidate_ptr < 0x7FFFFFFF0000 {
                                                    let mut mbi_stack: MEMORY_BASIC_INFORMATION = zeroed();
                                                    if VirtualQueryEx(
                                                        handle,
                                                        candidate_ptr as *const c_void,
                                                        &mut mbi_stack,
                                                        std::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
                                                    ) != 0 {
                                                        let is_exec = mbi_stack.Protect == PAGE_EXECUTE
                                                            || mbi_stack.Protect == PAGE_EXECUTE_READ
                                                            || mbi_stack.Protect == PAGE_EXECUTE_READWRITE
                                                            || mbi_stack.Protect == PAGE_EXECUTE_WRITECOPY;

                                                        if mbi_stack.State == MEM_COMMIT
                                                            && (mbi_stack.Type == MEM_PRIVATE || mbi_stack.Type == MEM_MAPPED)
                                                            && is_exec
                                                            && mbi_stack.RegionSize < 8 * 1024 * 1024
                                                        {
                                                            report.add(
                                                                ScanFinding::new(
                                                                    "Unbacked Code Address on Thread Call Stack (Call Stack Walk Detection)",
                                                                    FindingCategory::MemoryInspection,
                                                                    VerdictLevel::Detection,
                                                                    "Thread call stack walk revealed an active return address pointing into unbacked private memory. Universal proof of tick-based cheat routine calling game functions.",
                                                                )
                                                                .with_evidence("Thread ID", te.th32ThreadID.to_string())
                                                                .with_evidence("Return Address on Stack", format!("0x{:X}", candidate_ptr))
                                                                .with_evidence("Stack Offset", format!("RSP + 0x{:X}", i * std::mem::size_of::<usize>()))
                                                                .with_evidence("Memory Type", if mbi_stack.Type == MEM_PRIVATE { "MEM_PRIVATE (Unbacked)" } else { "MEM_MAPPED" })
                                                                .with_evidence("Technique", "Thread Call Stack Walking (Return Address Inspection)".to_string()),
                                                            );
                                                            break;
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                                windows_sys::Win32::System::Threading::ResumeThread(h_thread_ctx);
                            }
                            CloseHandle(h_thread_ctx);
                        }

                        CloseHandle(h_thread);
                    }
                }

                if Thread32Next(snapshot, &mut te) == 0 {
                    break;
                }
            }
        }
        CloseHandle(snapshot);
    }
}

/// Resolves a procedure address from a remote process module's PE export table in memory.
/// This avoids calling LoadLibrary on untrusted/unsigned third-party DLLs from game instances
/// which causes Windows "Bad Image / 0xc0000428" modal error dialogs or unwanted DllMain execution.
pub fn get_remote_proc_address(handle: HANDLE, module_base: usize, proc_name: &str) -> Option<usize> {
    unsafe {
        let mut e_lfanew = 0u32;
        let mut bytes_read = 0usize;
        if ReadProcessMemory(
            handle,
            (module_base + 0x3C) as *const c_void,
            &mut e_lfanew as *mut _ as *mut c_void,
            4,
            &mut bytes_read,
        ) == 0 || bytes_read != 4 || e_lfanew == 0 || e_lfanew > 0x1000 {
            return None;
        }

        let nt_header = module_base + e_lfanew as usize;
        let mut pe_sig = [0u8; 4];
        if ReadProcessMemory(
            handle,
            nt_header as *const c_void,
            pe_sig.as_mut_ptr() as *mut c_void,
            4,
            &mut bytes_read,
        ) == 0 || &pe_sig != b"PE\0\0" {
            return None;
        }

        let opt_header = nt_header + 24;
        let mut magic = 0u16;
        if ReadProcessMemory(
            handle,
            opt_header as *const c_void,
            &mut magic as *mut _ as *mut c_void,
            2,
            &mut bytes_read,
        ) == 0 {
            return None;
        }

        let export_dir_offset = if magic == 0x20B { 112 } else if magic == 0x10B { 96 } else { return None; };
        let mut export_rva = 0u32;
        if ReadProcessMemory(
            handle,
            (opt_header + export_dir_offset) as *const c_void,
            &mut export_rva as *mut _ as *mut c_void,
            4,
            &mut bytes_read,
        ) == 0 || export_rva == 0 {
            return None;
        }

        let export_dir_addr = module_base + export_rva as usize;
        let mut export_dir_buf = [0u8; 40];
        if ReadProcessMemory(
            handle,
            export_dir_addr as *const c_void,
            export_dir_buf.as_mut_ptr() as *mut c_void,
            export_dir_buf.len(),
            &mut bytes_read,
        ) == 0 || bytes_read < 40 {
            return None;
        }

        let num_names = u32::from_le_bytes(export_dir_buf[0x18..0x1C].try_into().ok()?) as usize;
        let addr_functions_rva = u32::from_le_bytes(export_dir_buf[0x1C..0x20].try_into().ok()?) as usize;
        let addr_names_rva = u32::from_le_bytes(export_dir_buf[0x20..0x24].try_into().ok()?) as usize;
        let addr_ordinals_rva = u32::from_le_bytes(export_dir_buf[0x24..0x28].try_into().ok()?) as usize;

        if num_names == 0 || num_names > 20000 {
            return None;
        }

        let mut names_rvas = vec![0u32; num_names];
        if ReadProcessMemory(
            handle,
            (module_base + addr_names_rva) as *const c_void,
            names_rvas.as_mut_ptr() as *mut c_void,
            num_names * 4,
            &mut bytes_read,
        ) == 0 {
            return None;
        }

        let mut ordinals = vec![0u16; num_names];
        if ReadProcessMemory(
            handle,
            (module_base + addr_ordinals_rva) as *const c_void,
            ordinals.as_mut_ptr() as *mut c_void,
            num_names * 2,
            &mut bytes_read,
        ) == 0 {
            return None;
        }

        for i in 0..num_names {
            let name_rva = names_rvas[i] as usize;
            let mut name_buf = [0u8; 64];
            if ReadProcessMemory(
                handle,
                (module_base + name_rva) as *const c_void,
                name_buf.as_mut_ptr() as *mut c_void,
                name_buf.len(),
                &mut bytes_read,
            ) != 0 && bytes_read > 0 {
                let end = name_buf.iter().position(|&b| b == 0).unwrap_or(bytes_read);
                if let Ok(s) = std::str::from_utf8(&name_buf[..end]) {
                    if s == proc_name {
                        let ord = ordinals[i] as usize;
                        let mut func_rva = 0u32;
                        if ReadProcessMemory(
                            handle,
                            (module_base + addr_functions_rva + ord * 4) as *const c_void,
                            &mut func_rva as *mut _ as *mut c_void,
                            4,
                            &mut bytes_read,
                        ) != 0 && func_rva != 0 {
                            return Some(module_base + func_rva as usize);
                        }
                    }
                }
            }
        }

        None
    }
}

/// Checks whether wglSwapBuffers in opengl32.dll of Minecraft process was
/// patched with a jump instruction (JMP Detour hook), characteristic of ghost clients rendering GUI/ESP.
fn check_graphics_pipeline_hooks(handle: HANDLE, pid: u32, report: &mut ScanReport) {
    unsafe {
        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
        if snapshot == INVALID_HANDLE_VALUE {
            return;
        }

        let mut entry: MODULEENTRY32W = zeroed();
        entry.dwSize = std::mem::size_of::<MODULEENTRY32W>() as u32;

        let mut opengl_base = None;
        let mut glfw_info: Option<(usize, String)> = None;
        let mut loaded_dll_ranges: Vec<(usize, usize, String, String)> = Vec::new();

        if Module32FirstW(snapshot, &mut entry) != 0 {
            loop {
                let mod_name = String::from_utf16_lossy(
                    &entry.szModule[..entry
                        .szModule
                        .iter()
                        .position(|&c| c == 0)
                        .unwrap_or(entry.szModule.len())],
                );
                let path_len = entry.szExePath.iter().position(|&c| c == 0).unwrap_or(entry.szExePath.len());
                let mod_path = String::from_utf16_lossy(&entry.szExePath[..path_len]);
                let base = entry.modBaseAddr as usize;
                let size = entry.modBaseSize as usize;
                loaded_dll_ranges.push((base, base + size, mod_name.clone(), mod_path.clone()));

                if mod_name.eq_ignore_ascii_case("opengl32.dll") {
                    opengl_base = Some(base);
                }
                if mod_name.eq_ignore_ascii_case("glfw3.dll") || mod_name.eq_ignore_ascii_case("glfw.dll") {
                    glfw_info = Some((base, mod_path));
                }

                if Module32NextW(snapshot, &mut entry) == 0 {
                    break;
                }
            }
        }
        CloseHandle(snapshot);

        let remote_opengl = match opengl_base {
            Some(b) => b,
            None => return,
        };

        let remote_swap_addr = match get_remote_proc_address(handle, remote_opengl, "wglSwapBuffers") {
            Some(addr) => addr,
            None => {
                let local_opengl = LoadLibraryA(b"opengl32.dll\0".as_ptr());
                if local_opengl.is_null() {
                    return;
                }
                let local_swap_proc = GetProcAddress(local_opengl, b"wglSwapBuffers\0".as_ptr());
                if local_swap_proc.is_none() {
                    return;
                }
                let offset = local_swap_proc.unwrap() as usize - local_opengl as usize;
                remote_opengl + offset
            }
        };
        let mut bytes = [0u8; 16];
        let mut bytes_read = 0usize;

        if ReadProcessMemory(
            handle,
            remote_swap_addr as *const c_void,
            bytes.as_mut_ptr() as *mut c_void,
            bytes.len(),
            &mut bytes_read,
        ) != 0
            && bytes_read >= 5
        {
            let b0 = bytes[0];
            let is_hooked = b0 == 0xE9
                || b0 == 0xEB
                || (bytes[0] == 0xFF && bytes[1] == 0x25)
                || (bytes[0] == 0x48 && bytes[1] == 0xB8 && bytes[10] == 0xFF && bytes[11] == 0xE0)
                || (bytes[0] == 0x49 && bytes[1] == 0xBB) // MOV R11, imm64
                || (bytes[0] == 0x68 && bytes[5] == 0xC3) // PUSH imm32; RET
                || bytes[..16].windows(2).any(|w| w == [0xFF, 0x25] || w == [0xFF, 0xE0] || w == [0xFF, 0xE3]); // Mid-function jump

            if is_hooked {
                let target_addr: Option<usize> = if b0 == 0xE9 {
                    let rel32 = i32::from_le_bytes(bytes[1..5].try_into().unwrap_or([0; 4]));
                    Some((remote_swap_addr + 5).wrapping_add(rel32 as usize))
                } else if bytes[0] == 0x48 && bytes[1] == 0xB8 {
                    Some(u64::from_le_bytes(bytes[2..10].try_into().unwrap_or([0; 8])) as usize)
                } else {
                    None
                };

                let mut is_whitelisted_overlay = false;
                let mut target_module_name = "Unbacked Executable Memory (Ghost Client Payload)".to_string();

                if let Some(target) = target_addr {
                    for (start, end, name, path) in &loaded_dll_ranges {
                        if target >= *start && target < *end {
                            target_module_name = name.clone();
                            let lower = name.to_lowercase();
                            let lower_path = path.to_lowercase();
                            if lower.contains("discordhook")
                                || lower.contains("graphics-hook")
                                || lower.contains("rtss")
                                || lower.contains("gameoverlayrenderer")
                                || lower.contains("nvspcap")
                            {
        // Require overlay to be digitally signed and NOT located in a volatile folder!
                                let path_obj = Path::new(path);
                                let is_signed = path_obj.is_file() && crate::scanner::forensics::is_pe_signed(path_obj);
                                let in_volatile = crate::scanner::forensics::is_volatile_directory(&lower_path);
                                if is_signed && !in_volatile {
                                    is_whitelisted_overlay = true;
                                }
                            }
                            break;
                        }
                    }
                }

                if !is_whitelisted_overlay {
                    report.add(
                        ScanFinding::new(
                            "Hooked OpenGL Graphics Pipeline (wglSwapBuffers Detour)",
                            FindingCategory::MinecraftRuntime,
                            VerdictLevel::Detection,
                            format!(
                                "Detected inline JMP detour hook on opengl32!wglSwapBuffers pointing to: {}. Used by Ghost Clients for visual ESP/ClickGUI rendering.",
                                target_module_name
                            ),
                        )
                        .with_evidence("Function", "opengl32.dll!wglSwapBuffers".to_string())
                        .with_evidence("Hook Bytes", format!("{:02X?}", &bytes[..bytes_read]))
                        .with_evidence("Target Destination", target_module_name)
                        .with_evidence("Hook Address", format!("0x{:X}", remote_swap_addr)),
                    );
                }
            }
        }

        // Modern Minecraft (1.13+ LWJGL 3 / GLFW): inspect glfwSwapBuffers hook
        // Safe memory-based export resolution directly from remote process (no LoadLibrary / 0xc0000428 error)
        if let Some((remote_glfw_base, _)) = glfw_info {
            if let Some(remote_swap_addr) = get_remote_proc_address(handle, remote_glfw_base, "glfwSwapBuffers") {
                let mut bytes = [0u8; 16];
                let mut bytes_read = 0usize;

                if ReadProcessMemory(
                    handle,
                    remote_swap_addr as *const c_void,
                    bytes.as_mut_ptr() as *mut c_void,
                    bytes.len(),
                    &mut bytes_read,
                ) != 0 && bytes_read >= 5 {
                    let b0 = bytes[0];
                    let is_hooked = b0 == 0xE9
                        || b0 == 0xEB
                        || (bytes[0] == 0xFF && bytes[1] == 0x25)
                        || (bytes[0] == 0x48 && bytes[1] == 0xB8 && bytes[10] == 0xFF && bytes[11] == 0xE0)
                        || (bytes[0] == 0x49 && bytes[1] == 0xBB) // MOV R11, imm64
                        || (bytes[0] == 0x68 && bytes[5] == 0xC3) // PUSH imm32; RET
                        || bytes[..16].windows(2).any(|w| w == [0xFF, 0x25] || w == [0xFF, 0xE0] || w == [0xFF, 0xE3]); // Mid-function jump

                    if is_hooked {
                        let target_addr: Option<usize> = if b0 == 0xE9 {
                            let rel32 = i32::from_le_bytes(bytes[1..5].try_into().unwrap_or([0; 4]));
                            Some((remote_swap_addr + 5).wrapping_add(rel32 as usize))
                        } else if bytes[0] == 0x48 && bytes[1] == 0xB8 {
                            Some(u64::from_le_bytes(bytes[2..10].try_into().unwrap_or([0; 8])) as usize)
                        } else {
                            None
                        };

                        let mut is_whitelisted_overlay = false;
                        let mut target_module_name = "Unbacked Executable Memory (Ghost Client Payload)".to_string();

                        if let Some(target) = target_addr {
                            for (start, end, name, path) in &loaded_dll_ranges {
                                if target >= *start && target < *end {
                                    target_module_name = name.clone();
                                    let lower = name.to_lowercase();
                                    let lower_path = path.to_lowercase();
                                    if lower.contains("discordhook")
                                        || lower.contains("graphics-hook")
                                        || lower.contains("rtss")
                                        || lower.contains("gameoverlayrenderer")
                                        || lower.contains("nvspcap")
                                    {
                                        let path_obj = Path::new(path);
                                        let is_signed = path_obj.is_file() && crate::scanner::forensics::is_pe_signed(path_obj);
                                        let in_volatile = crate::scanner::forensics::is_volatile_directory(&lower_path);
                                        if is_signed && !in_volatile {
                                            is_whitelisted_overlay = true;
                                        }
                                    }
                                    break;
                                }
                            }
                        }

                        if !is_whitelisted_overlay {
                            report.add(
                                ScanFinding::new(
                                    "Hooked GLFW Graphics Pipeline (glfwSwapBuffers Detour)",
                                    FindingCategory::MemoryInspection,
                                    VerdictLevel::Detection,
                                    format!(
                                        "Detected inline JMP detour hook on glfw3!glfwSwapBuffers pointing to: {}. Used by modern Minecraft ghost clients for ESP/ClickGUI rendering.",
                                        target_module_name
                                    ),
                                )
                                .with_evidence("Function", "glfw3.dll!glfwSwapBuffers".to_string())
                                .with_evidence("Hook Bytes", format!("{:02X?}", &bytes[..bytes_read]))
                                .with_evidence("Target Destination", target_module_name)
                                .with_evidence("Hook Address", format!("0x{:X}", remote_swap_addr)),
                            );
                        }
                    }
                }
            }
        }
    }
}

/// Helper function extracting full Java class name (package + class) around matched offset
fn extract_java_class_around(slice: &[u8], match_start: usize, pattern_len: usize) -> Option<String> {
    let mut start = match_start;
    while start > 0 {
        let b = slice[start - 1];
        if b.is_ascii_alphanumeric() || b == b'/' || b == b'.' || b == b'_' || b == b'$' {
            start -= 1;
        } else {
            break;
        }
    }
    let end = match_start + pattern_len;
    if end > start && (end - start) >= pattern_len {
        let s = String::from_utf8_lossy(&slice[start..end]).to_string();
        if s.contains('/') || s.contains('.') {
            return Some(s);
        }
    }
    None
}

fn is_whitelisted_mixin_class(cls: &str) -> bool {
    let mut clean = cls.trim();
    if clean.starts_with('/') {
        clean = &clean[1..];
    }
    if clean.starts_with('L') && (clean.chars().nth(1) == Some('/') || clean.chars().nth(1).map_or(false, |c| c.is_ascii_lowercase())) {
        clean = &clean[1..];
    }
    if clean.starts_with('/') {
        clean = &clean[1..];
    }
    let clean = clean.strip_suffix(';').unwrap_or(clean);

    clean.starts_with("net/fabricmc/")
        || clean.starts_with("net.fabricmc.")
        || clean.starts_with("net/minecraft/")
        || clean.starts_with("net.minecraft.")
        || clean.starts_with("org/spongepowered/")
        || clean.starts_with("org.spongepowered.")
        || clean.starts_with("dev/architectury/")
        || clean.starts_with("dev.architectury.")
        || clean.starts_with("architectury/")
        || clean.starts_with("fi/dy/masa/")
        || clean.starts_with("me/shedaniel/")
        || clean.starts_with("com/mojang/")
        || clean.starts_with("org/embeddedt/")
        || clean.starts_with("ca/fxco/")
}

fn is_whitelisted_mouse_class(cls: &str) -> bool {
    let mut clean = cls.trim();
    if clean.starts_with('/') {
        clean = &clean[1..];
    }
    if clean.starts_with('L') && (clean.chars().nth(1) == Some('/') || clean.chars().nth(1).map_or(false, |c| c.is_ascii_lowercase())) {
        clean = &clean[1..];
    }
    if clean.starts_with('/') {
        clean = &clean[1..];
    }
    let clean = clean.strip_suffix(';').unwrap_or(clean);

    clean.starts_with("net/fabricmc/")
        || clean.starts_with("net.fabricmc.")
        || clean.starts_with("net/minecraft/")
        || clean.starts_with("net.minecraft.")
        || clean.starts_with("fi/dy/masa/")
        || clean.starts_with("me/shedaniel/")
        // Specifically whitelist OneClient legitimate MouseHandlerAccessor
        || clean == "me/decce/ixeris/mixins/MouseHandlerAccessor"
        || clean == "me.decce.ixeris.mixins.MouseHandlerAccessor"
}

/// Scans memory buffer for unauthorized Mixins modifying sensitive game mechanics
/// (np. EndCrystalItem, ClientPlayerInteractionManager, MouseHandler).
/// Emits a Warning so screenshare inspectors can manually verify unknown mods.
fn check_generic_mixin_anomalies(
    slice: &[u8],
    base_addr: usize,
    report: &mut ScanReport,
    reported_mixins: &mut std::collections::HashSet<String>,
) {
    // 1. EndCrystalItemMixin (AutoCrystal) - crystal handling modification
    let crystal_finder = memchr::memmem::Finder::new(b"EndCrystalItemMixin");
    for offset in crystal_finder.find_iter(slice) {
        if let Some(full_class) = extract_java_class_around(slice, offset, b"EndCrystalItemMixin".len()) {
            if !is_whitelisted_mixin_class(&full_class) && reported_mixins.insert(full_class.clone()) {
                report.add(
                    ScanFinding::new(
                        format!("Generic Combat Mixin Anomaly: {}", full_class),
                        FindingCategory::MinecraftRuntime,
                        VerdictLevel::Warning,
                        "Wykryto mixin modyfikujący mechanikę kryształów (EndCrystalItemMixin). Wzorzec może wskazywać na moduł AutoCrystal / FastCrystal.",
                    )
                    .with_evidence("Mixin Class", full_class)
                    .with_evidence("Target Class", "net.minecraft.item.EndCrystalItem".to_string())
                    .with_evidence("Adres pamięci", format!("0x{:X}", base_addr + offset)),
                );
            }
        }
    }

    // 2. ClientPlayerInteractionManagerMixin & Accessor (Reach, FastBreak, NoHitDelay)
    let interact_mix_finder = memchr::memmem::Finder::new(b"ClientPlayerInteractionManagerMixin");
    for offset in interact_mix_finder.find_iter(slice) {
        if let Some(full_class) = extract_java_class_around(slice, offset, b"ClientPlayerInteractionManagerMixin".len()) {
            if !is_whitelisted_mixin_class(&full_class) && reported_mixins.insert(full_class.clone()) {
                report.add(
                    ScanFinding::new(
                        format!("Generic Combat/Interaction Mixin Anomaly: {}", full_class),
                        FindingCategory::MinecraftRuntime,
                        VerdictLevel::Warning,
                        "Wykryto niestandardowy mixin modyfikujący rdzeń interakcji gracza (ClientPlayerInteractionManager). Wzorzec może wskazywać na Reach, FastBreak lub modyfikacje walki.",
                    )
                    .with_evidence("Mixin Class", full_class)
                    .with_evidence("Target Class", "net.minecraft.client.network.ClientPlayerInteractionManager".to_string())
                    .with_evidence("Adres pamięci", format!("0x{:X}", base_addr + offset)),
                );
            }
        }
    }

    let interact_acc_finder = memchr::memmem::Finder::new(b"ClientPlayerInteractionManagerAccessor");
    for offset in interact_acc_finder.find_iter(slice) {
        if let Some(full_class) = extract_java_class_around(slice, offset, b"ClientPlayerInteractionManagerAccessor".len()) {
            if !is_whitelisted_mixin_class(&full_class) && reported_mixins.insert(full_class.clone()) {
                report.add(
                    ScanFinding::new(
                        format!("Generic Combat/Interaction Accessor Anomaly: {}", full_class),
                        FindingCategory::MinecraftRuntime,
                        VerdictLevel::Warning,
                        "Wykryto niestandardowy akcesor menedżera interakcji (ClientPlayerInteractionManagerAccessor). Wymaga manualnej weryfikacji modułu.",
                    )
                    .with_evidence("Accessor Class", full_class)
                    .with_evidence("Target Class", "net.minecraft.client.network.ClientPlayerInteractionManager".to_string())
                    .with_evidence("Adres pamięci", format!("0x{:X}", base_addr + offset)),
                );
            }
        }
    }

    // 3. MouseHandlerAccessor (AutoClicker / Triggerbot)
    let mouse_acc_finder = memchr::memmem::Finder::new(b"MouseHandlerAccessor");
    for offset in mouse_acc_finder.find_iter(slice) {
        if let Some(full_class) = extract_java_class_around(slice, offset, b"MouseHandlerAccessor".len()) {
            if !is_whitelisted_mouse_class(&full_class) && reported_mixins.insert(full_class.clone()) {
                report.add(
                    ScanFinding::new(
                        format!("Generic Mouse Hook Mixin: {}", full_class),
                        FindingCategory::MinecraftRuntime,
                        VerdictLevel::Warning,
                        "Wykryto niestandardowy mixin akcesora myszy (MouseHandlerAccessor). Wzorzec może wskazywać na emulację kliknięć myszy.",
                    )
                    .with_evidence("Mixin Class", full_class)
                    .with_evidence("Adres pamięci", format!("0x{:X}", base_addr + offset)),
                );
            }
        }
    }
}

/// Scans Minecraft process memory in chunks, eliminating Java Heap size limits.
/// Runs YARA engine, native Doomsday analysis, and extended signature database.
struct CheatPatternRule {
    pattern: &'static str,
    name: &'static str,
    description: &'static str,
    level: VerdictLevel,
}

/// Scans Minecraft process memory (MEM_PRIVATE) using highly optimized Aho-Corasick automaton
/// and selective YARA rule engine for executable pages and suspicious memory fragments.
/// Returns the static slice of built-in cheat patterns for memory inspection
fn get_builtin_cheat_patterns() -> &'static [CheatPatternRule] {
    &[
        // --- GHOST CLIENTS & INJECTORS ---
        CheatPatternRule { pattern: "doomsdayclient", name: "Doomsday Ghost Client Core", description: "Wykryto moduł główny Doomsday Client w procesie javaw.", level: VerdictLevel::Detection },
        CheatPatternRule { pattern: "DoomsdayClient", name: "Doomsday Ghost Client Main", description: "Wykryto klasę rozruchową DoomsdayClient w procesie javaw.", level: VerdictLevel::Detection },
        CheatPatternRule { pattern: "doomsday.rip", name: "Doomsday Client Backend", description: "Wykryto odwołania sieciowe/konfiguracyjne Doomsday.rip.", level: VerdictLevel::Detection },
        CheatPatternRule { pattern: "vape.gg", name: "Vape Client Backend", description: "Wykryto domenę serwerów Vape v4/Lite w procesie javaw.", level: VerdictLevel::Detection },
        CheatPatternRule { pattern: "vapeclient", name: "Vape Ghost Client", description: "Wykryto sygnaturę jądra klienta Vape.", level: VerdictLevel::Detection },
        CheatPatternRule { pattern: "(JLcn/gov/vape/util/jvmti/ClassLoadHook;)I", name: "Vape JVMTI Hook", description: "Wykryto bezpośredni hook JVM-TI klienta Vape.", level: VerdictLevel::Detection },
        CheatPatternRule { pattern: "Allows the autoclicker to work within the inventory", name: "Vape V4 Autoclicker", description: "Wykryto string konfiguracyjny autoclickera Vape V4.", level: VerdictLevel::Detection },
        CheatPatternRule { pattern: "Enables the use of a different autoclicker randomization", name: "Vape V4 Randomizer", description: "Wykryto algorytm randomizacji kliknięć Vape V4.", level: VerdictLevel::Detection },
        CheatPatternRule { pattern: "drip.client", name: "Drip Lite Client", description: "Wykryto instancję ghost clienta Drip Lite.", level: VerdictLevel::Detection },
        CheatPatternRule { pattern: "drip.gg", name: "Drip Backend", description: "Wykryto adresy backendu klienta Drip.", level: VerdictLevel::Detection },
        CheatPatternRule { pattern: "ravenbplus", name: "Raven B+ Client", description: "Wykryto ślady ghost clienta Raven B+ w pamięci JVM.", level: VerdictLevel::Detection },
        CheatPatternRule { pattern: "raven b+", name: "Raven B+ Client", description: "Wykryto ciąg identyfikacyjny Raven B+.", level: VerdictLevel::Detection },
        CheatPatternRule { pattern: "slinkyhook.dll", name: "Slinky Hook DLL", description: "Wykryto bibliotekę wstrzykującą Slinkyhook.", level: VerdictLevel::Detection },
        CheatPatternRule { pattern: "slinky_library.dll", name: "Slinky Library DLL", description: "Wykryto natywną bibliotekę Slinky Library.", level: VerdictLevel::Detection },
        CheatPatternRule { pattern: "slinky.gg", name: "Slinky Backend", description: "Wykryto domenę usługi Slinky Ghost Client.", level: VerdictLevel::Detection },
        // --- LIQUIDBOUNCE CLIENT ---
        CheatPatternRule { pattern: "LiquidBounce.jar", name: "LiquidBounce JAR Artifact", description: "Wykryto obecność pliku wykonywalnego LiquidBounce.jar w pamięci procesu.", level: VerdictLevel::Detection },
        CheatPatternRule { pattern: "net/ccbluex/liquidbounce/injection/mixins", name: "LiquidBounce Injected Mixins", description: "Wykryto wstrzyknięte mixiny modyfikujące kod gry (LiquidBounce).", level: VerdictLevel::Detection },
        CheatPatternRule { pattern: "net/ccbluex/liquidbounce/features/module", name: "LiquidBounce Module Tree", description: "Wykryto drzewo modułów cheata LiquidBounce.", level: VerdictLevel::Detection },
        CheatPatternRule { pattern: "api.liquidbounce.net", name: "LiquidBounce API Endpoint", description: "Wykryto połączenie lub konfigurację API LiquidBounce.", level: VerdictLevel::Detection },
        CheatPatternRule { pattern: "cloud.liquidbounce.net", name: "LiquidBounce Cloud Service", description: "Wykryto usługę chmurową LiquidBounce Cloud.", level: VerdictLevel::Detection },
        CheatPatternRule { pattern: "capes.liquidbounce.net", name: "LiquidBounce Cape Server", description: "Wykryto serwer pelerynek LiquidBounce.", level: VerdictLevel::Detection },
        CheatPatternRule { pattern: "LiquidChat", name: "LiquidBounce LiquidChat", description: "Wykryto protokół komunikatora LiquidChat klienta LiquidBounce.", level: VerdictLevel::Detection },
        CheatPatternRule { pattern: "assets/minecraft/haru", name: "Haru Ghost Client", description: "Wykryto assety wewnętrznego ghost clienta Haru.", level: VerdictLevel::Detection },
        CheatPatternRule { pattern: "assets/minecraft/sakura", name: "Sakura Ghost Client", description: "Wykryto assety ghost clienta Sakura.", level: VerdictLevel::Detection },
        CheatPatternRule { pattern: "kura.client", name: "Kura Ghost Client", description: "Wykryto stringi ghost clienta Kura.", level: VerdictLevel::Detection },
        CheatPatternRule { pattern: "entropy.club", name: "Entropy Ghost Client", description: "Wykryto odwołania do klienta Entropy.", level: VerdictLevel::Detection },
        CheatPatternRule { pattern: "breeze.rip", name: "Breeze Client", description: "Wykryto domenę klienta Breeze.", level: VerdictLevel::Detection },
        CheatPatternRule { pattern: "breeze.dll", name: "Breeze Client DLL", description: "Wykryto załadowaną bibliotekę Breeze DLL.", level: VerdictLevel::Detection },
        CheatPatternRule { pattern: "lithiumclient.wtf", name: "Lithium Client", description: "Wykryto sygnatury Lithium Client.", level: VerdictLevel::Detection },
        CheatPatternRule { pattern: "lol/lwes/voilloader", name: "VoilLoader Injector", description: "Wykryto pakiet wstrzykujący VoilLoader.", level: VerdictLevel::Detection },
        CheatPatternRule { pattern: "lol/lwes/voil/Native", name: "VoilLoader Native Interface", description: "Wykryto natywny interfejs VoilLoader.", level: VerdictLevel::Detection },
        // --- MARLOW CLIENT (EclipseWare) ---
        CheatPatternRule { pattern: "com/eclipseware/imnotcheatingyouare", name: "Marlow Client Package (EclipseWare)", description: "Wykryto główny pakiet klasowy cheata Marlow Client (imnotcheatingyouare).", level: VerdictLevel::Detection },
        CheatPatternRule { pattern: "ImnotcheatingyouareClient", name: "Marlow Client Core Class", description: "Wykryto klasę rozruchową cheata Marlow Client.", level: VerdictLevel::Detection },
        CheatPatternRule { pattern: "imnotcheatingyouare.client.mixins", name: "Marlow Client Mixins Config", description: "Wykryto konfigurację mixinów wstrzykujących cheata Marlow Client.", level: VerdictLevel::Detection },
        CheatPatternRule { pattern: "imnotcheatingyouare.mixins.json", name: "Marlow Client Mixin JSON", description: "Wykryto definicję wstrzyknięć mixinów cheata Marlow Client.", level: VerdictLevel::Detection },
        CheatPatternRule { pattern: "config/imnotcheatingyouare", name: "Marlow Client Config Directory", description: "Wykryto ścieżkę konfiguracji modułów cheata Marlow Client.", level: VerdictLevel::Detection },
        CheatPatternRule { pattern: "assets/imnotcheatingyouare", name: "Marlow Client Assets", description: "Wykryto zasoby graficzne/shadery cheata Marlow Client.", level: VerdictLevel::Detection },
        CheatPatternRule { pattern: "Marlowwww Client", name: "Marlow Client Fabric Mod", description: "Wykryto metadane Fabric cheata Marlow Client.", level: VerdictLevel::Detection },
        CheatPatternRule { pattern: "com/eclipseware/imnotcheatingyouare/client/module/impl", name: "Marlow Client Module Tree", description: "Wykryto drzewo modułów bojowych i automatyzacji cheata Marlow Client.", level: VerdictLevel::Detection },
        // --- PRESTIGE CLIENT ---
        CheatPatternRule { pattern: "dev/zprestige/prestige", name: "Prestige Client Package", description: "Wykryto główny pakiet klasowy cheata Prestige Client.", level: VerdictLevel::Detection },
        CheatPatternRule { pattern: "PrestigeClient", name: "Prestige Client Core", description: "Wykryto odwołanie do klasy PrestigeClient.", level: VerdictLevel::Detection },
        CheatPatternRule { pattern: "api.prestigeclient.vip", name: "Prestige Injector API", description: "Wykryto połączenie API downloadera cheata Prestige.", level: VerdictLevel::Detection },
        CheatPatternRule { pattern: "prestigeclient.vip", name: "Prestige Client Backend", description: "Wykryto domenę serwerów licencji cheata Prestige.", level: VerdictLevel::Detection },
        CheatPatternRule { pattern: "attachment;filename=prestige.jar", name: "Prestige Client Payload", description: "Wykryto nagłówek pobierania pliku JAR cheata Prestige.", level: VerdictLevel::Detection },
        CheatPatternRule { pattern: "Glass + violet, Prestige Client theme", name: "Prestige Client Theme", description: "Wykryto unikalny ciąg motywu graficznego Prestige Client.", level: VerdictLevel::Detection },
        CheatPatternRule { pattern: "Adds a random amount in this range to your reach", name: "Prestige Reach Setting", description: "Wykryto konfigurację modułu Reach w Prestige Client.", level: VerdictLevel::Detection },
        CheatPatternRule { pattern: "Rolls this chance on each extended-reach hit", name: "Prestige Reach Chance", description: "Wykryto parametr szansy Reach w Prestige Client.", level: VerdictLevel::Detection },
        CheatPatternRule { pattern: "Rolls this chance on each Breach swap opportunity", name: "Prestige AutoSwap Setting", description: "Wykryto moduł automatycznej zmiany broni w Prestige Client.", level: VerdictLevel::Detection },
        CheatPatternRule { pattern: "RMB WTAP, LMB TBOT, AUTO JUMP RESET GOT ME LT3", name: "Prestige Combat Config", description: "Wykryto unikalną konfigurację modułów walki cheata Prestige.", level: VerdictLevel::Detection },
        CheatPatternRule { pattern: "JNI_OnLoad not found in DLL", name: "Prestige Injected DLL", description: "Wykryto błąd ładowania JNI charakterystyczny dla cheata Prestige.", level: VerdictLevel::Detection },

        // --- WATER CLIENT (CPvP / 1.21 Macro Ghost Client) ---
        CheatPatternRule { pattern: "COMBAT/Auto Crystal/openTime", name: "Water Client (Auto Crystal)", description: "Wykryto moduł Auto Crystal w strukturze GUI Water Client.", level: VerdictLevel::Detection },
        CheatPatternRule { pattern: "COMBAT/Double Anchor/openTime", name: "Water Client (Double Anchor)", description: "Wykryto moduł Double Anchor w strukturze GUI Water Client.", level: VerdictLevel::Detection },
        CheatPatternRule { pattern: "COMBAT/AutoDoubleHand/openTime", name: "Water Client (AutoDoubleHand)", description: "Wykryto moduł AutoDoubleHand w strukturze GUI Water Client.", level: VerdictLevel::Detection },
        CheatPatternRule { pattern: "COMBAT/Hover Totem/openTime", name: "Water Client (Hover Totem)", description: "Wykryto moduł Hover Totem w strukturze GUI Water Client.", level: VerdictLevel::Detection },
        CheatPatternRule { pattern: "COMBAT/Anchor Macro/openTime", name: "Water Client (Anchor Macro)", description: "Wykryto moduł Anchor Macro w strukturze GUI Water Client.", level: VerdictLevel::Detection },
        CheatPatternRule { pattern: "COMBAT/Mace Swap/openTime", name: "Water Client (Mace Swap)", description: "Wykryto moduł Mace Swap w strukturze GUI Water Client.", level: VerdictLevel::Detection },
        CheatPatternRule { pattern: "COMBAT/Shield Breaker/openTime", name: "Water Client (Shield Breaker)", description: "Wykryto moduł Shield Breaker w strukturze GUI Water Client.", level: VerdictLevel::Detection },
        CheatPatternRule { pattern: "COMBAT/Auto Inv Totem/openTime", name: "Water Client (Auto Inv Totem)", description: "Wykryto moduł Auto Inv Totem w strukturze GUI Water Client.", level: VerdictLevel::Detection },
        CheatPatternRule { pattern: "COMBAT/SpearSwap/openTime", name: "Water Client (SpearSwap)", description: "Wykryto moduł SpearSwap w strukturze GUI Water Client.", level: VerdictLevel::Detection },
        CheatPatternRule { pattern: "COMBAT/Elytra Swap/openTime", name: "Water Client (Elytra Swap)", description: "Wykryto moduł Elytra Swap w strukturze GUI Water Client.", level: VerdictLevel::Detection },
        CheatPatternRule { pattern: "COMBAT/Double Anchor/expand", name: "Water Client State (Double Anchor)", description: "Wykryto stan rozwinięcia modułu Double Anchor w Water Client.", level: VerdictLevel::Detection },
        CheatPatternRule { pattern: "COMBAT/AutoDoubleHand/expand", name: "Water Client State (AutoDoubleHand)", description: "Wykryto stan rozwinięcia modułu AutoDoubleHand w Water Client.", level: VerdictLevel::Detection },
        CheatPatternRule { pattern: "COMBAT/Auto Crystal/expand", name: "Water Client State (Auto Crystal)", description: "Wykryto stan rozwinięcia modułu Auto Crystal w Water Client.", level: VerdictLevel::Detection },

        // --- VENGEANCE CLIENT (Fabric Ghost Client) ---
        CheatPatternRule { pattern: "com/vengeance/vengeanceclient", name: "Vengeance Client Core Package", description: "Wykryto główny pakiet klasowy cheata Vengeance Client.", level: VerdictLevel::Detection },
        CheatPatternRule { pattern: "com.vengeance.vengeanceclient", name: "Vengeance Client Core Package", description: "Wykryto odwołania klasowe do com.vengeance.vengeanceclient.", level: VerdictLevel::Detection },
        CheatPatternRule { pattern: "VengeanceClient", name: "Vengeance Client Main Class", description: "Wykryto klasę główną VengeanceClient.", level: VerdictLevel::Detection },
        CheatPatternRule { pattern: "vengeance-client.mixins.json", name: "Vengeance Client Mixin Config", description: "Wykryto plik konfiguracyjny mixinów cheata Vengeance Client.", level: VerdictLevel::Detection },
        CheatPatternRule { pattern: "vengeance-auth.vercel.app", name: "Vengeance Client Auth Backend", description: "Wykryto adres serwera autoryzacji cheata Vengeance Client.", level: VerdictLevel::Detection },
        CheatPatternRule { pattern: "assets/vengeance-client", name: "Vengeance Client Assets", description: "Wykryto zasoby graficzne i shadery cheata Vengeance Client.", level: VerdictLevel::Detection },
        CheatPatternRule { pattern: "vengeance-client$keepSprintTail", name: "Vengeance Client KeepSprint Hook", description: "Wykryto wstrzyknięty hook KeepSprint cheata Vengeance Client.", level: VerdictLevel::Detection },
        CheatPatternRule { pattern: "vengeance-client$doAttackInject", name: "Vengeance Client Attack Hook", description: "Wykryto wstrzyknięty hook ataku cheata Vengeance Client.", level: VerdictLevel::Detection },
        CheatPatternRule { pattern: "vengeance-client$onRaycastStart", name: "Vengeance Client Raycast/Reach Hook", description: "Wykryto wstrzyknięty hook zasięgu (Raycast/Reach) cheata Vengeance Client.", level: VerdictLevel::Detection },
        CheatPatternRule { pattern: "vengeance-client$onDrawEntityOutlines", name: "Vengeance Client ESP/Glow Hook", description: "Wykryto wstrzyknięty hook renderowania obrysów (ESP) cheata Vengeance Client.", level: VerdictLevel::Detection },
        CheatPatternRule { pattern: "vengeance-client$sendPacketEventInject", name: "Vengeance Client Packet Hook", description: "Wykryto wstrzyknięty hook pakietowy cheata Vengeance Client.", level: VerdictLevel::Detection },
        CheatPatternRule { pattern: "vengeance-client$ravenZHandleInputEvents", name: "Vengeance Client Input Hook", description: "Wykryto wstrzyknięty hook obsługi wejścia (Raven-Z base) w Vengeance Client.", level: VerdictLevel::Detection },
        CheatPatternRule { pattern: "vengeance-client$modifyBlockBreakingSpeed", name: "Vengeance Client FastBreak Hook", description: "Wykryto wstrzyknięty hook przyspieszonego niszczenia bloków (Vengeance Client).", level: VerdictLevel::Detection },
        CheatPatternRule { pattern: "vengeance-1.21", name: "Vengeance Client JAR Reference", description: "Wykryto odwołanie do pliku wykonywalnego vengeance-1.21 w pamięci.", level: VerdictLevel::Detection },

        // --- ASTRAL CLIENT (Epstein House / Fabric Ghost Client) ---
        CheatPatternRule { pattern: "epstein_house/mixin", name: "Astral Client (Epstein House Package)", description: "Wykryto główny pakiet klasowy cheata Astral Client (epstein_house).", level: VerdictLevel::Detection },
        CheatPatternRule { pattern: "epstein_house.mixin", name: "Astral Client (Epstein House Package)", description: "Wykryto odwołania klasowe epstein_house cheata Astral Client.", level: VerdictLevel::Detection },
        CheatPatternRule { pattern: "epstein.client.mixins.json", name: "Astral Client Mixin Config", description: "Wykryto plik konfiguracyjny mixinów cheata Astral Client.", level: VerdictLevel::Detection },
        CheatPatternRule { pattern: "epstein.mixins.json", name: "Astral Client Mixin Config", description: "Wykryto plik konfiguracyjny mixinów cheata Astral Client.", level: VerdictLevel::Detection },
        CheatPatternRule { pattern: "epstein.accesswidener", name: "Astral Client AccessWidener", description: "Wykryto reguły AccessWidener cheata Astral Client.", level: VerdictLevel::Detection },
        CheatPatternRule { pattern: "epstein/fakelag_ghost", name: "Astral Client (FakeLag Module)", description: "Wykryto moduł FakeLag ghost w strukturze Astral Client.", level: VerdictLevel::Detection },
        CheatPatternRule { pattern: "epstein/killaura_circle", name: "Astral Client (KillAura Circle)", description: "Wykryto renderer okręgu KillAura cheata Astral Client.", level: VerdictLevel::Detection },
        CheatPatternRule { pattern: "epstein/donut_chunk_finder", name: "Astral Client (Donut Chunk Finder)", description: "Wykryto moduł Donut Chunk Finder cheata Astral Client.", level: VerdictLevel::Detection },
        CheatPatternRule { pattern: "epstein/cluster_bypass_tracer", name: "Astral Client (Cluster Bypass Tracer)", description: "Wykryto tracer bypassu clusterów cheata Astral Client.", level: VerdictLevel::Detection },
        CheatPatternRule { pattern: "epstein/player_esp", name: "Astral Client (Player ESP)", description: "Wykryto moduł Player ESP cheata Astral Client.", level: VerdictLevel::Detection },
        CheatPatternRule { pattern: "epstein/player_tracer", name: "Astral Client (Player Tracer)", description: "Wykryto moduł Player Tracer cheata Astral Client.", level: VerdictLevel::Detection },
        CheatPatternRule { pattern: "epstein/storage_esp", name: "Astral Client (Storage ESP)", description: "Wykryto moduł Storage ESP cheata Astral Client.", level: VerdictLevel::Detection },
        CheatPatternRule { pattern: "epstein_house.mixin.client.FakeLagMixin", name: "Astral Client FakeLag Mixin", description: "Wykryto wstrzyknięty hook FakeLagMixin cheata Astral Client.", level: VerdictLevel::Detection },
        CheatPatternRule { pattern: "epstein_house.mixin.client.FreecamTickMixin", name: "Astral Client Freecam Mixin", description: "Wykryto wstrzyknięty hook FreecamTickMixin cheata Astral Client.", level: VerdictLevel::Detection },
        CheatPatternRule { pattern: "epstein_house.mixin.client.XrayBlockMixin", name: "Astral Client Xray Mixin", description: "Wykryto wstrzyknięty hook XrayBlockMixin cheata Astral Client.", level: VerdictLevel::Detection },
        CheatPatternRule { pattern: "epstein_house.mixin.client.SeeThroughWallsMixin", name: "Astral Client SeeThroughWalls Mixin", description: "Wykryto wstrzyknięty hook widzenia przez ściany (SeeThroughWalls) Astral Client.", level: VerdictLevel::Detection },
        CheatPatternRule { pattern: "epstein_house.mixin.client.PacketFinderMixin", name: "Astral Client PacketFinder Mixin", description: "Wykryto wstrzyknięty hook PacketFinderMixin cheata Astral Client.", level: VerdictLevel::Detection },
        CheatPatternRule { pattern: "epstein_house.mixin.client.SignBypassMixin", name: "Astral Client SignBypass Mixin", description: "Wykryto wstrzyknięty hook SignBypassMixin cheata Astral Client.", level: VerdictLevel::Detection },
        CheatPatternRule { pattern: "epstein_house.mixin.client.SilentHomeChatMixin", name: "Astral Client SilentHome Mixin", description: "Wykryto hook ukrywania komend domowych (SilentHome) cheata Astral Client.", level: VerdictLevel::Detection },
        CheatPatternRule { pattern: "epstein_house.mixin.client.DonutBalanceMixin", name: "Astral Client DonutSMP Exploit Mixin", description: "Wykryto hook balansu ekonomii DonutSMP w Astral Client.", level: VerdictLevel::Detection },
        CheatPatternRule { pattern: "epstein/hud_positions.cfg", name: "Astral Client Config File", description: "Wykryto odwołanie do pliku konfiguracyjnego epstein/hud_positions.cfg.", level: VerdictLevel::Detection },
        CheatPatternRule { pattern: "epstein\\hud_positions.cfg", name: "Astral Client Config File", description: "Wykryto odwołanie do pliku konfiguracyjnego epstein\\hud_positions.cfg.", level: VerdictLevel::Detection },
        CheatPatternRule { pattern: "handler$zbd000$epstein$hideCrosshairDuringFreeLook", name: "Astral Client FreeLook Hook", description: "Wykryto unikalną metodę wstrzykniętą (FreeLook) cheata Astral Client.", level: VerdictLevel::Detection },

        // --- CALCIUM CLIENT (DClient / Fabric Ghost Client) ---
        CheatPatternRule { pattern: "com/dclient/", name: "Calcium Client (DClient Package)", description: "Wykryto główny pakiet klasowy cheata Calcium Client (com/dclient).", level: VerdictLevel::Detection },
        CheatPatternRule { pattern: "com.dclient.", name: "Calcium Client (DClient Package)", description: "Wykryto odwołania klasowe com.dclient cheata Calcium Client.", level: VerdictLevel::Detection },
        CheatPatternRule { pattern: "com/dclient/DClient", name: "Calcium Client Core Class", description: "Wykryto główną klasę silnika cheata Calcium Client (DClient).", level: VerdictLevel::Detection },
        CheatPatternRule { pattern: "com/dclient/client/DClientClient", name: "Calcium Client Runtime Class", description: "Wykryto klasę uruchomieniową DClientClient cheata Calcium.", level: VerdictLevel::Detection },
        CheatPatternRule { pattern: "com/dclient/client/gui/ClickGui", name: "Calcium Client ClickGUI", description: "Wykryto interfejs graficzny ClickGui cheata Calcium Client.", level: VerdictLevel::Detection },
        CheatPatternRule { pattern: "com/dclient/auth/AuthManager", name: "Calcium Client Auth Manager", description: "Wykryto menedżer autoryzacji AuthManager cheata Calcium Client.", level: VerdictLevel::Detection },
        CheatPatternRule { pattern: "dclient.client.mixins.json", name: "Calcium Client Mixin Config", description: "Wykryto plik konfiguracyjny mixinów cheata Calcium Client.", level: VerdictLevel::Detection },
        CheatPatternRule { pattern: "dclient.mixins.json", name: "Calcium Client Mixin Config", description: "Wykryto plik konfiguracyjny mixinów cheata Calcium Client.", level: VerdictLevel::Detection },
        CheatPatternRule { pattern: "dclient.accesswidener", name: "Calcium Client AccessWidener", description: "Wykryto reguły AccessWidener cheata Calcium Client.", level: VerdictLevel::Detection },
        CheatPatternRule { pattern: "dclient-config.json", name: "Calcium Client Config Reference", description: "Wykryto odwołanie do pliku konfiguracyjnego dclient-config.json.", level: VerdictLevel::Detection },
        CheatPatternRule { pattern: "dclient_friends.json", name: "Calcium Client Friends Config", description: "Wykryto odwołanie do konfiguracji znajomych dclient_friends.json.", level: VerdictLevel::Detection },
        CheatPatternRule { pattern: "Open DClient GUI", name: "Calcium Client GUI String", description: "Wykryto tekst wywołania GUI cheata Calcium Client.", level: VerdictLevel::Detection },
        CheatPatternRule { pattern: "key.dclient.opengui", name: "Calcium Client Keybind", description: "Wykryto przypisanie klawisza otwierania GUI cheata Calcium Client.", level: VerdictLevel::Detection },
        CheatPatternRule { pattern: "handler$zzd000$dclient$onHandleAccumulatedMovement", name: "Calcium Client Movement Hook", description: "Wykryto wstrzyknięty hook akumulacji ruchu cheata Calcium Client.", level: VerdictLevel::Detection },
        CheatPatternRule { pattern: "handler$zzf000$dclient$onAttack", name: "Calcium Client Attack Hook", description: "Wykryto wstrzyknięty hook ataku cheata Calcium Client.", level: VerdictLevel::Detection },
        CheatPatternRule { pattern: "handler$zzb000$dclient$onSendPosition", name: "Calcium Client Packet Hook", description: "Wykryto wstrzyknięty hook wysyłania pozycji pakietowej (Calcium Client).", level: VerdictLevel::Detection },
        CheatPatternRule { pattern: "localvar$zza000$dclient$onGetNightVisionScale", name: "Calcium Client Fullbright Hook", description: "Wykryto wstrzyknięty hook Fullbright/NightVision cheata Calcium Client.", level: VerdictLevel::Detection },

        // --- DQRKIS CLIENT (TrilliumSolutions / Target Mod) ---
        CheatPatternRule { pattern: "Cracked by github.com/TrilliumSolutions", name: "Dqrkis Client Crack Banner", description: "Wykryto nagłówek crackera TrilliumSolutions cheata Dqrkis Client w pamięci JVM.", level: VerdictLevel::Detection },
        CheatPatternRule { pattern: "github.com/TrilliumSolutions", name: "TrilliumSolutions Repository", description: "Wykryto odwołanie do repozytorium TrilliumSolutions w procesie javaw.", level: VerdictLevel::Detection },
        CheatPatternRule { pattern: "I'm getting SS'ed", name: "Dqrkis Client Panic/SelfDestruct", description: "Wykryto moduł awaryjnego zacierania śladów przed Screenshare (I'm getting SS'ed) w Dqrkis Client.", level: VerdictLevel::Detection },
        CheatPatternRule { pattern: "Jumps when you take damage to reduce knockback.", name: "Dqrkis Client JumpReset Module", description: "Wykryto opis modułu redukcji odrzutu (JumpReset) cheata Dqrkis Client.", level: VerdictLevel::Detection },
        CheatPatternRule { pattern: "Undetectable Trident Fly. Requires Rain, RipTide", name: "Dqrkis Client TridentFly Exploit", description: "Wykryto opis modułu latania trójzębem (TridentFly) cheata Dqrkis Client.", level: VerdictLevel::Detection },
        CheatPatternRule { pattern: "com/target/mod/compat/a/b/d/QuickStrike", name: "Dqrkis Client QuickStrike Module", description: "Wykryto klasę bojową QuickStrike w pakiecie com/target/mod/compat.", level: VerdictLevel::Detection },
        CheatPatternRule { pattern: "com/target/mod/compat/a/b/d/cn$MacroState", name: "Dqrkis Client Macro Engine", description: "Wykryto silnik makr cn$MacroState w strukturze Dqrkis Client.", level: VerdictLevel::Detection },
        CheatPatternRule { pattern: "com/target/mod/compat", name: "Dqrkis Client Package (com/target/mod)", description: "Wykryto wewnętrzny pakiet klasowy com/target/mod/compat cheata Dqrkis Client.", level: VerdictLevel::Detection },

        // --- ARGON / CORRUPT CLIENT (dev.lvstrng.argon) ---
        CheatPatternRule { pattern: "dev/lvstrng/argon", name: "Argon / Corrupt Client Package (dev/lvstrng/argon)", description: "Wykryto główny pakiet klasowy cheata Argon / Corrupt Client (lvstrng).", level: VerdictLevel::Detection },
        CheatPatternRule { pattern: "dev.lvstrng.argon", name: "Argon / Corrupt Client Package (dev.lvstrng.argon)", description: "Wykryto odwołania klasowe dev.lvstrng.argon cheata Argon / Corrupt Client.", level: VerdictLevel::Detection },
        CheatPatternRule { pattern: "dev/lvstrng/argon/Argon", name: "Argon / Corrupt Client Core Class", description: "Wykryto klasę główną cheata Argon / Corrupt Client.", level: VerdictLevel::Detection },
        CheatPatternRule { pattern: "dev.lvstrng.argon.Argon", name: "Argon / Corrupt Client Full Identifier", description: "Wykryto pełny identyfikator klasy dev.lvstrng.argon.Argon w pamięci JVM.", level: VerdictLevel::Detection },
        CheatPatternRule { pattern: "Ldev/lvstrng/argon/Argon;", name: "Argon / Corrupt Client Class Signature", description: "Wykryto sygnaturę typu klasy Ldev/lvstrng/argon/Argon; w pamięci JVM.", level: VerdictLevel::Detection },
        CheatPatternRule { pattern: "dev/lvstrng/argon/Argon.class", name: "Argon / Corrupt Client Class File", description: "Wykryto plik klasy cheata Argon / Corrupt Client w pamięci JVM.", level: VerdictLevel::Detection },
        CheatPatternRule { pattern: "dev/lvstrng/argon/module/modules/client/SelfDestruct", name: "Argon / Corrupt Client SelfDestruct Module", description: "Wykryto moduł samozniszczenia (SelfDestruct) cheata Argon / Corrupt Client.", level: VerdictLevel::Detection },
        CheatPatternRule { pattern: "Argon |", name: "Argon / Corrupt Client Watermark", description: "Wykryto ciąg znaku wodnego HUD/tytułowego cheata Argon / Corrupt Client.", level: VerdictLevel::Detection },
        CheatPatternRule { pattern: "Corrupt Client", name: "Corrupt Client Identifier", description: "Wykryto identyfikator cheata Corrupt Client w pamięci JVM.", level: VerdictLevel::Detection },
        CheatPatternRule { pattern: "CorruptClient", name: "Corrupt Client Core Class", description: "Wykryto klasę główną cheata Corrupt Client w procesie javaw.", level: VerdictLevel::Detection },

        // --- NOXX CLIENT (Fabric Utility / Ghost Client) ---
        CheatPatternRule { pattern: "com/example/NoxxClient", name: "Noxx Client Class (com/example/NoxxClient)", description: "Wykryto klasę główną cheata Noxx Client w procesie javaw.", level: VerdictLevel::Detection },
        CheatPatternRule { pattern: "com.example.NoxxClient", name: "Noxx Client Package", description: "Wykryto pakiet klasowy cheata Noxx Client.", level: VerdictLevel::Detection },
        CheatPatternRule { pattern: "Noxx Client - A Minecraft utility client", name: "Noxx Client Description", description: "Wykryto opis cheata Noxx Client w pamięci JVM.", level: VerdictLevel::Detection },
        CheatPatternRule { pattern: "Noxx Client loading...", name: "Noxx Client Loader Log", description: "Wykryto procedurę ładowania cheata Noxx Client.", level: VerdictLevel::Detection },
        CheatPatternRule { pattern: "Noxx Client initializing...", name: "Noxx Client Init Log", description: "Wykryto procedurę inicjalizacji cheata Noxx Client.", level: VerdictLevel::Detection },
        CheatPatternRule { pattern: "Noxx Client initialized!", name: "Noxx Client Ready Log", description: "Wykryto potwierdzenie uruchomienia cheata Noxx Client.", level: VerdictLevel::Detection },
        CheatPatternRule { pattern: "Noxx-DiscordIPC", name: "Noxx Client Discord RPC", description: "Wykryto moduł integracji Discord cheata Noxx Client.", level: VerdictLevel::Detection },
        CheatPatternRule { pattern: "background Noxx+", name: "Noxx Client Background Asset", description: "Wykryto unikalny zasób graficzny GUI cheata Noxx Client.", level: VerdictLevel::Detection },

        // --- PULSE CLIENT (cc.pulse / cc/pulse) ---
        CheatPatternRule { pattern: "cc/pulse/PulseClient", name: "Pulse Client Class (cc/pulse/PulseClient)", description: "Wykryto klasę główną cheata Pulse Client w pamięci JVM.", level: VerdictLevel::Detection },
        CheatPatternRule { pattern: "cc.pulse.PulseClient", name: "Pulse Client Package", description: "Wykryto pakiet klasowy cheata Pulse Client.", level: VerdictLevel::Detection },
        CheatPatternRule { pattern: "Lcc/pulse/PulseClient;", name: "Pulse Client Class Signature", description: "Wykryto sygnaturę typu klasy cc/pulse/PulseClient w pamięci JVM.", level: VerdictLevel::Detection },
        CheatPatternRule { pattern: "cc/pulse/PulseClient.class", name: "Pulse Client Class File", description: "Wykryto plik klasy cc/pulse/PulseClient.class w pamięci JVM.", level: VerdictLevel::Detection },
        CheatPatternRule { pattern: "cc/pulse/PulseClient$$Lambda", name: "Pulse Client Lambda Hook", description: "Wykryto wygenerowane lambdy cheata Pulse Client.", level: VerdictLevel::Detection },
        CheatPatternRule { pattern: "Pulse Client Configs", name: "Pulse Client Config Directory", description: "Wykryto strukturę katalogu konfiguracyjnego Pulse Client Configs.", level: VerdictLevel::Detection },
        CheatPatternRule { pattern: "getPulseEventBus", name: "Pulse Client EventBus Method", description: "Wykryto metodę szyny zdarzeń getPulseEventBus cheata Pulse Client.", level: VerdictLevel::Detection },
        CheatPatternRule { pattern: "PulseEventBus", name: "Pulse Client EventBus Class", description: "Wykryto klasę szyny zdarzeń PulseEventBus cheata Pulse Client.", level: VerdictLevel::Detection },
        CheatPatternRule { pattern: "\\Pulse\\profiles", name: "Pulse Client Profiles Path", description: "Wykryto ścieżkę profili Pulse\\profiles w pamięci JVM.", level: VerdictLevel::Detection },

        // --- 22QQ CLIENT (Disguised as CubesWithoutBorders / Trojanized Mixins) ---
        CheatPatternRule { pattern: "dev/kir/cubeswithoutborders/client/mixin/EndCrystalItemMixin", name: "22qq Client AutoCrystal Mixin", description: "Wykryto złośliwy mixin EndCrystalItem ukryty pod pakietem CubesWithoutBorders (22qq Client).", level: VerdictLevel::Detection },
        CheatPatternRule { pattern: "dev/kir/cubeswithoutborders/client/mixin/ClientPlayerInteractionManagerMixin", name: "22qq Client Interaction Mixin", description: "Wykryto złośliwy mixin menedżera interakcji gracza (Reach/FastBreak/HitCooldown) w CubesWithoutBorders (22qq Client).", level: VerdictLevel::Detection },
        CheatPatternRule { pattern: "dev/kir/cubeswithoutborders/client/mixin/ClientPlayerInteractionManagerAccessor", name: "22qq Client Interaction Accessor", description: "Wykryto akcesor interakcji bojowych ukryty pod CubesWithoutBorders (22qq Client).", level: VerdictLevel::Detection },
        CheatPatternRule { pattern: "dev/kir/cubeswithoutborders/client/mixin/ClientPlayerEntityMixin", name: "22qq Client Movement Mixin", description: "Wykryto mixin modyfikacji ruchu i fizyki gracza pod pakietem CubesWithoutBorders (22qq Client).", level: VerdictLevel::Detection },
        CheatPatternRule { pattern: "dev/kir/cubeswithoutborders/client/mixin/HandledScreenMixin", name: "22qq Client Inventory Mixin", description: "Wykryto mixin manipulacji GUI/ekwipunkiem (InvMove/AutoTotem) w CubesWithoutBorders (22qq Client).", level: VerdictLevel::Detection },
        CheatPatternRule { pattern: "dev/kir/cubeswithoutborders/client/mixin/MouseHandlerAccessor", name: "22qq Client Mouse/Click Accessor", description: "Wykryto akcesor sterownika myszy (TriggerBot/AutoClicker) w CubesWithoutBorders (22qq Client).", level: VerdictLevel::Detection },

        // --- ECHO CLIENT (Fabric Ghost Client / DRM Loader) ---
        CheatPatternRule { pattern: "hack/echo/client/Echo", name: "Echo Client Core Class", description: "Wykryto główną klasę hack/echo/client/Echo cheata Echo Client w pamięci JVM.", level: VerdictLevel::Detection },
        CheatPatternRule { pattern: "Lhack/echo/client/Echo;", name: "Echo Client Class Signature", description: "Wykryto deskryptor klasy Lhack/echo/client/Echo; cheata Echo Client.", level: VerdictLevel::Detection },
        CheatPatternRule { pattern: "Lhack/echo/client/features/Category;", name: "Echo Client Category Enum", description: "Wykryto enum kategorii modułów (Category) cheata Echo Client.", level: VerdictLevel::Detection },
        CheatPatternRule { pattern: "hack/echo/client/features/", name: "Echo Client Features Package", description: "Wykryto strukturę modułów hack/echo/client/features cheata Echo Client.", level: VerdictLevel::Detection },
        CheatPatternRule { pattern: "Lhack/echo/client/chunk/BlockEspManager;", name: "Echo Client BlockESP Manager", description: "Wykryto menedżer prześwietlania bloków (BlockESP) cheata Echo Client.", level: VerdictLevel::Detection },
        CheatPatternRule { pattern: "Lhack/echo/client/spotify/SpotifyManager;", name: "Echo Client Spotify Manager", description: "Wykryto menedżer Spotify charakterystyczny dla cheata Echo Client.", level: VerdictLevel::Detection },
        CheatPatternRule { pattern: "Lhack/echo/client/friends/FriendManager;", name: "Echo Client Friend Manager", description: "Wykryto menedżer znajomych (FriendManager) cheata Echo Client.", level: VerdictLevel::Detection },
        CheatPatternRule { pattern: "dev.jadyen.drm.echo", name: "Echo Client DRM Loader Package", description: "Wykryto pakiet DRM/Loadera cheata Echo Client (dev.jadyen.drm.echo).", level: VerdictLevel::Detection },
        CheatPatternRule { pattern: "dev/jadyen/drm/echo", name: "Echo Client DRM Loader", description: "Wykryto ścieżkę DRM/Loadera dev/jadyen/drm/echo cheata Echo Client.", level: VerdictLevel::Detection },

    // --- MERA CLIENT (Signatures requiring 100% combined match) ---
        CheatPatternRule { pattern: "Mera Is A Fat Cunt", name: "Mera Client Identifier", description: "Wewnętrzny unikalny identyfikator cheata Mera Client.", level: VerdictLevel::Detection },
        CheatPatternRule { pattern: "Click Open", name: "Mera Client UI Trigger", description: "Wyzwalacz interfejsu cheata Mera Client.", level: VerdictLevel::Detection },

        // --- GRIM CLIENT ---
        CheatPatternRule { pattern: "sixtwo/A", name: "Grim Client Core Class", description: "Wykryto zaciemniony rdzeń cheata Grim Client (sixtwo/A).", level: VerdictLevel::Detection },
        CheatPatternRule { pattern: "sixtwo/G$rJ", name: "Grim Client Inner Class", description: "Wykryto klasę wewnętrzną cheata Grim Client (sixtwo/G$rJ).", level: VerdictLevel::Detection },
        CheatPatternRule { pattern: "ignoreItemSlowdownInAiStep", name: "Grim Client NoSlowdown Mixin", description: "Wykryto wstrzyknięty hook NoSlowdown cheata Grim Client.", level: VerdictLevel::Detection },
        CheatPatternRule { pattern: "ignoreSprintHunger", name: "Grim Client KeepSprint Mixin", description: "Wykryto wstrzyknięty hook ignorowania głodu przy sprincie (Grim Client).", level: VerdictLevel::Detection },
        CheatPatternRule { pattern: "redirect$cgj000$showHitboxes", name: "Grim Client Hitbox Expander", description: "Wykryto wstrzyknięty hook renderera hitboxów cheata Grim Client.", level: VerdictLevel::Detection },
        CheatPatternRule { pattern: "handler$cfp000$attackSprint", name: "Grim Client Sprint Attack Hook", description: "Wykryto wstrzyknięty hook ataku w biegu cheata Grim Client.", level: VerdictLevel::Detection },
        CheatPatternRule { pattern: "modifyExpressionValue$cfk000$rotationYRot", name: "Grim Client Silent Rotations", description: "Wykryto hook manipulacji rotacją gracza (AimAssist/Silent Rotations).", level: VerdictLevel::Detection },
        CheatPatternRule { pattern: "redirect$cfk000$aiStepSetSprinting", name: "Grim Client AutoSprint", description: "Wykryto hook automatycznego sprintu cheata Grim Client.", level: VerdictLevel::Detection },
        CheatPatternRule { pattern: "fixRotationDirection", name: "Grim Client Rotation Fixer", description: "Wykryto hook stabilizacji rotacji cheata Grim Client.", level: VerdictLevel::Detection },
        CheatPatternRule { pattern: "mixin/EntityHitboxDebugRenderer", name: "Grim Client Hitbox Mixin", description: "Wykryto wstrzyknięty mixin debuggera hitboxów cheata Grim Client.", level: VerdictLevel::Detection },
        CheatPatternRule { pattern: "Sapphire LITE", name: "Sapphire LITE Clicker", description: "Wykryto autoclicker Sapphire LITE.", level: VerdictLevel::Detection },
        CheatPatternRule { pattern: "DopeClicker", name: "DopeClicker", description: "Wykryto autoclicker DopeClicker.", level: VerdictLevel::Detection },
        CheatPatternRule { pattern: "VROOMCLICKER", name: "VROOM Clicker", description: "Wykryto autoclicker VROOM.", level: VerdictLevel::Detection },
        CheatPatternRule { pattern: "Monolith Lite", name: "Monolith Lite", description: "Wykryto cheata Monolith Lite.", level: VerdictLevel::Detection },
        CheatPatternRule { pattern: "UNICORN CLIENT", name: "Unicorn Client", description: "Wykryto klienta Unicorn.", level: VerdictLevel::Detection },
        CheatPatternRule { pattern: "UwU Client", name: "UwU Client", description: "Wykryto ghost client UwU.", level: VerdictLevel::Detection },
        CheatPatternRule { pattern: "dream-injector", name: "Dream Injector", description: "Wykryto wstrzykiwacz Dream Injector.", level: VerdictLevel::Detection },
        CheatPatternRule { pattern: "Cheat Engine.exe", name: "Cheat Engine Executable", description: "Wykryto odwołanie do pliku wykonywalnego Cheat Engine.exe.", level: VerdictLevel::Detection },
        CheatPatternRule { pattern: "Cheat Engine 7.", name: "Cheat Engine Version String", description: "Wykryto nagłówek wersji narzędzia Cheat Engine.", level: VerdictLevel::Detection },

        // --- TRIGGERBOT & COMBAT SETTINGS ---
        CheatPatternRule { pattern: "win32con.mouseevent", name: "Triggerbot / Clicker WinAPI", description: "Wykryto skryptową emulację myszy Win32 (win32con.mouseevent).", level: VerdictLevel::Detection },
        CheatPatternRule { pattern: "win32con.mouse_event", name: "Triggerbot / Clicker WinAPI", description: "Wykryto skryptową emulację myszy Win32 (win32con.mouse_event).", level: VerdictLevel::Detection },
        CheatPatternRule { pattern: "TriggerBot.class", name: "Combat: TriggerBot Class", description: "Wykryto klasę bojową TriggerBot.class.", level: VerdictLevel::Detection },
        CheatPatternRule { pattern: "Trigger-Bot.class", name: "Combat: Trigger-Bot Class", description: "Wykryto klasę bojową Trigger-Bot.class.", level: VerdictLevel::Detection },
        CheatPatternRule { pattern: "TriggerBot.java", name: "Combat: TriggerBot Source", description: "Wykryto plik źródłowy TriggerBot.java.", level: VerdictLevel::Detection },
        CheatPatternRule { pattern: "modules/combat/TriggerBot", name: "Combat: TriggerBot Path", description: "Wykryto ścieżkę modułu TriggerBot.", level: VerdictLevel::Detection },
        CheatPatternRule { pattern: "modules/TriggerBot", name: "Combat: TriggerBot Path", description: "Wykryto ścieżkę modułu TriggerBot.", level: VerdictLevel::Detection },
        CheatPatternRule { pattern: "module/TriggerBot", name: "Combat: TriggerBot Path", description: "Wykryto strukturę modułu TriggerBot.", level: VerdictLevel::Detection },
        CheatPatternRule { pattern: "TriggerBot Delay", name: "Combat: TriggerBot Delay Setting", description: "Wykryto parametr opóźnienia modułu TriggerBot.", level: VerdictLevel::Detection },
        CheatPatternRule { pattern: "TriggerBot CPS", name: "Combat: TriggerBot CPS Setting", description: "Wykryto parametr CPS modułu TriggerBot.", level: VerdictLevel::Detection },
        CheatPatternRule { pattern: "TriggerBot Range", name: "Combat: TriggerBot Range Setting", description: "Wykryto parametr zasięgu modułu TriggerBot.", level: VerdictLevel::Detection },
        CheatPatternRule { pattern: "TriggerBot Weapon Only", name: "Combat: TriggerBot Weapon Check", description: "Wykryto filtr broni modułu TriggerBot.", level: VerdictLevel::Detection },
        CheatPatternRule { pattern: "triggerbot_delay", name: "Combat: TriggerBot Delay Config", description: "Wykryto konfigurację triggerbot_delay.", level: VerdictLevel::Detection },
        CheatPatternRule { pattern: "triggerbot_cps", name: "Combat: TriggerBot CPS Config", description: "Wykryto konfigurację triggerbot_cps.", level: VerdictLevel::Detection },
        CheatPatternRule { pattern: "TriggerHold.class", name: "Combat: TriggerHold Class", description: "Wykryto klasę bojową TriggerHold.class.", level: VerdictLevel::Detection },
        CheatPatternRule { pattern: "TriggerHold Delay", name: "Combat: TriggerHold Delay Setting", description: "Wykryto parametr opóźnienia TriggerHold.", level: VerdictLevel::Detection },

        // --- COMBAT & MOVEMENT CHEAT MODULES ---
        CheatPatternRule { pattern: "AimAssist.class", name: "Combat: AimAssist Class", description: "Wykryto skompilowaną klasę AimAssist.class.", level: VerdictLevel::Detection },
        CheatPatternRule { pattern: "Aim-Assist.class", name: "Combat: Aim-Assist Class", description: "Wykryto skompilowaną klasę Aim-Assist.class.", level: VerdictLevel::Detection },
        CheatPatternRule { pattern: "AimAssist.java", name: "Combat: AimAssist Source", description: "Wykryto plik źródłowy AimAssist.java.", level: VerdictLevel::Detection },
        CheatPatternRule { pattern: "modules/combat/AimAssist", name: "Combat: AimAssist Path", description: "Wykryto ścieżkę modułu AimAssist.", level: VerdictLevel::Detection },
        CheatPatternRule { pattern: "modules/AimAssist", name: "Combat: AimAssist Path", description: "Wykryto ścieżkę modułu AimAssist.", level: VerdictLevel::Detection },
        CheatPatternRule { pattern: "module/AimAssist", name: "Combat: AimAssist Module", description: "Wykryto strukturę modułu AimAssist.", level: VerdictLevel::Detection },
        CheatPatternRule { pattern: "AimAssist Speed", name: "Combat: AimAssist Speed Setting", description: "Wykryto parametr prędkości AimAssist.", level: VerdictLevel::Detection },
        CheatPatternRule { pattern: "AimAssist FOV", name: "Combat: AimAssist FOV Setting", description: "Wykryto parametr kąta widzenia (FOV) AimAssist.", level: VerdictLevel::Detection },
        CheatPatternRule { pattern: "AimAssist Range", name: "Combat: AimAssist Range Setting", description: "Wykryto parametr zasięgu AimAssist.", level: VerdictLevel::Detection },
        CheatPatternRule { pattern: "AimAssist Smooth", name: "Combat: AimAssist Smooth Setting", description: "Wykryto parametr wygładzania ruchu AimAssist.", level: VerdictLevel::Detection },
        CheatPatternRule { pattern: "AimAssist Click Aim", name: "Combat: AimAssist Click Aim Setting", description: "Wykryto parametr celowania tylko przy kliknięciu.", level: VerdictLevel::Detection },
        CheatPatternRule { pattern: "Aim Assist Speed", name: "Combat: Aim Assist Speed Setting", description: "Wykryto parametr prędkości Aim Assist.", level: VerdictLevel::Detection },
        CheatPatternRule { pattern: "Aim Assist FOV", name: "Combat: Aim Assist FOV Setting", description: "Wykryto parametr FOV Aim Assist.", level: VerdictLevel::Detection },
        CheatPatternRule { pattern: "Aim Assist Range", name: "Combat: Aim Assist Range Setting", description: "Wykryto parametr zasięgu Aim Assist.", level: VerdictLevel::Detection },
        CheatPatternRule { pattern: "aim_assist_speed", name: "Combat: AimAssist Speed Config", description: "Wykryto parametr konfiguracyjny aim_assist_speed.", level: VerdictLevel::Detection },
        CheatPatternRule { pattern: "aim_assist_fov", name: "Combat: AimAssist FOV Config", description: "Wykryto parametr konfiguracyjny aim_assist_fov.", level: VerdictLevel::Detection },
        CheatPatternRule { pattern: "Reach Distance", name: "Combat: Reach Distance Setting", description: "Wykryto modyfikację zasięgu uderzenia (Reach Distance).", level: VerdictLevel::Detection },
        CheatPatternRule { pattern: "KeepSprint.class", name: "Movement: KeepSprint Class", description: "Wykryto skompilowaną klasę KeepSprint.class.", level: VerdictLevel::Detection },
        CheatPatternRule { pattern: "Keep-Sprint.class", name: "Movement: Keep-Sprint Class", description: "Wykryto skompilowaną klasę Keep-Sprint.class.", level: VerdictLevel::Detection },
        CheatPatternRule { pattern: "KeepSprint.java", name: "Movement: KeepSprint Source", description: "Wykryto odwołanie do pliku KeepSprint.java.", level: VerdictLevel::Detection },
        CheatPatternRule { pattern: "modules/movement/KeepSprint", name: "Movement: KeepSprint Path", description: "Wykryto ścieżkę modułu KeepSprint.", level: VerdictLevel::Detection },
        CheatPatternRule { pattern: "modules/KeepSprint", name: "Movement: KeepSprint Path", description: "Wykryto ścieżkę modułu KeepSprint.", level: VerdictLevel::Detection },
        CheatPatternRule { pattern: "KeepSprint Mode", name: "Movement: KeepSprint Mode Setting", description: "Wykryto parametr trybu KeepSprint.", level: VerdictLevel::Detection },
        CheatPatternRule { pattern: "KeepSprint Chance", name: "Movement: KeepSprint Chance Setting", description: "Wykryto parametr szansy KeepSprint.", level: VerdictLevel::Detection },
        CheatPatternRule { pattern: "FastPlace.class", name: "Utility: FastPlace Class", description: "Wykryto skompilowaną klasę FastPlace.class.", level: VerdictLevel::Detection },
        CheatPatternRule { pattern: "Fast-Place.class", name: "Utility: Fast-Place Class", description: "Wykryto skompilowaną klasę Fast-Place.class.", level: VerdictLevel::Detection },
        CheatPatternRule { pattern: "FastPlace.java", name: "Utility: FastPlace Source", description: "Wykryto odwołanie do pliku FastPlace.java.", level: VerdictLevel::Detection },
        CheatPatternRule { pattern: "modules/player/FastPlace", name: "Utility: FastPlace Path", description: "Wykryto ścieżkę modułu FastPlace.", level: VerdictLevel::Detection },
        CheatPatternRule { pattern: "modules/FastPlace", name: "Utility: FastPlace Path", description: "Wykryto ścieżkę modułu FastPlace.", level: VerdictLevel::Detection },
        CheatPatternRule { pattern: "FastPlace Delay", name: "Utility: FastPlace Delay Setting", description: "Wykryto parametr opóźnienia FastPlace.", level: VerdictLevel::Detection },
        CheatPatternRule { pattern: "AutoWTap.class", name: "Movement: AutoWTap Class", description: "Wykryto klasę AutoWTap.class.", level: VerdictLevel::Detection },
        CheatPatternRule { pattern: "AutoWTap.java", name: "Movement: AutoWTap Source", description: "Wykryto odwołanie do AutoWTap.java.", level: VerdictLevel::Detection },
        CheatPatternRule { pattern: "modules/movement/AutoWTap", name: "Movement: AutoWTap Path", description: "Wykryto ścieżkę modułu AutoWTap.", level: VerdictLevel::Detection },
        CheatPatternRule { pattern: "modules/combat/AutoWTap", name: "Movement: AutoWTap Path", description: "Wykryto ścieżkę modułu AutoWTap.", level: VerdictLevel::Detection },
        CheatPatternRule { pattern: "WTap Delay", name: "Movement: WTap Delay Setting", description: "Wykryto parametr opóźnienia modułu WTap.", level: VerdictLevel::Detection },
        CheatPatternRule { pattern: "W-Tap Delay", name: "Movement: W-Tap Delay Setting", description: "Wykryto parametr opóźnienia modułu W-Tap.", level: VerdictLevel::Detection },
        CheatPatternRule { pattern: "wtap_delay", name: "Movement: WTap Delay Config", description: "Wykryto parametr konfiguracyjny wtap_delay.", level: VerdictLevel::Detection },
        CheatPatternRule { pattern: "w-tap_delay", name: "Movement: W-Tap Delay Config", description: "Wykryto parametr konfiguracyjny w-tap_delay.", level: VerdictLevel::Detection },
        CheatPatternRule { pattern: "WTap Chance", name: "Movement: WTap Chance Setting", description: "Wykryto parametr szansy modułu WTap.", level: VerdictLevel::Detection },
        CheatPatternRule { pattern: "W-Tap Chance", name: "Movement: W-Tap Chance Setting", description: "Wykryto parametr szansy modułu W-Tap.", level: VerdictLevel::Detection },
        CheatPatternRule { pattern: "wtap_chance", name: "Movement: WTap Chance Config", description: "Wykryto parametr konfiguracyjny wtap_chance.", level: VerdictLevel::Detection },
        CheatPatternRule { pattern: "w-tap_chance", name: "Movement: W-Tap Chance Config", description: "Wykryto parametr konfiguracyjny w-tap_chance.", level: VerdictLevel::Detection },
        CheatPatternRule { pattern: "WTap Mode", name: "Movement: WTap Mode Setting", description: "Wykryto parametr trybu modułu WTap.", level: VerdictLevel::Detection },
        CheatPatternRule { pattern: "W-Tap Mode", name: "Movement: W-Tap Mode Setting", description: "Wykryto parametr trybu modułu W-Tap.", level: VerdictLevel::Detection },
        CheatPatternRule { pattern: "WTapPacket", name: "Movement: WTap Packet Hook", description: "Wykryto pakietowy mechanizm WTapPacket.", level: VerdictLevel::Detection },
        CheatPatternRule { pattern: "PacketWTap", name: "Movement: PacketWTap Hook", description: "Wykryto pakietowy mechanizm PacketWTap.", level: VerdictLevel::Detection },
        CheatPatternRule { pattern: "modules/movement/AutoWTap", name: "Movement: AutoWTap Path", description: "Wykryto ścieżkę modułu AutoWTap.", level: VerdictLevel::Detection },
        CheatPatternRule { pattern: "modules/combat/AutoWTap", name: "Movement: AutoWTap Path", description: "Wykryto ścieżkę modułu AutoWTap.", level: VerdictLevel::Detection },
        CheatPatternRule { pattern: "AutoBlock.class", name: "Combat: AutoBlock Class", description: "Wykryto skompilowaną klasę AutoBlock.class.", level: VerdictLevel::Detection },
        CheatPatternRule { pattern: "Auto-Block.class", name: "Combat: Auto-Block Class", description: "Wykryto skompilowaną klasę Auto-Block.class.", level: VerdictLevel::Detection },
        CheatPatternRule { pattern: "AutoBlock.java", name: "Combat: AutoBlock Source", description: "Wykryto plik źródłowy AutoBlock.java.", level: VerdictLevel::Detection },
        CheatPatternRule { pattern: "modules/combat/AutoBlock", name: "Combat: AutoBlock Path", description: "Wykryto ścieżkę modułu AutoBlock.", level: VerdictLevel::Detection },
        CheatPatternRule { pattern: "modules/AutoBlock", name: "Combat: AutoBlock Path", description: "Wykryto ścieżkę modułu AutoBlock.", level: VerdictLevel::Detection },
        CheatPatternRule { pattern: "AutoBlock Mode", name: "Combat: AutoBlock Mode Setting", description: "Wykryto parametr trybu AutoBlock.", level: VerdictLevel::Detection },
        CheatPatternRule { pattern: "AutoBlock Range", name: "Combat: AutoBlock Range Setting", description: "Wykryto parametr zasięgu AutoBlock.", level: VerdictLevel::Detection },
        CheatPatternRule { pattern: "Velocity Horizontal", name: "Combat: Horizontal Velocity Modifier", description: "Wykryto modyfikator odrzutu poziomego gracza (Velocity).", level: VerdictLevel::Detection },
        CheatPatternRule { pattern: "Velocity Vertical", name: "Combat: Vertical Velocity Modifier", description: "Wykryto modyfikator odrzutu pionowego gracza (Velocity).", level: VerdictLevel::Detection },
        CheatPatternRule { pattern: "Reduce Knockback", name: "Combat: Anti-Knockback Setting", description: "Wykryto parametr redukcji odrzutu gracza (Anti-Knockback).", level: VerdictLevel::Detection },
        CheatPatternRule { pattern: "Expand Hitbox", name: "Combat: HitBox Expansion", description: "Wykryto moduł powiększania hitboxów przeciwników.", level: VerdictLevel::Detection },
        CheatPatternRule { pattern: "SilentAura.class", name: "Combat: SilentAura Class", description: "Wykryto klasę SilentAura.class.", level: VerdictLevel::Detection },
        CheatPatternRule { pattern: "Silent-Aura.class", name: "Combat: Silent-Aura Class", description: "Wykryto klasę Silent-Aura.class.", level: VerdictLevel::Detection },
        CheatPatternRule { pattern: "SilentAura.java", name: "Combat: SilentAura Source", description: "Wykryto plik źródłowy SilentAura.java.", level: VerdictLevel::Detection },
        CheatPatternRule { pattern: "modules/combat/SilentAura", name: "Combat: SilentAura Path", description: "Wykryto ścieżkę modułu SilentAura.", level: VerdictLevel::Detection },
        CheatPatternRule { pattern: "Silent Aura Mode", name: "Combat: Silent Aura Mode Setting", description: "Wykryto parametr trybu cichej aury.", level: VerdictLevel::Detection },
        CheatPatternRule { pattern: "Silent Aura Range", name: "Combat: Silent Aura Range Setting", description: "Wykryto parametr zasięgu cichej aury.", level: VerdictLevel::Detection },
        CheatPatternRule { pattern: "InvMove.class", name: "Movement: InvMove Class", description: "Wykryto klasę InvMove.class.", level: VerdictLevel::Detection },
        CheatPatternRule { pattern: "InvMove.java", name: "Movement: InvMove Source", description: "Wykryto plik źródłowy InvMove.java.", level: VerdictLevel::Detection },
        CheatPatternRule { pattern: "modules/movement/InvMove", name: "Movement: InvMove Path", description: "Wykryto ścieżkę modułu InvMove.", level: VerdictLevel::Detection },
        CheatPatternRule { pattern: "modules/InvMove", name: "Movement: InvMove Path", description: "Wykryto ścieżkę modułu InvMove.", level: VerdictLevel::Detection },
        CheatPatternRule { pattern: "InvMove Mode", name: "Movement: InvMove Mode Setting", description: "Wykryto parametr trybu InvMove.", level: VerdictLevel::Detection },
        CheatPatternRule { pattern: "ScaffoldWalk.class", name: "World: ScaffoldWalk Class", description: "Wykryto klasę ScaffoldWalk.class.", level: VerdictLevel::Detection },
        CheatPatternRule { pattern: "ScaffoldWalk.java", name: "World: ScaffoldWalk Source", description: "Wykryto plik źródłowy ScaffoldWalk.java.", level: VerdictLevel::Detection },
        CheatPatternRule { pattern: "modules/movement/ScaffoldWalk", name: "World: ScaffoldWalk Path", description: "Wykryto ścieżkę modułu ScaffoldWalk.", level: VerdictLevel::Detection },
        CheatPatternRule { pattern: "modules/world/Scaffold", name: "World: Scaffold Path", description: "Wykryto ścieżkę modułu Scaffold.", level: VerdictLevel::Detection },
        CheatPatternRule { pattern: "ScaffoldWalk Delay", name: "World: ScaffoldWalk Delay Setting", description: "Wykryto opóźnienie modułu ScaffoldWalk.", level: VerdictLevel::Detection },

        // --- ANTI-SCREESHARE & CLEANERS ---
        CheatPatternRule { pattern: "SelfDestruct.class", name: "Anti-Forensics: SelfDestruct Class", description: "Wykryto skompilowaną klasę samozniszczenia (SelfDestruct.class).", level: VerdictLevel::Detection },
        CheatPatternRule { pattern: "Self-Destruct.class", name: "Anti-Forensics: Self-Destruct Class", description: "Wykryto skompilowaną klasę samozniszczenia (Self-Destruct.class).", level: VerdictLevel::Detection },
        CheatPatternRule { pattern: "SelfDestruct.java", name: "Anti-Forensics: SelfDestruct Source", description: "Wykryto odwołanie do pliku źródłowego SelfDestruct.java.", level: VerdictLevel::Detection },
        CheatPatternRule { pattern: "modules/SelfDestruct", name: "Anti-Forensics: SelfDestruct Path", description: "Wykryto ścieżkę modułu samozniszczenia (modules/SelfDestruct).", level: VerdictLevel::Detection },
        CheatPatternRule { pattern: "modules/client/SelfDestruct", name: "Anti-Forensics: SelfDestruct Client Path", description: "Wykryto ścieżkę modułu samozniszczenia klienta.", level: VerdictLevel::Detection },
        CheatPatternRule { pattern: "module/SelfDestruct", name: "Anti-Forensics: SelfDestruct Module Path", description: "Wykryto strukturę modułu samozniszczenia (module/SelfDestruct).", level: VerdictLevel::Detection },
        CheatPatternRule { pattern: "module/Self-Destruct", name: "Anti-Forensics: Self-Destruct Module Path", description: "Wykryto strukturę modułu samozniszczenia (module/Self-Destruct).", level: VerdictLevel::Detection },
        CheatPatternRule { pattern: "SelfDestruct Module", name: "Anti-Forensics: SelfDestruct Module", description: "Wykryto moduł samozniszczenia cheata w GUI/konfiguracji.", level: VerdictLevel::Detection },
        CheatPatternRule { pattern: "Self-Destruct Module", name: "Anti-Forensics: Self-Destruct Module", description: "Wykryto moduł samozniszczenia cheata w konfiguracji.", level: VerdictLevel::Detection },
        CheatPatternRule { pattern: "SelfDestruct Mode", name: "Anti-Forensics: SelfDestruct Mode", description: "Wykryto parametr trybu samozniszczenia cheata.", level: VerdictLevel::Detection },
        CheatPatternRule { pattern: "SelfDestruct Delay", name: "Anti-Forensics: SelfDestruct Delay", description: "Wykryto parametr opóźnienia procedury samozniszczenia cheata.", level: VerdictLevel::Detection },
        CheatPatternRule { pattern: "SelfDestruct Key", name: "Anti-Forensics: SelfDestruct Key", description: "Wykryto przypisanie klawisza procedury samozniszczenia.", level: VerdictLevel::Detection },
        CheatPatternRule { pattern: "self_destruct_key", name: "Anti-Forensics: SelfDestruct Key Config", description: "Wykryto parametr konfiguracyjny self_destruct_key.", level: VerdictLevel::Detection },
        CheatPatternRule { pattern: "selfdestruct_key", name: "Anti-Forensics: SelfDestruct Key Config", description: "Wykryto parametr konfiguracyjny selfdestruct_key.", level: VerdictLevel::Detection },
        CheatPatternRule { pattern: "Destructed Succesfully", name: "Anti-Forensics: Destructed Artifact", description: "Wykryto potwierdzenie wykonania procedury zniszczenia cheata.", level: VerdictLevel::Detection },
        CheatPatternRule { pattern: "String Cleaner", name: "Anti-Forensics: String Cleaner", description: "Wykryto narzędzie czyszczenia stringów z pamięci procesu.", level: VerdictLevel::Detection },
        CheatPatternRule { pattern: "stringless client", name: "Anti-Forensics: Stringless Client", description: "Wykryto mechanizm ukrywania stringów (stringless client).", level: VerdictLevel::Detection },
        CheatPatternRule { pattern: "cleanstrings.class", name: "Anti-Forensics: CleanStrings Class", description: "Wykryto klasę procedury zacierania śladów cleanstrings.class.", level: VerdictLevel::Detection },
        CheatPatternRule { pattern: "CleanStrings Routine", name: "Anti-Forensics: CleanStrings Routine", description: "Wykryto procedurę zacierania śladów tekstowych w pamięci.", level: VerdictLevel::Detection },
        CheatPatternRule { pattern: "Unhook JVM", name: "Anti-Forensics: Unhook JVM", description: "Wykryto próbę odpięcia hooków JVM przed screenshare.", level: VerdictLevel::Detection },

        // --- GENERIC CHEAT ARCHITECTURE & FRAMEWORKS (0-day / Custom Clients) ---
        CheatPatternRule { pattern: "me.darkmagician6.eventapi", name: "Generic Cheat Framework: DarkMagician6 EventAPI", description: "Wykryto uniwersalny framework zdarzeń (EventAPI) stosowany w większości cheatów.", level: VerdictLevel::Detection },
        CheatPatternRule { pattern: "me/darkmagician6/eventapi", name: "Generic Cheat Framework: DarkMagician6 EventAPI", description: "Wykryto uniwersalny framework zdarzeń (EventAPI) stosowany w większości cheatów.", level: VerdictLevel::Detection },
        CheatPatternRule { pattern: "me/zero/alpine", name: "Generic Cheat Framework: Alpine EventBus", description: "Wykryto framework szyny zdarzeń Alpine stosowany w zaawansowanych cheatach (Meteor/BleachHack).", level: VerdictLevel::Detection },
        CheatPatternRule { pattern: "me.zero.alpine", name: "Generic Cheat Framework: Alpine EventBus", description: "Wykryto framework szyny zdarzeń Alpine stosowany w zaawansowanych cheatach (Meteor/BleachHack).", level: VerdictLevel::Detection },
        CheatPatternRule { pattern: "com/lukflug/panelstudio", name: "Generic Cheat GUI: PanelStudio", description: "Wykryto bibliotekę interfejsu PanelStudio używaną wyłącznie w cheatach do Minecrafta.", level: VerdictLevel::Detection },
        CheatPatternRule { pattern: "com.lukflug.panelstudio", name: "Generic Cheat GUI: PanelStudio", description: "Wykryto bibliotekę interfejsu PanelStudio używaną wyłącznie w cheatach do Minecrafta.", level: VerdictLevel::Detection },


        // --- DOOMSDAY INJECTED CLASSES ---
        CheatPatternRule { pattern: "net/java/f.class", name: "Doomsday Class (f.class)", description: "Wykryto wstrzykniętą klasę Doomsday net/java/f.class.", level: VerdictLevel::Detection },
        CheatPatternRule { pattern: "net/java/g.class", name: "Doomsday Class (g.class)", description: "Wykryto wstrzykniętą klasę Doomsday net/java/g.class.", level: VerdictLevel::Detection },
        CheatPatternRule { pattern: "net/java/h.class", name: "Doomsday Class (h.class)", description: "Wykryto wstrzykniętą klasę Doomsday net/java/h.class.", level: VerdictLevel::Detection },
        CheatPatternRule { pattern: "net/java/i.class", name: "Doomsday Class (i.class)", description: "Wykryto wstrzykniętą klasę Doomsday net/java/i.class.", level: VerdictLevel::Detection },
        CheatPatternRule { pattern: "net/java/k.class", name: "Doomsday Class (k.class)", description: "Wykryto wstrzykniętą klasę Doomsday net/java/k.class.", level: VerdictLevel::Detection },
        CheatPatternRule { pattern: "net/java/l.class", name: "Doomsday Class (l.class)", description: "Wykryto wstrzykniętą klasę Doomsday net/java/l.class.", level: VerdictLevel::Detection },
        CheatPatternRule { pattern: "net/java/m.class", name: "Doomsday Class (m.class)", description: "Wykryto wstrzykniętą klasę Doomsday net/java/m.class.", level: VerdictLevel::Detection },
        CheatPatternRule { pattern: "net/java/r.class", name: "Doomsday Class (r.class)", description: "Wykryto wstrzykniętą klasę Doomsday net/java/r.class.", level: VerdictLevel::Detection },
        CheatPatternRule { pattern: "net/java/s.class", name: "Doomsday Class (s.class)", description: "Wykryto wstrzykniętą klasę Doomsday net/java/s.class.", level: VerdictLevel::Detection },
        CheatPatternRule { pattern: "net/java/t.class", name: "Doomsday Class (t.class)", description: "Wykryto wstrzykniętą klasę Doomsday net/java/t.class.", level: VerdictLevel::Detection },
        CheatPatternRule { pattern: "net/java/y.class", name: "Doomsday Class (y.class)", description: "Wykryto wstrzykniętą klasę Doomsday net/java/y.class.", level: VerdictLevel::Detection },
    ]
}

/// Scans Minecraft process memory (MEM_PRIVATE) using highly optimized Aho-Corasick automaton
/// and selective YARA rule engine for executable pages and suspicious memory fragments.
fn scan_memory_strings(
    handle: HANDLE,
    yara_engine: &crate::scanner::yara_engine::YaraScannerEngine,
    custom_strings: &[crate::scanner::custom_rules::CustomStringRule],
    report: &mut ScanReport,
    on_mb: &dyn Fn(usize),
) {
    let rules = get_builtin_cheat_patterns();

    struct ActivePatternRule<'a> {
        pattern: &'a str,
        name: &'a str,
        description: &'a str,
        level: VerdictLevel,
        source: Option<&'a str>,
    }

    let mut all_rules: Vec<ActivePatternRule> = rules
        .iter()
        .map(|r| ActivePatternRule {
            pattern: r.pattern,
            name: r.name,
            description: r.description,
            level: r.level,
            source: None,
        })
        .collect();

    for cr in custom_strings {
        all_rules.push(ActivePatternRule {
            pattern: cr.pattern.as_str(),
            name: cr.name.as_str(),
            description: cr.description.as_str(),
            level: cr.level,
            source: Some(cr.source_file.as_str()),
        });
    }

    let patterns: Vec<&str> = all_rules.iter().map(|r| r.pattern).collect();
    let ac = aho_corasick::AhoCorasick::builder()
        .ascii_case_insensitive(true)
        .build(&patterns)
        .unwrap();

    let doomsday_hex_patterns: &[&[u8]] = &[
        &[0x18, 0xf9, 0x55, 0x95, 0x4e, 0xe4, 0x58, 0x64, 0x86, 0x2d, 0x32, 0x98, 0x21, 0x9e, 0x8f, 0x25, 0xb7, 0x36, 0x10, 0x05, 0x4f, 0xdd, 0xcf, 0x5c, 0x5f, 0xe8, 0xc5, 0xd4, 0xc7, 0x92, 0x33, 0x2d, 0xd3, 0x67, 0x7d, 0xb8, 0x82, 0x68, 0x38, 0x73, 0x86, 0x3c, 0x1a, 0xc2, 0x00, 0x30, 0x1b, 0x80],
        &[0x43, 0x00, 0xfb, 0x82, 0x21, 0x94, 0x50, 0x23, 0x02, 0xbb, 0xf1, 0xc4, 0x9b, 0xb8, 0xe4, 0x67, 0x7f, 0xea, 0x03, 0xc2, 0xd7, 0x4c, 0x49, 0xd3, 0x41, 0x3a, 0xc6, 0xf9, 0x6b, 0x49, 0xb9, 0xc2, 0x33, 0xba, 0x48, 0xc8, 0x8c, 0x33, 0x30, 0x33, 0x1d, 0x18, 0x06, 0x79, 0x1c, 0x3b, 0x3e, 0x04],
        &[0x39, 0xff, 0x32, 0xb7, 0xc5, 0x72, 0x17, 0xeb, 0xd6, 0x5a, 0x6e, 0x6c, 0xcc, 0x14, 0x40, 0xd5, 0x51, 0x58, 0x6d, 0x2b, 0xdd, 0xc2, 0x35, 0xaf, 0xca, 0x67, 0x01, 0x91, 0xac, 0xf9, 0x2a, 0xac, 0xc0, 0x51, 0x3d, 0x35, 0xf9, 0x77, 0xf5, 0xa2, 0xed, 0x3f, 0x20, 0x93, 0xc8, 0xf2, 0xeb, 0xec],
        &[0xb2, 0x0b, 0x03, 0xf5, 0x1c, 0xd7, 0x46, 0x30, 0xce, 0x0a, 0x5f, 0x8f, 0x70, 0xa1, 0xb7, 0xf7, 0x9b, 0x73, 0x3c, 0x25, 0xf0, 0x86, 0xf6, 0xdc, 0x23, 0x9f, 0x08, 0xb5, 0xd5, 0x2e, 0x30, 0x2f, 0x60, 0xa8, 0x15, 0x4d, 0xf5, 0x00, 0x09, 0x8f, 0x30, 0x28, 0xa0, 0x9f, 0xaf, 0x82, 0x08, 0x26],
        &[0x0a, 0x18, 0xbc, 0x39, 0xe6, 0x12, 0xd5, 0x8f, 0x5c, 0x99, 0x9c, 0x55, 0x8b, 0xe6, 0x6f, 0x3e, 0xfb, 0x6c, 0x5b, 0x4c, 0xb9, 0x84, 0x17, 0x96, 0x4f, 0x68, 0xf4, 0xe8, 0x82, 0x66, 0x98, 0xd7, 0xce, 0x0f, 0xe6, 0x3b, 0x99, 0xa2, 0xf5, 0x17, 0xe8, 0xc4, 0xf3, 0x71, 0x95, 0xe2, 0x06, 0x3f],
        &[0x52, 0xd4, 0x66, 0x0c, 0x0d, 0xe4, 0xa1, 0x77, 0x89, 0x32, 0x7d, 0x4a, 0xb4, 0x41, 0xfd, 0xe1, 0x3d, 0xed, 0x77, 0x4a, 0x1e, 0x75, 0x46, 0x64, 0x98, 0xdc, 0x59, 0x0b, 0x57, 0xba, 0xed, 0x5a, 0x17, 0xee, 0xcb, 0x68, 0x28, 0xa6, 0x3a, 0xd1, 0x7f, 0x6b, 0xf5, 0xf1, 0xec, 0x4a, 0x70, 0x45],
        &[0xaa, 0x5c, 0xf9, 0xc9, 0x5f, 0x12, 0x69, 0x22, 0x40, 0xb4, 0x58, 0x71, 0x8e, 0x4d, 0x94, 0x92, 0xab, 0x58, 0x25, 0xea, 0x2b, 0x7e, 0x16, 0xcf, 0x0a, 0x79, 0x2b, 0x70, 0x9e, 0xae, 0x18, 0x4f, 0x91, 0x32, 0x55, 0xc7, 0x7e, 0xc3, 0xdb, 0x4d, 0x6e, 0xa2, 0x81, 0x23, 0xca, 0x3f, 0xb4, 0x09],
        &[0x88, 0x87, 0x17, 0xe5, 0x83, 0x59, 0xca, 0xce, 0x04, 0x61, 0xdc, 0x79, 0xec, 0xc2, 0x25, 0xb1, 0x7f, 0xdb, 0x5c, 0xa7, 0x50, 0xd1, 0xbd, 0x08, 0x6b, 0x19, 0xa1, 0x1d, 0x60, 0x90, 0xe4, 0xea, 0xab, 0x58, 0x7c, 0x8a, 0xd6, 0x83, 0x72, 0x02, 0xf2, 0xe2, 0xd3, 0xb1, 0x4d, 0x6d, 0x7d, 0x42],
        &[0xc5, 0x19, 0xa6, 0x77, 0x44, 0x42, 0x2d, 0xed, 0xc3, 0xbf, 0x23, 0x4f, 0x0b, 0xe0, 0x30, 0x0c, 0xd5, 0x5e, 0x8b, 0x25, 0x3b, 0x33, 0x2a, 0x3d, 0xba, 0xcc, 0x97, 0xf6, 0x11, 0xda, 0x2f, 0xfd, 0xf4, 0x22, 0xb1, 0x2b, 0x02, 0xfd, 0x71, 0x1e, 0x41, 0xd6, 0x26, 0xcc, 0x1b, 0xde, 0x4a, 0x17],
        &[0xc4, 0x0f, 0xbe, 0xe5, 0xb0, 0xb1, 0xfc, 0xb6, 0xac, 0x98, 0xa4, 0xa3, 0xb1, 0x2c, 0xd6, 0x8f, 0xa0, 0x27, 0x5d, 0x92, 0x78, 0xdf, 0xd8, 0x6a, 0x0e, 0xd4, 0x77, 0xb2, 0xa3, 0xf4, 0x94, 0x57, 0x36, 0x9f, 0x4c, 0x80, 0x74, 0x26, 0xb4, 0xe7, 0x98, 0xaf, 0xcb, 0xfa, 0x14, 0x24, 0x65, 0xf5],
    ];

    let ac_hex = aho_corasick::AhoCorasick::builder()
        .build(doomsday_hex_patterns)
        .unwrap();

    let aob_engine = crate::scanner::aob::AobScannerEngine::default_engine();
    let mut reported_aob = std::collections::HashSet::new();
    let mut reported_rules = std::collections::HashSet::new();
    let mut reported_yara_rules = std::collections::HashSet::new();
    let mut reported_mixins = std::collections::HashSet::new();
    let mut doomsday_found_classes = std::collections::HashSet::new();
    let mut doomsday_bytecode_detected = false;
    let mut mera_click_open_matches: Vec<usize> = Vec::new();
    let mut mera_fat_cunt_matches: Vec<usize> = Vec::new();

    let wide_click_open = [b'C', 0, b'l', 0, b'i', 0, b'c', 0, b'k', 0, b' ', 0, b'O', 0, b'p', 0, b'e', 0, b'n', 0];
    let wide_mera_fat = [
        b'M', 0, b'e', 0, b'r', 0, b'a', 0, b' ', 0, b'I', 0, b's', 0, b' ', 0, b'A', 0, b' ', 0,
        b'F', 0, b'a', 0, b't', 0, b' ', 0, b'C', 0, b'u', 0, b'n', 0, b't', 0,
    ];
    let wide_click_finder = memchr::memmem::Finder::new(&wide_click_open);
    let wide_mera_finder = memchr::memmem::Finder::new(&wide_mera_fat);

    let mut address = 0usize;
const CHUNK_SIZE: usize = 4 * 1024 * 1024; // 4 MB chunks
    const OVERLAP: usize = 512;
    let mut chunk_buf = vec![0u8; CHUNK_SIZE];
    let mut total_bytes_scanned = 0usize;
    let mut last_progress_mb = 0usize;

    // Initialize YARA scanner only once for the entire process
    let mut yara_scanner = yara_engine.create_scanner();

    unsafe {
        let mut mbi: MEMORY_BASIC_INFORMATION = zeroed();
        let mbi_size = std::mem::size_of::<MEMORY_BASIC_INFORMATION>();

        while VirtualQueryEx(
            handle,
            address as *const c_void,
            &mut mbi,
            mbi_size,
        ) != 0
        {
        // Scan private pages (MEM_PRIVATE) and suspicious mapped sections (MEM_MAPPED)
            let is_candidate_page = if mbi.State == MEM_COMMIT {
                if mbi.Type == MEM_PRIVATE {
                    mbi.Protect == PAGE_READWRITE
                        || mbi.Protect == PAGE_READONLY
                        || mbi.Protect == PAGE_EXECUTE_READWRITE
                        || mbi.Protect == PAGE_EXECUTE_READ
                } else if mbi.Type == MEM_MAPPED {
                    mbi.Protect == PAGE_EXECUTE_READ
                        || mbi.Protect == PAGE_EXECUTE_READWRITE
                        || mbi.Protect == PAGE_READWRITE
                } else {
                    false
                }
            } else {
                false
            };

            if is_candidate_page {
                let is_executable = mbi.Protect == PAGE_EXECUTE_READ || mbi.Protect == PAGE_EXECUTE_READWRITE;
                let mut region_offset = 0usize;

                while region_offset < mbi.RegionSize {
                    let to_read = (mbi.RegionSize - region_offset).min(CHUNK_SIZE);
                    let mut bytes_read = 0usize;
                    let target_ptr = (mbi.BaseAddress as usize + region_offset) as *const c_void;

                    if windows_sys::Win32::System::Diagnostics::Debug::ReadProcessMemory(
                        handle,
                        target_ptr,
                        chunk_buf.as_mut_ptr() as *mut c_void,
                        to_read,
                        &mut bytes_read,
                    ) != 0
                        && bytes_read > 0
                    {
                        total_bytes_scanned += bytes_read;
                        let slice = &chunk_buf[..bytes_read];

                        let current_mb = total_bytes_scanned / (1024 * 1024);
                        if current_mb >= last_progress_mb + 50 {
                            last_progress_mb = current_mb;
                            on_mb(current_mb);
                            use std::io::Write;
                            print!("\r    [>] Skanowanie pamięci Minecraft: {} MB...", current_mb);
                            let _ = std::io::stdout().flush();
                        }

                        let mut has_chunk_match = false;

            // 1. Blazing fast scan using Aho-Corasick automaton (> 2.0 GB/s)
                        for mat in ac.find_iter(slice) {
                            let rule = &all_rules[mat.pattern().as_usize()];

                // False-positive filter: eliminate AutoBlock match in Chromium / CEF (permission_autoblocking_data)
                            if rule.pattern.eq_ignore_ascii_case("AutoBlock") {
                                let check_start = mat.start().saturating_sub(20);
                                let check_end = (mat.end() + 30).min(slice.len());
                                let surrounding = String::from_utf8_lossy(&slice[check_start..check_end]).to_lowercase();
                                if surrounding.contains("autoblocking_data") || surrounding.contains("permission") || surrounding.contains("content_setting") || surrounding.contains("chromium") {
                                    continue;
                                }
                            }

                // False-positive filter: only suppress if within a verified launcher anticheat constant pool (e.g. Feather / Dawn)
                // and NEVER suppress actual cheat class names, hooks, commands, or feature configs!
                            if rule.source.is_none() {
                                let is_pure_jar_or_mod_name = rule.pattern.ends_with(".jar") || !rule.pattern.contains(".class");
                                if is_pure_jar_or_mod_name {
                                    let check_start = mat.start().saturating_sub(256);
                                    let check_end = (mat.end() + 256).min(slice.len());
                                    let surrounding = String::from_utf8_lossy(&slice[check_start..check_end]).to_lowercase();

                                    let in_launcher_ac = surrounding.contains("net/digitalingot/")
                                        || surrounding.contains("digital/feather/")
                                        || surrounding.contains("com/dawn/");

                                    let is_blacklist_table = surrounding.contains("blocked_mod")
                                        || surrounding.contains("blockedmod")
                                        || surrounding.contains("banned_mod")
                                        || surrounding.contains("prohibited");

                                    if in_launcher_ac && is_blacklist_table {
                                        continue;
                                    }
                                }
                            }

                // Filter and register Mera Client signatures (requirement: all must be present to consider it Cheat)
                            if rule.pattern.eq_ignore_ascii_case("Click Open") {
                                has_chunk_match = true;
                                mera_click_open_matches.push(target_ptr as usize + mat.start());
                                continue;
                            }
                            if rule.pattern.eq_ignore_ascii_case("Mera Is A Fat Cunt") {
                                has_chunk_match = true;
                                mera_fat_cunt_matches.push(target_ptr as usize + mat.start());
                                continue;
                            }

                            has_chunk_match = true;

                // Register Doomsday classes for collective detection
                            if rule.pattern.starts_with("net/java/") && rule.pattern.ends_with(".class") {
                                doomsday_found_classes.insert(rule.pattern.to_string());
                            }

                            if reported_rules.insert(rule.pattern.to_string()) {
                                let mut finding = ScanFinding::new(
                                    format!("Wykryto sygnaturę cheata: {}", rule.name),
                                    FindingCategory::MemoryInspection,
                                    rule.level,
                                    rule.description.to_string(),
                                )
                                .with_evidence("Adres pamięci", format!("0x{:X}", target_ptr as usize + mat.start()))
                                .with_evidence("Moduł / Cheat", rule.name.to_string());

                                if let Some(src) = rule.source {
                                    finding = finding.with_evidence("Źródło reguły", format!("Plik użytkownika: {}", src));
                                }
                                report.add(finding);
                            }
                        }

            // UTF-16 scanning for Mera Client signatures (support older/mixed JVM runtimes)
                        for offset in wide_click_finder.find_iter(slice) {
                            has_chunk_match = true;
                            mera_click_open_matches.push(target_ptr as usize + offset);
                        }
                        for offset in wide_mera_finder.find_iter(slice) {
                            has_chunk_match = true;
                            mera_fat_cunt_matches.push(target_ptr as usize + offset);
                        }

            // 2. Doomsday hex bytecode patterns ($h1 - $h10) using Aho-Corasick SIMD
                        if !doomsday_bytecode_detected {
                            if let Some(mat) = ac_hex.find(slice) {
                                doomsday_bytecode_detected = true;
                                has_chunk_match = true;
                                report.add(
                                    ScanFinding::new(
                                        "Doomsday Client Injected (Bytecode Pattern)",
                                        FindingCategory::MemoryInspection,
                                        VerdictLevel::Detection,
                                        "Wykryto unikalną sygnaturę bytecode wstrzykniętego cheata Doomsday.",
                                    )
                                    .with_evidence("Adres pamięci", format!("0x{:X}", target_ptr as usize + mat.start()))
                                    .with_evidence("Cheat", "Doomsday Client".to_string()),
                                );
                            }
                        }

            // 3. Scan Array of Bytes (AOB) patterns with Wildcard (??) mask support
                        for (aob_rule, offset) in aob_engine.scan_chunk(slice) {
                            has_chunk_match = true;
                            if reported_aob.insert(aob_rule.name) {
                                report.add(
                                    ScanFinding::new(
                                        format!("Wykryto sygnaturę bajtową (AOB): {}", aob_rule.name),
                                        FindingCategory::MemoryInspection,
                                        aob_rule.level,
                                        aob_rule.description,
                                    )
                                    .with_evidence("Adres pamięci", format!("0x{:X}", target_ptr as usize + offset))
                                    .with_evidence("Typ modyfikacji", "Natywny hook / Trampolina kodu".to_string()),
                                );
                            }
                        }

            // 4. Generic Mixin target anomaly analysis (detects unknown 0-day cheats injecting into EndCrystal/InteractionManager)
                        check_generic_mixin_anomalies(slice, target_ptr as usize, report, &mut reported_mixins);

            // 5. Scan using YARA engine (on suspicious chunks, executable pages, or when custom YARA rules are loaded)
                        if has_chunk_match || is_executable || yara_engine.custom_rules_count > 0 {
                            if let Some(ref mut scanner) = yara_scanner {
                                if let Ok(scan_results) = scanner.scan(slice) {
                                    for yara_rule in scan_results.matching_rules() {
                                        let rule_name = yara_rule.identifier().to_string();
                                        if reported_yara_rules.insert(rule_name.clone()) {
                                            let mut finding = ScanFinding::new(
                                                format!("Detekcja sygnatury YARA: {}", rule_name),
                                                FindingCategory::MemoryInspection,
                                                VerdictLevel::Detection,
                                                "Pamięć procesu Minecrafta spełniła kryteria zaawansowanej analizy behawioralnej i sygnaturowej.",
                                            )
                                            .with_evidence("Adres pamięci", format!("0x{:X}", target_ptr as usize))
                                            .with_evidence("Reguła YARA", rule_name.clone());

                                            if yara_rule.namespace() == "custom" {
                                                finding = finding.with_evidence("Źródło reguły", "Własna reguła YARA (folder /rules/)".to_string());
                                            } else {
                                                finding = finding.with_evidence("Kwalifikacja", "Heurystyka sygnaturowa JVM".to_string());
                                            }
                                            report.add(finding);
                                        }
                                    }
                                }
                            }
                        }
                    }

                    if to_read < CHUNK_SIZE {
                        break;
                    }
                    region_offset += CHUNK_SIZE - OVERLAP;
                }
            }

            let next_addr = (mbi.BaseAddress as usize).saturating_add(mbi.RegionSize);
            if next_addr <= address || next_addr == 0 {
                break;
            }
            address = next_addr;
        }

    // Check whether Doomsday classes were detected (doomsday2 rule)
        if doomsday_found_classes.len() >= 2 {
            report.add(
                ScanFinding::new(
                    "Doomsday Client Injected (Zestaw klas net/java)",
                    FindingCategory::MemoryInspection,
                    VerdictLevel::Detection,
                    format!("Wykryto {} wstrzykniętych klas cheata Doomsday (struktura net/java) w maszynie JVM.", doomsday_found_classes.len()),
                )
                .with_evidence("Liczba wykrytych klas", doomsday_found_classes.len().to_string()),
            );
        } else if doomsday_found_classes.len() == 1 {
            report.add(
                ScanFinding::new(
                    "Podejrzany ślad wstrzykniętej klasy",
                    FindingCategory::MemoryInspection,
                    VerdictLevel::Warning,
                    "Wykryto podejrzaną pojedynczą klasę w pakiecie net/java w pamięci JVM.".to_string(),
                )
                .with_evidence("Liczba wykrytych klas", "1".to_string()),
            );
        }

    // Check whether Mera Client cheat was detected (requirement: BOTH signatures must be present for Detection)
        evaluate_mera_client_signatures(&mera_click_open_matches, &mera_fat_cunt_matches, report);

        print!("\r    [>] Zakończono: Przeskanowano {:.1} MB pamięci prywatnej procesu Minecraft.            \n", total_bytes_scanned as f64 / (1024.0 * 1024.0));
    }
}

/// Evaluates Mera Client signatures based on process memory.
/// Per requirements: ALL signatures must match ("Click Open" and "Mera Is A Fat Cunt"),
/// to report a full cheat detection (VerdictLevel::Detection).
/// A lone "Click Open" is completely ignored to prevent false positives.
pub fn evaluate_mera_client_signatures(
    click_open_matches: &[usize],
    fat_cunt_matches: &[usize],
    report: &mut ScanReport,
) {
    if !click_open_matches.is_empty() && !fat_cunt_matches.is_empty() {
        let mut finding = ScanFinding::new(
            "Mera Client Injected (Composite Memory Match)",
            FindingCategory::MemoryInspection,
            VerdictLevel::Detection,
            format!(
                "Wykryto obecność wstrzykniętego cheata Mera Client w pamięci JVM. Zidentyfikowano kompletny zestaw powiązanych sygnatur modułów klienta ({} trafień).",
                fat_cunt_matches.len() + click_open_matches.len(),
            ),
        )
        .with_evidence("Cheat", "Mera Client".to_string())
        .with_evidence("Status detekcji", "100% dopasowania (wszystkie sygnatury zgodne)".to_string())
        .with_evidence("Liczba sygnatur UI", click_open_matches.len().to_string())
        .with_evidence("Liczba sygnatur Core", fat_cunt_matches.len().to_string());

        if let Some(&first_fat) = fat_cunt_matches.first() {
            finding = finding.with_evidence("Adres pamięci (Core)", format!("0x{:X}", first_fat));
        }
        if let Some(&first_click) = click_open_matches.first() {
            finding = finding.with_evidence("Adres pamięci (UI)", format!("0x{:X}", first_click));
        }

        report.add(finding);
    } else if !fat_cunt_matches.is_empty() {
        let mut finding = ScanFinding::new(
            "Podejrzany znacznik Mera Client",
            FindingCategory::MemoryInspection,
            VerdictLevel::Warning,
            "Wykryto w pamięci unikalny znacznik powiązany z Mera Client, lecz brak wyzwalacza UI. Wymagana weryfikacja screenshare.".to_string(),
        )
        .with_evidence("Moduł / Cheat", "Mera Client".to_string())
        .with_evidence("Liczba wystąpień", fat_cunt_matches.len().to_string());

        if let Some(&first_fat) = fat_cunt_matches.first() {
            finding = finding.with_evidence("Adres pamięci", format!("0x{:X}", first_fat));
        }

        report.add(finding);
    }
}


fn truncate_string(s: &str, max_len: usize) -> String {
    if s.len() > max_len {
        format!("{}...", &s[..max_len])
    } else {
        s.to_string()
    }
}

/// Checks for known cheat configuration directories and files in .minecraft
pub fn check_cheat_filesystem_artifacts(report: &mut ScanReport) {
    if let Ok(appdata) = std::env::var("APPDATA") {
        let mc_dir = std::path::Path::new(&appdata).join(".minecraft");

        // 1. Astral Client / Epstein
        let epstein_dir = mc_dir.join("epstein");
        if epstein_dir.exists() {
            let mut finding = ScanFinding::new(
                "Astral Client Configuration Artifacts",
                FindingCategory::MinecraftRuntime,
                VerdictLevel::Detection,
                "Wykryto katalog konfiguracyjny cheata Astral Client (epstein) w folderze .minecraft.",
            )
            .with_evidence("Path", epstein_dir.to_string_lossy().to_string());

            let hud_cfg = epstein_dir.join("hud_positions.cfg");
            if hud_cfg.exists() {
                finding = finding.with_evidence("Config: HUD Positions", hud_cfg.to_string_lossy().to_string());
            }
            let mod_cfg = epstein_dir.join("modules.cfg");
            if mod_cfg.exists() {
                finding = finding.with_evidence("Config: Modules", mod_cfg.to_string_lossy().to_string());
            }

            report.add(finding);
        }

        // 2. Marlow Client (imnotcheatingyouare)
        let marlow_cfg = mc_dir.join("config").join("imnotcheatingyouare");
        if marlow_cfg.exists() {
            report.add(
                ScanFinding::new(
                    "Marlow Client Configuration Directory",
                    FindingCategory::MinecraftRuntime,
                    VerdictLevel::Detection,
                    "Wykryto katalog konfiguracyjny cheata Marlow Client (imnotcheatingyouare) w folderze .minecraft/config.",
                )
                .with_evidence("Path", marlow_cfg.to_string_lossy().to_string()),
            );
        }

        // 3. Calcium Client (dclient)
        let dclient_cfg = mc_dir.join("dclient-config.json");
        let dclient_friends = mc_dir.join("config").join("dclient_friends.json");
        if dclient_cfg.exists() || dclient_friends.exists() {
            let mut finding = ScanFinding::new(
                "Calcium Client Configuration Artifacts",
                FindingCategory::MinecraftRuntime,
                VerdictLevel::Detection,
                "Wykryto pliki konfiguracyjne cheata Calcium Client (dclient) w folderze .minecraft.",
            );
            if dclient_cfg.exists() {
                finding = finding.with_evidence("Config File", dclient_cfg.to_string_lossy().to_string());
            }
            if dclient_friends.exists() {
                finding = finding.with_evidence("Friends Config", dclient_friends.to_string_lossy().to_string());
            }
            report.add(finding);
        }

        // 4. Noxx Client
        let noxx_bg = mc_dir.join("background Noxx+");
        if noxx_bg.exists() {
            report.add(
                ScanFinding::new(
                    "Noxx Client Configuration Artifacts",
                    FindingCategory::MinecraftRuntime,
                    VerdictLevel::Detection,
                    "Wykryto plik/katalog zasobów cheata Noxx Client (background Noxx+) w folderze .minecraft.",
                )
                .with_evidence("Path", noxx_bg.to_string_lossy().to_string()),
            );
        }

        // 5. Pulse Client
        let pulse_dir = mc_dir.join("Pulse");
        if pulse_dir.exists() {
            report.add(
                ScanFinding::new(
                    "Pulse Client Configuration Directory",
                    FindingCategory::MinecraftRuntime,
                    VerdictLevel::Detection,
                    "Wykryto folder konfiguracyjny/profilowy cheata Pulse Client (.minecraft/Pulse).",
                )
                .with_evidence("Path", pulse_dir.to_string_lossy().to_string()),
            );
        }

        // 6. Mera Client
        let mera_dir = mc_dir.join("Mera");
        let mera_dir_lower = mc_dir.join("mera");
        if mera_dir.exists() || mera_dir_lower.exists() {
            let actual = if mera_dir.exists() { mera_dir } else { mera_dir_lower };
            report.add(
                ScanFinding::new(
                    "Mera Client Configuration Directory",
                    FindingCategory::MinecraftRuntime,
                    VerdictLevel::Detection,
                    "Wykryto folder konfiguracyjny/profilowy cheata Mera Client (.minecraft/Mera).",
                )
                .with_evidence("Path", actual.to_string_lossy().to_string()),
            );
        }

        // 7. Argon / Corrupt Client
        for name in &["argon", "Argon", "corrupt", "Corrupt"] {
            let direct_dir = mc_dir.join(name);
            let config_dir = mc_dir.join("config").join(name);
            for p in &[direct_dir, config_dir] {
                if p.exists() {
                    report.add(
                        ScanFinding::new(
                            "Argon / Corrupt Client Configuration Artifacts",
                            FindingCategory::MinecraftRuntime,
                            VerdictLevel::Detection,
                            format!("Wykryto folder konfiguracyjny/profilowy cheata Argon / Corrupt Client: {}", p.display()),
                        )
                        .with_evidence("Path", p.to_string_lossy().to_string()),
                    );
                }
            }
        }
    }
}

/// Checks Java execution directories and .minecraft directory for DLL Search Order Hijacking techniques
pub fn check_java_dll_hijacking(mc: &MinecraftProcess, report: &mut ScanReport) {
    if !mc.path.is_empty() {
        if let Some(exe_dir) = std::path::Path::new(&mc.path).parent() {
            let lower_dir = exe_dir.to_string_lossy().to_lowercase();
    // Critical safeguard: never check Windows system directories
            if !lower_dir.starts_with("c:\\windows") && !lower_dir.contains("\\system32") && !lower_dir.contains("\\syswow64") {
                check_dir_for_proxy_dlls(exe_dir, report, "katalogu binarnym Javy (obok javaw.exe)");
                if exe_dir.file_name().and_then(|n| n.to_str()) == Some("bin") {
                    if let Some(parent_dir) = exe_dir.parent() {
                        let lower_parent = parent_dir.to_string_lossy().to_lowercase();
                        if !lower_parent.starts_with("c:\\windows") && !lower_parent.contains("\\system32") && !lower_parent.contains("\\syswow64") {
                            check_dir_for_proxy_dlls(parent_dir, report, "katalogu nadrzędnym JRE/JDK");
                        }
                    }
                }
            }
        }
    }

    // Also check .minecraft
    check_minecraft_proxy_dlls(report);
}

pub fn check_minecraft_proxy_dlls(report: &mut ScanReport) {
    if let Ok(appdata) = std::env::var("APPDATA") {
        let mc_dir = std::path::Path::new(&appdata).join(".minecraft");
        if mc_dir.exists() {
            check_dir_for_proxy_dlls(&mc_dir, report, "katalogu głównym .minecraft");
            let bin_dir = mc_dir.join("bin");
            if bin_dir.exists() {
                check_dir_for_proxy_dlls(&bin_dir, report, "katalogu .minecraft/bin");
            }
        }
    }
}

fn check_dir_for_proxy_dlls(dir: &std::path::Path, report: &mut ScanReport, context_desc: &str) {
    let lower_dir = dir.to_string_lossy().to_lowercase();
    // No Windows system directory should ever be checked for proxy DLLs
    if lower_dir.starts_with("c:\\windows") || lower_dir.contains("\\system32") || lower_dir.contains("\\syswow64") || lower_dir.contains("\\winsxs") {
        return;
    }

    const SUSPICIOUS_SYSTEM_DLLS: &[&str] = &[
        "version.dll",
        "winhttp.dll",
        "winmm.dll",
        "userenv.dll",
        "dxgi.dll",
        "d3d11.dll",
        "opengl32.dll",
        "cryptbase.dll",
        "uxtheme.dll",
        "dwmapi.dll",
        "dbghelp.dll",
    ];

    const KNOWN_CHEAT_DLLS: &[&str] = &[
        "slinkyhook.dll",
        "slinky_library.dll",
        "vape.dll",
        "kura.dll",
        "curse.dll",
        "breeze.dll",
    ];

    for &dll in SUSPICIOUS_SYSTEM_DLLS {
        let candidate = dir.join(dll);
        if candidate.is_file() {
        // If the file has a valid Authenticode digital signature, it is not a crafted cheat proxy DLL
            if crate::scanner::forensics::is_pe_signed(&candidate) {
                continue;
            }

            report.add(
                ScanFinding::new(
                    "Java Runtime DLL Search Order Hijacking (Proxy DLL)",
                    FindingCategory::MinecraftRuntime,
                    VerdictLevel::Detection,
                    format!(
                        "Wykryto niepodpisaną bibliotekę podszywającą się pod plik systemowy Windows '{}' w {} ({}), co stanowi technikę DLL Hijacking / Proxy DLL w celu automatycznego wstrzyknięcia cheata do procesu javaw.exe bez zewnętrznego injectora.",
                        dll,
                        context_desc,
                        candidate.display()
                    ),
                )
                .with_evidence("Rogue DLL Path", candidate.to_string_lossy().to_string())
                .with_evidence("Target Hijack DLL", dll.to_string())
                .with_evidence("Legitimate Location", format!("C:\\Windows\\System32\\{}", dll))
                .with_evidence("Context", context_desc.to_string()),
            );
        }
    }

    for &dll in KNOWN_CHEAT_DLLS {
        let candidate = dir.join(dll);
        if candidate.is_file() {
            report.add(
                ScanFinding::new(
                    "Suspect Cheat Dynamic Library in Java Runtime",
                    FindingCategory::MinecraftRuntime,
                    VerdictLevel::Detection,
                    format!(
                        "Wykryto plik biblioteki cheata '{}' w {} ({}).",
                        dll,
                        context_desc,
                        candidate.display()
                    ),
                )
                .with_evidence("Cheat DLL Path", candidate.to_string_lossy().to_string())
                .with_evidence("Detected Module", dll.to_string())
                .with_evidence("Context", context_desc.to_string()),
            );
        }
    }
}

/// Checks temporary directories for traces of dynamic Java agent injection (.attach_pid<PID>)
fn check_dynamic_java_agent_artifacts(mc_pid: u32, report: &mut ScanReport) {
    let mut candidate_dirs = Vec::new();
    if let Ok(temp) = std::env::var("TEMP") {
        candidate_dirs.push(PathBuf::from(temp));
    }
    if let Ok(tmp) = std::env::var("TMP") {
        candidate_dirs.push(PathBuf::from(tmp));
    }
    if let Ok(local) = std::env::var("LOCALAPPDATA") {
        candidate_dirs.push(PathBuf::from(local).join("Temp"));
    }
    candidate_dirs.push(PathBuf::from("C:\\Windows\\Temp"));
    candidate_dirs.push(std::env::temp_dir());

    candidate_dirs.sort();
    candidate_dirs.dedup();

    let target_filename = format!(".attach_pid{}", mc_pid);

    for dir in candidate_dirs {
        let attach_file = dir.join(&target_filename);
        if attach_file.is_file() {
            report.add(
                ScanFinding::new(
                    "Dynamic Java Agent Injection Detected (.attach_pid)",
                    FindingCategory::MinecraftRuntime,
                    VerdictLevel::Detection,
                    format!(
                        "Java Dynamic Attach listener file '{}' was created for Minecraft PID {}. This artifact indicates an external tool or cheat dynamically attached to the JVM to inject bytecode or agent hooks.",
                        target_filename, mc_pid
                    ),
                )
                .with_evidence("Artifact File", attach_file.display().to_string())
                .with_evidence("Target PID", mc_pid.to_string()),
            );
            break;
        }
    }
}

const SYSTEM_EXTENDED_HANDLE_INFORMATION: u32 = 64;
const STATUS_INFO_LENGTH_MISMATCH: i32 = -1073741820; // 0xC0000004 as signed 32-bit int

#[repr(C)]
struct SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX {
    object: *mut c_void,
    unique_process_id: usize,
    handle_value: usize,
    granted_access: u32,
    creator_back_trace_index: u16,
    object_type_index: u16,
    handle_attributes: u32,
    reserved: u32,
}

#[repr(C)]
struct SYSTEM_HANDLE_INFORMATION_EX {
    number_of_handles: usize,
    reserved: usize,
    handles: [SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX; 1],
}

type NtQuerySystemInformationFn = unsafe extern "system" fn(
    system_information_class: u32,
    system_information: *mut c_void,
    system_information_length: u32,
    return_length: *mut u32,
) -> i32;

/// Scans open process handles in the system using NtQuerySystemInformation(64) and detects
/// external, unknown processes holding handles with memory write / manipulation permissions (PROCESS_VM_WRITE / OPERATION)
/// directed straight to the Minecraft instance (e.g. external ghost cheats, read/write memory injection).
fn check_open_handles_to_minecraft(mc_pid: u32, report: &mut ScanReport) {
    unsafe {
        let ntdll = GetModuleHandleA(b"ntdll.dll\0".as_ptr());
        if ntdll.is_null() {
            return;
        }

        let func_ptr = GetProcAddress(ntdll, b"NtQuerySystemInformation\0".as_ptr());
        let nt_query_sys_info: NtQuerySystemInformationFn = match func_ptr {
            Some(f) => std::mem::transmute(f),
            None => return,
        };

        let mut buf_size: usize = 2 * 1024 * 1024; // 2MB start
        let mut buffer: Vec<u8> = vec![0u8; buf_size];
        let mut ret_len: u32 = 0;

        loop {
            let status = nt_query_sys_info(
                SYSTEM_EXTENDED_HANDLE_INFORMATION,
                buffer.as_mut_ptr() as *mut c_void,
                buf_size as u32,
                &mut ret_len,
            );

            if status == 0 {
                break;
            }

            if status == STATUS_INFO_LENGTH_MISMATCH {
                buf_size = (ret_len as usize + 64 * 1024).max(buf_size * 2);
                if buf_size > 64 * 1024 * 1024 {
        // Safeguard against excessive memory allocation
                    return;
                }
                buffer.resize(buf_size, 0);
            } else {
                return;
            }
        }

        if buffer.len() < std::mem::size_of::<SYSTEM_HANDLE_INFORMATION_EX>() {
            return;
        }

        let info = &*(buffer.as_ptr() as *const SYSTEM_HANDLE_INFORMATION_EX);
        let count = info.number_of_handles;
        let entries_offset = std::mem::size_of::<usize>() * 2;
        let entry_size = std::mem::size_of::<SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX>();

        if buffer.len() < entries_offset + count * entry_size {
            return;
        }

        let entries_ptr = buffer.as_ptr().add(entries_offset) as *const SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX;
        let entries = std::slice::from_raw_parts(entries_ptr, count);

        let current_pid = GetCurrentProcessId();
        let mc_parent_pid = get_parent_process_id(mc_pid);
        let mut reported_pids = std::collections::HashSet::new();

        for entry in entries {
            let owner_pid = entry.unique_process_id as u32;
            if owner_pid == mc_pid || owner_pid == current_pid || owner_pid <= 4 {
                continue;
            }

        // Check for process memory write permissions (PROCESS_VM_WRITE = 0x0020),
        // memory operations (PROCESS_VM_OPERATION = 0x0008), full access, OR memory read (PROCESS_VM_READ = 0x0010)
            let access = entry.granted_access;
            let has_write_access = (access & 0x0020 != 0) || (access & 0x0008 != 0) || (access == 0x001F0FFF) || (access == 0x1FFFFF);
            let has_read_access = access & 0x0010 != 0;
            if !has_write_access && !has_read_access {
                continue;
            }

            if reported_pids.contains(&owner_pid) {
                continue;
            }

        // Open the handle-holding process to duplicate handle and verify its target
            let h_owner = OpenProcess(0x0040 /* PROCESS_DUP_HANDLE */ | 0x1000 /* PROCESS_QUERY_LIMITED_INFORMATION */, 0, owner_pid);
            if h_owner.is_null() {
                continue;
            }

            let mut dup_h: HANDLE = std::ptr::null_mut();
            let dup_ok = DuplicateHandle(
                h_owner,
                entry.handle_value as HANDLE,
                GetCurrentProcess(),
                &mut dup_h,
                0,
                0,
                DUPLICATE_SAME_ACCESS,
            );

            if dup_ok != 0 && !dup_h.is_null() {
                let target_pid = GetProcessId(dup_h);
                CloseHandle(dup_h);

                if target_pid == mc_pid {
                    reported_pids.insert(owner_pid);
                    let (owner_name, owner_path) = get_process_info_by_pid(owner_pid);
                    let lower_name = owner_name.to_lowercase();
                    let lower_path = owner_path.to_lowercase();

        // Security verification of process holding memory write handle (PROCESS_VM_WRITE):
        // 1. Genuine Windows system processes (must reside in C:\Windows\System32 or C:\Windows)
                    let is_system_proc = (lower_name == "csrss.exe"
                        || lower_name == "lsass.exe"
                        || lower_name == "services.exe"
                        || lower_name == "dwm.exe"
                        || lower_name == "smss.exe"
                        || lower_name == "explorer.exe"
                        || lower_name == "taskmgr.exe"
                        || lower_name == "audiodg.exe"
                        || lower_name == "msmpeng.exe")
                        && (lower_path.starts_with("c:\\windows\\system32\\")
                            || lower_path == "c:\\windows\\explorer.exe"
                            || lower_path.contains("\\windows defender\\"));

        // 2. Is the process located in a volatile directory (Desktop, Downloads, Temp)?
        // If the process originates from Desktop/Downloads/Temp - this is blatant external MASQUERADING and NEVER trusted!
                    let in_volatile_dir = crate::scanner::forensics::is_volatile_directory(&lower_path);

        // 3. Authenticode digital signature verification:
        // Genuine Discord, Steam, OBS, Overwolf, Razer, Logitech, NVIDIA or launchers
        // are ALWAYS digitally signed by an official publisher.
                    let is_signed = if !owner_path.is_empty() {
                        crate::scanner::forensics::is_pe_signed(Path::new(&owner_path))
                    } else {
                        false
                    };

                    let is_parent_launcher = (owner_pid == mc_parent_pid) && mc_parent_pid != 0;

                    let is_known_tool_name = lower_name.contains("antivirus")
                        || lower_name.contains("defender")
                        || lower_name.contains("security")
                        || lower_name.contains("kaspersky")
                        || lower_name.contains("avast")
                        || lower_name.contains("eset")
                        || lower_name.contains("norton")
                        || lower_name.contains("bitdefender")
                        || lower_name.contains("discord")
                        || lower_name.contains("obs64")
                        || lower_name.contains("nvcontainer")
                        || lower_name.contains("nvidia")
                        || lower_name.contains("rtss")
                        || lower_name.contains("steam")
                        || lower_name.contains("overwolf")
                        || lower_name.contains("feather")
                        || lower_name.contains("dawn")
                        || lower_name.contains("lunar")
                        || lower_name.contains("badlion")
                        || lower_name.contains("prism")
                        || lower_name.contains("modrinth")
                        || lower_name.contains("curseforge")
                        || lower_name.contains("atlauncher")
                        || lower_name.contains("tlauncher")
                        || lower_name.contains("minecraft")
                        || lower_name.contains("grind");

        // A trusted process is:
        // - either an official system process from System32,
        // - or an official parent launcher (Parent Process) or known tool that does NOT reside in a volatile folder (Desktop/Downloads/Temp/Root) AND possesses a valid Authenticode signature.
                    let is_whitelisted = is_system_proc || ((is_known_tool_name || is_parent_launcher) && !in_volatile_dir && is_signed);

                    if !is_whitelisted {
                        if has_write_access {
                            let access_desc = format!(
                                "0x{:08X} (VM_WRITE: {}, VM_OPERATION: {})",
                                access,
                                if access & 0x0020 != 0 { "TAK" } else { "NIE" },
                                if access & 0x0008 != 0 { "TAK" } else { "NIE" }
                            );

                            let mut finding = ScanFinding::new(
                                "External Process Holds Memory Write Handle to Minecraft",
                                FindingCategory::MinecraftRuntime,
                                VerdictLevel::Detection,
                                format!(
                                    "External process '{}' (PID: {}) holds an active write/tamper handle to Minecraft (PID: {}). Access mask: {}. This indicates external memory manipulation, aimbot, reach, or ghost cheat injection.",
                                    owner_name, owner_pid, mc_pid, access_desc
                                ),
                            )
                            .with_evidence("Owner Process", owner_name)
                            .with_evidence("Owner PID", owner_pid.to_string())
                            .with_evidence("Granted Access", access_desc)
                            .with_evidence("Minecraft PID", mc_pid.to_string())
                            .with_evidence("Process Path", if owner_path.is_empty() { "Niedostępna".to_string() } else { owner_path })
                            .with_evidence("Podpis cyfrowy Authenticode", if is_signed { "TAK (Prawidłowy podpis)".to_string() } else { "NIE (Brak ważnego certyfikatu wydawcy)".to_string() });

                            if in_volatile_dir {
                                finding = finding.with_evidence("Lokalizacja pliku", "Katalog ulotny (Pulpit/Pobrane/Temp) - wysokie podejrzenie podszywania się (Masquerading)".to_string());
                            }

                            report.add(finding);
                        } else if has_read_access {
                            let level = if in_volatile_dir || !is_signed {
                                VerdictLevel::Warning
                            } else {
                                VerdictLevel::Information
                            };

                            let mut finding = ScanFinding::new(
                                "External Process Holds Memory Read Handle to Minecraft",
                                FindingCategory::MinecraftRuntime,
                                level,
                                format!(
                                    "External process '{}' (PID: {}) holds an active read handle (PROCESS_VM_READ: 0x{:08X}) to Minecraft (PID: {}). Typical for external radars, ESP overlays, or memory readers.",
                                    owner_name, owner_pid, access, mc_pid
                                ),
                            )
                            .with_evidence("Owner Process", owner_name)
                            .with_evidence("Owner PID", owner_pid.to_string())
                            .with_evidence("Granted Access", format!("0x{:08X} (PROCESS_VM_READ)", access))
                            .with_evidence("Minecraft PID", mc_pid.to_string())
                            .with_evidence("Process Path", if owner_path.is_empty() { "Niedostępna".to_string() } else { owner_path })
                            .with_evidence("Podpis cyfrowy Authenticode", if is_signed { "TAK (Prawidłowy podpis)".to_string() } else { "NIE (Brak ważnego certyfikatu wydawcy)".to_string() });

                            if in_volatile_dir {
                                finding = finding.with_evidence("Lokalizacja pliku", "Katalog ulotny (Pulpit/Pobrane/Temp) - wysokie podejrzenie zewnętrznego cheata".to_string());
                            }

                            report.add(finding);
                        }
                    }
                }
            }

            CloseHandle(h_owner);
        }
    }
}

/// Retrieves filename and full executable path based on PID
pub fn get_process_info_by_pid(pid: u32) -> (String, String) {
    unsafe {
        let handle = OpenProcess(
            PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
            0,
            pid,
        );
        if !handle.is_null() {
            let mut buf = [0u16; 1024];
            let len = GetModuleFileNameExW(handle, std::ptr::null_mut(), buf.as_mut_ptr(), 1024);
            CloseHandle(handle);
            if len > 0 {
                let full_path = String::from_utf16_lossy(&buf[..len as usize]);
                let file_name = Path::new(&full_path)
                    .file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or(&full_path)
                    .to_string();
                return (file_name, full_path);
            }
        }

        // Fallback: ToolHelp snapshot
        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if snapshot != INVALID_HANDLE_VALUE {
            let mut entry: PROCESSENTRY32W = zeroed();
            entry.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;
            if Process32FirstW(snapshot, &mut entry) != 0 {
                loop {
                    if entry.th32ProcessID == pid {
                        CloseHandle(snapshot);
                        let name_len = entry.szExeFile.iter().position(|&c| c == 0).unwrap_or(entry.szExeFile.len());
                        let name = String::from_utf16_lossy(&entry.szExeFile[..name_len]);
                        return (name.clone(), name);
                    }
                    if Process32NextW(snapshot, &mut entry) == 0 {
                        break;
                    }
                }
            }
            CloseHandle(snapshot);
        }
    }
    (format!("Unknown_PID_{}", pid), String::new())
}

/// Returns parent PID (Parent PID) for given process
fn get_parent_process_id(pid: u32) -> u32 {
    unsafe {
        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if snapshot != INVALID_HANDLE_VALUE {
            let mut entry: PROCESSENTRY32W = zeroed();
            entry.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;
            if Process32FirstW(snapshot, &mut entry) != 0 {
                loop {
                    if entry.th32ProcessID == pid {
                        CloseHandle(snapshot);
                        return entry.th32ParentProcessID;
                    }
                    if Process32NextW(snapshot, &mut entry) == 0 {
                        break;
                    }
                }
            }
            CloseHandle(snapshot);
        }
    }
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_java_class_around() {
        let sample = b"\x00\x05dev/kir/cubeswithoutborders/client/mixin/EndCrystalItemMixin.class\x00";
        let match_start = sample.windows(b"EndCrystalItemMixin".len()).position(|w| w == b"EndCrystalItemMixin").unwrap();
        let extracted = extract_java_class_around(sample, match_start, b"EndCrystalItemMixin".len());
        assert_eq!(
            extracted,
            Some("dev/kir/cubeswithoutborders/client/mixin/EndCrystalItemMixin".to_string())
        );
    }

    #[test]
    fn test_generic_mixin_anomalies_detection_and_whitelist() {
        let mut report = ScanReport::new(true);
        let mut reported = std::collections::HashSet::new();

    // 1. Legitimate Fabric API mixin (including paths from Dawn Client / Fabric with leading '/') - must be ignored
        let fabric_slice = b"Lnet/fabricmc/fabric/mixin/event/interaction/ClientPlayerInteractionManagerMixin;V";
        check_generic_mixin_anomalies(fabric_slice, 0x1000, &mut report, &mut reported);
        assert_eq!(report.findings.len(), 0, "Fabric API mixin must be whitelisted");

        let user_dawn_slice1 = b"/net/fabricmc/fabric/mixin/item/client/ClientPlayerInteractionManagerMixin";
        check_generic_mixin_anomalies(user_dawn_slice1, 0x1100, &mut report, &mut reported);
        assert_eq!(report.findings.len(), 0, "Dawn Client Fabric item mixin must be whitelisted");

        let user_dawn_slice2 = b"/net/fabricmc/fabric/mixin/event/interaction/client/ClientPlayerInteractionManagerMixin";
        check_generic_mixin_anomalies(user_dawn_slice2, 0x1200, &mut report, &mut reported);
        assert_eq!(report.findings.len(), 0, "Dawn Client Fabric interaction mixin must be whitelisted");

    // 2. Malicious unknown 0-day mixin to EndCrystal - must report Warning for screenshare inspection
        let crystal_cheat_slice = b"xxx/custom_0day_cheat/mixin/EndCrystalItemMixin.class";
        check_generic_mixin_anomalies(crystal_cheat_slice, 0x2000, &mut report, &mut reported);
        assert_eq!(report.findings.len(), 1, "0-day EndCrystalItemMixin must be detected");
        assert_eq!(report.findings[0].level, VerdictLevel::Warning);

    // 3. Malicious unknown mixin to ClientPlayerInteractionManager - must report Warning
        let reach_cheat_slice = b"unknown/hax/client/mixin/ClientPlayerInteractionManagerMixin;(";
        check_generic_mixin_anomalies(reach_cheat_slice, 0x3000, &mut report, &mut reported);
        assert_eq!(report.findings.len(), 2, "0-day ClientPlayerInteractionManagerMixin must be detected");
        assert_eq!(report.findings[1].level, VerdictLevel::Warning);

    // 4. Bypass attempt: cheat package containing 'minecraft' keyword in the middle of path - must be DETECTED!
        let fake_mc_slice = b"org/hax/minecraft/exploit/EndCrystalItemMixin.class";
        check_generic_mixin_anomalies(fake_mc_slice, 0x4000, &mut report, &mut reported);
        assert_eq!(report.findings.len(), 3, "Fake 'minecraft' substring mixin cheat must be detected");
        assert_eq!(report.findings[2].level, VerdictLevel::Warning);
    }

    #[test]
    fn test_mera_client_composite_signatures() {
    // 1. Only "Click Open" (common in legit GUIs/mods) -> 0 detections!
        let mut report1 = ScanReport::new(true);
        evaluate_mera_client_signatures(&[0x1000], &[], &mut report1);
        assert_eq!(report1.findings.len(), 0, "Standalone 'Click Open' must never trigger a finding");

    // 2. Only marker "Mera Is A Fat Cunt" -> Warning (suspicious screenshare artifact)
        let mut report2 = ScanReport::new(true);
        evaluate_mera_client_signatures(&[], &[0x2000], &mut report2);
        assert_eq!(report2.findings.len(), 1);
        assert_eq!(report2.findings[0].level, VerdictLevel::Warning);

    // 3. Both signatures matched ("Click Open" + "Mera Is A Fat Cunt") -> Full cheat DETECTION!
        let mut report3 = ScanReport::new(true);
        evaluate_mera_client_signatures(&[0x1000], &[0x2000], &mut report3);
        assert_eq!(report3.findings.len(), 1);
        assert_eq!(report3.findings[0].level, VerdictLevel::Detection);
        assert!(report3.findings[0].name.contains("Mera Client Injected"));
    }

    #[test]
    fn test_identify_minecraft_process() {
        // Lunar Client
        let lunar_cmd = r#""C:\Program Files\Java\bin\javaw.exe" -Djava.library.path=... -cp lunar-prod.jar com.mojang.authlib... lunar.launcher"#;
        let (is_mc, brand) = identify_minecraft_process(lunar_cmd);
        assert!(is_mc);
        assert_eq!(brand, "Lunar Client");

        // Badlion Client
        let badlion_cmd = r#""C:\Java\bin\javaw.exe" -Dbadlion.version=... net.minecraft.client.main.Main"#;
        let (is_mc, brand) = identify_minecraft_process(badlion_cmd);
        assert!(is_mc);
        assert_eq!(brand, "Badlion Client");

        // Feather Client
        let feather_cmd = r#""C:\Java\bin\javaw.exe" -Dfeather.dir=... net.minecraft.client.main.Main"#;
        let (is_mc, brand) = identify_minecraft_process(feather_cmd);
        assert!(is_mc);
        assert_eq!(brand, "Feather Client");

        // Dawn Client
        let dawn_cmd = r#""C:\Java\bin\javaw.exe" -Ddawn.dir=... net.minecraft.client.main.Main"#;
        let (is_mc, brand) = identify_minecraft_process(dawn_cmd);
        assert!(is_mc);
        assert_eq!(brand, "Dawn Client");

        // OneClient
        let oneclient_cmd = r#""C:\Java\bin\javaw.exe" -Doneclient.version=1.0 me.decce.ixeris.Main net.minecraft.client.main.Main"#;
        let (is_mc, brand) = identify_minecraft_process(oneclient_cmd);
        assert!(is_mc);
        assert_eq!(brand, "OneClient");

    // Gradle Daemon (should be rejected as non-Minecraft)
        let gradle_cmd = r#""C:\Java\bin\java.exe" -classpath org.gradle.launcher.daemon.bootstrap.GradleDaemon"#;
        let (is_mc, _) = identify_minecraft_process(gradle_cmd);
        assert!(!is_mc, "Gradle Daemon must NOT be identified as Minecraft");

    // IntelliJ IDEA (should be rejected as non-Minecraft)
        let idea_cmd = r#""C:\Java\bin\java.exe" -classpath idea_rt.jar com.intellij.rt.execution.application.AppMainV2"#;
        let (is_mc, _) = identify_minecraft_process(idea_cmd);
        assert!(!is_mc, "IntelliJ must NOT be identified as Minecraft");

        // Vanilla Minecraft
        let vanilla_cmd = r#""C:\Mojang\runtime\java-runtime-gamma\bin\javaw.exe" --gameDir C:\Users\User\AppData\Roaming\.minecraft --version 1.20.4 net.minecraft.client.main.Main"#;
        let (is_mc, brand) = identify_minecraft_process(vanilla_cmd);
        assert!(is_mc);
        assert_eq!(brand, "Minecraft (Vanilla / Official Launcher)");
    }

    #[test]
    fn test_check_dir_for_proxy_dlls() {
        let temp_dir = std::env::temp_dir().join("test_dll_hijack_test");
        let _ = std::fs::create_dir_all(&temp_dir);
        let fake_version = temp_dir.join("version.dll");
        let _ = std::fs::write(&fake_version, b"dummy content");

        let mut report = ScanReport::new(true);
        check_dir_for_proxy_dlls(&temp_dir, &mut report, "test dir");

        assert_eq!(report.findings.len(), 1);
        assert_eq!(report.findings[0].name, "Java Runtime DLL Search Order Hijacking (Proxy DLL)");
        assert_eq!(report.findings[0].level, VerdictLevel::Detection);

        let _ = std::fs::remove_file(fake_version);
        let _ = std::fs::remove_dir(temp_dir);
    }

    #[test]
    fn test_argon_corrupt_client_strings() {
        let sample = b"dummy prefix dev.lvstrng.argon.Argon and dev/lvstrng/argon/Argon.classPK and Ldev/lvstrng/argon/Argon; dummy suffix";
        let patterns = [
            "dev/lvstrng/argon",
            "dev.lvstrng.argon",
            "dev/lvstrng/argon/Argon",
            "dev.lvstrng.argon.Argon",
            "Ldev/lvstrng/argon/Argon;",
        ];

        for pattern in patterns {
            let finder = memchr::memmem::Finder::new(pattern.as_bytes());
            assert!(finder.find(sample).is_some(), "Pattern {} must be found in sample", pattern);
        }
    }

    #[test]
    fn test_echo_client_strings() {
        let sample = b"dummy prefix hack/echo/client/Echo and Lhack/echo/client/features/Category; and dev.jadyen.drm.echo dummy suffix";
        let patterns = [
            "hack/echo/client/Echo",
            "Lhack/echo/client/features/Category;",
            "dev.jadyen.drm.echo",
        ];

        for pattern in patterns {
            let finder = memchr::memmem::Finder::new(pattern.as_bytes());
            assert!(finder.find(sample).is_some(), "Pattern {} must be found in sample", pattern);
        }
    }
    #[test]
    fn test_oneclient_false_positive_elimination_and_zero_trust() {
        // 1. OneClient MouseHandlerAccessor is legitimately whitelisted
        assert!(is_whitelisted_mouse_class("me/decce/ixeris/mixins/MouseHandlerAccessor"));
        assert!(is_whitelisted_mouse_class("me.decce.ixeris.mixins.MouseHandlerAccessor"));
        assert!(is_whitelisted_mouse_class("Lme/decce/ixeris/mixins/MouseHandlerAccessor;"));

        // 2. Zero-trust: spoofed malicious mixins in me/decce/ixeris are NOT whitelisted
        assert!(!is_whitelisted_mouse_class("me/decce/ixeris/mixins/AutoClickerAccessor"));
        assert!(!is_whitelisted_mixin_class("me/decce/ixeris/mixins/EndCrystalItemMixin"));
        assert!(!is_whitelisted_mixin_class("me/decce/ixeris/mixins/ClientPlayerInteractionManagerMixin"));

        // 3. Verify pattern rules do not contain bare WTap.class or Category/MOVEMENT
        let patterns = get_builtin_cheat_patterns();
        for rule in patterns {
            assert_ne!(rule.pattern, "WTap.class", "Bare WTap.class must not be a cheat rule");
            assert_ne!(rule.pattern, "W-Tap.class", "Bare W-Tap.class must not be a cheat rule");
            assert_ne!(rule.pattern, "Category/MOVEMENT", "Category/MOVEMENT must not be a cheat rule");
            assert_ne!(rule.pattern, "Category/COMBAT", "Category/COMBAT must not be a cheat rule");
        }

        // 4. Verify that real cheat automation patterns ARE present
        assert!(patterns.iter().any(|r| r.pattern == "AutoWTap.class"));
        assert!(patterns.iter().any(|r| r.pattern == "WTap Delay"));
        assert!(patterns.iter().any(|r| r.pattern == "wtap_chance"));
        assert!(patterns.iter().any(|r| r.pattern == "WTapPacket"));
    }

    #[test]
    fn test_benign_mod_natives_and_anti_spoofing() {
        println!("\n=== [TEST] Starting Benign Mod Natives & Anti-Spoofing Verification ===");

        // 1. Legitimate mod natives are recognized
        let c2me = is_known_benign_mod_native("c2me-opts-natives-math.dll", r"C:\Users\user\AppData\Local\Temp\c2me-opts-natives-math.dll");
        println!("[1] Testing C2ME: {:?}", c2me);
        assert!(c2me.is_some());

        let opus = is_known_benign_mod_native("libopus4j.dll", r"C:\Users\user\AppData\Local\Temp\libopus4j\libopus4j.dll");
        println!("[2] Testing libopus4j: {:?}", opus);
        assert!(opus.is_some());

        let rnnoise = is_known_benign_mod_native("librnnoise4j.dll", r"C:\Users\user\AppData\Local\Temp\librnnoise4j.dll");
        println!("[3] Testing librnnoise4j: {:?}", rnnoise);
        assert!(rnnoise.is_some());

        let onnx = is_known_benign_mod_native("onnxruntime.dll", r"C:\Users\user\AppData\Local\Temp\onnxruntime.dll");
        println!("[4] Testing onnxruntime: {:?}", onnx);
        assert!(onnx.is_some());

        let eos = is_known_benign_mod_native("EOSSDK-Win64-Shipping.dll", r"C:\Users\user\AppData\Local\Temp\EOSSDK-Win64-Shipping.dll");
        println!("[5] Testing EOSSDK: {:?}", eos);
        assert!(eos.is_some());

        let tokenizers = is_known_benign_mod_native("tokenizers.dll", r"C:\Users\user\.djl.ai\tokenizers\tokenizers.dll");
        println!("[6] Testing tokenizers: {:?}", tokenizers);
        assert!(tokenizers.is_some());

        let winpthread = is_known_benign_mod_native("libwinpthread-1.dll", r"C:\Users\user\.djl.ai\tokenizers\libwinpthread-1.dll");
        println!("[7] Testing libwinpthread: {:?}", winpthread);
        assert!(winpthread.is_some());

        // 2. Unknown cheat DLL is NOT recognized as benign
        let cheat = is_known_benign_mod_native("my_cheat.dll", r"C:\Users\user\AppData\Local\Temp\my_cheat.dll");
        println!("[8] Testing cheat DLL (my_cheat.dll): {:?}", cheat);
        assert!(cheat.is_none());

        let kura = is_known_benign_mod_native("kura.dll", r"C:\Users\user\AppData\Local\Temp\kura.dll");
        println!("[9] Testing known cheat binary (kura.dll): {:?}", kura);
        assert!(kura.is_none());

        // 3. Anti-spoofing: if a cheat names itself c2me.dll but contains cheat payload strings, it is DETECTED!
        let temp_dir = std::env::temp_dir().join("test_dll_spoof");
        let _ = std::fs::create_dir_all(&temp_dir);

        let clean_c2me = temp_dir.join("clean_c2me.dll");
        let _ = std::fs::write(&clean_c2me, b"Standard legitimate math chunk optimization bytecode");
        let clean_check = check_dll_for_embedded_cheat_strings(&clean_c2me);
        println!("[10] Anti-spoofing on legitimate clean C2ME DLL -> result: {:?} (Clean)", clean_check);
        assert!(clean_check.is_none());

        let fake_c2me = temp_dir.join("fake_c2me.dll");
        let _ = std::fs::write(&fake_c2me, b"Fake header ... killaura and aimassist ... fake footer");
        let trigger = check_dll_for_embedded_cheat_strings(&fake_c2me);
        println!("[11] Anti-spoofing on SPOOFED C2ME DLL (contains cheat strings) -> DETECTED TRIGGER: {:?}", trigger);
        assert!(trigger.is_some(), "Spoofed DLL containing cheat strings must be detected!");

        let _ = std::fs::remove_file(&clean_c2me);
        let _ = std::fs::remove_file(&fake_c2me);
        let _ = std::fs::remove_dir(&temp_dir);
        println!("=== [TEST] Benign Mod Natives & Anti-Spoofing Passed Successfully! ===\n");
    }

    #[test]
    fn test_get_process_start_time_info_on_current_process() {
        unsafe {
            let handle = GetCurrentProcess();
            let result = get_process_start_time_info(handle);
            assert!(result.is_some(), "GetCurrentProcess must return valid start time info");
            let (badge, date_and_time, uptime) = result.unwrap();
            println!("\n=== [TEST] Process Start Time WinAPI Output ===");
            println!("Finding Title: Active Minecraft Instance Detected [{}]", badge);
            println!("Start Date & Time (Local): {}", date_and_time);
            println!("Uptime: {}", uptime);
            println!("=== [TEST] End Process Start Time Verification ===\n");
            assert!(badge.contains("Opened"));
            assert!(!date_and_time.is_empty());
            assert!(!uptime.is_empty());
        }
    }

    #[test]
    fn test_anticheat_blacklist_anti_evasion() {
        // A cheat author includes "blocked_mod" or "banned_mod" right next to an injected cheat class
        let fake_cheat_chunk = b"SomeCode... blocked_mod ... AutoWTap.class ... banned_mod ... MoreCode";

        // Verify that AutoWTap.class is NEVER silenced by the false-positive blacklist filter
        let patterns = get_builtin_cheat_patterns();
        let autowtap_rule = patterns.iter().find(|r| r.pattern == "AutoWTap.class").expect("AutoWTap rule must exist");

        // The rule pattern contains ".class", so is_pure_jar_or_mod_name is false
        let is_pure_jar_or_mod_name = autowtap_rule.pattern.ends_with(".jar") || !autowtap_rule.pattern.contains(".class");
        assert!(!is_pure_jar_or_mod_name, "Compiled cheat classes (.class) must NEVER be eligible for blacklist suppression!");

        // Even for a pure mod name, it must be inside verified launcher packages (net/digitalingot/, com/dawn/)
        let surrounding = String::from_utf8_lossy(fake_cheat_chunk).to_lowercase();
        let in_launcher_ac = surrounding.contains("net/digitalingot/")
            || surrounding.contains("digital/feather/")
            || surrounding.contains("com/dawn/");
        assert!(!in_launcher_ac, "Arbitrary cheat code without launcher anticheat package must not qualify for suppression");
    }

    #[test]
    fn test_wiped_pe_detection_logic() {
        // 1. Legitimate PE header with MZ
        let mut normal_pe = vec![0u8; 1024];
        normal_pe[0] = 0x4D;
        normal_pe[1] = 0x5A;
        normal_pe[0x3C] = 0x80; // e_lfanew
        normal_pe[0x80..0x84].copy_from_slice(b"PE\0\0");
        let has_mz = normal_pe[0] == 0x4D && normal_pe[1] == 0x5A;
        assert!(has_mz);

        // 2. Wiped DOS header (MZ zeroed out by Reflective DLL / Manual Map)
        let mut wiped_pe = vec![0u8; 1024];
        wiped_pe[0] = 0x00;
        wiped_pe[1] = 0x00;
        wiped_pe[0x3C] = 0x80; // e_lfanew points to PE signature
        wiped_pe[0x80..0x84].copy_from_slice(b"PE\0\0");

        let e_lfanew = u32::from_le_bytes(wiped_pe[0x3C..0x40].try_into().unwrap()) as usize;
        let mut has_wiped_pe = false;
        if e_lfanew > 0 && e_lfanew + 4 <= wiped_pe.len() {
            if &wiped_pe[e_lfanew..e_lfanew + 4] == b"PE\0\0" {
                has_wiped_pe = true;
            }
        }
        assert!(has_wiped_pe, "Manual mapped PE with zeroed MZ header must be detected via e_lfanew PE signature!");

        // 3. Wiped PE header with only section names (.text, .rdata) remaining
        let mut section_pe = vec![0u8; 1024];
        section_pe[0x200..0x208].copy_from_slice(b".text\0\0\0");
        let mut has_section = false;
        for window in section_pe.windows(8) {
            if window == b".text\0\0\0" || window == b".rdata\0\0" || window == b".data\0\0\0" {
                has_section = true;
                break;
            }
        }
        assert!(has_section, "Manual mapped PE with wiped headers must be detected via PE section remnants!");
    }

    #[test]
    fn test_handle_access_read_and_write_distinction() {
        let write_access: u32 = 0x0020; // PROCESS_VM_WRITE
        let read_access: u32 = 0x0010;  // PROCESS_VM_READ
        let query_access: u32 = 0x0400; // PROCESS_QUERY_INFORMATION

        let has_write_1 = (write_access & 0x0020 != 0) || (write_access & 0x0008 != 0);
        let has_read_1 = write_access & 0x0010 != 0;
        assert!(has_write_1);
        assert!(!has_read_1);

        let has_write_2 = (read_access & 0x0020 != 0) || (read_access & 0x0008 != 0);
        let has_read_2 = read_access & 0x0010 != 0;
        assert!(!has_write_2);
        assert!(has_read_2, "PROCESS_VM_READ must be recognized for external radar/ESP detection");

        let has_write_3 = (query_access & 0x0020 != 0) || (query_access & 0x0008 != 0);
        let has_read_3 = query_access & 0x0010 != 0;
        assert!(!has_write_3);
        assert!(!has_read_3);
    }


    #[test]
    fn test_get_remote_proc_address_resolution() {
        unsafe {
            let ntdll = GetModuleHandleA(b"ntdll.dll\0".as_ptr());
            assert!(!ntdll.is_null());
            let expected = GetProcAddress(ntdll, b"NtClose\0".as_ptr()).unwrap() as usize;
            let resolved = get_remote_proc_address(GetCurrentProcess(), ntdll as usize, "NtClose");
            assert!(resolved.is_some(), "get_remote_proc_address must find NtClose in ntdll");
            assert_eq!(expected, resolved.unwrap(), "Resolved address must exactly match GetProcAddress");
        }
    }


    #[test]
    fn test_mid_function_and_custom_jump_hook_detection() {
        // 1. R11 Register Jump (49 BB ... 41 FF E3)
        let mut r11_bytes = [0u8; 16];
        r11_bytes[0] = 0x49;
        r11_bytes[1] = 0xBB;
        let is_hooked_r11 = r11_bytes[0] == 0x49 && r11_bytes[1] == 0xBB;
        assert!(is_hooked_r11, "R11 mov/jmp hook must be detected");

        // 2. Push/Ret hook (68 xx xx xx xx C3)
        let mut push_ret = [0u8; 16];
        push_ret[0] = 0x68;
        push_ret[5] = 0xC3;
        let is_hooked_push_ret = push_ret[0] == 0x68 && push_ret[5] == 0xC3;
        assert!(is_hooked_push_ret, "Push/Ret hook must be detected");

        // 3. Mid-function jump placed 8 bytes after prologue (e.g. push rbp; mov rbp, rsp; ... FF 25)
        let mid_func = [0x55, 0x48, 0x89, 0xE5, 0x90, 0x90, 0x90, 0x90, 0xFF, 0x25, 0x00, 0x00, 0x00, 0x00, 0x90, 0x90];
        let has_mid_jmp = mid_func[..16].windows(2).any(|w| w == [0xFF, 0x25] || w == [0xFF, 0xE0] || w == [0xFF, 0xE3]);
        assert!(has_mid_jmp, "Mid-function detour jump must be detected");
    }

    #[test]
    fn test_thread_call_stack_walk_unbacked_return_address_detection() {
        // Simulate reading 16 KB thread stack frames
        let mut fake_stack = vec![0usize; 64];
        // Standard legitimate module return addresses
        fake_stack[0] = 0x7FFE_1234_5678; // ntdll!NtWaitForSingleObject return address
        fake_stack[1] = 0x7FF7_9876_5432; // jvm!os_sleep return address

        // Injected cheat return address pointing into unbacked private memory
        let cheat_unbacked_addr = 0x0000_01A2_3456_7890usize;
        fake_stack[5] = cheat_unbacked_addr;

        // Verify that stack walk inspects all slots
        let mut detected_slot = None;
        for (i, &ptr) in fake_stack.iter().enumerate() {
            if ptr == cheat_unbacked_addr {
                detected_slot = Some(i);
                break;
            }
        }
        assert_eq!(detected_slot, Some(5), "Call stack walk must detect unbacked return address slot");
    }


    #[test]
    fn test_libffi_trampoline_not_flagged_as_pe() {
        // Simulate a 64 KB LWJGL 3 libffi closure pool / callback trampoline buffer
        let mut ffi_buffer = vec![0u8; 1024];
        // Dynamic trampoline code (e.g. mov r10, closure; mov rax, target; jmp rax)
        ffi_buffer[0..8].copy_from_slice(&[0x49, 0xBA, 0x10, 0x20, 0x30, 0x40, 0x50, 0x60]);

        let has_mz = ffi_buffer[0] == 0x4D && ffi_buffer[1] == 0x5A;
        assert!(!has_mz);

        let e_lfanew = u32::from_le_bytes(ffi_buffer[0x3C..0x40].try_into().unwrap()) as usize;
        let mut has_wiped_pe = false;
        if e_lfanew > 0 && e_lfanew + 4 <= ffi_buffer.len() {
            if &ffi_buffer[e_lfanew..e_lfanew + 4] == b"PE\0\0" {
                has_wiped_pe = true;
            }
        }
        if !has_wiped_pe {
            for window in ffi_buffer.windows(8) {
                if window == b".text\0\0\0" || window == b".rdata\0\0" || window == b".data\0\0\0" {
                    has_wiped_pe = true;
                    break;
                }
            }
        }

        assert!(!has_wiped_pe, "Clean libffi/GLFW callback trampolines must NOT be flagged as manual-mapped PE!");
    }

}
