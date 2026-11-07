use crate::report::{FindingCategory, ScanFinding, ScanReport, VerdictLevel};

#[repr(C)]
struct DnsCacheEntry {
    next: *mut DnsCacheEntry,
    name: *const u16,
    type_id: u16,
    data_length: u16,
    flags: u32,
}

type DnsGetCacheDataTableFn = unsafe extern "system" fn(entry: *mut *mut DnsCacheEntry) -> i32;

pub fn scan_dns_cache(report: &mut ScanReport) {
    let known_cheat_domains = [
        "vape.gg",
        "drip.gg",
        "slinky.gg",
        "entropy.club",
        "ravenbplus",
        "doomsday.client",
        "doomsday.rip",
        "kura.client",
        "liquidbounce.net",
        "prestigeclient.vip",
        "breeze.rip",
        "lithiumclient.wtf",
        "vengeance-auth.vercel.app",
    ];

    unsafe {
        let dnsapi = windows_sys::Win32::System::LibraryLoader::LoadLibraryA(
            b"dnsapi.dll\0".as_ptr(),
        );
        if dnsapi.is_null() {
            return;
        }

        let func_ptr = windows_sys::Win32::System::LibraryLoader::GetProcAddress(
            dnsapi,
            b"DnsGetCacheDataTable\0".as_ptr(),
        );

        if let Some(func) = func_ptr {
            let get_cache_data_table: DnsGetCacheDataTableFn = std::mem::transmute(func);
            let mut cache_entry: *mut DnsCacheEntry = std::ptr::null_mut();

            if get_cache_data_table(&mut cache_entry) != 0 && !cache_entry.is_null() {
                let mut current = cache_entry;
                let mut hits = 0;

                while !current.is_null() {
                    let entry = &*current;
                    if !entry.name.is_null() {
                        let mut len = 0;
                        while *entry.name.add(len) != 0 {
                            len += 1;
                        }

                        let slice = std::slice::from_raw_parts(entry.name, len);
                        let domain = String::from_utf16_lossy(slice).to_lowercase();

                        for cheat_domain in &known_cheat_domains {
                            if domain.contains(cheat_domain) {
                                hits += 1;
                                report.add(
                                    ScanFinding::new(
                                        "Cheat Domain Found In DNS Cache",
                                        FindingCategory::NetworkAndDns,
                                        VerdictLevel::Warning,
                                        format!("DNS Client Cache maintains resolution trace for: {}", domain),
                                    )
                                    .with_evidence("Resolved Domain", domain.clone()),
                                );
                                break;
                            }
                        }
                    }

                    if hits >= 5 {
                        break;
                    }
                    current = entry.next;
                }
            }
        }

        windows_sys::Win32::Foundation::FreeLibrary(dnsapi);
    }
}

type GetExtendedTcpTableFn = unsafe extern "system" fn(
    p_tcp_table: *mut std::ffi::c_void,
    pdw_size: *mut u32,
    b_order: i32,
    ul_af: u32,
    table_class: u32,
    reserved: u32,
) -> u32;

#[repr(C)]
#[derive(Clone, Copy)]
struct MibTcpRowOwnerPid {
    dw_state: u32,
    dw_local_addr: u32,
    dw_local_port: u32,
    dw_remote_addr: u32,
    dw_remote_port: u32,
    dw_owning_pid: u32,
}

pub fn scan_active_connections(report: &mut ScanReport) {
    let mc_procs = crate::scanner::jvm::find_minecraft_processes();
    let mc_proc_map: std::collections::HashMap<u32, String> = mc_procs
        .into_iter()
        .map(|p| (p.pid, p.client_brand))
        .collect();

    let proc_map = get_system_process_map();

    unsafe {
        let iphlpapi = windows_sys::Win32::System::LibraryLoader::LoadLibraryA(
            b"iphlpapi.dll\0".as_ptr(),
        );
        if iphlpapi.is_null() {
            return;
        }

        let p_get_table = windows_sys::Win32::System::LibraryLoader::GetProcAddress(
            iphlpapi,
            b"GetExtendedTcpTable\0".as_ptr(),
        );

        if let Some(func) = p_get_table {
            let get_extended_tcp_table: GetExtendedTcpTableFn = std::mem::transmute(func);

            const AF_INET: u32 = 2;
            const TCP_TABLE_OWNER_PID_ALL: u32 = 5;

            let mut size = 0u32;
            let _ = get_extended_tcp_table(
                std::ptr::null_mut(),
                &mut size,
                1,
                AF_INET,
                TCP_TABLE_OWNER_PID_ALL,
                0,
            );

            if size > 0 {
                let mut buf = vec![0u8; size as usize];
                if get_extended_tcp_table(
                    buf.as_mut_ptr() as *mut std::ffi::c_void,
                    &mut size,
                    1,
                    AF_INET,
                    TCP_TABLE_OWNER_PID_ALL,
                    0,
                ) == 0
                {
                    let num_entries = *(buf.as_ptr() as *const u32);
                    let table_ptr = buf.as_ptr().add(4) as *const MibTcpRowOwnerPid;
                    let rows = std::slice::from_raw_parts(table_ptr, num_entries as usize);

                    for row in rows {
                        let local_port = u16::from_be((row.dw_local_port & 0xFFFF) as u16);
                        let remote_port = u16::from_be((row.dw_remote_port & 0xFFFF) as u16);
                        let local_ip = std::net::Ipv4Addr::from(row.dw_local_addr.to_ne_bytes());
                        let remote_ip = std::net::Ipv4Addr::from(row.dw_remote_addr.to_ne_bytes());
                        let proc_name = proc_map.get(&row.dw_owning_pid).map(|s| s.to_lowercase()).unwrap_or_default();

                        // 1. Sprawdzanie procesu Minecrafta pod kątem połączeń z Discord RPC lub lokalnym daemonem cheata
                        if let Some(brand) = mc_proc_map.get(&row.dw_owning_pid) {
                            if remote_ip.is_loopback() && (6463..=6472).contains(&remote_port) {
                                report.add(
                                    ScanFinding::new(
                                        "Minecraft Process Connected to Discord RPC",
                                        FindingCategory::NetworkAndDns,
                                        VerdictLevel::Information,
                                        format!(
                                            "Proces Minecrafta (PID: {}) utrzymuje aktywne połączenie IPC z Discord RPC (port: {}).",
                                            row.dw_owning_pid, remote_port
                                        ),
                                    )
                                    .with_evidence("PID procesu", row.dw_owning_pid.to_string())
                                    .with_evidence("Lokalny port", local_port.to_string())
                                    .with_evidence("Zdalny port RPC", remote_port.to_string()),
                                );
                            } else if remote_ip.is_loopback() && remote_port != 25565 && remote_port != 0 {
                                let is_launcher_ipc = brand.contains("Feather")
                                    || brand.contains("Dawn")
                                    || brand.contains("Lunar")
                                    || brand.contains("Badlion")
                                    || brand.contains("Prism")
                                    || brand.contains("Modrinth")
                                    || brand.contains("CurseForge")
                                    || brand.contains("LabyMod");

                                if is_launcher_ipc {
                                    report.add(
                                        ScanFinding::new(
                                            "Minecraft Client Launcher Localhost IPC",
                                            FindingCategory::NetworkAndDns,
                                            VerdictLevel::Information,
                                            format!(
                                                "Proces {} (PID: {}) utrzymuje lokalne połączenie IPC (localhost:{}:{}). Jest to standardowa komunikacja launchera (np. czat, skiny, status).",
                                                brand, row.dw_owning_pid, remote_ip, remote_port
                                            ),
                                        )
                                        .with_evidence("PID procesu", row.dw_owning_pid.to_string())
                                        .with_evidence("Klient", brand.clone())
                                        .with_evidence("Lokalny adres", format!("{}:{}", local_ip, local_port))
                                        .with_evidence("Adres docelowy", format!("{}:{}", remote_ip, remote_port)),
                                    );
                                } else {
                                    report.add(
                                        ScanFinding::new(
                                            "Minecraft Process Localhost IPC Connection",
                                            FindingCategory::NetworkAndDns,
                                            VerdictLevel::Warning,
                                            format!(
                                                "Proces Minecrafta (PID: {}) komunikuje się z lokalną usługą (localhost:{}:{}). Może to wskazywać na injector komunikujący się przez WebSockets/HTTP.",
                                                row.dw_owning_pid, remote_ip, remote_port
                                            ),
                                        )
                                        .with_evidence("PID procesu", row.dw_owning_pid.to_string())
                                        .with_evidence("Lokalny adres", format!("{}:{}", local_ip, local_port))
                                        .with_evidence("Adres docelowy", format!("{}:{}", remote_ip, remote_port)),
                                    );
                                }
                            }
                        }

                        // 2. Detekcja podejrzanego użycia sieci przez cmd.exe (PE Injection / Process Hollowing)
                        const MIB_TCP_STATE_CLOSED: u32 = 1;
                        if proc_name == "cmd.exe" && row.dw_state != MIB_TCP_STATE_CLOSED {
                            report.add(
                                ScanFinding::new(
                                    "App Has Suspicious Data Usage (Possible PE Injection/Bypass Related): cmd.exe",
                                    FindingCategory::NetworkAndDns,
                                    VerdictLevel::Detection,
                                    format!(
                                        "Proces wiersza poleceń cmd.exe (PID: {}) posiada aktywne gniazdo sieciowe TCP ({}:{} -> {}:{}). Standardowy cmd.exe nie korzysta z sieci – wskazuje to na wstrzyknięcie kodu (PE Injection / Process Hollowing) lub ukrytego loadera cheata.",
                                        row.dw_owning_pid, local_ip, local_port, remote_ip, remote_port
                                    ),
                                )
                                .with_evidence("Aplikacja", "C:\\Windows\\System32\\cmd.exe".to_string())
                                .with_evidence("PID procesu", row.dw_owning_pid.to_string())
                                .with_evidence("Lokalny adres", format!("{}:{}", local_ip, local_port))
                                .with_evidence("Zdalny adres", format!("{}:{}", remote_ip, remote_port))
                                .with_evidence("Stan gniazda TCP", format!("{}", row.dw_state)),
                            );
                        }

                        // 3. Detekcja podejrzanego użycia sieci przez powershell.exe
                        if proc_name == "powershell.exe" && row.dw_state != MIB_TCP_STATE_CLOSED {
                            let cheat_ports = [1337, 31337, 20888, 4444];
                            if cheat_ports.contains(&remote_port) || (remote_ip.is_loopback() && remote_port != 0) {
                                report.add(
                                    ScanFinding::new(
                                        "App Has Suspicious Data Usage (Possible PE Injection/Bypass Related): powershell.exe",
                                        FindingCategory::NetworkAndDns,
                                        VerdictLevel::Warning,
                                        format!(
                                            "Proces PowerShell (PID: {}) komunikuje się przez sieć z adresem {}:{}. Weryfikacja pod kątem pobierania lub sterowania zewnętrznym narzędziem cheata.",
                                            row.dw_owning_pid, remote_ip, remote_port
                                        ),
                                    )
                                    .with_evidence("Aplikacja", "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe".to_string())
                                    .with_evidence("PID procesu", row.dw_owning_pid.to_string())
                                    .with_evidence("Zdalny adres", format!("{}:{}", remote_ip, remote_port)),
                                );
                            }
                        }

                        // 4. Sprawdzanie czy jakikolwiek proces nasłuchuje na typowych portach cheatów (np. 1337, 31337)
                        const MIB_TCP_STATE_LISTEN: u32 = 2;
                        if row.dw_state == MIB_TCP_STATE_LISTEN {
                            let cheat_ports = [1337, 31337, 20888];
                            if cheat_ports.contains(&local_port) {
                                report.add(
                                    ScanFinding::new(
                                        "Suspicious Cheat Port Listener Detected",
                                        FindingCategory::NetworkAndDns,
                                        VerdictLevel::Warning,
                                        format!(
                                            "Wykryto proces (PID: {}) nasłuchujący na podejrzanym porcie sterowania cheatami: {}.",
                                            row.dw_owning_pid, local_port
                                        ),
                                    )
                                    .with_evidence("PID procesu", row.dw_owning_pid.to_string())
                                    .with_evidence("Port nasłuchu", local_port.to_string()),
                                );
                            }
                        }
                    }
                }
            }
        }

        windows_sys::Win32::Foundation::FreeLibrary(iphlpapi);
    }

    check_cmd_module_injection(report, &proc_map);
}

fn get_system_process_map() -> std::collections::HashMap<u32, String> {
    let mut map = std::collections::HashMap::new();
    unsafe {
        let snapshot = windows_sys::Win32::System::Diagnostics::ToolHelp::CreateToolhelp32Snapshot(
            windows_sys::Win32::System::Diagnostics::ToolHelp::TH32CS_SNAPPROCESS,
            0,
        );
        if snapshot != windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE {
            let mut entry: windows_sys::Win32::System::Diagnostics::ToolHelp::PROCESSENTRY32W = std::mem::zeroed();
            entry.dwSize = std::mem::size_of::<windows_sys::Win32::System::Diagnostics::ToolHelp::PROCESSENTRY32W>() as u32;

            if windows_sys::Win32::System::Diagnostics::ToolHelp::Process32FirstW(snapshot, &mut entry) != 0 {
                loop {
                    let len = entry.szExeFile.iter().position(|&c| c == 0).unwrap_or(entry.szExeFile.len());
                    let name = String::from_utf16_lossy(&entry.szExeFile[..len]);
                    map.insert(entry.th32ProcessID, name);

                    if windows_sys::Win32::System::Diagnostics::ToolHelp::Process32NextW(snapshot, &mut entry) == 0 {
                        break;
                    }
                }
            }
            windows_sys::Win32::Foundation::CloseHandle(snapshot);
        }
    }
    map
}

fn check_cmd_module_injection(
    report: &mut ScanReport,
    proc_map: &std::collections::HashMap<u32, String>,
) {
    for (pid, name) in proc_map {
        let is_non_network_host = name.eq_ignore_ascii_case("cmd.exe")
            || name.eq_ignore_ascii_case("notepad.exe")
            || name.eq_ignore_ascii_case("calc.exe");

        if is_non_network_host {
            unsafe {
                let snapshot = windows_sys::Win32::System::Diagnostics::ToolHelp::CreateToolhelp32Snapshot(
                    windows_sys::Win32::System::Diagnostics::ToolHelp::TH32CS_SNAPMODULE
                        | windows_sys::Win32::System::Diagnostics::ToolHelp::TH32CS_SNAPMODULE32,
                    *pid,
                );

                if snapshot != windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE {
                    let mut entry: windows_sys::Win32::System::Diagnostics::ToolHelp::MODULEENTRY32W = std::mem::zeroed();
                    entry.dwSize = std::mem::size_of::<windows_sys::Win32::System::Diagnostics::ToolHelp::MODULEENTRY32W>() as u32;

                    if windows_sys::Win32::System::Diagnostics::ToolHelp::Module32FirstW(snapshot, &mut entry) != 0 {
                        loop {
                            let len = entry.szModule.iter().position(|&c| c == 0).unwrap_or(entry.szModule.len());
                            let mod_name = String::from_utf16_lossy(&entry.szModule[..len]).to_lowercase();

                            if mod_name == "ws2_32.dll" || mod_name == "wininet.dll" || mod_name == "winhttp.dll" {
                                let path_len = entry.szExePath.iter().position(|&c| c == 0).unwrap_or(entry.szExePath.len());
                                let mod_path = String::from_utf16_lossy(&entry.szExePath[..path_len]);

                                report.add(
                                    ScanFinding::new(
                                        format!("Winsock Network Module Injected into {} (PE Injection Detected)", name),
                                        FindingCategory::TamperingAndAntiForensics,
                                        VerdictLevel::Detection,
                                        format!(
                                            "W procesie {} (PID: {}) wykryto załadowany moduł sieciowy {}. Czysty proces {} nie korzysta z sieci. Jest to bezpośredni dowód na PE Injection / wstrzyknięcie złośliwego kodu.",
                                            name, pid, mod_name, name
                                        ),
                                    )
                                    .with_evidence("Proces docelowy", name.clone())
                                    .with_evidence("PID", pid.to_string())
                                    .with_evidence("Załadowana biblioteka sieciowa", mod_name)
                                    .with_evidence("Ścieżka modułu", mod_path),
                                );
                                break;
                            }

                            if windows_sys::Win32::System::Diagnostics::ToolHelp::Module32NextW(snapshot, &mut entry) == 0 {
                                break;
                            }
                        }
                    }
                    windows_sys::Win32::Foundation::CloseHandle(snapshot);
                }
            }
        }
    }
}

pub fn check_hosts_file_integrity(report: &mut ScanReport) {
    let hosts_path = std::path::Path::new("C:\\Windows\\System32\\drivers\\etc\\hosts");
    if !hosts_path.exists() {
        return;
    }

    let mtime = std::fs::metadata(hosts_path)
        .and_then(|m| m.modified())
        .ok();
    let (mod_time_str, in_current_session) = if let Some(st) = mtime {
        (
            crate::scanner::forensics::format_system_time(st),
            crate::scanner::forensics::is_system_time_in_current_session(st),
        )
    } else {
        ("Nieznany".to_string(), false)
    };

    let content = match std::fs::read_to_string(hosts_path) {
        Ok(c) => c,
        Err(_) => return,
    };

    scan_hosts_text(&content, &mod_time_str, in_current_session, report);
}

fn scan_hosts_text(
    content: &str,
    mod_time_str: &str,
    in_current_session: bool,
    report: &mut ScanReport,
) {
    let anticheat_domains = [
        "detect.ac",
        "api.detect.ac",
        "echo.ac",
        "paladin.ac",
        "badlion.net",
        "lunarclient.com",
        "authserver.mojang.com",
        "sessionserver.mojang.com",
        "api.mojang.com",
        "minecraft.net",
    ];

    let cheat_auth_domains = [
        "vape.gg",
        "drip.gg",
        "slinky.gg",
        "entropy.club",
        "doomsday.client",
        "doomsday.rip",
        "kura.client",
        "prestigeclient.vip",
        "breeze.rip",
    ];

    let mut custom_entries_count = 0;

    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }

        // Podziel linię na IP oraz nazwy hostów
        let parts: Vec<&str> = trimmed.split_whitespace().collect();
        if parts.len() < 2 {
            continue;
        }

        let ip = parts[0];
        for &domain in &parts[1..] {
            let domain_lower = domain.to_lowercase();

            // Pomiń standardowy localhost
            if domain_lower == "localhost"
                || domain_lower == "localhost.localdomain"
                || domain_lower == "broadcasthost"
                || domain_lower.ends_with(".local")
                || domain_lower == "host.docker.internal"
            {
                continue;
            }

            custom_entries_count += 1;

            // 1. Sprawdź blokowanie / przekierowywanie antycheatów lub autoryzacji Minecraft
            for ac in &anticheat_domains {
                if domain_lower == *ac || domain_lower.ends_with(&format!(".{}", ac)) {
                    let (verdict, scope_desc) = if in_current_session {
                        (
                            VerdictLevel::Detection,
                            "Plik hosts zmodyfikowany w BIEŻĄCEJ sesji systemu (po uruchomieniu PC)",
                        )
                    } else {
                        (
                            VerdictLevel::Detection,
                            "Trwała modyfikacja pliku hosts",
                        )
                    };

                    let title = if ip == "127.0.0.1" || ip == "0.0.0.0" {
                        "Anti-Cheat / Mojang Auth Domain Blocked in Hosts File"
                    } else {
                        "DNS Spoofing / Mock Authentication Server in Hosts File"
                    };

                    report.add(
                        ScanFinding::new(
                            title,
                            FindingCategory::NetworkAndDns,
                            verdict,
                            format!(
                                "W pliku hosts wykryto zablokowanie lub przekierowanie domeny antycheata / autoryzacji Minecraft: {} -> {}. Celem może być ukrycie cheatów lub ominięcie weryfikacji konta.",
                                domain_lower, ip
                            ),
                        )
                        .with_evidence("Przekierowana domena", domain_lower.clone())
                        .with_evidence("Adres IP docelowy", ip.to_string())
                        .with_evidence("Ścieżka pliku hosts", "C:\\Windows\\System32\\drivers\\etc\\hosts".to_string())
                        .with_evidence("Czas modyfikacji pliku", mod_time_str.to_string())
                        .with_evidence("Stan sesji", scope_desc.to_string()),
                    );
                    break;
                }
            }

            // 2. Sprawdź emulację serwera licencji cheatów (crack / license emulator)
            for ch in &cheat_auth_domains {
                if domain_lower == *ch || domain_lower.ends_with(&format!(".{}", ch)) {
                    report.add(
                        ScanFinding::new(
                            "Cheat Authentication Server Spoofing in Hosts File",
                            FindingCategory::NetworkAndDns,
                            VerdictLevel::Detection,
                            format!(
                                "W pliku hosts wykryto przekierowanie domeny autoryzacji cheata {} na {} (lokalny emulator licencji / crack cheata).",
                                domain_lower, ip
                            ),
                        )
                        .with_evidence("Domena cheata", domain_lower.clone())
                        .with_evidence("Adres IP docelowy", ip.to_string())
                        .with_evidence("Ścieżka pliku hosts", "C:\\Windows\\System32\\drivers\\etc\\hosts".to_string())
                        .with_evidence("Czas modyfikacji pliku", mod_time_str.to_string()),
                    );
                    break;
                }
            }
        }
    }

    if custom_entries_count > 0 && report.findings.iter().all(|f| f.name != "Custom Hosts File Redirections Present") {
        report.add(
            ScanFinding::new(
                "Custom Hosts File Entries Present",
                FindingCategory::NetworkAndDns,
                VerdictLevel::Information,
                format!(
                    "Plik hosts zawiera {} niestandardowych reguł mapowania domen IP. Ostatnia modyfikacja: {}.",
                    custom_entries_count, mod_time_str
                ),
            )
            .with_evidence("Liczba niestandardowych wpisów", custom_entries_count.to_string())
            .with_evidence("Czas modyfikacji pliku", mod_time_str.to_string()),
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scan_hosts_text_detection() {
        let hosts_content = r#"
# Copyright (c) 1993-2009 Microsoft Corp.
127.0.0.1       localhost
::1             localhost
127.0.0.1       detect.ac
0.0.0.0         api.detect.ac
127.0.0.1       authserver.mojang.com
127.0.0.1       vape.gg
"#;
        let mut report = ScanReport::new(true);
        scan_hosts_text(hosts_content, "2026-10-04 12:00:00", true, &mut report);

        let titles: Vec<&str> = report.findings.iter().map(|f| f.name.as_str()).collect();
        assert!(titles.contains(&"Anti-Cheat / Mojang Auth Domain Blocked in Hosts File"));
        assert!(titles.contains(&"Cheat Authentication Server Spoofing in Hosts File"));
    }
}
