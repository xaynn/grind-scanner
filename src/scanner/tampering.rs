use crate::report::{FindingCategory, ScanFinding, ScanReport, VerdictLevel};
use std::mem::zeroed;
use windows_sys::Win32::System::Services::{
    CloseServiceHandle, OpenSCManagerW, OpenServiceW, QueryServiceStatus, SC_MANAGER_CONNECT,
    SERVICE_QUERY_STATUS, SERVICE_RUNNING, SERVICE_STATUS,
};

#[derive(Clone, Debug)]
pub struct SystemBootInfo {
    pub boot_time: chrono::DateTime<chrono::Local>,
    #[allow(dead_code)]
    pub uptime_secs: u64,
    pub uptime_formatted: String,
    pub is_recent_reboot: bool,
}

pub fn get_system_boot_info() -> SystemBootInfo {
    let uptime_ms = unsafe {
        windows_sys::Win32::System::SystemInformation::GetTickCount64()
    };
    let uptime_secs = uptime_ms / 1000;
    let now = chrono::Local::now();
    let boot_time = now - chrono::Duration::milliseconds(uptime_ms as i64);

    let days = uptime_secs / 86400;
    let hours = (uptime_secs % 86400) / 3600;
    let mins = (uptime_secs % 3600) / 60;
    let secs = uptime_secs % 60;

    let uptime_formatted = if days > 0 {
        format!("{}d {}h {}m", days, hours, mins)
    } else if hours > 0 {
        format!("{}h {}m", hours, mins)
    } else {
        format!("{}m {}s", mins, secs)
    };

    // If system was booted/rebooted less than 25 minutes ago
    let is_recent_reboot = uptime_secs < 25 * 60;

    SystemBootInfo {
        boot_time,
        uptime_secs,
        uptime_formatted,
        is_recent_reboot,
    }
}

pub fn check_system_tampering(report: &mut ScanReport) {
    check_system_boot_and_uptime(report);
    check_forensic_services(report);
    check_event_log_clearing(report);
    check_windows_boot_log(report);
    check_event_id_7045_drivers(report);
    check_system_time_manipulation(report);
    check_loaded_kernel_drivers(report);
    check_system_code_integrity(report);
    check_clear_explorer_tampering(report);
}

fn check_system_boot_and_uptime(report: &mut ScanReport) {
    let info = get_system_boot_info();
    let boot_str = info.boot_time.format("%Y-%m-%d %H:%M:%S").to_string();

    if info.is_recent_reboot {
        report.add(
            ScanFinding::new(
                "Niedawny restart systemu Windows",
                FindingCategory::TamperingAndAntiForensics,
                VerdictLevel::Warning,
                format!(
                    "Komputer został zrestartowany/uruchomiony zaledwie {} temu (start: {}). Często restart wykonuje się tuż przed sprawdzeniem (screenshare), aby oczyścić pamięć RAM i usunąć procesy injectora.",
                    info.uptime_formatted, boot_str
                ),
            )
            .with_evidence("Czas włączenia (Boot Time)", boot_str)
            .with_evidence("Czas działania (Uptime)", info.uptime_formatted),
        );
    } else {
        report.add(
            ScanFinding::new(
                "Czas uruchomienia systemu Windows",
                FindingCategory::WindowsForensics,
                VerdictLevel::Information,
                format!(
                    "System Windows został uruchomiony: {} (działa nieprzerwanie od: {}).",
                    boot_str, info.uptime_formatted
                ),
            )
            .with_evidence("Czas włączenia (Boot Time)", boot_str)
            .with_evidence("Czas działania (Uptime)", info.uptime_formatted),
        );
    }
}

fn check_forensic_services(report: &mut ScanReport) {
    let services = [
        ("SysMain", "SysMain (Prefetch/SuperFetch Service)", VerdictLevel::Warning),
        ("PcaSvc", "Program Compatibility Assistant (PcaSvc)", VerdictLevel::Information),
        ("DPS", "Diagnostic Policy Service (DPS / SRUM Engine)", VerdictLevel::Warning),
        ("EventLog", "Windows Event Log (EventLog)", VerdictLevel::Detection),
        ("Dnscache", "DNS Client Cache Service (Dnscache)", VerdictLevel::Warning),
        ("W32Time", "Windows Time Synchronization Service (W32Time)", VerdictLevel::Warning),
    ];

    unsafe {
        let scm = OpenSCManagerW(std::ptr::null(), std::ptr::null(), SC_MANAGER_CONNECT);
        if scm.is_null() {
            return;
        }

        for (svc_name, display_name, severity) in &services {
            let svc_w: Vec<u16> = format!("{}\0", svc_name).encode_utf16().collect();
            let service = OpenServiceW(scm, svc_w.as_ptr(), SERVICE_QUERY_STATUS);

            if service.is_null() {
                report.add(
                    ScanFinding::new(
                        format!("Critical Service Missing: {}", svc_name),
                        FindingCategory::TamperingAndAntiForensics,
                        *severity,
                        format!("Service {} could not be queried or has been uninstalled.", display_name),
                    )
                    .with_evidence("Service", svc_name.to_string()),
                );
                continue;
            }

            let mut status: SERVICE_STATUS = zeroed();
            if QueryServiceStatus(service, &mut status) != 0 {
                if status.dwCurrentState != SERVICE_RUNNING {
                    report.add(
                        ScanFinding::new(
                            format!("Forensic Service Not Running: {}", svc_name),
                            FindingCategory::TamperingAndAntiForensics,
                            *severity,
                            format!("{} is stopped or disabled (State: {}). Often done by bypassers to stop artifacts.", display_name, status.dwCurrentState),
                        )
                        .with_evidence("Service", svc_name.to_string())
                        .with_evidence("State Code", status.dwCurrentState.to_string()),
                    );
                }
            }

            CloseServiceHandle(service);
        }

        CloseServiceHandle(scm);
    }
}

type EvtHandle = *mut std::ffi::c_void;

type EvtQueryFn = unsafe extern "system" fn(
    session: EvtHandle,
    path: *const u16,
    query: *const u16,
    flags: u32,
) -> EvtHandle;

type EvtNextFn = unsafe extern "system" fn(
    result_set: EvtHandle,
    event_array_size: u32,
    event_array: *mut EvtHandle,
    timeout: u32,
    flags: u32,
    returned: *mut u32,
) -> i32;

type EvtCloseFn = unsafe extern "system" fn(handle: EvtHandle) -> i32;

type EvtRenderFn = unsafe extern "system" fn(
    context: EvtHandle,
    fragment: EvtHandle,
    flags: u32,
    buffer_size: u32,
    buffer: *mut std::ffi::c_void,
    buffer_used: *mut u32,
    property_count: *mut u32,
) -> i32;

fn check_event_log_clearing(report: &mut ScanReport) {
    unsafe {
        let wevtapi = windows_sys::Win32::System::LibraryLoader::LoadLibraryA(
            b"wevtapi.dll\0".as_ptr(),
        );
        if wevtapi.is_null() {
            return;
        }

        let p_query = windows_sys::Win32::System::LibraryLoader::GetProcAddress(
            wevtapi,
            b"EvtQuery\0".as_ptr(),
        );
        let p_next = windows_sys::Win32::System::LibraryLoader::GetProcAddress(
            wevtapi,
            b"EvtNext\0".as_ptr(),
        );
        let p_close = windows_sys::Win32::System::LibraryLoader::GetProcAddress(
            wevtapi,
            b"EvtClose\0".as_ptr(),
        );
        let p_render = windows_sys::Win32::System::LibraryLoader::GetProcAddress(
            wevtapi,
            b"EvtRender\0".as_ptr(),
        );

        if let (Some(f_query), Some(f_next), Some(f_close), Some(f_render)) = (p_query, p_next, p_close, p_render) {
            let evt_query: EvtQueryFn = std::mem::transmute(f_query);
            let evt_next: EvtNextFn = std::mem::transmute(f_next);
            let evt_close: EvtCloseFn = std::mem::transmute(f_close);
            let evt_render: EvtRenderFn = std::mem::transmute(f_render);

            let checks = [
                ("Security", "*[System[(EventID=1102)]]", 1102, "The audit log was cleared"),
                ("System", "*[System[(EventID=104)]]", 104, "The log file was cleared"),
            ];

            const EVT_QUERY_CHANNEL_PATH: u32 = 0x1;
            const EVT_QUERY_REVERSE_DIRECTION: u32 = 0x200;
            let query_flags = EVT_QUERY_CHANNEL_PATH | EVT_QUERY_REVERSE_DIRECTION;

            for (channel, query, event_id, desc) in checks {
                let chan_w: Vec<u16> = format!("{}\0", channel).encode_utf16().collect();
                let query_w: Vec<u16> = format!("{}\0", query).encode_utf16().collect();

                let h_query = evt_query(
                    std::ptr::null_mut(),
                    chan_w.as_ptr(),
                    query_w.as_ptr(),
                    query_flags,
                );

                if !h_query.is_null() {
                    let mut events: [EvtHandle; 1] = [std::ptr::null_mut()];
                    let mut returned = 0u32;

                    if evt_next(h_query, 1, events.as_mut_ptr(), 500, 0, &mut returned) != 0 && returned > 0 {
                        let h_event = events[0];
                        let mut time_str = "Zarejestrowano w dzienniku zdarzeń".to_string();

                        // Attempt to render event XML and extract timestamp
                        let mut buf = [0u16; 2048];
                        let mut used = 0u32;
                        let mut prop_count = 0u32;
                        if evt_render(
                            std::ptr::null_mut(),
                            h_event,
                            1, // EvtRenderEventXml
                            (buf.len() * 2) as u32,
                            buf.as_mut_ptr() as *mut std::ffi::c_void,
                            &mut used,
                            &mut prop_count,
                        ) != 0 && used > 0 {
                            let xml_len = (used as usize / 2).saturating_sub(1);
                            let xml_text = String::from_utf16_lossy(&buf[..xml_len]);
                            if let Some(pos) = xml_text.find("SystemTime='") {
                                if let Some(end) = xml_text[pos + 12..].find('\'') {
                                    time_str = xml_text[pos + 12..pos + 12 + end].to_string();
                                }
                            } else if let Some(pos) = xml_text.find("SystemTime=\"") {
                                if let Some(end) = xml_text[pos + 12..].find('"') {
                                    time_str = xml_text[pos + 12..pos + 12 + end].to_string();
                                }
                            }
                        }

                        evt_close(h_event);

                        report.add(
                            ScanFinding::new(
                                format!("Windows Event Log Cleared (Event ID {})", event_id),
                                FindingCategory::TamperingAndAntiForensics,
                                VerdictLevel::Detection,
                                format!(
                                    "Wykryto wyczyszczenie dziennika zdarzeń '{}' ({}). Jest to krytyczny wskaźnik użycia narzędzia typu cleaner lub polecenia wevtutil cl.",
                                    channel, desc
                                ),
                            )
                            .with_evidence("Dziennik zdarzeń", channel.to_string())
                            .with_evidence("Identyfikator zdarzenia", format!("{} ({})", event_id, desc))
                            .with_evidence("Czas zdarzenia (SystemTime)", time_str),
                        );
                    }

                    evt_close(h_query);
                }
            }
        }

        windows_sys::Win32::Foundation::FreeLibrary(wevtapi);
    }
}

fn extract_xml_system_time(xml: &str) -> Option<String> {
    if let Some(pos) = xml.find("SystemTime='") {
        if let Some(end) = xml[pos + 12..].find('\'') {
            return Some(xml[pos + 12..pos + 12 + end].to_string());
        }
    } else if let Some(pos) = xml.find("SystemTime=\"") {
        if let Some(end) = xml[pos + 12..].find('"') {
            return Some(xml[pos + 12..pos + 12 + end].to_string());
        }
    }
    None
}

pub fn check_event_id_7045_drivers(report: &mut ScanReport) {
    unsafe {
        let wevtapi = windows_sys::Win32::System::LibraryLoader::LoadLibraryA(
            b"wevtapi.dll\0".as_ptr(),
        );
        if wevtapi.is_null() {
            return;
        }

        let p_query = windows_sys::Win32::System::LibraryLoader::GetProcAddress(
            wevtapi,
            b"EvtQuery\0".as_ptr(),
        );
        let p_next = windows_sys::Win32::System::LibraryLoader::GetProcAddress(
            wevtapi,
            b"EvtNext\0".as_ptr(),
        );
        let p_close = windows_sys::Win32::System::LibraryLoader::GetProcAddress(
            wevtapi,
            b"EvtClose\0".as_ptr(),
        );
        let p_render = windows_sys::Win32::System::LibraryLoader::GetProcAddress(
            wevtapi,
            b"EvtRender\0".as_ptr(),
        );

        if let (Some(f_query), Some(f_next), Some(f_close), Some(f_render)) = (p_query, p_next, p_close, p_render) {
            let evt_query: EvtQueryFn = std::mem::transmute(f_query);
            let evt_next: EvtNextFn = std::mem::transmute(f_next);
            let evt_close: EvtCloseFn = std::mem::transmute(f_close);
            let evt_render: EvtRenderFn = std::mem::transmute(f_render);

            const EVT_QUERY_CHANNEL_PATH: u32 = 0x1;
            const EVT_QUERY_REVERSE_DIRECTION: u32 = 0x200;
            let query_flags = EVT_QUERY_CHANNEL_PATH | EVT_QUERY_REVERSE_DIRECTION;

            let chan_w: Vec<u16> = "System\0".encode_utf16().collect();
            let query_w: Vec<u16> = "*[System[(EventID=7045)]]\0".encode_utf16().collect();

            let h_query = evt_query(
                std::ptr::null_mut(),
                chan_w.as_ptr(),
                query_w.as_ptr(),
                query_flags,
            );

            if !h_query.is_null() {
                let mut events: [EvtHandle; 64] = [std::ptr::null_mut(); 64];
                let mut returned = 0u32;

                if evt_next(h_query, 64, events.as_mut_ptr(), 500, 0, &mut returned) != 0 && returned > 0 {
                    let mut reported_services = std::collections::HashSet::new();

                    for i in 0..returned as usize {
                        let h_event = events[i];
                        let mut buf = [0u16; 4096];
                        let mut used = 0u32;
                        let mut prop_count = 0u32;

                        if evt_render(
                            std::ptr::null_mut(),
                            h_event,
                            1, // EvtRenderEventXml
                            (buf.len() * 2) as u32,
                            buf.as_mut_ptr() as *mut std::ffi::c_void,
                            &mut used,
                            &mut prop_count,
                        ) != 0 && used > 0 {
                            let xml_len = (used as usize / 2).saturating_sub(1);
                            let xml_text = String::from_utf16_lossy(&buf[..xml_len]);

                            let service_name = extract_xml_data_val(&xml_text, "ServiceName").unwrap_or_default();
                            let raw_image_path = extract_xml_data_val(&xml_text, "ImagePath").unwrap_or_default();
                            let service_type = extract_xml_data_val(&xml_text, "ServiceType").unwrap_or_default();
                            let time_created_str = extract_xml_system_time(&xml_text);

                            let clean_path = crate::scanner::forensics::normalize_device_path(&raw_image_path);
                            let lower_path = clean_path.to_lowercase();
                            let lower_svc = service_name.to_lowercase();
                            let lower_type = service_type.to_lowercase();

                            // Determine if event occurred in the current session
                            let mut is_current_session = false;
                            let mut time_display = time_created_str.clone().unwrap_or_else(|| "Nieznany".to_string());

                            if let Some(ref t_str) = time_created_str {
                                if let Ok(dt) = chrono::DateTime::parse_from_rfc3339(t_str) {
                                    let unix_secs = dt.timestamp().max(0) as u64;
                                    let boot_secs = crate::scanner::forensics::get_boot_unix_timestamp();
                                    is_current_session = unix_secs >= boot_secs.saturating_sub(60);
                                    let local_dt: chrono::DateTime<chrono::Local> = dt.with_timezone(&chrono::Local);
                                    time_display = local_dt.format("%Y-%m-%d %H:%M:%S").to_string();
                                }
                            }

                            // 1. Check for match against known vulnerable BYOVD drivers
                            let mut matched_vuln = None;
                            for info in KNOWN_VULNERABLE_DRIVERS {
                                let driver_base = info.driver_name.strip_suffix(".sys").unwrap_or(info.driver_name);
                                if lower_path.ends_with(info.driver_name)
                                    || lower_svc == info.driver_name
                                    || lower_svc == driver_base
                                {
                                    matched_vuln = Some(*info);
                                    break;
                                }
                            }

                            if let Some(vuln) = matched_vuln {
                                // Ignore driver installations from prior system boot sessions
                                if !is_current_session {
                                    continue;
                                }

                                if reported_services.insert(format!("vuln_{}", vuln.driver_name)) {
                                    let verdict = VerdictLevel::Detection;
                                    let title = format!("Vulnerable Kernel Driver Service Installed (Event ID 7045): {}", vuln.driver_name);
                                    let session_desc = "w BIEŻĄCEJ SESJI gry (Active Gaming Session)";

                                    report.add(
                                        ScanFinding::new(
                                            title,
                                            FindingCategory::TamperingAndAntiForensics,
                                            verdict,
                                            format!(
                                                "Wykryto rejestrację podatnego sterownika jądra (BYOVD) w Dzienniku Zdarzeń System {} (o: {}): {}. Sterownik ten mógł zostać wyładowany przed sprawdzeniem screenshare (sc stop / sc delete), jednak rejestr zdarzeń zachował trwały dowód jego instalacji. {}",
                                                session_desc, time_display, vuln.driver_name, vuln.threat_description
                                            ),
                                        )
                                        .with_evidence("Nazwa usługi (ServiceName)", service_name)
                                        .with_evidence("Ścieżka pliku sterownika (ImagePath)", clean_path)
                                        .with_evidence("Czas instalacji (TimeCreated)", time_display)
                                        .with_evidence("Status sesji", "BIEŻĄCA SESJA SYSTEMU (Active Session)".to_string())
                                        .with_evidence("Wektor ataku / Podatność", vuln.cve_or_vector.to_string())
                                        .with_evidence("Opis podatności", vuln.threat_description.to_string()),
                                    );
                                }
                            } else if is_current_session && (lower_type.contains("driver") || lower_path.ends_with(".sys")) {
                                // 2. Kernel driver installed in current session from a suspicious volatile path (Temp, Downloads, Desktop, Public, PerfLogs)
                                let is_in_volatile = crate::scanner::forensics::is_volatile_directory(&lower_path);
                                let is_in_appdata = lower_path.contains("\\appdata\\");

                                if is_in_volatile && reported_services.insert(format!("temp_driver_{}", lower_svc)) {
                                    report.add(
                                        ScanFinding::new(
                                            format!("Suspicious Kernel Driver Installed from Temp/User Directory (Event ID 7045): {}", service_name),
                                            FindingCategory::TamperingAndAntiForensics,
                                            VerdictLevel::Detection,
                                            format!(
                                                "Wykryto rejestrację sterownika jądra bezpośrednio z katalogu tymczasowego/użytkownika w bieżącej sesji gry ({}). Jest to krytyczna sygnatura użycia kdmapper / Ring0 manual mappera zacierającego ślady.",
                                                clean_path
                                            ),
                                        )
                                        .with_evidence("Nazwa usługi (ServiceName)", service_name)
                                        .with_evidence("Ścieżka sterownika (ImagePath)", clean_path)
                                        .with_evidence("Typ usługi", service_type)
                                        .with_evidence("Czas instalacji (TimeCreated)", time_display)
                                        .with_evidence("Klasyfikacja", "BYOVD / Kdmapper Staging in User Directory".to_string()),
                                    );
                                } else if is_in_appdata && reported_services.insert(format!("appdata_driver_{}", lower_svc)) {
                                    report.add(
                                        ScanFinding::new(
                                            format!("Kernel Driver Installed from AppData (Event ID 7045): {}", service_name),
                                            FindingCategory::TamperingAndAntiForensics,
                                            VerdictLevel::Warning,
                                            format!(
                                                "Wykryto instalację sterownika jądra z katalogu AppData w bieżącej sesji: {}.",
                                                clean_path
                                            ),
                                        )
                                        .with_evidence("Nazwa usługi", service_name)
                                        .with_evidence("Ścieżka", clean_path)
                                        .with_evidence("Czas instalacji", time_display),
                                    );
                                }
                            }
                        }

                        evt_close(h_event);
                    }
                }

                evt_close(h_query);
            }
        }

        windows_sys::Win32::Foundation::FreeLibrary(wevtapi);
    }
}

fn check_system_time_manipulation(report: &mut ScanReport) {
    unsafe {
        let wevtapi = windows_sys::Win32::System::LibraryLoader::LoadLibraryA(
            b"wevtapi.dll\0".as_ptr(),
        );
        if wevtapi.is_null() {
            return;
        }

        let p_query = windows_sys::Win32::System::LibraryLoader::GetProcAddress(
            wevtapi,
            b"EvtQuery\0".as_ptr(),
        );
        let p_next = windows_sys::Win32::System::LibraryLoader::GetProcAddress(
            wevtapi,
            b"EvtNext\0".as_ptr(),
        );
        let p_close = windows_sys::Win32::System::LibraryLoader::GetProcAddress(
            wevtapi,
            b"EvtClose\0".as_ptr(),
        );
        let p_render = windows_sys::Win32::System::LibraryLoader::GetProcAddress(
            wevtapi,
            b"EvtRender\0".as_ptr(),
        );

        if let (Some(f_query), Some(f_next), Some(f_close), Some(f_render)) = (p_query, p_next, p_close, p_render) {
            let evt_query: EvtQueryFn = std::mem::transmute(f_query);
            let evt_next: EvtNextFn = std::mem::transmute(f_next);
            let evt_close: EvtCloseFn = std::mem::transmute(f_close);
            let evt_render: EvtRenderFn = std::mem::transmute(f_render);

            const EVT_QUERY_CHANNEL_PATH: u32 = 0x1;
            const EVT_QUERY_REVERSE_DIRECTION: u32 = 0x200;
            let query_flags = EVT_QUERY_CHANNEL_PATH | EVT_QUERY_REVERSE_DIRECTION;

            let chan_w: Vec<u16> = "System\0".encode_utf16().collect();
            let query_w: Vec<u16> = "*[System[Provider[@Name='Microsoft-Windows-Kernel-General'] and (EventID=1)]]\0"
                .encode_utf16()
                .collect();

            let h_query = evt_query(
                std::ptr::null_mut(),
                chan_w.as_ptr(),
                query_w.as_ptr(),
                query_flags,
            );

            if !h_query.is_null() {
                let mut events: [EvtHandle; 5] = [std::ptr::null_mut(); 5];
                let mut returned = 0u32;

                if evt_next(h_query, 5, events.as_mut_ptr(), 500, 0, &mut returned) != 0 && returned > 0 {
                    for i in 0..returned as usize {
                        let h_event = events[i];
                        let mut buf = [0u16; 2048];
                        let mut used = 0u32;
                        let mut prop_count = 0u32;

                        if evt_render(
                            std::ptr::null_mut(),
                            h_event,
                            1, // EvtRenderEventXml
                            (buf.len() * 2) as u32,
                            buf.as_mut_ptr() as *mut std::ffi::c_void,
                            &mut used,
                            &mut prop_count,
                        ) != 0 && used > 0 {
                            let xml_len = (used as usize / 2).saturating_sub(1);
                            let xml_text = String::from_utf16_lossy(&buf[..xml_len]);

                            let old_time = extract_xml_data_val(&xml_text, "OldTime");
                            let new_time = extract_xml_data_val(&xml_text, "NewTime");

                            if let (Some(ref old_str), Some(ref new_str)) = (old_time, new_time) {
                                if let (Ok(old_dt), Ok(new_dt)) = (
                                    chrono::DateTime::parse_from_rfc3339(old_str),
                                    chrono::DateTime::parse_from_rfc3339(new_str),
                                ) {
                                    // Check if time was rolled backwards (NewTime < OldTime)
                                    if new_dt < old_dt {
                                        let diff = (old_dt - new_dt).num_seconds();
                                        // Filter out minor NTP synchronization jitter (e.g. under 15 seconds)
                                        if diff > 15 {
                                            let days = diff / 86400;
                                            let hours = (diff % 86400) / 3600;
                                            let mins = (diff % 3600) / 60;
                                            let secs = diff % 60;
                                            let diff_fmt = if days > 0 {
                                                format!("{}d {}h {}m ({} s wstecz)", days, hours, mins, diff)
                                            } else if hours > 0 {
                                                format!("{}h {}m {}s ({} s wstecz)", hours, mins, secs, diff)
                                            } else {
                                                format!("{}m {}s ({} s wstecz)", mins, secs, diff)
                                            };

                                            report.add(
                                                ScanFinding::new(
                                                    "System Time Rollback Detected (Event ID 1)",
                                                    FindingCategory::TamperingAndAntiForensics,
                                                    VerdictLevel::Detection,
                                                    format!(
                                                        "Wykryto celowe cofnięcie zegara systemowego Windows o {}. Technika ta służy do zafałszowania znaczników czasu w Prefetch, USN Journal i BAM przed sprawdzeniem screenshare.",
                                                        diff_fmt
                                                    ),
                                                )
                                                .with_evidence("Nowy czas (NewTime)", new_str.clone())
                                                .with_evidence("Poprzedni czas (OldTime)", old_str.clone())
                                                .with_evidence("Wartość cofnięcia zegara", diff_fmt)
                                                .with_evidence("Źródło zdarzenia", "System (Microsoft-Windows-Kernel-General)".to_string()),
                                            );
                                            evt_close(h_event);
                                            break;
                                        }
                                    }
                                }
                            }
                        }

                        evt_close(h_event);
                    }
                }

                evt_close(h_query);
            }
        }

        windows_sys::Win32::Foundation::FreeLibrary(wevtapi);
    }
}

fn extract_xml_data_val(xml: &str, data_name: &str) -> Option<String> {
    let patterns = [
        format!("Name='{}'>", data_name),
        format!("Name=\"{}\">", data_name),
    ];
    for p in &patterns {
        if let Some(pos) = xml.find(p) {
            let start = pos + p.len();
            if let Some(end) = xml[start..].find("</Data>") {
                return Some(xml[start..start + end].trim().to_string());
            }
        }
    }
    None
}

#[derive(Clone, Copy)]
pub struct VulnerableDriverInfo {
    pub driver_name: &'static str,
    pub threat_description: &'static str,
    pub cve_or_vector: &'static str,
    pub verdict: VerdictLevel,
}

pub const KNOWN_VULNERABLE_DRIVERS: &[VulnerableDriverInfo] = &[
    VulnerableDriverInfo {
        driver_name: "gdrv.sys",
        threat_description: "Sterownik Gigabyte z podatnością arbitralnego odczytu/zapisu pamięci jądra (CVE-2018-19320), masowo nadużywany przez cheat mappers (kdmapper / ring0 mappers)",
        cve_or_vector: "CVE-2018-19320 (Arbitrary Ring0 RW / DSE Bypass)",
        verdict: VerdictLevel::Detection,
    },
    VulnerableDriverInfo {
        driver_name: "mhyprot2.sys",
        threat_description: "Podatny sterownik Genshin Impact nadużywany do omijania DSE, manipulacji pamięcią procesów gry i blokowania callbacków bezpieczeństwa",
        cve_or_vector: "CVE-2020-28432 (Arbitrary Kernel RW)",
        verdict: VerdictLevel::Detection,
    },
    VulnerableDriverInfo {
        driver_name: "mhyprot3.sys",
        threat_description: "Podatny sterownik jądra z rodziny mhyprot nadużywany w exploitach i loaderach cheatów",
        cve_or_vector: "Kernel Ring0 Arbitrary RW",
        verdict: VerdictLevel::Detection,
    },
    VulnerableDriverInfo {
        driver_name: "rtcore64.sys",
        threat_description: "Sterownik MSI Afterburner z podatnością na bezpośredni odczyt/zapis pamięci fizycznej i wirtualnej (CVE-2019-16098)",
        cve_or_vector: "CVE-2019-16098 (Arbitrary Physical/Virtual Memory RW)",
        verdict: VerdictLevel::Detection,
    },
    VulnerableDriverInfo {
        driver_name: "rtcore32.sys",
        threat_description: "Sterownik MSI Afterburner (32-bit) z podatnością na bezpośredni odczyt/zapis pamięci",
        cve_or_vector: "CVE-2019-16098 (Arbitrary Physical/Virtual Memory RW)",
        verdict: VerdictLevel::Detection,
    },
    VulnerableDriverInfo {
        driver_name: "kprocesshacker.sys",
        threat_description: "Sterownik jądra Process Hacker / System Informer - nadużywany przez cheaty do otwierania uchwytów PROCESS_ALL_ACCESS i usuwania hooków",
        cve_or_vector: "Kernel Process Handle Duplication & RW",
        verdict: VerdictLevel::Detection,
    },
    VulnerableDriverInfo {
        driver_name: "kprocesshacker-2.sys",
        threat_description: "Sterownik jądra Process Hacker v2 - nadużywany do manipulacji procesami gier w ring0",
        cve_or_vector: "Kernel Process Handle Duplication & RW",
        verdict: VerdictLevel::Detection,
    },
    VulnerableDriverInfo {
        driver_name: "iqvw64e.sys",
        threat_description: "Sterownik diagnostyczny Intel Network Adapter, kluczowy sterownik kdmapper używany do manual mapingu niepodpisanych modułów w jądrze Windows",
        cve_or_vector: "kdmapper / Ring0 Memory Mapper",
        verdict: VerdictLevel::Detection,
    },
    VulnerableDriverInfo {
        driver_name: "dbutil_2_3.sys",
        threat_description: "Podatny sterownik Dell BIOS Utility (CVE-2021-21551) pozwalający na arbitralne nadpisanie pamięci jądra",
        cve_or_vector: "CVE-2021-21551 (Arbitrary Kernel Memory Write)",
        verdict: VerdictLevel::Detection,
    },
    VulnerableDriverInfo {
        driver_name: "dbutil.sys",
        threat_description: "Podatny sterownik Dell BIOS Update pozwalający na nadpisanie pamięci jądra",
        cve_or_vector: "Arbitrary Kernel Memory Write",
        verdict: VerdictLevel::Detection,
    },
    VulnerableDriverInfo {
        driver_name: "echo.sys",
        threat_description: "Sterownik jądra narzędzia Echo / screenshare / cheat loader",
        cve_or_vector: "Kernel Driver Trace",
        verdict: VerdictLevel::Warning,
    },
    VulnerableDriverInfo {
        driver_name: "echodriver.sys",
        threat_description: "Sterownik jądra powiązany z narzędziami screenshare / echo tool",
        cve_or_vector: "Kernel Driver Trace",
        verdict: VerdictLevel::Warning,
    },
    VulnerableDriverInfo {
        driver_name: "capcom.sys",
        threat_description: "Podatny sterownik Capcom wyłączający SMEP i umożliwiający wykonanie kodu usermode w ring0",
        cve_or_vector: "Capcom SMEP Disable Exploit",
        verdict: VerdictLevel::Detection,
    },
    VulnerableDriverInfo {
        driver_name: "asiodrv.sys",
        threat_description: "Podatny sterownik ASUS (CVE-2018-18537) z arbitralnym dostępem do pamięci fizycznej",
        cve_or_vector: "CVE-2018-18537 (Physical Memory RW)",
        verdict: VerdictLevel::Detection,
    },
    VulnerableDriverInfo {
        driver_name: "asusio.sys",
        threat_description: "Podatny sterownik ASUS IO z niekontrolowanym dostępem do portów i pamięci jądra",
        cve_or_vector: "Kernel IO Access Exploit",
        verdict: VerdictLevel::Detection,
    },
    VulnerableDriverInfo {
        driver_name: "winring0.sys",
        threat_description: "Sterownik WinRing0 (OpenLibSys) pozwalający na nieautoryzowany dostęp usermode do portów I/O i rejestrów MSR procesora",
        cve_or_vector: "Arbitrary Ring0 Port/MSR Access",
        verdict: VerdictLevel::Detection,
    },
    VulnerableDriverInfo {
        driver_name: "winring0x64.sys",
        threat_description: "Sterownik WinRing0 x64 (OpenLibSys) z arbitralnym dostępem usermode do ring0",
        cve_or_vector: "Arbitrary Ring0 Port/MSR Access",
        verdict: VerdictLevel::Detection,
    },
    VulnerableDriverInfo {
        driver_name: "speedfan.sys",
        threat_description: "Podatny sterownik SpeedFan (CVE-2007-5633) pozwalający na arbitralny odczyt/zapis pamięci fizycznej",
        cve_or_vector: "CVE-2007-5633 (Arbitrary Physical Memory RW)",
        verdict: VerdictLevel::Detection,
    },
    VulnerableDriverInfo {
        driver_name: "enctool.sys",
        threat_description: "Podatny sterownik Enctool pozwalający na nieautoryzowaną modyfikację pamięci fizycznej",
        cve_or_vector: "Physical Memory RW",
        verdict: VerdictLevel::Detection,
    },
    VulnerableDriverInfo {
        driver_name: "ene.sys",
        threat_description: "Podatny sterownik ENE Technology z arbitralnym odczytem/zapisem pamięci fizycznej",
        cve_or_vector: "Physical Memory RW",
        verdict: VerdictLevel::Detection,
    },
    VulnerableDriverInfo {
        driver_name: "eneio.sys",
        threat_description: "Podatny sterownik ENE IO z dostępem do pamięci jądra",
        cve_or_vector: "Physical Memory RW",
        verdict: VerdictLevel::Detection,
    },
    VulnerableDriverInfo {
        driver_name: "blackbone.sys",
        threat_description: "Sterownik jądra BlackBone służący do wstrzykiwania kodu i manual mapingu do procesów",
        cve_or_vector: "BlackBone Kernel Injection Engine",
        verdict: VerdictLevel::Detection,
    },
    VulnerableDriverInfo {
        driver_name: "atsiv.sys",
        threat_description: "Narzędzie ładowania niepodpisanych sterowników jądra (Atsiv signed loader)",
        cve_or_vector: "Unsigned Driver Ring0 Loader",
        verdict: VerdictLevel::Detection,
    },
];

type EnumDeviceDriversFn = unsafe extern "system" fn(
    lp_image_base: *mut *mut std::ffi::c_void,
    cb: u32,
    lpcb_needed: *mut u32,
) -> i32;

type GetDeviceDriverBaseNameAFn = unsafe extern "system" fn(
    image_base: *mut std::ffi::c_void,
    lp_filename: *mut u8,
    n_size: u32,
) -> u32;

type GetDeviceDriverFileNameAFn = unsafe extern "system" fn(
    image_base: *mut std::ffi::c_void,
    lp_filename: *mut u8,
    n_size: u32,
) -> u32;

pub fn check_loaded_kernel_drivers(report: &mut ScanReport) {
    unsafe {
        let psapi = windows_sys::Win32::System::LibraryLoader::LoadLibraryA(b"psapi.dll\0".as_ptr());
        let (mut p_enum, mut p_base, mut p_file) = if !psapi.is_null() {
            (
                windows_sys::Win32::System::LibraryLoader::GetProcAddress(psapi, b"EnumDeviceDrivers\0".as_ptr()),
                windows_sys::Win32::System::LibraryLoader::GetProcAddress(psapi, b"GetDeviceDriverBaseNameA\0".as_ptr()),
                windows_sys::Win32::System::LibraryLoader::GetProcAddress(psapi, b"GetDeviceDriverFileNameA\0".as_ptr()),
            )
        } else {
            (None, None, None)
        };

        let mut kernel32 = std::ptr::null_mut();
        if p_enum.is_none() {
            kernel32 = windows_sys::Win32::System::LibraryLoader::LoadLibraryA(b"kernel32.dll\0".as_ptr());
            if !kernel32.is_null() {
                p_enum = windows_sys::Win32::System::LibraryLoader::GetProcAddress(kernel32, b"K32EnumDeviceDrivers\0".as_ptr());
                p_base = windows_sys::Win32::System::LibraryLoader::GetProcAddress(kernel32, b"K32GetDeviceDriverBaseNameA\0".as_ptr());
                p_file = windows_sys::Win32::System::LibraryLoader::GetProcAddress(kernel32, b"K32GetDeviceDriverFileNameA\0".as_ptr());
            }
        }

        if let (Some(enum_raw), Some(base_raw)) = (p_enum, p_base) {
            let enum_drivers: EnumDeviceDriversFn = std::mem::transmute(enum_raw);
            let get_base_name: GetDeviceDriverBaseNameAFn = std::mem::transmute(base_raw);
            let get_file_name: Option<GetDeviceDriverFileNameAFn> = p_file.map(|f| std::mem::transmute(f));

            let mut drivers: [*mut std::ffi::c_void; 2048] = [std::ptr::null_mut(); 2048];
            let mut cb_needed: u32 = 0;

            if enum_drivers(
                drivers.as_mut_ptr(),
                (drivers.len() * std::mem::size_of::<*mut std::ffi::c_void>()) as u32,
                &mut cb_needed,
            ) != 0
            {
                let count = (cb_needed as usize / std::mem::size_of::<*mut std::ffi::c_void>()).min(drivers.len());

                for &driver_base in &drivers[..count] {
                    if driver_base.is_null() {
                        continue;
                    }

                    let mut base_name_buf = [0u8; 260];
                    let name_len = get_base_name(driver_base, base_name_buf.as_mut_ptr(), base_name_buf.len() as u32);
                    if name_len > 0 {
                        let base_name = String::from_utf8_lossy(&base_name_buf[..name_len as usize]).to_lowercase();

                        for info in KNOWN_VULNERABLE_DRIVERS {
                            if base_name == info.driver_name {
                                let mut full_path = String::new();
                                if let Some(file_fn) = get_file_name {
                                    let mut path_buf = [0u8; 512];
                                    let path_len = file_fn(driver_base, path_buf.as_mut_ptr(), path_buf.len() as u32);
                                    if path_len > 0 {
                                        full_path = String::from_utf8_lossy(&path_buf[..path_len as usize]).to_string();
                                    }
                                }

                                let mut finding = ScanFinding::new(
                                    format!("Vulnerable Kernel Driver Loaded: {}", info.driver_name),
                                    FindingCategory::TamperingAndAntiForensics,
                                    info.verdict,
                                    format!(
                                        "Wykryto załadowany podatny lub podejrzany sterownik jądra Windows (BYOVD): {}. {}",
                                        info.driver_name, info.threat_description
                                    ),
                                )
                                .with_evidence("Nazwa sterownika", info.driver_name.to_string())
                                .with_evidence("Wektor zagrożenia", info.cve_or_vector.to_string())
                                .with_evidence("Adres bazowy w ring0", format!("0x{:X}", driver_base as usize));

                                if !full_path.is_empty() {
                                    finding = finding.with_evidence("Ścieżka systemowa", full_path);
                                }

                                report.add(finding);
                                break;
                            }
                        }
                    }
                }
            }
        }

        if !psapi.is_null() {
            windows_sys::Win32::Foundation::FreeLibrary(psapi);
        }
        if !kernel32.is_null() {
            windows_sys::Win32::Foundation::FreeLibrary(kernel32);
        }
    }
}

pub fn check_system_code_integrity(report: &mut ScanReport) {
    unsafe {
        let ntdll = windows_sys::Win32::System::LibraryLoader::LoadLibraryA(b"ntdll.dll\0".as_ptr());
        if ntdll.is_null() {
            return;
        }

        let p_query = windows_sys::Win32::System::LibraryLoader::GetProcAddress(
            ntdll,
            b"NtQuerySystemInformation\0".as_ptr(),
        );

        if let Some(p_query) = p_query {
            #[repr(C)]
            struct SystemCodeIntegrityInformation {
                length: u32,
                code_integrity_options: u32,
            }

            type NtQuerySystemInformationFn = unsafe extern "system" fn(
                system_information_class: u32,
                system_information: *mut std::ffi::c_void,
                system_information_length: u32,
                return_length: *mut u32,
            ) -> i32;

            let query_fn: NtQuerySystemInformationFn = std::mem::transmute(p_query);
            let mut sci = SystemCodeIntegrityInformation {
                length: std::mem::size_of::<SystemCodeIntegrityInformation>() as u32,
                code_integrity_options: 0,
            };
            let mut ret_len = 0u32;

            // SystemCodeIntegrityInformation = 103 (0x67)
            if query_fn(103, &mut sci as *mut _ as *mut std::ffi::c_void, sci.length, &mut ret_len) == 0 {
                // CODEINTEGRITY_OPTION_TESTSIGN = 0x02
                if sci.code_integrity_options & 0x02 != 0 {
                    report.add(
                        ScanFinding::new(
                            "Windows Kernel Test-Signing Mode Active (TESTSIGNING ON)",
                            FindingCategory::TamperingAndAntiForensics,
                            VerdictLevel::Detection,
                            "System Windows działa w trybie Test-Signing (podpisywanie testowe sterowników). Umożliwia to załadowanie dowolnego niepodpisanego sterownika cheatów do pamięci jądra.",
                        )
                        .with_evidence("CodeIntegrity Options", format!("0x{:08X}", sci.code_integrity_options))
                        .with_evidence("Stan integralności", "Driver Signature Enforcement jest wyłączone lub w trybie testowym".to_string()),
                    );
                }

                // CODEINTEGRITY_OPTION_DEBUGMODE_ENABLED = 0x80
                if sci.code_integrity_options & 0x80 != 0 {
                    report.add(
                        ScanFinding::new(
                            "Windows Kernel Debugging Enabled",
                            FindingCategory::TamperingAndAntiForensics,
                            VerdictLevel::Warning,
                            "W systemie Windows aktywny jest tryb debugowania jądra (Kernel Debugging). Tryb ten może być używany do manipulacji pamięcią jądra i omijania osłon antycheatowych.",
                        )
                        .with_evidence("CodeIntegrity Options", format!("0x{:08X}", sci.code_integrity_options)),
                    );
                }
            }
        }

        windows_sys::Win32::Foundation::FreeLibrary(ntdll);
    }
}

pub fn check_clear_explorer_tampering(report: &mut ScanReport) {
    check_explorer_process_restart(report);
    check_explorer_mru_and_recent_clearing(report);
    check_explorer_thumbcache_tampering(report);
}

fn check_explorer_process_restart(report: &mut ScanReport) {
    unsafe {
        let snapshot = windows_sys::Win32::System::Diagnostics::ToolHelp::CreateToolhelp32Snapshot(
            windows_sys::Win32::System::Diagnostics::ToolHelp::TH32CS_SNAPPROCESS,
            0,
        );
        if snapshot == windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE {
            return;
        }

        let mut entry: windows_sys::Win32::System::Diagnostics::ToolHelp::PROCESSENTRY32W = zeroed();
        entry.dwSize = std::mem::size_of::<windows_sys::Win32::System::Diagnostics::ToolHelp::PROCESSENTRY32W>() as u32;

        if windows_sys::Win32::System::Diagnostics::ToolHelp::Process32FirstW(snapshot, &mut entry) != 0 {
            loop {
                let name_len = entry.szExeFile.iter().position(|&c| c == 0).unwrap_or(entry.szExeFile.len());
                let proc_name = String::from_utf16_lossy(&entry.szExeFile[..name_len]).to_lowercase();

                if proc_name == "explorer.exe" {
                    let h_proc = windows_sys::Win32::System::Threading::OpenProcess(
                        windows_sys::Win32::System::Threading::PROCESS_QUERY_LIMITED_INFORMATION,
                        0,
                        entry.th32ProcessID,
                    );

                    if !h_proc.is_null() && h_proc != windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE {
                        let mut creation_time: windows_sys::Win32::Foundation::FILETIME = zeroed();
                        let mut exit_time: windows_sys::Win32::Foundation::FILETIME = zeroed();
                        let mut kernel_time: windows_sys::Win32::Foundation::FILETIME = zeroed();
                        let mut user_time: windows_sys::Win32::Foundation::FILETIME = zeroed();

                        if windows_sys::Win32::System::Threading::GetProcessTimes(
                            h_proc,
                            &mut creation_time,
                            &mut exit_time,
                            &mut kernel_time,
                            &mut user_time,
                        ) != 0 {
                            let ft = ((creation_time.dwHighDateTime as u64) << 32)
                                | (creation_time.dwLowDateTime as u64);

                            if let Some(explorer_unix_secs) = crate::scanner::forensics::filetime_to_unix_secs(ft) {
                                let boot_unix_secs = crate::scanner::forensics::get_boot_unix_timestamp();
                                let now_unix_secs = chrono::Utc::now().timestamp().max(0) as u64;

                                let explorer_uptime_secs = now_unix_secs.saturating_sub(explorer_unix_secs);
                                let system_uptime_secs = now_unix_secs.saturating_sub(boot_unix_secs);

                                // If system has been up for more than 3 minutes (180s),
                                // and explorer.exe started more than 90s after system boot:
                                // this indicates explorer.exe was killed and restarted (Explorer Clear)!
                                if system_uptime_secs > 180 && explorer_unix_secs > boot_unix_secs + 90 {
                                    let restart_time_str = crate::scanner::forensics::format_filetime(ft)
                                        .unwrap_or_else(|| "Nieznany".to_string());
                                    let time_since_restart_fmt = if explorer_uptime_secs < 60 {
                                        format!("{} sekund temu", explorer_uptime_secs)
                                    } else if explorer_uptime_secs < 3600 {
                                        format!("{} minut temu", explorer_uptime_secs / 60)
                                    } else {
                                        format!("{}h {}m temu", explorer_uptime_secs / 3600, (explorer_uptime_secs % 3600) / 60)
                                    };

                                    report.add(
                                        ScanFinding::new(
                                            "Explorer.exe Restarted During Session (Clear Explorer Anti-Forensics)",
                                            FindingCategory::TamperingAndAntiForensics,
                                            VerdictLevel::Detection,
                                            format!(
                                                "Wykryto restart procesu Windows Explorer (explorer.exe, PID: {}) zaledwie {} (o: {}), podczas gdy system Windows działa od {}. W cheatach funkcja 'Clear explorer' / self-destruct zabija i restartuje explorer.exe, aby wyczyścić pamięć podręczną, uchwyty plików i historię powłoki.",
                                                entry.th32ProcessID,
                                                time_since_restart_fmt,
                                                restart_time_str,
                                                get_system_boot_info().uptime_formatted
                                            ),
                                        )
                                        .with_evidence("PID explorer.exe", entry.th32ProcessID.to_string())
                                        .with_evidence("Czas startu explorer.exe", restart_time_str)
                                        .with_evidence("Czas działania explorer.exe", format!("{} s ({})", explorer_uptime_secs, time_since_restart_fmt))
                                        .with_evidence("Czas działania systemu (Uptime)", get_system_boot_info().uptime_formatted)
                                        .with_evidence("Technika zacierania", "Kill & Restart explorer.exe (Clear Explorer)".to_string()),
                                    );
                                }
                            }
                        }

                        windows_sys::Win32::Foundation::CloseHandle(h_proc);
                    }
                }

                if windows_sys::Win32::System::Diagnostics::ToolHelp::Process32NextW(snapshot, &mut entry) == 0 {
                    break;
                }
            }
        }

        windows_sys::Win32::Foundation::CloseHandle(snapshot);
    }
}

fn get_reg_dword_hkcu(sub_key: &str, val_name: &str) -> Option<u32> {
    let key_w: Vec<u16> = format!("{}\0", sub_key).encode_utf16().collect();
    let val_w: Vec<u16> = format!("{}\0", val_name).encode_utf16().collect();

    unsafe {
        let mut h_key = std::ptr::null_mut();
        if windows_sys::Win32::System::Registry::RegOpenKeyExW(
            windows_sys::Win32::System::Registry::HKEY_CURRENT_USER,
            key_w.as_ptr(),
            0,
            windows_sys::Win32::System::Registry::KEY_READ,
            &mut h_key,
        ) == 0 {
            let mut val_type = 0u32;
            let mut data = 0u32;
            let mut data_size = std::mem::size_of::<u32>() as u32;

            let res = windows_sys::Win32::System::Registry::RegQueryValueExW(
                h_key,
                val_w.as_ptr(),
                std::ptr::null_mut(),
                &mut val_type,
                &mut data as *mut _ as *mut u8,
                &mut data_size,
            );
            windows_sys::Win32::System::Registry::RegCloseKey(h_key);

            if res == 0 && (val_type == 4 || val_type == 3) {
                return Some(data);
            }
        }
    }
    None
}

pub fn is_run_mru_tracking_disabled() -> bool {
    // 1. Check HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Start_TrackProgs
    if let Some(val) = get_reg_dword_hkcu(
        "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced",
        "Start_TrackProgs",
    ) {
        if val == 0 {
            return true;
        }
    }

    // 2. Check HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\NoInstrumentation
    if let Some(val) = get_reg_dword_hkcu(
        "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer",
        "NoInstrumentation",
    ) {
        if val == 1 {
            return true;
        }
    }

    // 3. Check HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\NoRun
    if let Some(val) = get_reg_dword_hkcu(
        "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer",
        "NoRun",
    ) {
        if val == 1 {
            return true;
        }
    }

    false
}

pub fn is_recent_docs_tracking_disabled() -> bool {
    // 1. Check HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Start_TrackDocs
    if let Some(val) = get_reg_dword_hkcu(
        "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced",
        "Start_TrackDocs",
    ) {
        if val == 0 {
            return true;
        }
    }

    // 2. Check HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\NoRecentDocsHistory
    if let Some(val) = get_reg_dword_hkcu(
        "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer",
        "NoRecentDocsHistory",
    ) {
        if val == 1 {
            return true;
        }
    }

    // 3. Check HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\ClearRecentDocsOnExit
    if let Some(val) = get_reg_dword_hkcu(
        "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer",
        "ClearRecentDocsOnExit",
    ) {
        if val == 1 {
            return true;
        }
    }

    false
}

fn check_explorer_mru_and_recent_clearing(report: &mut ScanReport) {
    let boot_info = get_system_boot_info();
    let boot_unix_secs = crate::scanner::forensics::get_boot_unix_timestamp();

    // 1. Check HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs
    let is_recent_disabled = is_recent_docs_tracking_disabled();
    if is_recent_disabled {
        report.add(
            ScanFinding::new(
                "Windows Recent Documents Tracking Disabled (Privacy Settings / Policies)",
                FindingCategory::WindowsForensics,
                VerdictLevel::Information,
                "Śledzenie ostatnio otwieranych dokumentów w Windows jest wyłączone w ustawieniach prywatności lub polisach systemowych (Start_TrackDocs = 0, NoRecentDocsHistory lub ClearRecentDocsOnExit). Klucz RecentDocs i katalog Recent celowo nie gromadzą wpisów.",
            )
            .with_evidence("Status konfiguracji", "Wyłączone przez ustawienia prywatności użytkownika".to_string()),
        );
    } else {
        let recent_docs_w: Vec<u16> = "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RecentDocs\0"
            .encode_utf16()
            .collect();

        unsafe {
            let mut h_key = std::ptr::null_mut();
            if windows_sys::Win32::System::Registry::RegOpenKeyExW(
                windows_sys::Win32::System::Registry::HKEY_CURRENT_USER,
                recent_docs_w.as_ptr(),
                0,
                windows_sys::Win32::System::Registry::KEY_READ,
                &mut h_key,
            ) == 0
            {
                let mut num_subkeys = 0u32;
                let mut num_values = 0u32;
                let mut last_write = zeroed();

                if windows_sys::Win32::System::Registry::RegQueryInfoKeyW(
                    h_key,
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    std::ptr::null(),
                    &mut num_subkeys,
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    &mut num_values,
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    &mut last_write,
                ) == 0
                {
                    let ft = ((last_write.dwHighDateTime as u64) << 32) | (last_write.dwLowDateTime as u64);
                    let was_written_current_session = crate::scanner::forensics::was_executed_in_current_session(ft);
                    let write_unix_secs = crate::scanner::forensics::filetime_to_unix_secs(ft).unwrap_or(0);
                    let last_write_str = crate::scanner::forensics::format_filetime(ft).unwrap_or_else(|| "Nieznany".to_string());

                    // Ignore Windows login startup window (first 3 minutes from boot) and uptime under 10 minutes
                    let is_mid_session_wipe = boot_info.uptime_secs > 600
                        && write_unix_secs > boot_unix_secs + 180
                        && was_written_current_session;

                    if is_mid_session_wipe && (num_values <= 2 || num_subkeys <= 1) {
                        report.add(
                            ScanFinding::new(
                                "Explorer RecentDocs Cleared Mid-Session (Anti-Forensics)",
                                FindingCategory::TamperingAndAntiForensics,
                                VerdictLevel::Detection,
                                format!(
                                    "Wykryto wyczyszczenie historii otwieranych plików Windows Explorer (RecentDocs) w trakcie trwania sesji: {}. Klucz zawiera zaledwie {} wartości i {} podkluczy (Clear Explorer).",
                                    last_write_str, num_values, num_subkeys
                                ),
                            )
                            .with_evidence("Czas modyfikacji klucza", last_write_str)
                            .with_evidence("Liczba wpisów RecentDocs", num_values.to_string())
                            .with_evidence("Liczba podkluczy rozszerzeń", num_subkeys.to_string())
                            .with_evidence("Czas działania systemu", boot_info.uptime_formatted.clone())
                            .with_evidence("Ścieżka rejestru", "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RecentDocs".to_string()),
                        );
                    }
                }

                windows_sys::Win32::System::Registry::RegCloseKey(h_key);
            }
        }
    }

    // 2. Check HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
    let is_run_mru_disabled = is_run_mru_tracking_disabled();
    if is_run_mru_disabled {
        report.add(
            ScanFinding::new(
                "Windows RunMRU App Tracking Disabled (Privacy Settings)",
                FindingCategory::WindowsForensics,
                VerdictLevel::Information,
                "Śledzenie uruchamianych programów w oknie Uruchom (Win+R) jest wyłączone w ustawieniach prywatności Windows (Start_TrackProgs = 0 lub polisa NoInstrumentation). Historia RunMRU nie jest rejestrowana przez system.",
            )
            .with_evidence("Status śledzenia", "Wyłączone (Start_TrackProgs = 0 / NoInstrumentation)".to_string()),
        );
    } else {
        let run_mru_w: Vec<u16> = "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RunMRU\0"
            .encode_utf16()
            .collect();

        unsafe {
            let mut h_key = std::ptr::null_mut();
            if windows_sys::Win32::System::Registry::RegOpenKeyExW(
                windows_sys::Win32::System::Registry::HKEY_CURRENT_USER,
                run_mru_w.as_ptr(),
                0,
                windows_sys::Win32::System::Registry::KEY_READ,
                &mut h_key,
            ) == 0
            {
                let mut num_subkeys = 0u32;
                let mut num_values = 0u32;
                let mut last_write = zeroed();

                if windows_sys::Win32::System::Registry::RegQueryInfoKeyW(
                    h_key,
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    std::ptr::null(),
                    &mut num_subkeys,
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    &mut num_values,
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    &mut last_write,
                ) == 0
                {
                    let ft = ((last_write.dwHighDateTime as u64) << 32) | (last_write.dwLowDateTime as u64);
                    let was_written_current_session = crate::scanner::forensics::was_executed_in_current_session(ft);
                    let write_unix_secs = crate::scanner::forensics::filetime_to_unix_secs(ft).unwrap_or(0);
                    let last_write_str = crate::scanner::forensics::format_filetime(ft).unwrap_or_else(|| "Nieznany".to_string());

                    // Ignore Windows login startup window (first 3 minutes from boot) and uptime under 10 minutes
                    let is_mid_session_wipe = boot_info.uptime_secs > 600
                        && write_unix_secs > boot_unix_secs + 180
                        && was_written_current_session;

                    if is_mid_session_wipe && num_values <= 1 {
                        report.add(
                            ScanFinding::new(
                                "Explorer RunMRU (Win+R) History Wiped Mid-Session",
                                FindingCategory::TamperingAndAntiForensics,
                                VerdictLevel::Detection,
                                format!(
                                    "Wykryto wyczyszczenie historii okna Uruchom (RunMRU / Win+R) w trakcie trwania sesji gry: {}. Klucz jest pusty lub zresetowany przy aktywnym śledzeniu.",
                                    last_write_str
                                ),
                            )
                            .with_evidence("Czas modyfikacji klucza", last_write_str)
                            .with_evidence("Liczba wpisów RunMRU", num_values.to_string())
                            .with_evidence("Czas działania systemu", boot_info.uptime_formatted.clone())
                            .with_evidence("Ścieżka rejestru", "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RunMRU".to_string()),
                        );
                    }
                }

                windows_sys::Win32::System::Registry::RegCloseKey(h_key);
            }
        }
    }

    // 3. Check %APPDATA%\Microsoft\Windows\Recent shortcut directory (only when tracking is enabled)
    if !is_recent_disabled {
        if let Ok(appdata) = std::env::var("APPDATA") {
            let recent_dir = std::path::Path::new(&appdata).join("Microsoft\\Windows\\Recent");
            if recent_dir.is_dir() {
                if let Ok(entries) = std::fs::read_dir(&recent_dir) {
                    let lnk_count = entries
                        .flatten()
                        .filter(|e| e.path().extension().map_or(false, |ext| ext.eq_ignore_ascii_case("lnk")))
                        .count();

                    if boot_info.uptime_secs > 900 && lnk_count <= 1 {
                        report.add(
                            ScanFinding::new(
                                "Windows Recent Shortcuts Directory Purged (Anti-Forensics)",
                                FindingCategory::TamperingAndAntiForensics,
                                VerdictLevel::Detection,
                                format!(
                                    "Katalog skrótów niedawno otwieranych plików (Recent) jest nienaturalnie pusty (znaleziono zaledwie {} plików .lnk) przy czasie działania komputera {}. Świadczy to o użyciu narzędzia czyszczącego ślady (Clear Explorer / Destruct).",
                                    lnk_count, boot_info.uptime_formatted
                                ),
                            )
                            .with_evidence("Ścieżka katalogu", recent_dir.to_string_lossy().to_string())
                            .with_evidence("Liczba plików .lnk", lnk_count.to_string())
                            .with_evidence("Czas działania systemu", boot_info.uptime_formatted.clone()),
                        );
                    }
                }
            }

            // 4. Check JumpLists (AutomaticDestinations)
            let auto_dest = std::path::Path::new(&appdata).join("Microsoft\\Windows\\Recent\\AutomaticDestinations");
            if auto_dest.is_dir() {
                if let Ok(entries) = std::fs::read_dir(&auto_dest) {
                    let ms_count = entries
                        .flatten()
                        .filter(|e| e.path().extension().map_or(false, |ext| ext.eq_ignore_ascii_case("automaticDestinations-ms")))
                        .count();

                    if boot_info.uptime_secs > 900 && ms_count == 0 {
                        report.add(
                            ScanFinding::new(
                                "Windows JumpLists (AutomaticDestinations) Cleared",
                                FindingCategory::TamperingAndAntiForensics,
                                VerdictLevel::Detection,
                                format!(
                                    "Katalog list szybkiego dostępu (JumpLists / AutomaticDestinations) został wyczyszczony do zera (znaleziono 0 plików). Standardowo Windows przechowuje tu pliki historii pasków zadań.",
                                ),
                            )
                            .with_evidence("Ścieżka katalogu", auto_dest.to_string_lossy().to_string())
                            .with_evidence("Czas działania systemu", boot_info.uptime_formatted.clone()),
                        );
                    }
                }
            }
        }
    }
}

fn check_explorer_thumbcache_tampering(report: &mut ScanReport) {
    let boot_info = get_system_boot_info();
    if let Ok(local_appdata) = std::env::var("LOCALAPPDATA") {
        let explorer_dir = std::path::Path::new(&local_appdata).join("Microsoft\\Windows\\Explorer");
        if explorer_dir.is_dir() {
            if let Ok(entries) = std::fs::read_dir(&explorer_dir) {
                let mut thumb_count = 0usize;
                let mut icon_count = 0usize;
                let mut newest_thumb_created: Option<std::time::SystemTime> = None;
                let mut idx_file_size: Option<u64> = None;

                for entry in entries.flatten() {
                    let file_name = entry.file_name().to_string_lossy().to_lowercase();
                    if file_name.starts_with("thumbcache_") && file_name.ends_with(".db") {
                        thumb_count += 1;
                        if file_name == "thumbcache_idx.db" {
                            if let Ok(meta) = entry.metadata() {
                                idx_file_size = Some(meta.len());
                            }
                        }
                        if let Ok(meta) = entry.metadata() {
                            if let Ok(created) = meta.created() {
                                newest_thumb_created = match newest_thumb_created {
                                    Some(t) => Some(t.max(created)),
                                    None => Some(created),
                                };
                            }
                        }
                    } else if file_name.starts_with("iconcache_") && file_name.ends_with(".db") {
                        icon_count += 1;
                    }
                }

                // 1. If uptime exceeds 15 minutes and thumbcache database was completely wiped (0 files)
                if boot_info.uptime_secs > 900 && thumb_count == 0 {
                    report.add(
                        ScanFinding::new(
                            "Windows Explorer Thumbcache Purged / Wiped (Anti-Forensics)",
                            FindingCategory::TamperingAndAntiForensics,
                            VerdictLevel::Detection,
                            format!(
                                "Katalog bazy miniatur Windows Explorer (thumbcache_*.db) jest całkowicie pusty (0 plików) przy czasie działania komputera {}. Świadczy to o użyciu narzędzia czyszczącego miniatury i podglądy plików graficznych/video (Clear Explorer / Destruct).",
                                boot_info.uptime_formatted
                            ),
                        )
                        .with_evidence("Ścieżka katalogu", explorer_dir.to_string_lossy().to_string())
                        .with_evidence("Liczba plików thumbcache_*.db", thumb_count.to_string())
                        .with_evidence("Liczba plików iconcache_*.db", icon_count.to_string())
                        .with_evidence("Czas działania systemu (Uptime)", boot_info.uptime_formatted),
                    );
                } else if boot_info.uptime_secs > 1800 && thumb_count > 0 {
                    // 2. If computer uptime > 30 minutes, but thumbcache files were recreated in the last 10 minutes
                    if let Some(created) = newest_thumb_created {
                        if let Ok(elapsed) = std::time::SystemTime::now().duration_since(created) {
                            let file_age_secs = elapsed.as_secs();
                            if file_age_secs < 600 {
                                let created_ft_str = crate::scanner::forensics::format_system_time(created);
                                report.add(
                                    ScanFinding::new(
                                        "Windows Explorer Thumbcache Database Recreated Mid-Session",
                                        FindingCategory::TamperingAndAntiForensics,
                                        VerdictLevel::Detection,
                                        format!(
                                            "Baza miniatur Windows Explorer została wyczyszczona i utworzona od zera w trakcie bieżącej sesji (najnowszy plik utworzony zaledwie {} s temu: {}), podczas gdy system Windows działa od {}. Wskazuje to na reset bazy miniatur po wykonaniu 'Clear explorer'.",
                                            file_age_secs, created_ft_str, boot_info.uptime_formatted
                                        ),
                                    )
                                    .with_evidence("Czas utworzenia bazy miniatur", created_ft_str)
                                    .with_evidence("Wiek pliku bazy", format!("{} sekund temu", file_age_secs))
                                    .with_evidence("Rozmiar pliku indeksu (thumbcache_idx.db)", idx_file_size.map(|s| format!("{} bajtów", s)).unwrap_or_else(|| "N/A".to_string()))
                                    .with_evidence("Czas działania systemu", boot_info.uptime_formatted),
                                );
                            }
                        }
                    }
                }
            }
        }
    }
}

pub fn decode_bytes_lossy_utf8_or_utf16(bytes: &[u8]) -> String {
    if bytes.is_empty() {
        return String::new();
    }

    // Check UTF-16 LE with BOM: 0xFF, 0xFE
    if bytes.len() >= 2 && bytes[0] == 0xFF && bytes[1] == 0xFE {
        let u16_slice: Vec<u16> = bytes[2..]
            .chunks_exact(2)
            .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
            .collect();
        return String::from_utf16_lossy(&u16_slice);
    }

    // Check UTF-16 BE with BOM: 0xFE, 0xFF
    if bytes.len() >= 2 && bytes[0] == 0xFE && bytes[1] == 0xFF {
        let u16_slice: Vec<u16> = bytes[2..]
            .chunks_exact(2)
            .map(|chunk| u16::from_be_bytes([chunk[0], chunk[1]]))
            .collect();
        return String::from_utf16_lossy(&u16_slice);
    }

    // Check heuristic UTF-16 LE without BOM: if alternate bytes are 0x00 for ASCII characters
    if bytes.len() >= 4 && bytes[1] == 0x00 && bytes[3] == 0x00 {
        let u16_slice: Vec<u16> = bytes
            .chunks_exact(2)
            .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
            .collect();
        return String::from_utf16_lossy(&u16_slice);
    }

    // Fallback: UTF-8 lossy
    String::from_utf8_lossy(bytes).to_string()
}

pub fn read_file_lossy_utf8_or_utf16(path: &std::path::Path) -> Option<String> {
    let bytes = std::fs::read(path).ok()?;
    Some(decode_bytes_lossy_utf8_or_utf16(&bytes))
}

pub fn scan_boot_log_content(content: &str, log_path: &std::path::Path) -> Vec<ScanFinding> {
    let mut findings = Vec::new();
    let mut reported_drivers = std::collections::HashSet::new();

    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        let lower = trimmed.to_lowercase();
        for vuln in KNOWN_VULNERABLE_DRIVERS {
            let driver_name_lower = vuln.driver_name.to_lowercase();
            if lower.contains(&driver_name_lower) {
                if reported_drivers.insert(vuln.driver_name) {
                    findings.push(
                        ScanFinding::new(
                            format!("Vulnerable Kernel Driver in Windows Boot Log: {}", vuln.driver_name),
                            FindingCategory::TamperingAndAntiForensics,
                            vuln.verdict,
                            format!(
                                "Dziennik rozruchu Windows (ntbtlog.txt) zawiera wpis o załadowaniu podatnego sterownika jądra (BYOVD): {}. Oznacza to próbę załadowania exploita ring0 podczas rozruchu systemu. {}",
                                vuln.driver_name, vuln.threat_description
                            ),
                        )
                        .with_evidence("Ścieżka logu rozruchu", log_path.to_string_lossy().to_string())
                        .with_evidence("Wykryty sterownik jądra", vuln.driver_name.to_string())
                        .with_evidence("Wpis w ntbtlog.txt", trimmed.to_string())
                        .with_evidence("Wektor ataku / CVE", vuln.cve_or_vector.to_string())
                        .with_evidence("Opis zagrożenia", vuln.threat_description.to_string()),
                    );
                }
            }
        }
    }

    findings
}

pub fn check_windows_boot_log(report: &mut ScanReport) {
    let sys_root = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".to_string());
    let boot_log_path = std::path::Path::new(&sys_root).join("ntbtlog.txt");

    if !boot_log_path.exists() {
        return;
    }

    if let Some(content) = read_file_lossy_utf8_or_utf16(&boot_log_path) {
        let findings = scan_boot_log_content(&content, &boot_log_path);
        for finding in findings {
            report.add(finding);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_xml_data_val() {
        let sample_xml = r#"<Event><EventData><Data Name="NewTime">2026-10-04T10:00:00.000000000Z</Data><Data Name='OldTime'>2026-10-04T12:00:00.000000000Z</Data></EventData></Event>"#;
        assert_eq!(
            extract_xml_data_val(sample_xml, "NewTime"),
            Some("2026-10-04T10:00:00.000000000Z".to_string())
        );
        assert_eq!(
            extract_xml_data_val(sample_xml, "OldTime"),
            Some("2026-10-04T12:00:00.000000000Z".to_string())
        );
        assert_eq!(extract_xml_data_val(sample_xml, "NonExistent"), None);
    }

    #[test]
    fn test_extract_xml_system_time() {
        let sample_xml = r#"<Event><System><TimeCreated SystemTime="2026-10-04T12:00:00.000000000Z"/></System></Event>"#;
        assert_eq!(
            extract_xml_system_time(sample_xml),
            Some("2026-10-04T12:00:00.000000000Z".to_string())
        );
        let sample_xml_single = r#"<Event><System><TimeCreated SystemTime='2026-10-04T15:30:00.000000000Z'/></System></Event>"#;
        assert_eq!(
            extract_xml_system_time(sample_xml_single),
            Some("2026-10-04T15:30:00.000000000Z".to_string())
        );
    }

    #[test]
    fn test_known_vulnerable_drivers_list() {
        let names: Vec<&str> = KNOWN_VULNERABLE_DRIVERS.iter().map(|d| d.driver_name).collect();
        assert!(names.contains(&"gdrv.sys"));
        assert!(names.contains(&"mhyprot2.sys"));
        assert!(names.contains(&"iqvw64e.sys"));
        assert!(names.contains(&"rtcore64.sys"));
    }

    #[test]
    fn test_privacy_settings_functions() {
        // Query registry and return bool without panicking
        let _ = is_run_mru_tracking_disabled();
        let _ = is_recent_docs_tracking_disabled();
    }

    #[test]
    fn test_decode_bytes_lossy_utf8_or_utf16() {
        // UTF-8
        let utf8_text = "Hello world";
        assert_eq!(decode_bytes_lossy_utf8_or_utf16(utf8_text.as_bytes()), "Hello world");

        // UTF-16 LE z BOM (0xFF, 0xFE)
        let mut utf16_le_bom = vec![0xFF, 0xFE];
        for b in "Test Driver".encode_utf16() {
            utf16_le_bom.extend_from_slice(&b.to_le_bytes());
        }
        assert_eq!(decode_bytes_lossy_utf8_or_utf16(&utf16_le_bom), "Test Driver");

        // UTF-16 LE bez BOM
        let mut utf16_le = Vec::new();
        for b in "Kernel Log".encode_utf16() {
            utf16_le.extend_from_slice(&b.to_le_bytes());
        }
        assert_eq!(decode_bytes_lossy_utf8_or_utf16(&utf16_le), "Kernel Log");
    }

    #[test]
    fn test_scan_boot_log_content() {
        let dummy_path = std::path::Path::new(r"C:\Windows\ntbtlog.txt");
        let fake_log = "\
Loaded driver \\SystemRoot\\system32\\drivers\\disk.sys\r\n\
Loaded driver \\SystemRoot\\System32\\Drivers\\gdrv.sys\r\n\
Loaded driver \\SystemRoot\\System32\\Drivers\\gdrv.sys\r\n\
Did not load driver \\SystemRoot\\System32\\Drivers\\mhyprot2.sys\r\n\
Loaded driver \\SystemRoot\\System32\\Drivers\\safe.sys\r\n";

        let findings = scan_boot_log_content(fake_log, dummy_path);
        assert_eq!(findings.len(), 2);
        let titles: Vec<String> = findings.iter().map(|f| f.name.clone()).collect();
        assert!(titles.iter().any(|t| t.contains("gdrv.sys")));
        assert!(titles.iter().any(|t| t.contains("mhyprot2.sys")));
    }
}
