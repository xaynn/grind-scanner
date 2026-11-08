use crate::report::{FindingCategory, ScanFinding, ScanReport, VerdictLevel};
use crate::scanner::forensics::{
    format_filetime, get_boot_unix_timestamp, was_executed_in_current_session,
};
use std::collections::HashSet;
use windows_sys::Win32::Storage::FileSystem::GetDriveTypeW;
use windows_sys::Win32::System::Registry::{
    RegCloseKey, RegEnumKeyExW, RegOpenKeyExW, RegQueryValueExW, HKEY_CURRENT_USER,
    HKEY_LOCAL_MACHINE, KEY_READ,
};

pub fn scan_usbstor(report: &mut ScanReport) {
    scan_usbstor_registry(report);
    scan_mountpoints2_registry(report);
    scan_active_drives(report);
    scan_network_shares_and_nodrives(report);
    scan_usb_event_logs(report);
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceConnectionStatus {
    Connected,
    Disconnected,
    Unknown,
}

/// Queries Windows SetupAPI / Configuration Manager (cfgmgr32.dll) to determine
/// whether a device is physically present/connected in the live hardware tree,
/// or disconnected (phantom device node, Code 45).
pub fn query_device_pnp_status(pnp_id: &str) -> DeviceConnectionStatus {
    unsafe {
        let cfgmgr32 =
            windows_sys::Win32::System::LibraryLoader::LoadLibraryA(b"cfgmgr32.dll\0".as_ptr());
        if cfgmgr32.is_null() {
            return DeviceConnectionStatus::Unknown;
        }

        let p_locate = windows_sys::Win32::System::LibraryLoader::GetProcAddress(
            cfgmgr32,
            b"CM_Locate_DevNodeW\0".as_ptr(),
        );
        let p_status = windows_sys::Win32::System::LibraryLoader::GetProcAddress(
            cfgmgr32,
            b"CM_Get_DevNode_Status\0".as_ptr(),
        );

        if let (Some(f_locate), Some(f_status)) = (p_locate, p_status) {
            #[allow(non_camel_case_types, non_snake_case)]
            type CM_Locate_DevNodeW_Fn = unsafe extern "system" fn(
                pdnDevInst: *mut u32,
                pDeviceID: *const u16,
                ulFlags: u32,
            ) -> u32;

            #[allow(non_camel_case_types, non_snake_case)]
            type CM_Get_DevNode_Status_Fn = unsafe extern "system" fn(
                pulStatus: *mut u32,
                pulProblemNumber: *mut u32,
                dnDevInst: u32,
                ulFlags: u32,
            ) -> u32;

            let cm_locate: CM_Locate_DevNodeW_Fn = std::mem::transmute(f_locate);
            let cm_get_status: CM_Get_DevNode_Status_Fn = std::mem::transmute(f_status);

            let mut dev_id_w: Vec<u16> = pnp_id.encode_utf16().collect();
            dev_id_w.push(0);

            let mut dev_inst: u32 = 0;
            const CM_LOCATE_DEVNODE_NORMAL: u32 = 0x00000000;
            const CM_LOCATE_DEVNODE_PHANTOM: u32 = 0x00000001;
            const CR_SUCCESS: u32 = 0;
            const DN_STARTED: u32 = 0x00000008;
            const CM_PROB_PHANTOM: u32 = 45;

            // 1. Try normal lookup (present in live hardware tree)
            let ret_normal = cm_locate(&mut dev_inst, dev_id_w.as_ptr(), CM_LOCATE_DEVNODE_NORMAL);
            if ret_normal == CR_SUCCESS {
                let mut status: u32 = 0;
                let mut problem: u32 = 0;
                let ret_st = cm_get_status(&mut status, &mut problem, dev_inst, 0);
                if ret_st == CR_SUCCESS {
                    if problem == CM_PROB_PHANTOM {
                        return DeviceConnectionStatus::Disconnected;
                    }
                    if (status & DN_STARTED) != 0 || problem == 0 {
                        return DeviceConnectionStatus::Connected;
                    }
                } else {
                    return DeviceConnectionStatus::Connected;
                }
            }

            // 2. Normal lookup failed (not present live) - try phantom lookup
            let mut phantom_inst: u32 = 0;
            let ret_phantom = cm_locate(
                &mut phantom_inst,
                dev_id_w.as_ptr(),
                CM_LOCATE_DEVNODE_PHANTOM,
            );
            if ret_phantom == CR_SUCCESS {
                let mut status: u32 = 0;
                let mut problem: u32 = 0;
                let ret_st = cm_get_status(&mut status, &mut problem, phantom_inst, 0);
                if ret_st == CR_SUCCESS && problem == CM_PROB_PHANTOM {
                    return DeviceConnectionStatus::Disconnected;
                }
                return DeviceConnectionStatus::Disconnected;
            }

            DeviceConnectionStatus::Disconnected
        } else {
            DeviceConnectionStatus::Unknown
        }
    }
}

/// Skanuje klucz rejestru HKLM\SYSTEM\CurrentControlSet\Enum\USBSTOR
/// to detect USB mass storage devices (flash drives, external drives).
fn scan_usbstor_registry(report: &mut ScanReport) {
    let usbstor_root: Vec<u16> = "SYSTEM\\CurrentControlSet\\Enum\\USBSTOR\0"
        .encode_utf16()
        .collect();

    unsafe {
        let mut h_root = std::ptr::null_mut();
        if RegOpenKeyExW(
            HKEY_LOCAL_MACHINE,
            usbstor_root.as_ptr(),
            0,
            KEY_READ,
            &mut h_root,
        ) != 0
        {
            return;
        }

        let mut dev_index = 0u32;
        let mut dev_name = [0u16; 256];
        let mut dev_len = 256u32;

        while RegEnumKeyExW(
            h_root,
            dev_index,
            dev_name.as_mut_ptr(),
            &mut dev_len,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        ) == 0
        {
            let device_key = String::from_utf16_lossy(&dev_name[..dev_len as usize]);
            scan_usbstor_device(h_root, &device_key, report);

            dev_index += 1;
            dev_len = 256;
        }

        RegCloseKey(h_root);
    }
}

unsafe fn scan_usbstor_device(
    h_root: windows_sys::Win32::System::Registry::HKEY,
    device_key: &str,
    report: &mut ScanReport,
) {
    let dev_w: Vec<u16> = format!("{}\0", device_key).encode_utf16().collect();
    let mut h_dev = std::ptr::null_mut();

    unsafe {
        if RegOpenKeyExW(h_root, dev_w.as_ptr(), 0, KEY_READ, &mut h_dev) != 0 {
            return;
        }

        let mut inst_index = 0u32;
        let mut inst_name = [0u16; 256];
        let mut inst_len = 256u32;
        let mut last_write_time = windows_sys::Win32::Foundation::FILETIME {
            dwLowDateTime: 0,
            dwHighDateTime: 0,
        };

        while RegEnumKeyExW(
            h_dev,
            inst_index,
            inst_name.as_mut_ptr(),
            &mut inst_len,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut last_write_time,
        ) == 0
        {
            let serial = String::from_utf16_lossy(&inst_name[..inst_len as usize]);
            let ft_raw = ((last_write_time.dwHighDateTime as u64) << 32)
                | (last_write_time.dwLowDateTime as u64);

            let friendly_name = query_friendly_name(h_dev, &serial)
                .unwrap_or_else(|| device_key.to_string());

            let in_session = was_executed_in_current_session(ft_raw);
            let time_str = format_filetime(ft_raw)
                .unwrap_or_else(|| "Brak znacznika czasu".to_string());

            let pnp_id = format!("USBSTOR\\{}\\{}", device_key, serial);
            let pnp_status = query_device_pnp_status(&pnp_id);

            if in_session {
                match pnp_status {
                    DeviceConnectionStatus::Disconnected => {
                        report.add(
                            ScanFinding::new(
                                "USB Storage Device Unplugged / Disconnected in Current Session (Evasion Indicator)",
                                FindingCategory::TamperingAndAntiForensics,
                                VerdictLevel::Detection,
                                format!(
                                    "Wykryto zewnętrzną pamięć masową USB ({}), która była podłączona i aktywna w bieżącej sesji systemu Windows, ale została FIZYCZNIE ODŁĄCZONA (wypięta z portu USB) przed zakończeniem skanowania! Jest to powszechna technika ukrywania cheatów (uruchomienie exploita/loadera z pendrive'a i natychmiastowe wyjęcie nośnika).",
                                    friendly_name
                                ),
                            )
                            .with_evidence("Urządzenie USB", friendly_name.clone())
                            .with_evidence(
                                "Status sprzętowy PnP",
                                "ODŁĄCZONE (Brak urządzenia w porcie USB / Kod stanu: CM_PROB_PHANTOM 45)".to_string(),
                            )
                            .with_evidence("Identyfikator sprzętowy PnP", pnp_id.clone())
                            .with_evidence("Numer seryjny / Instancja", serial.clone())
                            .with_evidence("Czas ostatniej aktywności / modyfikacji rejestru", time_str.clone()),
                        );
                    }
                    DeviceConnectionStatus::Connected => {
                        report.add(
                            ScanFinding::new(
                                "Active USB Storage Device Connected in Current Session",
                                FindingCategory::TamperingAndAntiForensics,
                                VerdictLevel::Warning,
                                format!(
                                    "Wykryto zewnętrzną pamięć USB ({}), która jest OBECNIE PODŁĄCZONA do komputera i była aktywna w bieżącej sesji systemu Windows.",
                                    friendly_name
                                ),
                            )
                            .with_evidence("Urządzenie USB", friendly_name.clone())
                            .with_evidence(
                                "Status sprzętowy PnP",
                                "PODŁĄCZONE (Wpięte w port USB, aktywne w systemie Windows)".to_string(),
                            )
                            .with_evidence("Identyfikator sprzętowy PnP", pnp_id.clone())
                            .with_evidence("Numer seryjny / Instancja", serial.clone())
                            .with_evidence("Czas ostatniej aktywności / modyfikacji rejestru", time_str.clone()),
                        );
                    }
                    DeviceConnectionStatus::Unknown => {
                        report.add(
                            ScanFinding::new(
                                "USB Storage Device Connected in Current Session",
                                FindingCategory::TamperingAndAntiForensics,
                                VerdictLevel::Warning,
                                format!(
                                    "Wykryto podłączenie zewnętrznej pamięci USB w bieżącej sesji systemu Windows: {}. Cheaty i injectory są często uruchamiane z pendrive'a i odłączane przed sprawdzeniem.",
                                    friendly_name
                                ),
                            )
                            .with_evidence("Urządzenie USB", friendly_name.clone())
                            .with_evidence("Identyfikator sprzętowy", device_key.to_string())
                            .with_evidence("Numer seryjny / Instancja", serial.clone())
                            .with_evidence("Czas ostatniej modyfikacji / podłączenia", time_str),
                        );
                    }
                }
            }

            inst_index += 1;
            inst_len = 256;
        }

        RegCloseKey(h_dev);
    }
}

unsafe fn query_friendly_name(
    h_dev: windows_sys::Win32::System::Registry::HKEY,
    inst_name: &str,
) -> Option<String> {
    let inst_w: Vec<u16> = format!("{}\0", inst_name).encode_utf16().collect();
    let mut h_inst = std::ptr::null_mut();

    unsafe {
        if RegOpenKeyExW(h_dev, inst_w.as_ptr(), 0, KEY_READ, &mut h_inst) != 0 {
            return None;
        }

        let val_w: Vec<u16> = "FriendlyName\0".encode_utf16().collect();
        let mut val_data = [0u16; 256];
        let mut val_size = 512u32;
        let mut val_type = 0u32;

        let res = RegQueryValueExW(
            h_inst,
            val_w.as_ptr(),
            std::ptr::null_mut(),
            &mut val_type,
            val_data.as_mut_ptr() as *mut u8,
            &mut val_size,
        );

        RegCloseKey(h_inst);

        if res == 0 && val_size > 2 {
            let len = (val_size as usize / 2).saturating_sub(1);
            Some(String::from_utf16_lossy(&val_data[..len]))
        } else {
            None
        }
    }
}

/// Scans volume mount points in HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2
fn scan_mountpoints2_registry(report: &mut ScanReport) {
    let mp_root: Vec<u16> = "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\MountPoints2\0"
        .encode_utf16()
        .collect();

    unsafe {
        let mut h_root = std::ptr::null_mut();
        if RegOpenKeyExW(
            HKEY_CURRENT_USER,
            mp_root.as_ptr(),
            0,
            KEY_READ,
            &mut h_root,
        ) != 0
        {
            return;
        }

        let mut index = 0u32;
        let mut name_buf = [0u16; 256];
        let mut name_len = 256u32;
        let mut last_write_time = windows_sys::Win32::Foundation::FILETIME {
            dwLowDateTime: 0,
            dwHighDateTime: 0,
        };

        while RegEnumKeyExW(
            h_root,
            index,
            name_buf.as_mut_ptr(),
            &mut name_len,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut last_write_time,
        ) == 0
        {
            let key_str = String::from_utf16_lossy(&name_buf[..name_len as usize]);
            let ft_raw = ((last_write_time.dwHighDateTime as u64) << 32)
                | (last_write_time.dwLowDateTime as u64);

            let in_session = was_executed_in_current_session(ft_raw);
            let time_str = format_filetime(ft_raw).unwrap_or_else(|| "Brak daty".to_string());

            // 1. Check if this is an SMB network share (e.g. ##192.168.1.100#share or ##UNC#server#share)
            let is_unc_share = key_str.starts_with("##UNC#")
                || (key_str.starts_with("##") && key_str.len() > 4 && key_str[2..].contains('#'));

            if is_unc_share {
                let share_path = format!("\\\\{}", key_str.trim_start_matches('#').replace('#', "\\"));
                if in_session {
                    report.add(
                        ScanFinding::new(
                            "Network Share Mounted via SMB / net use in Current Session",
                            FindingCategory::TamperingAndAntiForensics,
                            VerdictLevel::Warning,
                            format!(
                                "Zarejestrowano dostęp/montowanie zdalnego udziału sieciowego SMB w bieżącej sesji: {}. Technika ta bywa stosowana do uruchamiania cheata bezpośrednio ze zdalnego zasobu lub telefonu i natychmiastowego odłączania go przed sprawdzeniem.",
                                share_path
                            ),
                        )
                        .with_evidence("Ścieżka sieciowa UNC", share_path)
                        .with_evidence("Czas zamontowania / aktywności", time_str)
                        .with_evidence("Klucz rejestru", format!("MountPoints2\\{}", key_str)),
                    );
                }
            } else if (key_str.starts_with("##") || key_str.starts_with('{')) && in_session {
                let clean_name = if key_str.starts_with("##") && key_str.len() >= 4 {
                    format!("{}:", &key_str[2..3])
                } else {
                    key_str.clone()
                };

                if !clean_name.eq_ignore_ascii_case("c:") {
                    report.add(
                        ScanFinding::new(
                            "Removable / External Volume Mounted in Current Session",
                            FindingCategory::WindowsForensics,
                            VerdictLevel::Information,
                            format!("Zarejestrowano montowanie wolumenu {} w bieżącej sesji systemu.", clean_name),
                        )
                        .with_evidence("Punkt montowania (MountPoint)", clean_name)
                        .with_evidence("Czas zamontowania / aktywności", time_str),
                    );
                }
            }

            index += 1;
            name_len = 256;
        }

        RegCloseKey(h_root);
    }
}

/// Scans active drive letters for removable (DRIVE_REMOVABLE = 2) and network (DRIVE_REMOTE = 4) media
fn scan_active_drives(report: &mut ScanReport) {
    const DRIVE_REMOVABLE: u32 = 2;
    const DRIVE_REMOTE: u32 = 4;

    for letter in b'D'..=b'Z' {
        let root_str = format!("{}:\\\0", letter as char);
        let root_w: Vec<u16> = root_str.encode_utf16().collect();

        let drive_type = unsafe { GetDriveTypeW(root_w.as_ptr()) };
        if drive_type == DRIVE_REMOVABLE {
            report.add(
                ScanFinding::new(
                    "Active Removable Drive (USB) Connected",
                    FindingCategory::TamperingAndAntiForensics,
                    VerdictLevel::Warning,
                    format!("W systemie znajduje się obecnie podłączony aktywny nośnik wymienny USB: {}:\\", letter as char),
                )
                .with_evidence("Litera dysku", format!("{}:\\", letter as char))
                .with_evidence("Typ nośnika", "DRIVE_REMOVABLE (Pamięć flash USB / Dysk zewnętrzny)".to_string()),
            );
        } else if drive_type == DRIVE_REMOTE {
            report.add(
                ScanFinding::new(
                    "Active Remote Network Drive (SMB) Connected",
                    FindingCategory::TamperingAndAntiForensics,
                    VerdictLevel::Warning,
                    format!("W systemie znajduje się obecnie aktywny zdalny dysk sieciowy: {}:\\", letter as char),
                )
                .with_evidence("Litera dysku", format!("{}:\\", letter as char))
                .with_evidence("Typ nośnika", "DRIVE_REMOTE (Udział sieciowy SMB/WebDAV)".to_string()),
            );
        }
    }
}

/// Scans registry for hidden drives (NoDrives) and network mapping history (HKCU\Network)
fn scan_network_shares_and_nodrives(report: &mut ScanReport) {
    scan_nodrives_policy(report);
    scan_hkcu_network(report);
}

fn scan_nodrives_policy(report: &mut ScanReport) {
    let policy_paths = [
        (HKEY_CURRENT_USER, "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\0", "HKCU"),
        (HKEY_LOCAL_MACHINE, "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\0", "HKLM"),
    ];

    for (root_key, path, hive_name) in policy_paths {
        let path_w: Vec<u16> = path.encode_utf16().collect();
        unsafe {
            let mut h_key = std::ptr::null_mut();
            if RegOpenKeyExW(root_key, path_w.as_ptr(), 0, KEY_READ, &mut h_key) == 0 {
                let val_w: Vec<u16> = "NoDrives\0".encode_utf16().collect();
                let mut data = 0u32;
                let mut size = 4u32;
                let mut val_type = 0u32;

                if RegQueryValueExW(
                    h_key,
                    val_w.as_ptr(),
                    std::ptr::null_mut(),
                    &mut val_type,
                    &mut data as *mut u32 as *mut u8,
                    &mut size,
                ) == 0 && data > 0 {
                    let mut hidden = Vec::new();
                    for i in 0..26 {
                        if (data & (1 << i)) != 0 {
                            hidden.push(format!("{}:", (b'A' + i as u8) as char));
                        }
                    }

                    report.add(
                        ScanFinding::new(
                            "Disk Hiding Policy Active (NoDrives)",
                            FindingCategory::TamperingAndAntiForensics,
                            VerdictLevel::Detection,
                            format!(
                                "W rejestrze systemowym ({}\\Policies\\Explorer) wykryto aktywną polisę NoDrives celowo ukrywającą litery dysków: {}. Jest to technika anti-forensics stosowana do zatajenia dysków lub udziałów sieciowych z cheatami.",
                                hive_name, hidden.join(", ")
                            ),
                        )
                        .with_evidence("Ukryte litery dysków", hidden.join(", "))
                        .with_evidence("Wartość NoDrives", format!("0x{:08X}", data))
                        .with_evidence("Gałąź rejestru", format!("{}\\{}", hive_name, path.trim_end_matches('\0'))),
                    );
                }

                RegCloseKey(h_key);
            }
        }
    }
}

fn scan_hkcu_network(report: &mut ScanReport) {
    let net_root: Vec<u16> = "Network\0".encode_utf16().collect();
    unsafe {
        let mut h_root = std::ptr::null_mut();
        if RegOpenKeyExW(HKEY_CURRENT_USER, net_root.as_ptr(), 0, KEY_READ, &mut h_root) != 0 {
            return;
        }

        let mut index = 0u32;
        let mut name_buf = [0u16; 64];
        let mut name_len = 64u32;

        while RegEnumKeyExW(
            h_root,
            index,
            name_buf.as_mut_ptr(),
            &mut name_len,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        ) == 0 {
            let letter = String::from_utf16_lossy(&name_buf[..name_len as usize]);
            let letter_w: Vec<u16> = format!("{}\0", letter).encode_utf16().collect();

            let mut h_drive = std::ptr::null_mut();
            if RegOpenKeyExW(h_root, letter_w.as_ptr(), 0, KEY_READ, &mut h_drive) == 0 {
                let val_w: Vec<u16> = "RemotePath\0".encode_utf16().collect();
                let mut data_buf = [0u16; 512];
                let mut size = 1024u32;
                let mut val_type = 0u32;

                if RegQueryValueExW(
                    h_drive,
                    val_w.as_ptr(),
                    std::ptr::null_mut(),
                    &mut val_type,
                    data_buf.as_mut_ptr() as *mut u8,
                    &mut size,
                ) == 0 && size > 2 {
                    let len = (size as usize / 2).saturating_sub(1);
                    let remote_path = String::from_utf16_lossy(&data_buf[..len]);

                    report.add(
                        ScanFinding::new(
                            "Persistent Mapped Network Drive in Registry",
                            FindingCategory::WindowsForensics,
                            VerdictLevel::Information,
                            format!("W rejestrze Windows zarejestrowano trwały zmapowany dysk sieciowy {}: -> {}", letter, remote_path),
                        )
                        .with_evidence("Litera dysku", format!("{}:", letter))
                        .with_evidence("Ścieżka zdalna (RemotePath)", remote_path),
                    );
                }

                RegCloseKey(h_drive);
            }

            index += 1;
            name_len = 64;
        }

        RegCloseKey(h_root);
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

/// Skanuje dzienniki zdarzeń Windows w poszukiwaniu śladów odpięcia i podłączenia urządzeń USB w bieżącej sesji.
fn scan_usb_event_logs(report: &mut ScanReport) {
    unsafe {
        let wevtapi =
            windows_sys::Win32::System::LibraryLoader::LoadLibraryA(b"wevtapi.dll\0".as_ptr());
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

        if let (Some(f_query), Some(f_next), Some(f_close), Some(f_render)) =
            (p_query, p_next, p_close, p_render)
        {
            let evt_query: EvtQueryFn = std::mem::transmute(f_query);
            let evt_next: EvtNextFn = std::mem::transmute(f_next);
            let evt_close: EvtCloseFn = std::mem::transmute(f_close);
            let evt_render: EvtRenderFn = std::mem::transmute(f_render);

            let mut reported_events = HashSet::new();
            scan_stor_diag_events(report, evt_query, evt_next, evt_close, evt_render, &mut reported_events);
            scan_driver_frameworks_events(report, evt_query, evt_next, evt_close, evt_render, &mut reported_events);
            scan_partition_diagnostic_events(report, evt_query, evt_next, evt_close, evt_render, &mut reported_events);
        }
    }
}

/// 1. Microsoft-Windows-Storage-ClassPnP/Operational (Event 507)
/// SenseKey 2 (Not Ready), AdditionalSenseCode 58 (0x3A = Medium Not Present).
/// Wykrywa natychmiastowe/gwałtowne wyciągnięcie pendrive'a z portu USB.
unsafe fn scan_stor_diag_events(
    report: &mut ScanReport,
    evt_query: EvtQueryFn,
    evt_next: EvtNextFn,
    evt_close: EvtCloseFn,
    evt_render: EvtRenderFn,
    reported_events: &mut HashSet<String>,
) {
    unsafe {
        const EVT_QUERY_CHANNEL_PATH: u32 = 0x1;
        const EVT_QUERY_REVERSE_DIRECTION: u32 = 0x200;
        let query_flags = EVT_QUERY_CHANNEL_PATH | EVT_QUERY_REVERSE_DIRECTION;

        let chan_w: Vec<u16> = "Microsoft-Windows-Storage-ClassPnP/Operational\0"
            .encode_utf16()
            .collect();
        let query_w: Vec<u16> =
            "*[System[Provider[@Name='Microsoft-Windows-StorDiag'] and EventID=507]]\0"
                .encode_utf16()
                .collect();

        let h_query = evt_query(
            std::ptr::null_mut(),
            chan_w.as_ptr(),
            query_w.as_ptr(),
            query_flags,
        );
        if h_query.is_null() {
            return;
        }

        let mut events: [EvtHandle; 32] = [std::ptr::null_mut(); 32];
        let mut returned = 0u32;

        if evt_next(h_query, 32, events.as_mut_ptr(), 500, 0, &mut returned) != 0 && returned > 0 {
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
                ) != 0
                    && used > 0
                {
                    let xml_len = (used as usize / 2).saturating_sub(1);
                    let xml_text = String::from_utf16_lossy(&buf[..xml_len]);

                    let sense_key = extract_xml_data(&xml_text, "SenseKey").unwrap_or_default();
                    let asc = extract_xml_data(&xml_text, "AdditionalSenseCode").unwrap_or_default();

                    // SenseKey 2 = Not Ready, ASC 58 (0x3A) = Medium Not Present (USB abruptly removed)
                    if sense_key == "2" && asc == "58" {
                        let (in_session, time_str) = parse_xml_time_session(extract_xml_time(&xml_text).as_deref());
                        if in_session {
                            let vendor = extract_xml_data(&xml_text, "Vendor").unwrap_or_else(|| "USB".to_string());
                            let model = extract_xml_data(&xml_text, "Model").unwrap_or_else(|| "Storage Device".to_string());
                            let serial = extract_xml_data(&xml_text, "SerialNumber").unwrap_or_else(|| "Nieznany".to_string());
                            let full_name = format!("{} {}", vendor.trim(), model.trim());

                            let dedup_key = format!("507_{}_{}", serial, time_str);
                            if reported_events.insert(dedup_key) {
                                report.add(
                                    ScanFinding::new(
                                        "Abrupt USB Storage Removal Detected (ClassPnP Event 507 / Medium Not Present)",
                                        FindingCategory::TamperingAndAntiForensics,
                                        VerdictLevel::Detection,
                                        format!(
                                            "Sterownik pamięci masowej Windows zarejestrował nagłe odłączenie/wyciągnięcie nośnika USB bez bezpiecznego wysunięcia (SenseKey 2 / ASC 58: Medium Not Present) w bieżącej sesji: {}. Jest to silny dowód na gwałtowne wyjęcie pendrive'a z portu USB.",
                                            full_name
                                        ),
                                    )
                                    .with_evidence("Urządzenie USB", full_name)
                                    .with_evidence("Numer seryjny nośnika", serial)
                                    .with_evidence("Kod błędu SCSI", "SenseKey 2 (Not Ready), ASC 58 (Medium Not Present / Abrupt Removal)".to_string())
                                    .with_evidence("Dokładny czas odłączenia", time_str),
                                );
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

/// 2. Microsoft-Windows-DriverFrameworks-UserMode/Operational (Event 2102, 2103, 2105)
/// Wykrywa fizyczne odłączenie/usunięcie urządzenia PnP z portu.
unsafe fn scan_driver_frameworks_events(
    report: &mut ScanReport,
    evt_query: EvtQueryFn,
    evt_next: EvtNextFn,
    evt_close: EvtCloseFn,
    evt_render: EvtRenderFn,
    reported_events: &mut HashSet<String>,
) {
    unsafe {
        const EVT_QUERY_CHANNEL_PATH: u32 = 0x1;
        const EVT_QUERY_REVERSE_DIRECTION: u32 = 0x200;
        let query_flags = EVT_QUERY_CHANNEL_PATH | EVT_QUERY_REVERSE_DIRECTION;

        let chan_w: Vec<u16> = "Microsoft-Windows-DriverFrameworks-UserMode/Operational\0"
            .encode_utf16()
            .collect();
        let query_w: Vec<u16> =
            "*[System[Provider[@Name='Microsoft-Windows-DriverFrameworks-UserMode'] and (EventID=2102 or EventID=2103 or EventID=2105)]]\0"
                .encode_utf16()
                .collect();

        let h_query = evt_query(
            std::ptr::null_mut(),
            chan_w.as_ptr(),
            query_w.as_ptr(),
            query_flags,
        );
        if h_query.is_null() {
            return;
        }

        let mut events: [EvtHandle; 32] = [std::ptr::null_mut(); 32];
        let mut returned = 0u32;

        if evt_next(h_query, 32, events.as_mut_ptr(), 500, 0, &mut returned) != 0 && returned > 0 {
            for i in 0..returned as usize {
                let h_event = events[i];
                let mut buf = [0u16; 4096];
                let mut used = 0u32;
                let mut prop_count = 0u32;

                if evt_render(
                    std::ptr::null_mut(),
                    h_event,
                    1,
                    (buf.len() * 2) as u32,
                    buf.as_mut_ptr() as *mut std::ffi::c_void,
                    &mut used,
                    &mut prop_count,
                ) != 0
                    && used > 0
                {
                    let xml_len = (used as usize / 2).saturating_sub(1);
                    let xml_text = String::from_utf16_lossy(&buf[..xml_len]);

                    let (in_session, time_str) = parse_xml_time_session(extract_xml_time(&xml_text).as_deref());
                    if in_session {
                        let event_id = if xml_text.contains("<EventID>2102</EventID>") {
                            "2102 (Device Unplug / Stop)"
                        } else if xml_text.contains("<EventID>2103</EventID>") {
                            "2103 (Device Removal)"
                        } else {
                            "2105 (Device Removal Complete)"
                        };

                        let instance_id = extract_xml_data(&xml_text, "InstanceId")
                            .or_else(|| extract_xml_data(&xml_text, "DeviceInstanceId"))
                            .unwrap_or_else(|| "Urządzenie USB / PnP".to_string());

                        let dedup_key = format!("umdf_{}_{}", instance_id, time_str);
                        if reported_events.insert(dedup_key) {
                            report.add(
                                ScanFinding::new(
                                    "USB Device Unplugged / Disconnected (DriverFrameworks Event)",
                                    FindingCategory::TamperingAndAntiForensics,
                                    VerdictLevel::Detection,
                                    format!(
                                        "W dzienniku zdarzeń sterowników Windows (DriverFrameworks-UserMode) zarejestrowano fizyczne odłączenie/usunięcie urządzenia w bieżącej sesji: {}.",
                                        instance_id
                                    ),
                                )
                                .with_evidence("Zidentyfikowane urządzenie", instance_id)
                                .with_evidence("Zdarzenie PnP", event_id.to_string())
                                .with_evidence("Dokładny czas odłączenia", time_str),
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

/// 3. Microsoft-Windows-Partition/Diagnostic (Event 1006)
/// BusType 7 = BusTypeUsb.
/// Wykrywa aktywność wolumenu USB, weryfikując czy nośnik został wypięty z portu.
unsafe fn scan_partition_diagnostic_events(
    report: &mut ScanReport,
    evt_query: EvtQueryFn,
    evt_next: EvtNextFn,
    evt_close: EvtCloseFn,
    evt_render: EvtRenderFn,
    reported_events: &mut HashSet<String>,
) {
    unsafe {
        const EVT_QUERY_CHANNEL_PATH: u32 = 0x1;
        const EVT_QUERY_REVERSE_DIRECTION: u32 = 0x200;
        let query_flags = EVT_QUERY_CHANNEL_PATH | EVT_QUERY_REVERSE_DIRECTION;

        let chan_w: Vec<u16> = "Microsoft-Windows-Partition/Diagnostic\0"
            .encode_utf16()
            .collect();
        let query_w: Vec<u16> =
            "*[System[Provider[@Name='Microsoft-Windows-Partition'] and EventID=1006]]\0"
                .encode_utf16()
                .collect();

        let h_query = evt_query(
            std::ptr::null_mut(),
            chan_w.as_ptr(),
            query_w.as_ptr(),
            query_flags,
        );
        if h_query.is_null() {
            return;
        }

        let mut events: [EvtHandle; 32] = [std::ptr::null_mut(); 32];
        let mut returned = 0u32;

        if evt_next(h_query, 32, events.as_mut_ptr(), 500, 0, &mut returned) != 0 && returned > 0 {
            for i in 0..returned as usize {
                let h_event = events[i];
                let mut buf = [0u16; 4096];
                let mut used = 0u32;
                let mut prop_count = 0u32;

                if evt_render(
                    std::ptr::null_mut(),
                    h_event,
                    1,
                    (buf.len() * 2) as u32,
                    buf.as_mut_ptr() as *mut std::ffi::c_void,
                    &mut used,
                    &mut prop_count,
                ) != 0
                    && used > 0
                {
                    let xml_len = (used as usize / 2).saturating_sub(1);
                    let xml_text = String::from_utf16_lossy(&buf[..xml_len]);

                    let bus_type = extract_xml_data(&xml_text, "BusType").unwrap_or_default();
                    // BusType 7 = BusTypeUsb in Windows
                    if bus_type == "7" {
                        let (in_session, time_str) = parse_xml_time_session(extract_xml_time(&xml_text).as_deref());
                        if in_session {
                            let mfg = extract_xml_data(&xml_text, "Manufacturer").unwrap_or_else(|| "USB".to_string());
                            let model = extract_xml_data(&xml_text, "Model").unwrap_or_else(|| "Storage Device".to_string());
                            let serial = extract_xml_data(&xml_text, "SerialNumber").unwrap_or_else(|| "Nieznany".to_string());
                            let parent_id = extract_xml_data(&xml_text, "ParentId").unwrap_or_default();
                            let full_name = format!("{} {}", mfg.trim(), model.trim());

                            let pnp_status = if !parent_id.is_empty() {
                                query_device_pnp_status(&parent_id)
                            } else {
                                DeviceConnectionStatus::Unknown
                            };

                            // If the USB volume was active in this session, but the device is now Disconnected!
                            if pnp_status == DeviceConnectionStatus::Disconnected {
                                let dedup_key = format!("1006_{}_{}", serial, time_str);
                                if reported_events.insert(dedup_key) {
                                    report.add(
                                        ScanFinding::new(
                                            "USB Volume Disconnected / Unplugged in Current Session (Partition Event 1006)",
                                            FindingCategory::TamperingAndAntiForensics,
                                            VerdictLevel::Detection,
                                            format!(
                                                "Dziennik partycji Windows zarejestrował wolumen pamięci USB ({}, S/N: {}), który był zamontowany w bieżącej sesji, lecz urządzenie zostało ODŁĄCZONE (wypięte z portu) przed wykonaniem skanowania.",
                                                full_name, serial
                                            ),
                                        )
                                        .with_evidence("Urządzenie USB", full_name)
                                        .with_evidence("Numer seryjny / Identyfikator", serial)
                                        .with_evidence("Status urządzenia", "ODŁĄCZONE (Urządzenie nie znajduje się obecnie w portach USB)".to_string())
                                        .with_evidence("Identyfikator nadrzędny PnP", parent_id)
                                        .with_evidence("Czas zdarzenia partycji", time_str),
                                    );
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

fn extract_xml_data(xml: &str, tag_name: &str) -> Option<String> {
    for prefix in [
        format!("<Data Name='{}'>", tag_name),
        format!("<Data Name=\"{}\">", tag_name),
    ] {
        if let Some(pos) = xml.find(&prefix) {
            let start = pos + prefix.len();
            if let Some(end) = xml[start..].find("</Data>") {
                return Some(xml[start..start + end].trim().to_string());
            }
        }
    }
    None
}

fn extract_xml_time(xml: &str) -> Option<String> {
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

fn parse_xml_time_session(time_str: Option<&str>) -> (bool, String) {
    if let Some(t_str) = time_str {
        if let Ok(dt) = chrono::DateTime::parse_from_rfc3339(t_str) {
            let unix_secs = dt.timestamp().max(0) as u64;
            let boot_secs = get_boot_unix_timestamp();
            let is_current_session = unix_secs >= boot_secs.saturating_sub(60);
            let local_dt: chrono::DateTime<chrono::Local> = dt.with_timezone(&chrono::Local);
            let formatted = local_dt.format("%Y-%m-%d %H:%M:%S").to_string();
            return (is_current_session, formatted);
        }
    }
    (false, "Brak daty".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_device_pnp_status_query() {
        // Querying a completely non-existent device should return Disconnected or Unknown, never panic
        let status = query_device_pnp_status("USBSTOR\\Disk&Ven_Fake&Prod_Fake&Rev_0000\\123456789&0");
        assert!(matches!(
            status,
            DeviceConnectionStatus::Disconnected | DeviceConnectionStatus::Unknown
        ));
    }

    #[test]
    fn test_extract_xml_helpers() {
        let sample_xml = r#"<Event><System><TimeCreated SystemTime='2026-11-08T22:08:53.1479756Z'/></System><EventData><Data Name='Vendor'>Kingston</Data><Data Name='Model'>DataTraveler 3.0</Data><Data Name='SenseKey'>2</Data><Data Name='AdditionalSenseCode'>58</Data></EventData></Event>"#;
        assert_eq!(extract_xml_data(sample_xml, "Vendor"), Some("Kingston".to_string()));
        assert_eq!(extract_xml_data(sample_xml, "Model"), Some("DataTraveler 3.0".to_string()));
        assert_eq!(extract_xml_data(sample_xml, "SenseKey"), Some("2".to_string()));
        assert_eq!(extract_xml_data(sample_xml, "AdditionalSenseCode"), Some("58".to_string()));
        assert_eq!(extract_xml_time(sample_xml), Some("2026-11-08T22:08:53.1479756Z".to_string()));
    }
}
