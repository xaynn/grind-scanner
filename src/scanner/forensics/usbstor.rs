use crate::report::{FindingCategory, ScanFinding, ScanReport, VerdictLevel};
use crate::scanner::forensics::{format_filetime, was_executed_in_current_session};
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
}

/// Skanuje klucz rejestru HKLM\SYSTEM\CurrentControlSet\Enum\USBSTOR
/// w celu wykrycia urządzeń pamięci masowej USB (pendrive, dyski zewnętrzne).
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
            let time_str = format_filetime(ft_raw).unwrap_or_else(|| "Brak znacznika czasu".to_string());

            if in_session {
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

/// Skanuje punkty montowania wolumenów w HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2
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

            // 1. Sprawdzamy czy to udział sieciowy SMB (np. ##192.168.1.100#share lub ##UNC#server#share)
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

/// Skanuje aktywne litery dysków w poszukiwaniu nośników wymiennych (DRIVE_REMOVABLE = 2) i sieciowych (DRIVE_REMOTE = 4)
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

/// Skanuje rejestr pod kątem ukrywania dysków (NoDrives) oraz historii mapowania sieci (HKCU\Network)
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
