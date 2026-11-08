use crate::report::{FindingCategory, ScanFinding, ScanReport, VerdictLevel};
use crate::scanner::forensics::get_boot_unix_timestamp;
use windows_sys::Win32::System::Registry::{
    RegCloseKey, RegEnumValueW, RegOpenKeyExW, HKEY_CURRENT_USER, KEY_READ,
};

pub fn scan_virtual_and_network_drives(report: &mut ScanReport) {
    scan_map_network_drive_mru(report);
    scan_vhdmp_events(report);
    scan_ramdisk_and_virtual_drivers(report);
    scan_non_journaled_and_ram_volumes(report);
}

/// 1. Scans network drive mapping history in Map Network Drive MRU
fn scan_map_network_drive_mru(report: &mut ScanReport) {
    let mru_key: Vec<u16> = "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Map Network Drive MRU\0"
        .encode_utf16()
        .collect();

    unsafe {
        let mut h_key = std::ptr::null_mut();
        if RegOpenKeyExW(HKEY_CURRENT_USER, mru_key.as_ptr(), 0, KEY_READ, &mut h_key) != 0 {
            return;
        }

        let mut val_idx = 0u32;
        let mut name_buf = [0u16; 64];
        let mut data_buf = [0u16; 512];

        loop {
            let mut name_len = 64u32;
            let mut data_len = 1024u32;
            let mut val_type = 0u32;

            let ret = RegEnumValueW(
                h_key,
                val_idx,
                name_buf.as_mut_ptr(),
                &mut name_len,
                std::ptr::null_mut(),
                &mut val_type,
                data_buf.as_mut_ptr() as *mut u8,
                &mut data_len,
            );

            if ret != 0 {
                break;
            }

            let val_name = String::from_utf16_lossy(&name_buf[..name_len as usize]);
            if !val_name.eq_ignore_ascii_case("MRUList") && data_len > 2 {
                let char_len = (data_len as usize / 2).saturating_sub(1);
                let remote_path = String::from_utf16_lossy(&data_buf[..char_len]);

                if remote_path.starts_with(r"\\") {
                    report.add(
                        ScanFinding::new(
                            "Network Share Traced in Map Network Drive MRU",
                            FindingCategory::WindowsForensics,
                            VerdictLevel::Information,
                            format!(
                                "W historii kreatora mapowania dysków sieciowych Windows Explorer zarejestrowano udział: {}.",
                                remote_path
                            ),
                        )
                        .with_evidence("Litera/Klucz MRU", val_name)
                        .with_evidence("Zdalny udział sieciowy (UNC)", remote_path),
                    );
                }
            }

            val_idx += 1;
        }

        RegCloseKey(h_key);
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

/// 2. Scans VHDMP driver events (Event ID 1 and 2) for mounting and unmounting virtual VHD/VHDX disks
fn scan_vhdmp_events(report: &mut ScanReport) {
    unsafe {
        let wevtapi = windows_sys::Win32::System::LibraryLoader::LoadLibraryA(b"wevtapi.dll\0".as_ptr());
        if wevtapi.is_null() {
            return;
        }

        let p_query = windows_sys::Win32::System::LibraryLoader::GetProcAddress(wevtapi, b"EvtQuery\0".as_ptr());
        let p_next = windows_sys::Win32::System::LibraryLoader::GetProcAddress(wevtapi, b"EvtNext\0".as_ptr());
        let p_close = windows_sys::Win32::System::LibraryLoader::GetProcAddress(wevtapi, b"EvtClose\0".as_ptr());
        let p_render = windows_sys::Win32::System::LibraryLoader::GetProcAddress(wevtapi, b"EvtRender\0".as_ptr());

        if let (Some(f_query), Some(f_next), Some(f_close), Some(f_render)) = (p_query, p_next, p_close, p_render) {
            let evt_query: EvtQueryFn = std::mem::transmute(f_query);
            let evt_next: EvtNextFn = std::mem::transmute(f_next);
            let evt_close: EvtCloseFn = std::mem::transmute(f_close);
            let evt_render: EvtRenderFn = std::mem::transmute(f_render);

            const EVT_QUERY_CHANNEL_PATH: u32 = 0x1;
            const EVT_QUERY_REVERSE_DIRECTION: u32 = 0x200;
            let query_flags = EVT_QUERY_CHANNEL_PATH | EVT_QUERY_REVERSE_DIRECTION;

            let chan_w: Vec<u16> = "System\0".encode_utf16().collect();
            let query_w: Vec<u16> = "*[System[Provider[@Name='Microsoft-Windows-VHDMP'] and (EventID=1 or EventID=2)]]\0"
                .encode_utf16()
                .collect();

            let h_query = evt_query(std::ptr::null_mut(), chan_w.as_ptr(), query_w.as_ptr(), query_flags);
            if !h_query.is_null() {
                let mut events: [EvtHandle; 32] = [std::ptr::null_mut(); 32];
                let mut returned = 0u32;

                if evt_next(h_query, 32, events.as_mut_ptr(), 500, 0, &mut returned) != 0 && returned > 0 {
                    let mut reported_vhds = std::collections::HashSet::new();

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

                            let is_detach = xml_text.contains("<EventID>2</EventID>") || xml_text.contains("EventID='2'");
                            let vhd_path = extract_vhd_path(&xml_text).unwrap_or_else(|| "Plik wirtualnego dysku VHD".to_string());
                            let time_created = extract_vhd_time(&xml_text);

                            let mut is_current_session = false;
                            let mut time_str = time_created.clone().unwrap_or_else(|| "Nieznany".to_string());

                            if let Some(ref t_str) = time_created {
                                if let Ok(dt) = chrono::DateTime::parse_from_rfc3339(t_str) {
                                    let unix_secs = dt.timestamp().max(0) as u64;
                                    let boot_secs = get_boot_unix_timestamp();
                                    is_current_session = unix_secs >= boot_secs.saturating_sub(60);
                                    let local_dt: chrono::DateTime<chrono::Local> = dt.with_timezone(&chrono::Local);
                                    time_str = local_dt.format("%Y-%m-%d %H:%M:%S").to_string();
                                }
                            }

                            if reported_vhds.insert(format!("{}_{}_{}", vhd_path, is_detach, is_current_session)) {
                                if is_detach && is_current_session {
                                    report.add(
                                        ScanFinding::new(
                                            "Virtual Hard Disk (VHD) Dismounted in Current Session",
                                            FindingCategory::TamperingAndAntiForensics,
                                            VerdictLevel::Detection,
                                            format!(
                                                "Wykryto odmontowanie wirtualnego kontenera dyskowego (VHD/VHDX) w bieżącej sesji gry ({} o: {}). Technika ta służy do ukrywania cheatów na wirtualnym dysku i jego odłączania przed procedurą screenshare.",
                                                vhd_path, time_str
                                            ),
                                        )
                                        .with_evidence("Ścieżka pliku VHD", vhd_path.clone())
                                        .with_evidence("Czas odmontowania", time_str)
                                        .with_evidence("Zdarzenie", "Microsoft-Windows-VHDMP (Event ID 2 - Detach)".to_string()),
                                    );
                                } else if is_current_session {
                                    report.add(
                                        ScanFinding::new(
                                            "Virtual Hard Disk (VHD) Mounted in Current Session",
                                            FindingCategory::WindowsForensics,
                                            VerdictLevel::Warning,
                                            format!(
                                                "Zarejestrowano zamontowanie wirtualnego kontenera dyskowego (VHD/VHDX) w bieżącej sesji gry: {} (o: {}).",
                                                vhd_path, time_str
                                            ),
                                        )
                                        .with_evidence("Ścieżka pliku VHD", vhd_path)
                                        .with_evidence("Czas zamontowania", time_str)
                                        .with_evidence("Zdarzenie", "Microsoft-Windows-VHDMP (Event ID 1 - Surface)".to_string()),
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

fn extract_vhd_path(xml: &str) -> Option<String> {
    for pattern in ["VhdFile\">", "VhdPath\">", "VhdFile'>", "VhdPath'>"] {
        if let Some(pos) = xml.find(pattern) {
            let start = pos + pattern.len();
            if let Some(end) = xml[start..].find("</Data>") {
                return Some(xml[start..start + end].trim().to_string());
            }
        }
    }
    None
}

fn extract_vhd_time(xml: &str) -> Option<String> {
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

struct VirtualDiskDriverInfo {
    driver_name: &'static str,
    software_name: &'static str,
    threat_description: &'static str,
    verdict: VerdictLevel,
}

const KNOWN_VIRTUAL_DISK_DRIVERS: &[VirtualDiskDriverInfo] = &[
    VirtualDiskDriverInfo {
        driver_name: "imdisk.sys",
        software_name: "ImDisk Virtual Disk Driver",
        threat_description: "Sterownik wirtualnego dysku RAM. Powszechnie używany do tworzenia ulotnych partycji pamięci operacyjnej do odpalania cheatów bez zapisu na dysku fizycznym.",
        verdict: VerdictLevel::Warning,
    },
    VirtualDiskDriverInfo {
        driver_name: "awealloc.sys",
        software_name: "ImDisk AWE Memory Allocator",
        threat_description: "Komponent sterownika ImDisk alokujący pamięć fizyczną AWE dla dysku RAM.",
        verdict: VerdictLevel::Warning,
    },
    VirtualDiskDriverInfo {
        driver_name: "pramdisk.sys",
        software_name: "Primo Ramdisk",
        threat_description: "Komercyjny sterownik dysku RAM używany do ukrywania plików cheatów w pamięci ulotnej.",
        verdict: VerdictLevel::Warning,
    },
    VirtualDiskDriverInfo {
        driver_name: "osfmnt.sys",
        software_name: "OSFMount Virtual Disk",
        threat_description: "Sterownik montowania obrazów dysków i wolumenów RAM w systemie Windows.",
        verdict: VerdictLevel::Warning,
    },
    VirtualDiskDriverInfo {
        driver_name: "arsenalimage.sys",
        software_name: "Arsenal Image Mounter",
        threat_description: "Sterownik montowania wirtualnych kontenerów i obrazów dysków w Windows.",
        verdict: VerdictLevel::Warning,
    },
    VirtualDiskDriverInfo {
        driver_name: "veracrypt.sys",
        software_name: "VeraCrypt Container Driver",
        threat_description: "Sterownik szyfrowanych wolumenów VeraCrypt. Używany do ukrywania cheatów w zaszyfrowanych plikach kontenerowych.",
        verdict: VerdictLevel::Warning,
    },
    VirtualDiskDriverInfo {
        driver_name: "truecrypt.sys",
        software_name: "TrueCrypt Container Driver",
        threat_description: "Sterownik szyfrowanych kontenerów dyskowych TrueCrypt.",
        verdict: VerdictLevel::Warning,
    },
    VirtualDiskDriverInfo {
        driver_name: "shadow.sys",
        software_name: "Shadow Defender System Freezer",
        threat_description: "Sterownik zamrażania dysku (Shadow Mode). Przekierowuje wszystkie zapisy dyskowe do RAM i cofa stan systemu po restarcie, zacierając ślady cheatów.",
        verdict: VerdictLevel::Detection,
    },
    VirtualDiskDriverInfo {
        driver_name: "diskgo.sys",
        software_name: "Deep Freeze Kernel Driver",
        threat_description: "Sterownik zamrażania partycji systemowej Deep Freeze.",
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

/// 3. Scans loaded kernel drivers for RAM disks, virtual containers, and disk shadow/freezer utilities
fn scan_ramdisk_and_virtual_drivers(report: &mut ScanReport) {
    unsafe {
        let psapi = windows_sys::Win32::System::LibraryLoader::LoadLibraryA(b"psapi.dll\0".as_ptr());
        let (mut p_enum, mut p_base) = if !psapi.is_null() {
            (
                windows_sys::Win32::System::LibraryLoader::GetProcAddress(psapi, b"EnumDeviceDrivers\0".as_ptr()),
                windows_sys::Win32::System::LibraryLoader::GetProcAddress(psapi, b"GetDeviceDriverBaseNameA\0".as_ptr()),
            )
        } else {
            (None, None)
        };

        let mut kernel32 = std::ptr::null_mut();
        if p_enum.is_none() {
            kernel32 = windows_sys::Win32::System::LibraryLoader::LoadLibraryA(b"kernel32.dll\0".as_ptr());
            if !kernel32.is_null() {
                p_enum = windows_sys::Win32::System::LibraryLoader::GetProcAddress(kernel32, b"K32EnumDeviceDrivers\0".as_ptr());
                p_base = windows_sys::Win32::System::LibraryLoader::GetProcAddress(kernel32, b"K32GetDeviceDriverBaseNameA\0".as_ptr());
            }
        }

        if let (Some(enum_raw), Some(base_raw)) = (p_enum, p_base) {
            let enum_drivers: EnumDeviceDriversFn = std::mem::transmute(enum_raw);
            let get_base_name: GetDeviceDriverBaseNameAFn = std::mem::transmute(base_raw);

            let mut drivers: [*mut std::ffi::c_void; 2048] = [std::ptr::null_mut(); 2048];
            let mut cb_needed: u32 = 0;

            if enum_drivers(
                drivers.as_mut_ptr(),
                (drivers.len() * std::mem::size_of::<*mut std::ffi::c_void>()) as u32,
                &mut cb_needed,
            ) != 0 {
                let count = (cb_needed as usize / std::mem::size_of::<*mut std::ffi::c_void>()).min(drivers.len());

                for &driver_base in &drivers[..count] {
                    if driver_base.is_null() {
                        continue;
                    }

                    let mut base_name_buf = [0u8; 260];
                    let name_len = get_base_name(driver_base, base_name_buf.as_mut_ptr(), base_name_buf.len() as u32);
                    if name_len > 0 {
                        let base_name = String::from_utf8_lossy(&base_name_buf[..name_len as usize]).to_lowercase();

                        for info in KNOWN_VIRTUAL_DISK_DRIVERS {
                            if base_name == info.driver_name {
                                report.add(
                                    ScanFinding::new(
                                        format!("Virtual Disk / Ramdisk Driver Active: {}", info.driver_name),
                                        FindingCategory::TamperingAndAntiForensics,
                                        info.verdict,
                                        format!(
                                            "W jądrze Windows wykryto załadowany sterownik wirtualizacji dyskowej: {} ({}). {}",
                                            info.driver_name, info.software_name, info.threat_description
                                        ),
                                    )
                                    .with_evidence("Sterownik jądra", info.driver_name.to_string())
                                    .with_evidence("Oprogramowanie", info.software_name.to_string())
                                    .with_evidence("Wektor zagrożenia", info.threat_description.to_string())
                                    .with_evidence("Adres bazowy w ring0", format!("0x{:X}", driver_base as usize)),
                                );
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

/// 4. Scans all mounted volumes to identify non-journaled file systems (FAT, FAT32, exFAT, RAW)
/// and RAM disks where NTFS USN change journaling is unavailable.
pub fn scan_non_journaled_and_ram_volumes(report: &mut ScanReport) {
    unsafe {
        let mut buf = [0u16; 512];
        let len = windows_sys::Win32::Storage::FileSystem::GetLogicalDriveStringsW(buf.len() as u32, buf.as_mut_ptr());
        if len == 0 || len >= buf.len() as u32 {
            return;
        }

        let mut idx = 0usize;
        while idx < len as usize {
            let start = idx;
            while idx < len as usize && buf[idx] != 0 {
                idx += 1;
            }
            if idx > start {
                let root_slice = &buf[start..idx];
                let drive_str = String::from_utf16_lossy(root_slice);

                let root_with_null: Vec<u16> = root_slice.iter().copied().chain(std::iter::once(0)).collect();
                let drive_type = windows_sys::Win32::Storage::FileSystem::GetDriveTypeW(root_with_null.as_ptr());

                let mut vol_name = [0u16; 260];
                let mut fs_name = [0u16; 260];
                let mut serial = 0u32;
                let mut max_comp_len = 0u32;
                let mut flags = 0u32;

                if windows_sys::Win32::Storage::FileSystem::GetVolumeInformationW(
                    root_with_null.as_ptr(),
                    vol_name.as_mut_ptr(),
                    vol_name.len() as u32,
                    &mut serial,
                    &mut max_comp_len,
                    &mut flags,
                    fs_name.as_mut_ptr(),
                    fs_name.len() as u32,
                ) != 0 {
                    let fs_len = fs_name.iter().position(|&c| c == 0).unwrap_or(fs_name.len());
                    let fs_str = String::from_utf16_lossy(&fs_name[..fs_len]).to_uppercase();

                    let is_ramdisk = drive_type == 6; // DRIVE_RAMDISK
                    let is_non_journaled = fs_str.contains("FAT") || fs_str == "EXFAT" || fs_str == "RAW";

                    if is_ramdisk || is_non_journaled {
                        let drive_type_desc = match drive_type {
                            2 => "Removable Drive (USB Flash Drive)",
                            3 => "Fixed Local Disk",
                            4 => "Remote Network Drive",
                            6 => "RAM Disk (Volatile Memory)",
                            _ => "Storage Volume",
                        };

                        report.add(
                            ScanFinding::new(
                                format!("Non-Journaled File System Detected: {}", drive_str),
                                FindingCategory::WindowsForensics,
                                VerdictLevel::Warning,
                                format!(
                                    "Drive {} uses {} file system ({}). This file system does not support NTFS USN change journaling - deleted or renamed cheat files cannot be tracked on this volume. Manual screenshare verification required.",
                                    drive_str, fs_str, drive_type_desc
                                ),
                            )
                            .with_evidence("Drive", drive_str)
                            .with_evidence("File System", fs_str)
                            .with_evidence("Drive Type", drive_type_desc.to_string())
                            .with_evidence("USN Journal Supported", "NO (Non-NTFS volume)".to_string()),
                        );
                    }
                }
            }
            idx += 1;
        }
    }
}
