//! Moduł wielojęzyczności i detekcji języka systemu Windows (i18n)
//! Automatycznie wykrywa język interfejsu Windows (pl-PL -> Polish, inne -> English)
//! oraz pozwala na testowe wymuszenie zmienną środowiskową GRIND_LANG=pl/en.

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Language {
    Polish,
    English,
}

impl Language {
    /// Wykrywa język systemu Windows na podstawie GetUserDefaultUILanguage()
    /// lub zmiennej środowiskowej GRIND_LANG / LANG.
    pub fn current() -> Self {
        // 1. Opcjonalne wymuszenie zmienną środowiskową (do testów lub preferencji usera)
        if let Ok(val) = std::env::var("GRIND_LANG") {
            let lower = val.to_lowercase();
            if lower.starts_with("pl") {
                return Language::Polish;
            } else if lower.starts_with("en") {
                return Language::English;
            }
        }

        // 2. Natywna detekcja Win32 API (GetUserDefaultUILanguage)
        #[cfg(windows)]
        {
            unsafe {
                let kernel32 = windows_sys::Win32::System::LibraryLoader::GetModuleHandleA(
                    b"kernel32.dll\0".as_ptr(),
                );
                if !kernel32.is_null() {
                    let p_func = windows_sys::Win32::System::LibraryLoader::GetProcAddress(
                        kernel32,
                        b"GetUserDefaultUILanguage\0".as_ptr(),
                    );
                    if let Some(func) = p_func {
                        let get_ui_lang: unsafe extern "system" fn() -> u16 =
                            std::mem::transmute(func);
                        let lang_id = get_ui_lang();
                        // Primary language mask: 0x03FF; LANG_POLISH to 0x0015 (LCID 0x0415)
                        if (lang_id & 0x03FF) == 0x0015 {
                            return Language::Polish;
                        }
                    }
                }
            }
        }

        // 3. Fallback dla standardowych zmiennych środowiskowych systemów POSIX/Wine
        if let Ok(lang) = std::env::var("LANG") {
            if lang.to_lowercase().starts_with("pl") {
                return Language::Polish;
            }
        }
        if let Ok(lang) = std::env::var("LC_ALL") {
            if lang.to_lowercase().starts_with("pl") {
                return Language::Polish;
            }
        }

        Language::English
    }

    #[inline]
    pub fn is_polish(&self) -> bool {
        matches!(self, Language::Polish)
    }

    /// Tłumaczenie nazwy etapu skanera (Kroki 1 - 17)
    pub fn stage_name(&self, step: usize) -> &'static str {
        match self {
            Language::Polish => match step {
                1 => "Weryfikacja integralności skanera i API (Anti-Hooking Self-Defense)",
                2 => "Inicjalizacja reguł detekcji (YARA i własne sygnatury)",
                3 => "Inspekcja JVM, sterty, modułów i DLL Hijacking (javaw.exe)",
                4 => "Ślady zapisu na dysku NTFS USN Journal",
                5 => "Pamięć podręczna wykonania programów Windows Prefetch",
                6 => "Rejestr wykonania programów użytkownika (BAM)",
                7 => "Baza kompatybilności programów Windows Amcache.hve",
                8 => "Pamięć powłoki Windows Shell MuiCache i usunięte aplikacje",
                9 => "Historia wykonania aplikacji GUI (UserAssist ROT-13)",
                10 => "Kosz systemowy Windows ($Recycle.Bin - usunięte cheaty i skrypty)",
                11 => "Kompatybilność aplikacji Windows (ShimCache / AppCompatCache)",
                12 => "Historia poleceń konsoli PowerShell (ConsoleHost)",
                13 => "Wirtualne kontenery VHD/VHDX, dyski RAM i udziały sieciowe",
                14 => "Rejestr nośników USB, dysków wymiennych i sieciowych (USBSTOR)",
                15 => "Dzienniki PcaSvc, skróty Recent, Jump Lists i awarie WER",
                16 => "Integralność jądra, sterowniki BYOVD, usługi i EventLog (1102 / 104)",
                17 => "Połączenia TCP, DNS Cache, sockety cmd/powershell i plik hosts",
                _ => "Procedura analizy śledczej w toku...",
            },
            Language::English => match step {
                1 => "Scanner Integrity & WinAPI Verification (Anti-Hooking Self-Defense)",
                2 => "Detection Rules Initialization (YARA & Custom Signatures)",
                3 => "JVM, Heap, Loaded Modules & DLL Hijacking Inspection (javaw.exe)",
                4 => "NTFS USN Journal Forensic Trace Analysis",
                5 => "Windows Prefetch Execution History Analysis",
                6 => "User Background Activity Moderator Registry (BAM)",
                7 => "Amcache.hve Compatibility & Execution Database",
                8 => "MuiCache Windows Shell Cache & Deleted Applications",
                9 => "GUI Application Execution History (UserAssist ROT-13)",
                10 => "Recycle Bin Artifacts ($Recycle.Bin - Deleted Cheats & Scripts)",
                11 => "ShimCache / AppCompatCache Compatibility DB Analysis",
                12 => "PowerShell ConsoleHost Command History & Cleaners",
                13 => "Virtual Containers (VHD/VHDX), RAM Disks & Network Shares",
                14 => "USB & Removable Storage Registry Artifacts (USBSTOR)",
                15 => "PcaSvc Logs, Recent LNK, Jump Lists & WER Crash Reports",
                16 => "Kernel Integrity, BYOVD Drivers, Services & EventLog (1102 / 104)",
                17 => "Active TCP Connections, DNS Cache History & Hosts File Integrity",
                _ => "Forensic scan procedure in progress...",
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stage_names_all_steps_translated() {
        for step in 1..=17 {
            let pl = Language::Polish.stage_name(step);
            let en = Language::English.stage_name(step);
            assert!(!pl.is_empty());
            assert!(!en.is_empty());
            assert_ne!(pl, en, "Step {} should have different PL and EN names", step);
        }
    }

    #[test]
    fn test_env_override() {
        unsafe {
            std::env::set_var("GRIND_LANG", "pl");
            assert_eq!(Language::current(), Language::Polish);

            std::env::set_var("GRIND_LANG", "en");
            assert_eq!(Language::current(), Language::English);

            std::env::remove_var("GRIND_LANG");
        }
    }
}
