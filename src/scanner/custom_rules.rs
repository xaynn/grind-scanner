use crate::report::VerdictLevel;
use serde::Deserialize;
use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Clone, Debug)]
pub struct CustomYaraRule {
    pub file_name: String,
    #[allow(dead_code)]
    pub path: PathBuf,
    pub content: String,
}

#[derive(Clone, Debug)]
pub struct CustomStringRule {
    pub pattern: String,
    pub name: String,
    pub description: String,
    pub level: VerdictLevel,
    pub source_file: String,
}

#[derive(Clone, Debug, Default)]
pub struct CustomRulesManager {
    pub rules_dir: Option<PathBuf>,
    pub yara_rules: Vec<CustomYaraRule>,
    pub string_rules: Vec<CustomStringRule>,
    pub loaded_files_count: usize,
    pub syntax_errors: Vec<String>,
}

#[derive(Deserialize)]
struct JsonRuleItem {
    pattern: String,
    name: Option<String>,
    description: Option<String>,
    level: Option<String>,
}

/// Upewnia się, że folder /rules/ oraz pliki README.txt, readme_en.txt i example_rules.txt.example
/// istnieją natychmiast po uruchomieniu programu (obok exe lub w CWD).
pub fn ensure_rules_templates_exist() {
    let mut candidate_dirs = Vec::new();

    // 1. Obok pliku wykonywalnego (np. w folderze Pobrane / Pulpit)
    if let Ok(exe_path) = std::env::current_exe() {
        if let Some(parent) = exe_path.parent() {
            candidate_dirs.push(parent.join("rules"));
        }
    }

    // 2. W bieżącym katalogu roboczym (CWD)
    if let Ok(cwd) = std::env::current_dir() {
        let cwd_rules = cwd.join("rules");
        if !candidate_dirs.contains(&cwd_rules) {
            candidate_dirs.push(cwd_rules);
        }
    }

    let mut created_any = false;
    for dir in &candidate_dirs {
        if dir.is_dir() {
            create_default_rules_templates(dir);
            created_any = true;
        }
    }

    // Jeśli folder nie istniał w żadnej lokalizacji, utwórz go obok pliku exe
    if !created_any {
        if let Some(target_dir) = candidate_dirs.first() {
            if fs::create_dir_all(target_dir).is_ok() {
                create_default_rules_templates(target_dir);
            }
        }
    }
}

impl CustomRulesManager {
    /// Wyszukuje katalog /rules/ w pobliżu pliku wykonywalnego oraz w katalogu roboczym (CWD).
    /// Jeśli folder nie istnieje, tworzy go wraz z plikiem README i szablonem przykładu.
    pub fn load() -> Self {
        ensure_rules_templates_exist();

        let mut manager = CustomRulesManager::default();

        let mut candidate_dirs = Vec::new();

        // 1. Obok pliku wykonywalnego (np. w folderze Pobrane / Pulpit)
        if let Ok(exe_path) = std::env::current_exe() {
            if let Some(parent) = exe_path.parent() {
                candidate_dirs.push(parent.join("rules"));
            }
        }

        // 2. W bieżącym katalogu roboczym (CWD)
        if let Ok(cwd) = std::env::current_dir() {
            let cwd_rules = cwd.join("rules");
            if !candidate_dirs.contains(&cwd_rules) {
                candidate_dirs.push(cwd_rules);
            }
        }

        let mut existing_dirs = Vec::new();
        for dir in &candidate_dirs {
            if dir.is_dir() {
                create_default_rules_templates(dir);
                existing_dirs.push(dir.clone());
            }
        }

        if let Some(first) = existing_dirs.first() {
            manager.rules_dir = Some(first.clone());
        }

        let mut seen_files = HashSet::new();
        let mut all_files = Vec::new();

        for dir in &existing_dirs {
            collect_files_recursive(dir, &mut all_files);
        }

        for file_path in all_files {
            if !seen_files.insert(file_path.clone()) {
                continue;
            }

            let file_name = match file_path.file_name() {
                Some(name) => name.to_string_lossy().to_string(),
                None => continue,
            };

            // Ignorujemy szablony, pliki README oraz ukryte pliki konfiguracyjne
            let lower_name = file_name.to_lowercase();
            if file_name.ends_with(".example")
                || lower_name.starts_with("readme")
                || file_name.starts_with('.')
            {
                continue;
            }

            let ext = file_path
                .extension()
                .and_then(|s| s.to_str())
                .unwrap_or("")
                .to_lowercase();

            match ext.as_str() {
                "yar" | "yara" => {
                    match fs::read_to_string(&file_path) {
                        Ok(content) => {
                            manager.yara_rules.push(CustomYaraRule {
                                file_name: file_name.clone(),
                                path: file_path.clone(),
                                content,
                            });
                            manager.loaded_files_count += 1;
                        }
                        Err(err) => {
                            manager.syntax_errors.push(format!(
                                "Nie można odczytać pliku YARA {}: {}",
                                file_name, err
                            ));
                        }
                    }
                }
                "txt" | "strings" => {
                    match fs::read(&file_path) {
                        Ok(raw_bytes) => {
                            let text = String::from_utf8_lossy(&raw_bytes);
                            let added = parse_string_rules_from_text(
                                &text,
                                &file_name,
                                &mut manager.string_rules,
                            );
                            if added > 0 {
                                manager.loaded_files_count += 1;
                            }
                        }
                        Err(err) => {
                            manager.syntax_errors.push(format!(
                                "Nie można odczytać pliku tekstowego {}: {}",
                                file_name, err
                            ));
                        }
                    }
                }
                "json" => {
                    match fs::read_to_string(&file_path) {
                        Ok(content) => {
                            let added = parse_json_rules(
                                &content,
                                &file_name,
                                &mut manager.string_rules,
                                &mut manager.syntax_errors,
                            );
                            if added > 0 {
                                manager.loaded_files_count += 1;
                            }
                        }
                        Err(err) => {
                            manager.syntax_errors.push(format!(
                                "Nie można odczytać pliku JSON {}: {}",
                                file_name, err
                            ));
                        }
                    }
                }
                _ => {}
            }
        }

        manager
    }

    #[allow(dead_code)]
    pub fn has_yara_rules(&self) -> bool {
        !self.yara_rules.is_empty()
    }

    #[allow(dead_code)]
    pub fn has_string_rules(&self) -> bool {
        !self.string_rules.is_empty()
    }
}

/// Rekursywnie zbiera pliki z katalogu i podkatalogów
fn collect_files_recursive(dir: &Path, out: &mut Vec<PathBuf>) {
    if let Ok(entries) = fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                collect_files_recursive(&path, out);
            } else if path.is_file() {
                out.push(path);
            }
        }
    }
}

/// Parsuje reguły tekstowe linijka po linijce:
/// Format A: wzorzec
/// Format B: wzorzec | Nazwa | Opis | Poziom
fn parse_string_rules_from_text(
    text: &str,
    source_file: &str,
    out: &mut Vec<CustomStringRule>,
) -> usize {
    let mut added = 0;

    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with("//") {
            continue;
        }

        // Usunięcie ewentualnych komentarzy na końcu linii (inline comments)
        let clean = if let Some(idx) = trimmed.find('#') {
            trimmed[..idx].trim()
        } else if let Some(idx) = trimmed.find("//") {
            trimmed[..idx].trim()
        } else {
            trimmed
        };

        if clean.is_empty() {
            continue;
        }

        let parts: Vec<&str> = clean.split('|').map(|s| s.trim()).collect();
        let pattern = parts[0];

        // Zabezpieczenie przed zbyt krótkimi wzorcami wywołującymi masowe false-positive
        if pattern.len() < 3 {
            continue;
        }

        let name = if parts.len() > 1 && !parts[1].is_empty() {
            parts[1].to_string()
        } else {
            format!("Własna sygnatura: {}", pattern)
        };

        let description = if parts.len() > 2 && !parts[2].is_empty() {
            parts[2].to_string()
        } else {
            "Wykryto zdefiniowaną przez użytkownika sygnaturę tekstową w pamięci procesu gry.".to_string()
        };

        let level = if parts.len() > 3 {
            parse_verdict_level(parts[3])
        } else {
            VerdictLevel::Detection
        };

        out.push(CustomStringRule {
            pattern: pattern.to_string(),
            name,
            description,
            level,
            source_file: source_file.to_string(),
        });
        added += 1;
    }

    added
}

/// Parsuje reguły w formacie JSON (pojedynczy obiekt lub tablica obiektów)
fn parse_json_rules(
    json_text: &str,
    source_file: &str,
    out: &mut Vec<CustomStringRule>,
    errors: &mut Vec<String>,
) -> usize {
    let mut added = 0;

    // Próba 1: tablica obiektów
    if let Ok(items) = serde_json::from_str::<Vec<JsonRuleItem>>(json_text) {
        for item in items {
            if item.pattern.trim().len() < 3 {
                continue;
            }
            let name = item.name.unwrap_or_else(|| format!("Własna sygnatura: {}", item.pattern));
            let desc = item.description.unwrap_or_else(|| {
                "Wykryto zdefiniowaną przez użytkownika sygnaturę JSON w pamięci procesu gry.".to_string()
            });
            let level = item
                .level
                .as_deref()
                .map(parse_verdict_level)
                .unwrap_or(VerdictLevel::Detection);

            out.push(CustomStringRule {
                pattern: item.pattern,
                name,
                description: desc,
                level,
                source_file: source_file.to_string(),
            });
            added += 1;
        }
        return added;
    }

    // Próba 2: pojedynczy obiekt
    if let Ok(item) = serde_json::from_str::<JsonRuleItem>(json_text) {
        if item.pattern.trim().len() >= 3 {
            let name = item.name.unwrap_or_else(|| format!("Własna sygnatura: {}", item.pattern));
            let desc = item.description.unwrap_or_else(|| {
                "Wykryto zdefiniowaną przez użytkownika sygnaturę JSON w pamięci procesu gry.".to_string()
            });
            let level = item
                .level
                .as_deref()
                .map(parse_verdict_level)
                .unwrap_or(VerdictLevel::Detection);

            out.push(CustomStringRule {
                pattern: item.pattern,
                name,
                description: desc,
                level,
                source_file: source_file.to_string(),
            });
            added += 1;
        }
        return added;
    }

    errors.push(format!(
        "Błąd składni pliku JSON {}: plik musi zawierać obiekt lub tablicę obiektów z polem 'pattern'.",
        source_file
    ));

    added
}

fn parse_verdict_level(s: &str) -> VerdictLevel {
    match s.trim().to_lowercase().as_str() {
        "warning" | "warn" | "ostrzeżenie" | "ostrzezenie" => VerdictLevel::Warning,
        "info" | "information" | "informacja" => VerdictLevel::Information,
        _ => VerdictLevel::Detection,
    }
}

/// Tworzy czytelną dokumentację i przykładowy szablon w nowo utworzonym folderze /rules/
fn create_default_rules_templates(rules_dir: &Path) {
    let readme_path = rules_dir.join("README.txt");
    if !readme_path.exists() {
        let readme_content = r#"=== GRIND SCANNER - FOLDER WŁASNYCH REGUŁ (CUSTOM RULES) ===

W tym folderze możesz umieszczać własne sygnatury i reguły detekcji, które będą
automatycznie ładowane i uruchamiane przez skaner podczas inspekcji pamięci Minecrafta.

Obsługiwane formaty:

1. Pliki tekstowe (.txt, .strings)
   - Każda linijka to wzorzec tekstowy (string) szukany w pamięci procesu gry (MEM_PRIVATE).
   - Linie zaczynające się od '#' lub '//' są traktowane jako komentarze.
   - Minimalna długość wzorca: 3 znaki.
   - Prosty format (jeden string w linii):
       dev/mycheat/Main
       my_ghost_client.dll
   - Rozszerzony format (oddzielony znakiem '|'):
       wzorzec | Nazwa Cheata | Opis detekcji | Poziom
     Przykłady:
       dev/mycheat/Main | MyCheat Core | Wykryto klasę główną MyCheat | Detection
       myhook.dll | MyHook Injector | Wykryto bibliotekę DLL iniektora | Detection
       myclient/config | MyClient Config | Wykryto ścieżkę konfiguracji | Warning

2. Pliki reguł YARA (.yar, .yara)
   - Standardowe pliki reguł YARA kompilowane automatycznie w pamięci RAM.
   Przykład:
       rule MojaRegulaYARA {
           meta:
               description = "Wykrycie własnego ghost clienta"
           strings:
               $a = "com.cheat.module"
               $b = "InjectedGhostClient"
           condition:
               any of them
       }

3. Pliki JSON (.json)
   - Tablica obiektów zawierających pola "pattern", "name", "description", "level".
   Przykład:
       [
         {
           "pattern": "dev/sample/Hack",
           "name": "Sample Hack",
           "description": "Własna detekcja modułu Hack",
           "level": "Detection"
         }
       ]

Wskazówka: Pliki z rozszerzeniem .example są ignorowane (służą jako szablony).
Sprawdź gotowe szablony w języku angielskim:
  - echo_client.txt.example (format tekstowy)
  - echo_client.json.example (format JSON)
  - echo_client.yar.example (format YARA)
Aby aktywować regułę, usuń rozszerzenie .example z nazwy pliku.
"#;
        let _ = fs::write(readme_path, readme_content);
    }

    let readme_en_path = rules_dir.join("readme_en.txt");
    if !readme_en_path.exists() {
        let readme_en_content = r#"=== GRIND SCANNER - CUSTOM RULES DIRECTORY ===

In this directory, you can place your own custom detection signatures and rules.
They will be automatically loaded and executed by Grind Scanner during Minecraft memory inspection.

Supported Formats:

1. Plain Text Files (.txt, .strings)
   - Each line represents a string pattern to search for in Minecraft process memory (MEM_PRIVATE).
   - Empty lines and lines starting with '#' or '//' are treated as comments.
   - Minimum pattern length: 3 characters.
   - Simple format (one pattern per line):
       dev/mycheat/Main
       my_ghost_client.dll
   - Extended format (delimited by '|'):
       pattern | Cheat Name | Detection Description | Verdict Level
     Examples:
       dev/mycheat/Main | MyCheat Core | Detected main class of MyCheat | Detection
       myhook.dll | MyHook Injector | Detected injector native DLL module | Detection
       myclient/config | MyClient Config | Configuration artifact detected | Warning

2. YARA Rule Files (.yar, .yara)
   - Standard YARA rule files compiled dynamically in RAM within the "custom" namespace.
   Example:
       rule MyCustomGhostClient {
           meta:
               description = "Detection of custom private ghost client"
           strings:
               $a = "com.cheat.module"
               $b = "InjectedGhostClient"
           condition:
               any of them
       }

3. JSON Files (.json)
   - Array of objects containing "pattern", "name", "description", and "level" fields.
   Example:
       [
         {
           "pattern": "dev/sample/Hack",
           "name": "Sample Hack",
           "description": "Custom detection of Hack module",
           "level": "Detection"
         }
       ]

Tip: Files ending with '.example' or starting with 'readme' are ignored (used for templates & docs).
Ready-to-use English templates provided:
  - echo_client.txt.example (Plaintext format)
  - echo_client.json.example (JSON format)
  - echo_client.yar.example (YARA-X format)
To activate any template, simply remove the '.example' extension from its filename.
"#;
        let _ = fs::write(readme_en_path, readme_en_content);
    }

    let example_path = rules_dir.join("example_rules.txt.example");
    if !example_path.exists() {
        let example_content = r#"# Przykładowy plik własnych sygnatur stringowych.
# Aby go aktywować, usuń rozszerzenie .example (zmień nazwę na np. custom_rules.txt).

# Prosty string do wyszukania w pamięci:
# dev/mycustomclient/ClientMain

# String z pełnym opisem i poziomem zagrożenia (Detection / Warning / Information):
# com/custom/autoclicker | Custom Autoclicker Module | Wykryto moduł autoclickera | Detection
# custom_hook.dll | Custom Hook DLL | Wykryto nieautoryzowaną bibliotekę hookującą | Warning
"#;
        let _ = fs::write(example_path, example_content);
    }

    let echo_txt_path = rules_dir.join("echo_client.txt.example");
    if !echo_txt_path.exists() {
        let echo_txt_content = r#"# ==============================================================================
# GRIND SCANNER - ECHO CLIENT CUSTOM STRING RULES TEMPLATE (.txt / .strings)
# ==============================================================================
# To activate this rule file, remove the '.example' extension (e.g. rename to echo_client.txt).
# Each non-empty line without '#' or '//' represents a string pattern to search for
# within Minecraft process memory (MEM_PRIVATE JVM heap).
#
# Supported formats:
# Format A (Simple pattern per line):
#   pattern
#
# Format B (Extended format with custom metadata):
#   pattern | Cheat Name | Detection Description | Verdict Level (Detection / Warning / Information)
# ==============================================================================

# --- Format A: Simple Class & Package Signatures ---
hack/echo/client/Echo
Lhack/echo/client/features/Category;

# --- Format B: Extended Patterns with Metadata ---
Lhack/echo/client/chunk/BlockEspManager; | Echo Client BlockESP | Detected Block ESP module descriptor in JVM memory | Detection
Lhack/echo/client/spotify/SpotifyManager; | Echo Client Spotify | Detected Spotify integration module in JVM memory | Detection
hack/echo/client/features/ | Echo Client Features | Detected cheat features package tree | Detection
dev.jadyen.drm.echo | Echo Client DRM Loader | Detected Echo DRM loader package identifier | Detection
"#;
        let _ = fs::write(echo_txt_path, echo_txt_content);
    }

    let echo_json_path = rules_dir.join("echo_client.json.example");
    if !echo_json_path.exists() {
        let echo_json_content = r#"[
  {
    "pattern": "hack/echo/client/Echo",
    "name": "Echo Client Core Class",
    "description": "Detected Echo Client main core class in Minecraft JVM memory.",
    "level": "Detection"
  },
  {
    "pattern": "Lhack/echo/client/features/Category;",
    "name": "Echo Client Category Enum",
    "description": "Detected Echo Client module category enum descriptor.",
    "level": "Detection"
  },
  {
    "pattern": "Lhack/echo/client/chunk/BlockEspManager;",
    "name": "Echo Client BlockESP Manager",
    "description": "Detected Echo Client BlockESP rendering module.",
    "level": "Detection"
  },
  {
    "pattern": "Lhack/echo/client/spotify/SpotifyManager;",
    "name": "Echo Client Spotify Manager",
    "description": "Detected Echo Client Spotify integration manager.",
    "level": "Detection"
  },
  {
    "pattern": "dev.jadyen.drm.echo",
    "name": "Echo Client DRM Loader",
    "description": "Detected Echo Client DRM/Loader package in JVM heap.",
    "level": "Detection"
  }
]
"#;
        let _ = fs::write(echo_json_path, echo_json_content);
    }

    let echo_yar_path = rules_dir.join("echo_client.yar.example");
    if !echo_yar_path.exists() {
        let echo_yar_content = r#"/*
   GRIND SCANNER - ECHO CLIENT YARA RULE TEMPLATE (.yar / .yara)
   To activate this rule, remove the '.example' extension from the filename (e.g. echo_client.yar).
   This rule is compiled dynamically in RAM by yara-x under the 'custom' namespace.
*/

rule Echo_Ghost_Client {
    meta:
        description = "Detects Echo Ghost Client classes and modules in Minecraft JVM memory"
        author = "Grind Scanner Community"
        level = "Detection"
    strings:
        $pkg = "hack/echo/client/" ascii
        $main = "hack/echo/client/Echo" ascii
        $cat = "Lhack/echo/client/features/Category;" ascii
        $block_esp = "Lhack/echo/client/chunk/BlockEspManager;" ascii
        $spotify = "Lhack/echo/client/spotify/SpotifyManager;" ascii
        $drm = "dev.jadyen.drm.echo" ascii
    condition:
        $pkg or ($main and $cat) or $drm or 2 of ($*)
}
"#;
        let _ = fs::write(echo_yar_path, echo_yar_content);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_string_rules_from_text() {
        let sample = r#"
            # To jest komentarz
            // To też komentarz
            
            dev/lvstrng/custom
            com/cheat/Aimbot | Custom Aimbot | Wykryto moduł Aimbot | Detection
            some/warning/string | Warning Module | Moduł ostrzegawczy | Warning
            info_marker | Info Item | Informacja | Information
            ab # Za krótki string (< 3 znaki), powinien zostać odrzucony
        "#;

        let mut rules = Vec::new();
        let added = parse_string_rules_from_text(sample, "test.txt", &mut rules);

        assert_eq!(added, 4);
        assert_eq!(rules[0].pattern, "dev/lvstrng/custom");
        assert_eq!(rules[0].name, "Własna sygnatura: dev/lvstrng/custom");
        assert_eq!(rules[0].level, VerdictLevel::Detection);

        assert_eq!(rules[1].pattern, "com/cheat/Aimbot");
        assert_eq!(rules[1].name, "Custom Aimbot");
        assert_eq!(rules[1].description, "Wykryto moduł Aimbot");
        assert_eq!(rules[1].level, VerdictLevel::Detection);

        assert_eq!(rules[2].level, VerdictLevel::Warning);
        assert_eq!(rules[3].level, VerdictLevel::Information);
    }

    #[test]
    fn test_parse_json_rules() {
        let sample_array = r#"[
            {
                "pattern": "dev/json/cheat",
                "name": "JSON Cheat",
                "description": "Opis",
                "level": "Detection"
            },
            {
                "pattern": "warn/json/test",
                "level": "Warning"
            }
        ]"#;

        let mut rules = Vec::new();
        let mut errors = Vec::new();
        let count = parse_json_rules(sample_array, "test.json", &mut rules, &mut errors);

        assert_eq!(count, 2);
        assert!(errors.is_empty());
        assert_eq!(rules[0].pattern, "dev/json/cheat");
        assert_eq!(rules[1].level, VerdictLevel::Warning);
    }

    #[test]
    fn test_create_default_rules_templates() {
        let temp_dir = std::env::temp_dir().join("test_rules_gen_dir");
        let _ = fs::create_dir_all(&temp_dir);

        create_default_rules_templates(&temp_dir);

        assert!(temp_dir.join("README.txt").exists());
        assert!(temp_dir.join("readme_en.txt").exists());
        assert!(temp_dir.join("example_rules.txt.example").exists());
        assert!(temp_dir.join("echo_client.txt.example").exists());
        assert!(temp_dir.join("echo_client.json.example").exists());
        assert!(temp_dir.join("echo_client.yar.example").exists());

        let _ = fs::remove_dir_all(&temp_dir);
    }
}
