use crate::scanner::custom_rules::CustomYaraRule;
use crate::scanner::embedded_rules::{decrypt_rule, EMBEDDED_RULES};
use yara_x::{Compiler, Rules, Scanner};

pub struct YaraScannerEngine {
    pub rules: Option<Rules>,
    pub compiled_rules_count: usize,
    pub custom_rules_count: usize,
}

impl YaraScannerEngine {
    /// Loads and decrypts embedded YARA rules directly from memory (no files on disk, encrypted in binary)
    #[allow(dead_code)]
    pub fn new_embedded() -> Self {
        let (engine, _) = Self::new_with_custom(&[]);
        engine
    }

    /// Loads embedded rules and compiles user-defined YARA rules from the /rules/ folder
    pub fn new_with_custom(custom_yara_rules: &[CustomYaraRule]) -> (Self, Vec<String>) {
        let mut compiler = Compiler::new();
        let mut loaded = 0;
        let mut custom_loaded = 0;
        let mut errors = Vec::new();

        // 1. Compile embedded rules
        for rule in EMBEDDED_RULES {
            let mut decrypted_content = decrypt_rule(rule.data);
            if rule.name == "CheatA.yar" {
                // False-positive prevention: GenericA rule contains the generic phrase "In Inventory",
                // which appears in vanilla Minecraft language files. Require at least 2 cheat indicators.
                decrypted_content = decrypted_content.replace("any of ($gen_*)", "2 of ($gen_*)");
            }
            match compiler.add_source(decrypted_content.as_str()) {
                Ok(_) => {
                    loaded += 1;
                }
                Err(err) => {
                    errors.push(format!("Błąd kompilacji wbudowanej reguły {}: {}", rule.name, err));
                }
            }
        }

        // 2. Safely compile custom user rules
        if !custom_yara_rules.is_empty() {
            let _ = compiler.new_namespace("custom");

            for custom_rule in custom_yara_rules {
                // Pre-validate in an isolated compiler so syntax errors do not corrupt the main engine state
                let mut validator = Compiler::new();
                match validator.add_source(custom_rule.content.as_str()) {
                    Ok(_) => {
                        if compiler.add_source(custom_rule.content.as_str()).is_ok() {
                            loaded += 1;
                            custom_loaded += 1;
                        } else {
                            errors.push(format!(
                                "Błąd dołączania reguły YARA w pliku {}.",
                                custom_rule.file_name
                            ));
                        }
                    }
                    Err(err) => {
                        errors.push(format!(
                            "Błąd składni reguły YARA w pliku {}: {}",
                            custom_rule.file_name, err
                        ));
                    }
                }
            }
        }

        let rules = if loaded > 0 {
            Some(compiler.build())
        } else {
            None
        };

        (
            Self {
                rules,
                compiled_rules_count: loaded,
                custom_rules_count: custom_loaded,
            },
            errors,
        )
    }

    pub fn create_scanner(&self) -> Option<Scanner<'_>> {
        self.rules.as_ref().map(|r| Scanner::new(r))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_all_embedded_rules_compile() {
        let engine = YaraScannerEngine::new_embedded();
        assert_eq!(
            engine.compiled_rules_count,
            EMBEDDED_RULES.len(),
            "All embedded YARA rules must compile successfully without syntax errors"
        );
        assert!(engine.rules.is_some());
    }

    #[test]
    fn test_custom_yara_rules_compilation_and_errors() {
        let valid_rule = CustomYaraRule {
            file_name: "valid.yar".to_string(),
            path: std::path::PathBuf::from("valid.yar"),
            content: r#"
                rule ValidTestRule {
                    strings:
                        $s = "test_custom_signature_string"
                    condition:
                        $s
                }
            "#.to_string(),
        };

        let invalid_rule = CustomYaraRule {
            file_name: "invalid.yar".to_string(),
            path: std::path::PathBuf::from("invalid.yar"),
            content: r#"
                rule InvalidTestRule {
                    this is not valid yara syntax!
                }
            "#.to_string(),
        };

        let (engine, errors) = YaraScannerEngine::new_with_custom(&[valid_rule, invalid_rule]);
        assert_eq!(engine.custom_rules_count, 1);
        assert_eq!(errors.len(), 1);
        assert!(errors[0].contains("invalid.yar"));
        assert!(engine.rules.is_some());

        // Verify that scanner detects a matching pattern from the rule
        let mut scanner = engine.create_scanner().unwrap();
        let scan_res = scanner.scan(b"here is test_custom_signature_string in buffer").unwrap();
        let matched: Vec<_> = scan_res.matching_rules().map(|r| r.identifier().to_string()).collect();
        assert!(matched.contains(&"ValidTestRule".to_string()));
    }
}

