use crate::report::VerdictLevel;

/// Represents a byte pattern with optional wildcards ('??').
#[derive(Clone, Debug)]
pub struct AobPattern {
    pub name: &'static str,
    pub description: &'static str,
    pub level: VerdictLevel,
    pub pattern: Vec<Option<u8>>,
    // Anchor for fast scanning with memchr (first non-wildcard byte)
    pub anchor_offset: usize,
    pub anchor_byte: u8,
}

impl AobPattern {
    /// Creates a new AOB pattern from a hex string supporting wildcards ('??' or '?')
    /// e.g. "48 89 5C 24 ?? 48 89 74 24 ?? 57 48 83 EC 20"
    pub fn new(
        name: &'static str,
        hex_pattern: &str,
        description: &'static str,
        level: VerdictLevel,
    ) -> Result<Self, String> {
        let mut pattern = Vec::new();
        let parts: Vec<&str> = hex_pattern.split_whitespace().collect();

        if parts.is_empty() {
            return Err("Wzorzec AOB nie może być pusty".to_string());
        }

        let mut anchor: Option<(usize, u8)> = None;

        for (idx, part) in parts.iter().enumerate() {
            if *part == "??" || *part == "?" {
                pattern.push(None);
            } else {
                let byte = u8::from_str_radix(part, 16)
                    .map_err(|e| format!("Błąd parsowania bajtu hex '{}': {}", part, e))?;
                pattern.push(Some(byte));
                if anchor.is_none() {
                    anchor = Some((idx, byte));
                }
            }
        }

        let (anchor_offset, anchor_byte) = anchor
            .ok_or_else(|| "Wzorzec AOB musi zawierać co najmniej jeden konkretny bajt (nie tylko ??)".to_string())?;

        Ok(Self {
            name,
            description,
            level,
            pattern,
            anchor_offset,
            anchor_byte,
        })
    }

    /// Checks if the pattern matches a memory slice at the given offset
    #[inline(always)]
    pub fn matches_at(&self, data: &[u8], offset: usize) -> bool {
        if offset + self.pattern.len() > data.len() {
            return false;
        }

        for (i, expected) in self.pattern.iter().enumerate() {
            if let Some(expected_byte) = expected {
                if data[offset + i] != *expected_byte {
                    return false;
                }
            }
        }

        true
    }

    /// Finds the first occurrence of the pattern in memory using memchr acceleration
    pub fn find_in(&self, data: &[u8]) -> Option<usize> {
        if data.len() < self.pattern.len() {
            return None;
        }

        let mut search_from = self.anchor_offset;

        while search_from < data.len() {
            if let Some(pos) = memchr::memchr(self.anchor_byte, &data[search_from..]) {
                let absolute_pos = search_from + pos;
                let match_start = absolute_pos - self.anchor_offset;

                if self.matches_at(data, match_start) {
                    return Some(match_start);
                }

                search_from = absolute_pos + 1;
            } else {
                break;
            }
        }

        None
    }
}

/// Memory scanning engine using an Array of Bytes (AOB) signature database
pub struct AobScannerEngine {
    patterns: Vec<AobPattern>,
}

impl AobScannerEngine {
    pub fn new(patterns: Vec<AobPattern>) -> Self {
        Self { patterns }
    }

    /// Returns the number of loaded AOB patterns
    #[allow(dead_code)]
    pub fn len(&self) -> usize {
        self.patterns.len()
    }

    #[allow(dead_code)]
    pub fn is_empty(&self) -> bool {
        self.patterns.is_empty()
    }

    /// Scans a memory chunk and returns all matched patterns with their offsets
    pub fn scan_chunk<'a>(&'a self, data: &[u8]) -> Vec<(&'a AobPattern, usize)> {
        let mut results = Vec::new();

        for pattern in &self.patterns {
            if let Some(offset) = pattern.find_in(data) {
                results.push((pattern, offset));
            }
        }

        results
    }

    /// Creates the default engine with built-in cheat signatures
    pub fn default_engine() -> Self {
        let mut list = Vec::new();

        // 1. Doomsday Hex Bytecode Signatures ($h1 - $h10)
        let doomsday_hex_definitions = [
            ("Doomsday Bytecode Pattern #1", "18 f9 55 95 4e e4 58 64 86 2d 32 98 21 9e 8f 25 b7 36 10 05 4f dd cf 5c 5f e8 c5 d4 c7 92 33 2d d3 67 7d b8 82 68 38 73 86 3c 1a c2 00 30 1b 80"),
            ("Doomsday Bytecode Pattern #2", "43 00 fb 82 21 94 50 23 02 bb f1 c4 9b b8 e4 67 7f ea 03 c2 d7 4c 49 d3 41 3a c6 f9 6b 49 b9 c2 33 ba 48 c8 8c 33 30 33 1d 18 06 79 1c 3b 3e 04"),
            ("Doomsday Bytecode Pattern #3", "39 ff 32 b7 c5 72 17 eb d6 5a 6e 6c cc 14 40 d5 51 58 6d 2b dd c2 35 af ca 67 01 91 ac f9 2a ac c0 51 3d 35 f9 77 f5 a2 ed 3f 20 93 c8 f2 eb ec"),
            ("Doomsday Bytecode Pattern #4", "b2 0b 03 f5 1c d7 46 30 ce 0a 5f 8f 70 a1 b7 f7 9b 73 3c 25 f0 86 f6 dc 23 9f 08 b5 d5 2e 30 2f 60 a8 15 4d f5 00 09 8f 30 28 a0 9f af 82 08 26"),
            ("Doomsday Bytecode Pattern #5", "0a 18 bc 39 e6 12 d5 8f 5c 99 9c 55 8b e6 6f 3e fb 6c 5b 4c b9 84 17 96 4f 68 f4 e8 82 66 98 d7 ce 0f e6 3b 99 a2 f5 17 e8 c4 f3 71 95 e2 06 3f"),
            ("Doomsday Bytecode Pattern #6", "52 d4 66 0c 0d e4 a1 77 89 32 7d 4a b4 41 fd e1 3d ed 77 4a 1e 75 46 64 98 dc 59 0b 57 ba ed 5a 17 ee cb 68 28 a6 3a d1 7f 6b f5 f1 ec 4a 70 45"),
            ("Doomsday Bytecode Pattern #7", "aa 5c f9 c9 5f 12 69 22 40 b4 58 71 8e 4d 94 92 ab 58 25 ea 2b 7e 16 cf 0a 79 2b 70 9e ae 18 4f 91 32 55 c7 7e c3 db 4d 6e a2 81 23 ca 3f b4 09"),
            ("Doomsday Bytecode Pattern #8", "88 87 17 e5 83 59 ca ce 04 61 dc 79 ec c2 25 b1 7f db 5c a7 50 d1 bd 08 6b 19 a1 1d 60 90 e4 ea ab 58 7c 8a d6 83 72 02 f2 e2 d3 b1 4d 6d 7d 42"),
            ("Doomsday Bytecode Pattern #9", "c5 19 a6 77 44 42 2d ed c3 bf 23 4f 0b e0 30 0c d5 5e 8b 25 3b 33 2a 3d ba cc 97 f6 11 da 2f fd f4 22 b1 2b 02 fd 71 1e 41 d6 26 cc 1b de 4a 17"),
            ("Doomsday Bytecode Pattern #10", "c4 0f be e5 b0 b1 fc b6 ac 98 a4 a3 b1 2c d6 8f a0 27 5d 92 78 df d8 6a 0e d4 77 b2 a3 f4 94 57 36 9f 4c 80 74 26 b4 e7 98 af cb fa 14 24 65 f5"),
        ];

        for (name, hex) in doomsday_hex_definitions {
            if let Ok(p) = AobPattern::new(
                name,
                hex,
                "Detected unique bytecode sequence of injected Doomsday client.",
                VerdictLevel::Detection,
            ) {
                list.push(p);
            }
        }

        // Only unique, long signatures of specific cheats (np. Doomsday $h1 - $h10).
        // Never add short generic ASM sequences (np. 'mov rax; jmp rax' czy 'jmp rel32 int3'),
        // as HotSpot JVM JIT compiler (C1/C2) legally generates them for Java methods.

        Self::new(list)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_aob_exact_match() {
        let pattern = AobPattern::new(
            "Test",
            "DE AD BE EF",
            "Test desc",
            VerdictLevel::Detection,
        ).unwrap();

        let buffer = [0x00, 0x11, 0xDE, 0xAD, 0xBE, 0xEF, 0x22];
        assert_eq!(pattern.find_in(&buffer), Some(2));
    }

    #[test]
    fn test_aob_wildcard_match() {
        let pattern = AobPattern::new(
            "Test Wildcard",
            "48 8B ?? ?? 48 85 C0",
            "Test desc",
            VerdictLevel::Detection,
        ).unwrap();

        let buffer = [
            0x90, 0x90, 0x48, 0x8B, 0x05, 0xFA, 0x48, 0x85, 0xC0, 0x90,
        ];
        assert_eq!(pattern.find_in(&buffer), Some(2));
    }

    #[test]
    fn test_aob_no_match() {
        let pattern = AobPattern::new(
            "Test",
            "AA BB CC",
            "Test desc",
            VerdictLevel::Detection,
        ).unwrap();

        let buffer = [0xAA, 0xBB, 0xDD, 0xEE];
        assert_eq!(pattern.find_in(&buffer), None);
    }
}
