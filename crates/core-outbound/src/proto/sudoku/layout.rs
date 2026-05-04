//! Byte layout —— ASCII / Entropy / Custom 三种编码方案。
//!
//! 与 mihomo `transport/sudoku/obfs/sudoku/layout.go` 等价。
//!
//! ASCII 模式：所有字节带 0x40 高位 → 输出可见 ASCII 字符
//! Entropy 模式：高熵分布的 byte
//! Custom 模式：8 字符 pattern（2x + 2p + 4v）自定义比特位映射

#[derive(Debug, Clone)]
pub struct ByteLayout {
    pub name: String,
    pub padding_pool: Vec<u8>,
    pub is_ascii: bool,
    /// encode_hint[val 0..3][pos 0..15] -> wire byte
    pub encode_hint: [[u8; 16]; 4],
    /// encode_group[group 0..63] -> wire byte
    pub encode_group: [u8; 64],
    /// decode_group[wire byte] -> packed (val<<4 | pos)
    pub decode_group: [u8; 256],
    /// group_valid[wire byte] -> 是否有效
    pub group_valid: [bool; 256],
    /// hint_table[wire byte] -> 是否是 hint 字节
    pub hint_table: [bool; 256],
}

impl ByteLayout {
    pub fn hint_byte(&self, val: u8, pos: u8) -> u8 {
        self.encode_hint[(val & 0x03) as usize][(pos & 0x0F) as usize]
    }

    pub fn group_byte(&self, group: u8) -> u8 {
        self.encode_group[(group & 0x3F) as usize]
    }

    pub fn decode_packed_group(&self, b: u8) -> Option<u8> {
        if self.group_valid[b as usize] {
            Some(self.decode_group[b as usize])
        } else {
            None
        }
    }

    pub fn is_hint(&self, b: u8) -> bool {
        self.hint_table[b as usize]
    }
}

pub fn resolve_layout(mode: &str, custom_pattern: &str) -> Result<ByteLayout, String> {
    match mode.to_ascii_lowercase().as_str() {
        "ascii" | "prefer_ascii" => Ok(new_ascii_layout()),
        "entropy" | "prefer_entropy" | "" => {
            let cleaned = custom_pattern.trim();
            if !cleaned.is_empty() {
                new_custom_layout(cleaned)
            } else {
                Ok(new_entropy_layout())
            }
        }
        other => Err(format!("invalid ascii mode: {other}")),
    }
}

pub fn new_ascii_layout() -> ByteLayout {
    let mut padding_pool = Vec::with_capacity(32);
    for i in 0..32 {
        padding_pool.push(0x20 + i);
    }

    let mut encode_hint = [[0u8; 16]; 4];
    for val in 0..4 {
        for pos in 0..16 {
            let mut b = 0x40 | ((val as u8) << 4) | (pos as u8);
            if b == 0x7F {
                b = b'\n';
            }
            encode_hint[val][pos] = b;
        }
    }
    let mut encode_group = [0u8; 64];
    for group in 0..64 {
        let mut b = 0x40 | (group as u8);
        if b == 0x7F {
            b = b'\n';
        }
        encode_group[group] = b;
    }
    let mut hint_table = [false; 256];
    let mut decode_group = [0u8; 256];
    let mut group_valid = [false; 256];
    for b in 0..256 {
        let wire = b as u8;
        if (wire & 0x40) == 0x40 {
            hint_table[b] = true;
            decode_group[b] = wire & 0x3F;
            group_valid[b] = true;
        }
    }
    // 特殊：0x7F 替换为 '\n'
    hint_table[b'\n' as usize] = true;
    decode_group[b'\n' as usize] = 0x3F;
    group_valid[b'\n' as usize] = true;

    ByteLayout {
        name: "ascii".into(),
        padding_pool,
        is_ascii: true,
        encode_hint,
        encode_group,
        decode_group,
        group_valid,
        hint_table,
    }
}

pub fn new_entropy_layout() -> ByteLayout {
    let mut padding_pool = Vec::with_capacity(16);
    for i in 0..8 {
        padding_pool.push(0x80 + i);
        padding_pool.push(0x10 + i);
    }

    let mut encode_hint = [[0u8; 16]; 4];
    for val in 0..4 {
        for pos in 0..16 {
            encode_hint[val][pos] = ((val as u8) << 5) | (pos as u8);
        }
    }
    let mut encode_group = [0u8; 64];
    for group in 0..64u8 {
        let v = group;
        encode_group[group as usize] = ((v & 0x30) << 1) | (v & 0x0F);
    }
    let mut hint_table = [false; 256];
    let mut decode_group = [0u8; 256];
    let mut group_valid = [false; 256];
    for b in 0..256 {
        let wire = b as u8;
        if (wire & 0x90) != 0 {
            continue;
        }
        hint_table[b] = true;
        decode_group[b] = ((wire >> 1) & 0x30) | (wire & 0x0F);
        group_valid[b] = true;
    }

    ByteLayout {
        name: "entropy".into(),
        padding_pool,
        is_ascii: false,
        encode_hint,
        encode_group,
        decode_group,
        group_valid,
        hint_table,
    }
}

pub fn new_custom_layout(pattern: &str) -> Result<ByteLayout, String> {
    let cleaned: String = pattern
        .to_ascii_lowercase()
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect();
    if cleaned.len() != 8 {
        return Err(format!(
            "custom table must have 8 symbols, got {}",
            cleaned.len()
        ));
    }

    let mut x_bits: Vec<u8> = Vec::new();
    let mut p_bits: Vec<u8> = Vec::new();
    let mut v_bits: Vec<u8> = Vec::new();
    for (i, c) in cleaned.chars().enumerate() {
        let bit = 7 - i as u8;
        match c {
            'x' => x_bits.push(bit),
            'p' => p_bits.push(bit),
            'v' => v_bits.push(bit),
            other => return Err(format!("invalid char '{other}' in custom table")),
        }
    }

    if x_bits.len() != 2 || p_bits.len() != 2 || v_bits.len() != 4 {
        return Err("custom table must contain exactly 2 x, 2 p, 4 v".into());
    }

    let x_mask: u8 = x_bits.iter().fold(0u8, |acc, b| acc | (1 << b));

    let encode_bits = |val: u8, pos: u8, drop_x: i32| -> u8 {
        let mut out = x_mask;
        if drop_x >= 0 {
            out &= !(1 << x_bits[drop_x as usize]);
        }
        if (val & 0x02) != 0 {
            out |= 1 << p_bits[0];
        }
        if (val & 0x01) != 0 {
            out |= 1 << p_bits[1];
        }
        for (i, &bit) in v_bits.iter().enumerate() {
            if (pos >> (3 - i as u8)) & 0x01 == 1 {
                out |= 1 << bit;
            }
        }
        out
    };

    let mut padding_set = std::collections::BTreeSet::new();
    for drop in 0..x_bits.len() as i32 {
        for val in 0..4u8 {
            for pos in 0..16u8 {
                let b = encode_bits(val, pos, drop);
                if b.count_ones() >= 5 {
                    padding_set.insert(b);
                }
            }
        }
    }
    let padding_pool: Vec<u8> = padding_set.into_iter().collect();
    if padding_pool.is_empty() {
        return Err("custom table produced empty padding pool".into());
    }

    let mut encode_hint = [[0u8; 16]; 4];
    for val in 0..4u8 {
        for pos in 0..16u8 {
            encode_hint[val as usize][pos as usize] = encode_bits(val, pos, -1);
        }
    }
    let mut encode_group = [0u8; 64];
    for group in 0..64u8 {
        let val = (group >> 4) & 0x03;
        let pos = group & 0x0F;
        encode_group[group as usize] = encode_bits(val, pos, -1);
    }

    let mut hint_table = [false; 256];
    let mut decode_group = [0u8; 256];
    let mut group_valid = [false; 256];
    for b in 0..256 {
        let wire = b as u8;
        if (wire & x_mask) != x_mask {
            continue;
        }
        hint_table[b] = true;
        let mut val = 0u8;
        let mut pos = 0u8;
        if wire & (1 << p_bits[0]) != 0 {
            val |= 0x02;
        }
        if wire & (1 << p_bits[1]) != 0 {
            val |= 0x01;
        }
        for (i, &bit) in v_bits.iter().enumerate() {
            if wire & (1 << bit) != 0 {
                pos |= 1 << (3 - i as u8);
            }
        }
        decode_group[b] = (val << 4) | pos;
        group_valid[b] = true;
    }

    Ok(ByteLayout {
        name: format!("custom({cleaned})"),
        padding_pool,
        is_ascii: false,
        encode_hint,
        encode_group,
        decode_group,
        group_valid,
        hint_table,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ascii_layout_padding_size() {
        let l = new_ascii_layout();
        assert_eq!(l.padding_pool.len(), 32);
        assert!(l.is_ascii);
    }

    #[test]
    fn entropy_layout_padding_size() {
        let l = new_entropy_layout();
        assert_eq!(l.padding_pool.len(), 16);
        assert!(!l.is_ascii);
    }

    #[test]
    fn custom_layout_validates_pattern() {
        let l = new_custom_layout("xpvvxpvv").unwrap();
        assert!(!l.padding_pool.is_empty());
    }

    #[test]
    fn custom_layout_rejects_bad_pattern() {
        assert!(new_custom_layout("xxxxx").is_err()); // 太短
        assert!(new_custom_layout("xxpvvvvv").is_err()); // 多个 x
        assert!(new_custom_layout("xpvvxpv?").is_err()); // 非法字符
    }

    #[test]
    fn ascii_canonical_encode_decode() {
        // 对每个 group (0..63)，encode_group(group) → wire_byte → decode 应回到 group
        let l = new_ascii_layout();
        for group in 0..64u8 {
            let wire = l.group_byte(group);
            assert!(l.group_valid[wire as usize]);
            let decoded = l.decode_packed_group(wire).unwrap();
            assert_eq!(decoded, group, "group {} encode→decode mismatch", group);
        }
    }

    #[test]
    fn ascii_recognizes_high_bit_variants() {
        // 0xC0 与 0x40 都带 0x40 bit；都应被识别为 hint
        let l = new_ascii_layout();
        assert!(l.is_hint(0x40));
        assert!(l.is_hint(0xc0));
        assert!(!l.is_hint(0x00));
        assert!(!l.is_hint(0x20));
    }
}
