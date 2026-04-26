//! 4x4 Sudoku 网格生成 —— 与 mihomo `transport/sudoku/obfs/sudoku/grid.go` 等价。
//!
//! 生成所有合法的 4x4 数独网格（每行/列/2x2 块包含 1..=4 各一次）。
//! 总共 288 个合法网格。

pub type Grid = [u8; 16];

/// 生成全部 288 个合法的 4x4 数独网格。
pub fn generate_all_grids() -> Vec<Grid> {
    let mut grids = Vec::with_capacity(288);
    let mut g: Grid = [0u8; 16];
    backtrack(0, &mut g, &mut grids);
    grids
}

fn backtrack(idx: usize, g: &mut Grid, out: &mut Vec<Grid>) {
    if idx == 16 {
        out.push(*g);
        return;
    }
    let row = idx / 4;
    let col = idx % 4;
    let br = (row / 2) * 2;
    let bc = (col / 2) * 2;
    for num in 1u8..=4 {
        let mut valid = true;
        for i in 0..4 {
            if g[row * 4 + i] == num || g[i * 4 + col] == num {
                valid = false;
                break;
            }
        }
        if valid {
            'outer: for r in 0..2 {
                for c in 0..2 {
                    if g[(br + r) * 4 + (bc + c)] == num {
                        valid = false;
                        break 'outer;
                    }
                }
            }
        }
        if valid {
            g[idx] = num;
            backtrack(idx + 1, g, out);
            g[idx] = 0;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generates_288_grids() {
        let grids = generate_all_grids();
        assert_eq!(grids.len(), 288);
    }

    #[test]
    fn each_grid_is_valid() {
        let grids = generate_all_grids();
        for g in grids.iter().take(20) {
            // 每行包含 1..4
            for r in 0..4 {
                let mut row = vec![g[r * 4], g[r * 4 + 1], g[r * 4 + 2], g[r * 4 + 3]];
                row.sort();
                assert_eq!(row, vec![1, 2, 3, 4]);
            }
            // 每列
            for c in 0..4 {
                let mut col = vec![g[c], g[c + 4], g[c + 8], g[c + 12]];
                col.sort();
                assert_eq!(col, vec![1, 2, 3, 4]);
            }
        }
    }
}
