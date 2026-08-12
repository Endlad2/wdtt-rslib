use anyhow::{anyhow, Result};
use image::{ImageBuffer, Rgb};
use rand::Rng;
use rayon::prelude::*;
use serde_json::Value;
use std::collections::HashMap;
use std::cmp::Ordering;

#[derive(Debug, Clone)]
pub struct sliderPuzzleV2 {
    pub image: ImageBuffer<Rgb<u8>, Vec<u8>>,
    pub size: usize,
    pub swaps: Vec<usize>,
    pub attempts: usize,
}

#[derive(Debug, Clone)]
pub struct sliderGuessV2 {
    pub index: usize,
    pub swaps: Vec<usize>,
    pub score: i64,
    pub score_rgb: i64,
    pub score_luma: i64,
    pub score_text: f64,
    pub consensus_rank: usize,
}

pub fn rankSliderGuessesV2(
    img: &ImageBuffer<Rgb<u8>, Vec<u8>>,
    grid_size: usize,
    swaps: &[usize],
) -> Result<Vec<sliderGuessV2>> {
    let candidate_count = swaps.len() / 2;
    if candidate_count == 0 {
        return Err(anyhow!("slider has no candidates"));
    }

    let mut guesses: Vec<sliderGuessV2> = (1..=candidate_count)
        .into_par_iter()
        .map(|idx| {
            let active = activeSwapsForIndexV2(swaps, idx);
            let mapping = applySliderSwapsV2(grid_size, &active).unwrap_or_else(|_| vec![]);
            let score_luma = seamScoreLumaV2(img, grid_size, &mapping);
            sliderGuessV2 {
                index: idx,
                swaps: active,
                score: 0,
                score_rgb: 0,
                score_luma,
                score_text: 0.0,
                consensus_rank: 0,
            }
        })
        .collect();

    let mut luma_order = guesses.clone();
    luma_order.sort_by(|a, b| {
        a.score_luma
            .cmp(&b.score_luma)
            .then_with(|| a.index.cmp(&b.index))
    });

    let luma_rank: HashMap<usize, usize> = luma_order
        .iter()
        .enumerate()
        .map(|(rank, g)| (g.index, rank))
        .collect();

    let stage2_count = candidate_count.min(12);
    let stage2_set: Vec<usize> = luma_order
        .iter()
        .take(stage2_count)
        .map(|g| g.index)
        .collect();

    let stage2_results: Vec<(usize, i64, f64)> = stage2_set
        .par_iter()
        .map(|&idx| {
            let guess = &guesses[idx - 1];
            let mapping = applySliderSwapsV2(grid_size, &guess.swaps).unwrap_or_else(|_| vec![]);
            let (score_rgb, score_text) = seamScoreRGBTextV2(img, grid_size, &mapping);
            (idx, score_rgb, score_text)
        })
        .collect();

    for (idx, score_rgb, score_text) in stage2_results {
        if let Some(g) = guesses.get_mut(idx - 1) {
            g.score_rgb = score_rgb;
            g.score_text = score_text;
        }
    }

    let mut rgb_order: Vec<&sliderGuessV2> = guesses
        .iter()
        .filter(|g| stage2_set.contains(&g.index))
        .collect();
    rgb_order.sort_by(|a, b| {
        a.score_rgb
            .cmp(&b.score_rgb)
            .then_with(|| a.index.cmp(&b.index))
    });

    let rgb_rank: HashMap<usize, usize> = rgb_order
        .iter()
        .enumerate()
        .map(|(rank, g)| (g.index, rank))
        .collect();

    let mut text_order = rgb_order.clone();
    text_order.sort_by(|a, b| {
        a.score_text
            .partial_cmp(&b.score_text)
            .unwrap_or(Ordering::Equal)
            .then_with(|| a.index.cmp(&b.index))
    });

    let text_rank: HashMap<usize, usize> = text_order
        .iter()
        .enumerate()
        .map(|(rank, g)| (g.index, rank))
        .collect();

    for g in guesses.iter_mut() {
        g.consensus_rank = luma_rank.get(&g.index).copied().unwrap_or(0);
        if stage2_set.contains(&g.index) {
            g.consensus_rank += rgb_rank.get(&g.index).copied().unwrap_or(0);
            g.consensus_rank += text_rank.get(&g.index).copied().unwrap_or(0);
        } else {
            g.consensus_rank += candidate_count;
        }
        g.score = g.consensus_rank as i64;
    }

    guesses.sort_by(|a, b| {
        a.consensus_rank
            .cmp(&b.consensus_rank)
            .then_with(|| a.score_luma.cmp(&b.score_luma))
            .then_with(|| a.index.cmp(&b.index))
    });

    Ok(guesses)
}

pub fn parseSliderPuzzleV2(raw: &Value) -> Result<sliderPuzzleV2> {
    let resp = raw
        .get("response")
        .and_then(|v| v.as_object())
        .ok_or_else(|| anyhow!("invalid slider content response"))?;

    let status = resp
        .get("status")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    if !status.eq_ignore_ascii_case("ok") {
        return Err(anyhow!("slider getContent status: {}", status));
    }

    let raw_image = resp
        .get("image")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow!("slider image missing"))?;

    let raw_steps = resp
        .get("steps")
        .and_then(|v| v.as_array())
        .ok_or_else(|| anyhow!("slider steps missing"))?;

    let steps: Vec<usize> = raw_steps
        .iter()
        .map(|v| {
            v.as_i64()
                .or_else(|| v.as_str().and_then(|s| s.parse().ok()))
                .map(|n| n as usize)
                .ok_or_else(|| anyhow!("invalid numeric value: {:?}", v))
        })
        .collect::<Result<_>>()?;

    let (size, swaps, attempts) = splitSliderStepsV2(&steps)?;

    use base64::engine::general_purpose::STANDARD;
    use base64::Engine;
    let data = STANDARD.decode(raw_image)?;
    let img = image::load_from_memory(&data)?;
    let rgb_img = img.to_rgb8();

    Ok(sliderPuzzleV2 {
        image: rgb_img,
        size,
        swaps,
        attempts,
    })
}

pub fn splitSliderStepsV2(steps: &[usize]) -> Result<(usize, Vec<usize>, usize)> {
    if steps.len() < 3 {
        return Err(anyhow!("slider steps payload too short"));
    }

    let size = steps[0];
    if size == 0 {
        return Err(anyhow!("invalid slider size: {}", size));
    }

    let mut tail = steps[1..].to_vec();
    let mut attempts = 4;

    if tail.len() % 2 != 0 {
        attempts = tail.last().copied().unwrap_or(4);
        tail.pop();
    }

    if attempts == 0 {
        attempts = 4;
    }

    if tail.is_empty() || tail.len() % 2 != 0 {
        return Err(anyhow!("invalid slider swap payload"));
    }

    Ok((size, tail, attempts))
}

pub fn activeSwapsForIndexV2(swaps: &[usize], index: usize) -> Vec<usize> {
    if index == 0 {
        return vec![];
    }
    let end = (index * 2).min(swaps.len());
    swaps[..end].to_vec()
}

pub fn applySliderSwapsV2(grid_size: usize, swaps: &[usize]) -> Result<Vec<usize>> {
    let tile_count = grid_size * grid_size;
    if tile_count == 0 {
        return Err(anyhow!("invalid slider tile count: {}", tile_count));
    }
    if swaps.len() % 2 != 0 {
        return Err(anyhow!("invalid slider swaps length: {}", swaps.len()));
    }

    let mut mapping: Vec<usize> = (0..tile_count).collect();
    for chunk in swaps.chunks(2) {
        let left = chunk[0];
        let right = chunk[1];
        if left >= tile_count || right >= tile_count {
            return Err(anyhow!("slider step out of range: {},{}", left, right));
        }
        mapping.swap(left, right);
    }
    Ok(mapping)
}

pub fn absFloatV2(v: f64) -> f64 {
    v.abs()
}

pub fn absIntV2(v: i32) -> i32 {
    v.abs()
}

pub fn buildSliderCursorV2(candidate_index: usize, candidate_count: usize) -> String {
    if candidate_count == 0 {
        return "[]".to_string();
    }

    let idx = if candidate_index < 1 {
        1
    } else if candidate_index > candidate_count {
        candidate_count
    } else {
        candidate_index
    };

    let mut rng = rand::thread_rng();

    let start_x: i32 = 570 + rng.gen_range(0..40);
    let start_y: i32 = 875 + rng.gen_range(0..30);

    let denom = if candidate_count < 2 { 1 } else { candidate_count - 1 };
    let base_target_x: i32 = 734 + (937 - 734) * ((idx - 1) as i32) / (denom as i32);
    let target_x: i32 = base_target_x + rng.gen_range(-5..10);
    let target_y: i32 = 655 + rng.gen_range(0..14);

    let mut points: Vec<(i32, i32)> = Vec::new();

    for _ in 0..(1 + rng.gen_range(0..3)) {
        points.push((
            start_x + rng.gen_range(-2..5),
            start_y + rng.gen_range(-2..5),
        ));
    }

    let transit_steps = 2 + rng.gen_range(0..3);
    let arc_off_x: i32 = rng.gen_range(-30..60);
    let arc_off_y: i32 = -(rng.gen_range(10..40));

    for i in 1..=transit_steps {
        let t = i as f64 / (transit_steps + 1) as f64;
        let cx = (start_x + target_x) as f64 / 2.0 + arc_off_x as f64;
        let cy = (start_y + target_y) as f64 / 2.0 + arc_off_y as f64;
        let bx = (1.0 - t).powi(2) * start_x as f64 + 2.0 * t * (1.0 - t) * cx + t.powi(2) * target_x as f64;
        let by = (1.0 - t).powi(2) * start_y as f64 + 2.0 * t * (1.0 - t) * cy + t.powi(2) * target_y as f64;
        let jitter = ((1.0 - t) * 8.0) as i32 + 2;
        points.push((
            bx.round() as i32 + rng.gen_range(-jitter..=jitter),
            by.round() as i32 + rng.gen_range(-jitter..=jitter),
        ));
    }

    let prev = points.last().copied().unwrap_or((start_x, start_y));
    let approach_steps = 4 + rng.gen_range(0..4);

    for i in 1..=approach_steps {
        let t = i as f64 / approach_steps as f64;
        let ax = prev.0 + ((t * (target_x - prev.0) as f64).round() as i32) + rng.gen_range(-2..5);
        let ay = prev.1 + ((t * (target_y - prev.1) as f64).round() as i32) + rng.gen_range(-2..5);
        points.push((ax, ay));
    }

    let settle_count = 3 + rng.gen_range(0..5);
    for _ in 0..settle_count {
        points.push((
            target_x + rng.gen_range(-3..7),
            target_y + rng.gen_range(-3..7),
        ));
    }

    serde_json::to_string(&points).unwrap_or_else(|_| "[]".to_string())
}

fn sliderTileRect(bounds: (u32, u32, u32, u32), grid_size: usize, index: usize) -> (u32, u32, u32, u32) {
    let (min_x, min_y, max_x, max_y) = bounds;
    let width = max_x - min_x;
    let height = max_y - min_y;
    let col = index % grid_size;
    let row = index / grid_size;

    let x1 = min_x + (col * width as usize / grid_size) as u32;
    let y1 = min_y + (row * height as usize / grid_size) as u32;
    let x2 = min_x + ((col + 1) * width as usize / grid_size) as u32;
    let y2 = min_y + ((row + 1) * height as usize / grid_size) as u32;
    (x1, y1, x2, y2)
}

fn pixelDiff(a: Rgb<u8>, b: Rgb<u8>) -> i64 {
    let dr = (a[0] as i64 - b[0] as i64).abs();
    let dg = (a[1] as i64 - b[1] as i64).abs();
    let db = (a[2] as i64 - b[2] as i64).abs();
    dr + dg + db
}

fn sampleColorMappedV2(
    img: &ImageBuffer<Rgb<u8>, Vec<u8>>,
    dst_rect: (u32, u32, u32, u32),
    src_rect: (u32, u32, u32, u32),
    dst_x: u32,
    dst_y: u32,
) -> Rgb<u8> {
    let (dst_x1, dst_y1, dst_x2, dst_y2) = dst_rect;
    let (src_x1, src_y1, src_x2, src_y2) = src_rect;

    let dx = (dst_x2 - dst_x1).max(1);
    let dy = (dst_y2 - dst_y1).max(1);

    let sx = src_x1 + (dst_x - dst_x1) * (src_x2 - src_x1) / dx;
    let sy = src_y1 + (dst_y - dst_y1) * (src_y2 - src_y1) / dy;

    *img.get_pixel(sx, sy)
}

fn sampleLumaMappedV2(
    img: &ImageBuffer<Rgb<u8>, Vec<u8>>,
    dst_rect: (u32, u32, u32, u32),
    src_rect: (u32, u32, u32, u32),
    dst_x: u32,
    dst_y: u32,
) -> u8 {
    let c = sampleColorMappedV2(img, dst_rect, src_rect, dst_x, dst_y);
    let r = c[0] as u32;
    let g = c[1] as u32;
    let b = c[2] as u32;
    ((299 * r + 587 * g + 114 * b) / 1000) as u8
}

fn seamScoreLumaV2(
    img: &ImageBuffer<Rgb<u8>, Vec<u8>>,
    grid_size: usize,
    mapping: &[usize],
) -> i64 {
    let (width, height) = img.dimensions();
    let bounds = (0, 0, width, height);
    let mut score = 0i64;

    for row in 0..grid_size {
        for col in 0..grid_size - 1 {
            let left_idx = row * grid_size + col;
            let right_idx = left_idx + 1;

            let left_dst = sliderTileRect(bounds, grid_size, left_idx);
            let right_dst = sliderTileRect(bounds, grid_size, right_idx);
            let left_src = sliderTileRect(bounds, grid_size, mapping[left_idx]);
            let right_src = sliderTileRect(bounds, grid_size, mapping[right_idx]);

            let h = (left_dst.3 - left_dst.1).min(right_dst.3 - right_dst.1);
            for y in 0..h {
                let yy = left_dst.1 + y;
                let a = sampleLumaMappedV2(img, left_dst, left_src, left_dst.2 - 1, yy);
                let b = sampleLumaMappedV2(img, right_dst, right_src, right_dst.0, yy);
                score += (a as i64 - b as i64).abs();
            }
        }
    }

    for row in 0..grid_size - 1 {
        for col in 0..grid_size {
            let top_idx = row * grid_size + col;
            let bottom_idx = (row + 1) * grid_size + col;

            let top_dst = sliderTileRect(bounds, grid_size, top_idx);
            let bottom_dst = sliderTileRect(bounds, grid_size, bottom_idx);
            let top_src = sliderTileRect(bounds, grid_size, mapping[top_idx]);
            let bottom_src = sliderTileRect(bounds, grid_size, mapping[bottom_idx]);

            let w = (top_dst.2 - top_dst.0).min(bottom_dst.2 - bottom_dst.0);
            for x in 0..w {
                let xx = top_dst.0 + x;
                let a = sampleLumaMappedV2(img, top_dst, top_src, xx, top_dst.3 - 1);
                let b = sampleLumaMappedV2(img, bottom_dst, bottom_src, xx, bottom_dst.1);
                score += (a as i64 - b as i64).abs();
            }
        }
    }

    score
}

fn seamScoreRGBTextV2(
    img: &ImageBuffer<Rgb<u8>, Vec<u8>>,
    grid_size: usize,
    mapping: &[usize],
) -> (i64, f64) {
    let (width, height) = img.dimensions();
    let bounds = (0, 0, width, height);
    let mut rgb_score = 0i64;
    let mut text_score = 0.0;

    let text_centers = [
        height as f64 * 0.2,
        height as f64 * 0.5,
        height as f64 * 0.8,
    ];
    let sigma = (height as f64 * 0.14).max(1.0);

    let weight = |y: u32| {
        let yf = y as f64;
        let best = text_centers
            .iter()
            .map(|&c| (yf - c).abs())
            .fold(f64::INFINITY, |a, b| a.min(b));
        1.0 + 3.0 * (-(best * best) / (2.0 * sigma * sigma)).exp()
    };

    for row in 0..grid_size {
        for col in 0..grid_size - 1 {
            let left_idx = row * grid_size + col;
            let right_idx = left_idx + 1;

            let left_dst = sliderTileRect(bounds, grid_size, left_idx);
            let right_dst = sliderTileRect(bounds, grid_size, right_idx);
            let left_src = sliderTileRect(bounds, grid_size, mapping[left_idx]);
            let right_src = sliderTileRect(bounds, grid_size, mapping[right_idx]);

            let h = (left_dst.3 - left_dst.1).min(right_dst.3 - right_dst.1);
            for y in 0..h {
                let yy = left_dst.1 + y;
                let l = sampleColorMappedV2(img, left_dst, left_src, left_dst.2 - 1, yy);
                let r = sampleColorMappedV2(img, right_dst, right_src, right_dst.0, yy);
                rgb_score += pixelDiff(l, r);
                let lb = l[2] as i64;
                let rb = r[2] as i64;
                text_score += weight(yy) * (lb - rb).abs() as f64;
            }
        }
    }

    for row in 0..grid_size - 1 {
        for col in 0..grid_size {
            let top_idx = row * grid_size + col;
            let bottom_idx = (row + 1) * grid_size + col;

            let top_dst = sliderTileRect(bounds, grid_size, top_idx);
            let bottom_dst = sliderTileRect(bounds, grid_size, bottom_idx);
            let top_src = sliderTileRect(bounds, grid_size, mapping[top_idx]);
            let bottom_src = sliderTileRect(bounds, grid_size, mapping[bottom_idx]);

            let w = (top_dst.2 - top_dst.0).min(bottom_dst.2 - bottom_dst.0);
            for x in 0..w {
                let xx = top_dst.0 + x;
                let t = sampleColorMappedV2(img, top_dst, top_src, xx, top_dst.3 - 1);
                let b = sampleColorMappedV2(img, bottom_dst, bottom_src, xx, bottom_dst.1);
                rgb_score += pixelDiff(t, b);
                let tb = t[2] as f64;
                let bb = b[2] as f64;
                text_score += 0.65 * (tb - bb).abs();
            }
        }
    }

    (rgb_score, text_score)
}