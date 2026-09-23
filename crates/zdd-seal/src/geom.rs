use std::f64::consts::TAU;

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Pt {
    pub x: f64,
    pub y: f64,
}

pub const CENTRE: Pt = Pt { x: 100.0, y: 100.0 };

impl Pt {
    pub fn polar(radius: f64, turns: f64) -> Pt {
        let theta = turns * TAU;
        Pt {
            x: CENTRE.x + radius * theta.cos(),
            y: CENTRE.y + radius * theta.sin(),
        }
    }

    pub fn svg(&self) -> String {
        format!("{:.3} {:.3}", self.x, self.y)
    }

    pub fn offset(&self, dx: f64, dy: f64) -> Pt {
        Pt {
            x: self.x + dx,
            y: self.y + dy,
        }
    }

    pub fn lerp(&self, other: Pt, t: f64) -> Pt {
        Pt {
            x: self.x + (other.x - self.x) * t,
            y: self.y + (other.y - self.y) * t,
        }
    }
}

pub fn hex8(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(8);
    for b in bytes.iter().take(4) {
        use core::fmt::Write as _;
        let _ = write!(out, "{b:02x}");
    }
    out
}

pub fn n(value: f64) -> String {
    format!("{value:.3}")
}

pub fn closed_smooth_radial(radii: &[f64]) -> String {
    let count = radii.len();
    assert!(count >= 3, "a closed outline needs at least three samples");

    let points: Vec<Pt> = radii
        .iter()
        .enumerate()
        .map(|(i, &r)| Pt::polar(r, i as f64 / count as f64))
        .collect();

    let mut path = format!("M {} ", points[0].svg());

    for i in 0..count {
        let p0 = points[(i + count - 1) % count];
        let p1 = points[i];
        let p2 = points[(i + 1) % count];
        let p3 = points[(i + 2) % count];

        let c1 = Pt {
            x: p1.x + (p2.x - p0.x) / 6.0,
            y: p1.y + (p2.y - p0.y) / 6.0,
        };
        let c2 = Pt {
            x: p2.x - (p3.x - p1.x) / 6.0,
            y: p2.y - (p3.y - p1.y) / 6.0,
        };

        path.push_str(&format!("C {} {} {} ", c1.svg(), c2.svg(), p2.svg()));
    }

    path.push('Z');
    path
}

pub fn arc(radius: f64, start: f64, end: f64) -> String {
    let sweep = end - start;
    if sweep.abs() >= 1.0 {
        return format!(
            "M {} A {r} {r} 0 1 1 {} A {r} {r} 0 1 1 {} Z",
            Pt::polar(radius, start).svg(),
            Pt::polar(radius, start + 0.5).svg(),
            Pt::polar(radius, start).svg(),
            r = n(radius)
        );
    }
    let large = if sweep.abs() > 0.5 { 1 } else { 0 };
    let positive = if sweep >= 0.0 { 1 } else { 0 };
    format!(
        "M {} A {r} {r} 0 {large} {positive} {}",
        Pt::polar(radius, start).svg(),
        Pt::polar(radius, end).svg(),
        r = n(radius)
    )
}

pub fn spoke(inner: f64, outer: f64, turns: f64) -> String {
    format!(
        "M {} L {}",
        Pt::polar(inner, turns).svg(),
        Pt::polar(outer, turns).svg()
    )
}

pub fn wedge(inner: f64, outer: f64, start: f64, end: f64) -> String {
    let large = if (end - start).abs() > 0.5 { 1 } else { 0 };
    format!(
        "M {} L {} A {ro} {ro} 0 {large} 1 {} L {} A {ri} {ri} 0 {large} 0 {} Z",
        Pt::polar(inner, start).svg(),
        Pt::polar(outer, start).svg(),
        Pt::polar(outer, end).svg(),
        Pt::polar(inner, end).svg(),
        Pt::polar(inner, start).svg(),
        ro = n(outer),
        ri = n(inner)
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn polar_lands_where_expected() {
        let east = Pt::polar(10.0, 0.0);
        assert!((east.x - 110.0).abs() < 1e-9);
        assert!((east.y - 100.0).abs() < 1e-9);

        let south = Pt::polar(10.0, 0.25);
        assert!((south.x - 100.0).abs() < 1e-9);
        assert!((south.y - 110.0).abs() < 1e-9);

        let round = Pt::polar(10.0, 1.0);
        assert!((round.x - east.x).abs() < 1e-9);
        assert!((round.y - east.y).abs() < 1e-9);
    }

    #[test]
    fn coordinates_are_fixed_precision() {
        assert_eq!(
            Pt {
                x: 1.0 / 3.0,
                y: 2.0 / 3.0
            }
            .svg(),
            "0.333 0.667"
        );
        assert_eq!(n(1.0 / 7.0), "0.143");
        assert_eq!(n(100.0), "100.000");
    }

    #[test]
    fn a_smooth_outline_closes() {
        let radii = vec![80.0, 82.0, 79.0, 81.0, 80.5, 78.0];
        let path = closed_smooth_radial(&radii);
        assert!(path.starts_with("M "));
        assert!(path.ends_with('Z'));

        assert_eq!(path.matches("C ").count(), radii.len());
    }

    #[test]
    fn the_outline_is_deterministic() {
        let radii = vec![80.0, 82.0, 79.0, 81.0];
        assert_eq!(closed_smooth_radial(&radii), closed_smooth_radial(&radii));
    }

    #[test]
    #[should_panic(expected = "at least three")]
    fn a_degenerate_outline_is_refused() {
        closed_smooth_radial(&[80.0, 82.0]);
    }

    #[test]
    fn a_full_turn_arc_is_split_in_two() {
        let full = arc(50.0, 0.0, 1.0);
        assert_eq!(
            full.matches(" A ").count(),
            2,
            "a full ring needs two arc segments"
        );
        assert!(full.ends_with('Z'));
    }

    #[test]
    fn partial_arcs_set_the_large_flag_correctly() {
        assert!(
            arc(50.0, 0.0, 0.25).contains(" 0 0 1 "),
            "a quarter turn is not large"
        );
        assert!(
            arc(50.0, 0.0, 0.75).contains(" 0 1 1 "),
            "three quarters is large"
        );
        assert!(
            arc(50.0, 0.0, -0.25).contains(" 0 0 0 "),
            "negative sweep reverses"
        );
    }

    #[test]
    fn a_wedge_is_a_closed_ring_segment() {
        let w = wedge(40.0, 60.0, 0.0, 0.1);
        assert!(w.starts_with("M "));
        assert!(w.ends_with('Z'));
        assert_eq!(
            w.matches(" A ").count(),
            2,
            "a wedge has an outer and an inner arc"
        );
    }

    #[test]
    fn a_spoke_runs_outward() {
        let s = spoke(10.0, 50.0, 0.0);
        assert!(s.contains("M 110.000 100.000"));
        assert!(s.contains("L 150.000 100.000"));
    }

    #[test]
    fn lerp_and_offset_behave() {
        let a = Pt { x: 0.0, y: 0.0 };
        let b = Pt { x: 10.0, y: 20.0 };
        assert_eq!(a.lerp(b, 0.5), Pt { x: 5.0, y: 10.0 });
        assert_eq!(a.offset(3.0, 4.0), Pt { x: 3.0, y: 4.0 });
    }
}
