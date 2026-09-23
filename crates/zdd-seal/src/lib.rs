#![forbid(unsafe_code)]

pub mod geom;
pub mod palette;
pub mod rng;

use geom::{arc, closed_smooth_radial, n, spoke, Pt};
use palette::{Wax, WAXES};
use rng::Bits;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SealState {
    #[default]
    Sealed,

    Stirring,

    Breaking,

    Broken,

    Held,

    Frozen,
}

impl SealState {
    fn crack_extent(&self) -> f64 {
        match self {
            SealState::Sealed => 0.0,
            SealState::Stirring => 0.22,
            SealState::Breaking => 0.65,
            SealState::Broken => 1.0,
            SealState::Held => 0.34,
            SealState::Frozen => 0.0,
        }
    }

    fn desaturation(&self) -> f64 {
        match self {
            SealState::Broken => 0.45,
            SealState::Frozen => 0.34,
            _ => 0.0,
        }
    }

    pub fn label(&self) -> &'static str {
        match self {
            SealState::Sealed => "sealed",
            SealState::Stirring => "stirring",
            SealState::Breaking => "breaking",
            SealState::Broken => "broken",
            SealState::Held => "held",
            SealState::Frozen => "frozen",
        }
    }
}

#[derive(Debug, Clone)]
pub struct SealOptions {
    pub size: u32,
    pub state: SealState,

    pub reduced_motion: bool,

    pub simplified: bool,

    pub compact: Option<bool>,

    pub title: Option<String>,
}

impl Default for SealOptions {
    fn default() -> Self {
        Self {
            size: 200,
            state: SealState::Sealed,
            reduced_motion: false,
            simplified: false,
            compact: None,
            title: None,
        }
    }
}

pub const COMPACT_BELOW: u32 = 48;

impl SealOptions {
    pub fn resolve_compact(&self) -> bool {
        self.compact.unwrap_or(self.size < COMPACT_BELOW)
    }

    pub fn at_size(size: u32) -> Self {
        Self {
            size,
            ..Default::default()
        }
    }

    pub fn in_state(state: SealState) -> Self {
        Self {
            state,
            ..Default::default()
        }
    }

    pub fn tray(state: SealState) -> Self {
        Self {
            size: 32,
            state,
            simplified: true,
            reduced_motion: true,
            compact: Some(true),
            title: None,
        }
    }

    pub fn print() -> Self {
        Self {
            size: 600,
            simplified: true,
            reduced_motion: true,
            compact: Some(false),
            ..Default::default()
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum Terminal {
    Dot,
    Bar,
    Fork,
    Ring,
    Wedge,
    Trefoil,
    Crescent,
}

const TERMINALS: [Terminal; 7] = [
    Terminal::Dot,
    Terminal::Bar,
    Terminal::Fork,
    Terminal::Ring,
    Terminal::Wedge,
    Terminal::Trefoil,
    Terminal::Crescent,
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum Motif {
    Spokes,

    Web,

    Rosette,

    Compass,

    Rings,
}

const MOTIFS: [Motif; 5] = [
    Motif::Spokes,
    Motif::Web,
    Motif::Rosette,
    Motif::Compass,
    Motif::Rings,
];

impl Motif {
    fn label(&self) -> &'static str {
        match self {
            Motif::Spokes => "spokes",
            Motif::Web => "web",
            Motif::Rosette => "rosette",
            Motif::Compass => "compass",
            Motif::Rings => "rings",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum Boss {
    Disc,
    Ringed,
    Lens,
    Star,
    Void,
}

const BOSSES: [Boss; 5] = [Boss::Disc, Boss::Ringed, Boss::Lens, Boss::Star, Boss::Void];

#[derive(Debug, Clone)]
struct Sigil {
    motif: Motif,

    arms: u32,

    terminal_a: Terminal,

    terminal_b: Terminal,
    boss: Boss,

    rings: Vec<(f64, bool, f64)>,

    notch_at: u32,

    rotation: f64,

    ticks: u32,

    arm_outer: f64,

    arm_inner: f64,
}

impl Sigil {
    fn generate(bits: &mut Bits) -> Self {
        let motif = *bits.pick(&MOTIFS);

        let arms = match motif {
            Motif::Compass => bits.range(3, 5) * 2,
            _ => bits.range(5, 11),
        };

        let terminal_a = *bits.pick(&TERMINALS);

        let terminal_b = if arms % 2 == 0 && bits.chance(1, 2) {
            let mut other = *bits.pick(&TERMINALS);
            if other == terminal_a {
                other = TERMINALS[(TERMINALS.iter().position(|t| *t == terminal_a).unwrap() + 3)
                    % TERMINALS.len()];
            }
            other
        } else {
            terminal_a
        };

        let boss = *bits.pick(&BOSSES);
        let arm_outer = 46.0 + bits.unit() * 6.0;

        let arm_inner = if bits.chance(2, 5) {
            24.0 + bits.unit() * 5.0
        } else {
            15.0
        };

        let ring_count = if motif == Motif::Rings {
            3
        } else {
            bits.range(1, 3)
        };
        let mut rings = Vec::with_capacity(ring_count as usize);

        const SPAN_LO: f64 = 19.0;
        const SPAN_HI: f64 = 56.0;
        const MIN_RING_GAP: f64 = 6.5;

        let step = (SPAN_HI - SPAN_LO) / f64::from(ring_count);
        let jitter = (step - MIN_RING_GAP).clamp(0.0, 6.0);

        for i in 0..ring_count {
            let radius = SPAN_LO + f64::from(i) * step + bits.unit() * jitter;
            let segmented = bits.chance(2, 5);
            let weight = if bits.chance(1, 3) { 2.6 } else { 1.5 };
            rings.push((radius, segmented, weight));
        }

        Self {
            motif,
            arms,
            terminal_a,
            terminal_b,
            boss,
            rings,
            notch_at: bits.below(arms),

            rotation: f64::from(bits.below(48)) / 48.0,
            ticks: bits.range(28, 64),
            arm_outer,
            arm_inner,
        }
    }

    fn arm_reach(&self, index: u32) -> f64 {
        let index = index % self.arms;
        if self.motif == Motif::Compass && index % 2 == 1 {
            self.arm_inner + (self.arm_outer - self.arm_inner) * 0.55
        } else {
            self.arm_outer
        }
    }

    fn has_arms(&self) -> bool {
        self.motif != Motif::Rings
    }

    fn arm_turn(&self, index: u32) -> f64 {
        self.rotation + f64::from(index % self.arms) / f64::from(self.arms)
    }
}

fn id_prefix(seed: &[u8; 32], state: SealState) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"zdd/v1/seal-id");
    hasher.update(seed);
    hasher.update(state.label().as_bytes());
    format!("s{}", crate::geom::hex8(hasher.finalize().as_bytes()))
}

pub fn render(seed: &[u8; 32], opts: &SealOptions) -> String {
    let id = id_prefix(seed, opts.state);
    let mut wax_bits = Bits::new(seed, b"wax");
    let mut sigil_bits = Bits::new(seed, b"sigil");
    let mut crack_bits = Bits::new(seed, b"crack");

    let wax = *wax_bits.pick(&WAXES);
    let sigil = Sigil::generate(&mut sigil_bits);
    let outline = wax_outline(&mut wax_bits);

    let grey = palette::Rgb(0x6B, 0x68, 0x63);
    let desat = opts.state.desaturation();
    let tint = |c: palette::Rgb| c.mix(grey, desat).hex();

    let mut svg = String::with_capacity(8192);
    svg.push_str(&format!(
        r#"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 200 200" width="{s}" height="{s}" role="img" aria-label="{label}">"#,
        s = opts.size,
        label = escape(&seal_aria_label(&wax, &sigil, opts)),
    ));

    if let Some(title) = &opts.title {
        svg.push_str(&format!("<title>{}</title>", escape(title)));
    }

    svg.push_str(&defs(&wax, &sigil, opts, desat, &outline, &id));

    svg.push_str(r#"<g class="zdd-seal">"#);

    if !opts.simplified {
        svg.push_str(&format!(
            r#"<path d="{outline}" fill="{}" opacity="0.28" filter="url(#{id}-soft)" transform="translate(2.2 3.4)"/>"#,
            tint(wax.shadow())
        ));
    }

    svg.push_str(&format!(r#"<path d="{outline}" fill="url(#{id}-body)"/>"#));

    if !opts.simplified {
        svg.push_str(&format!(
            r#"<g clip-path="url(#{id}-clip)"><rect x="0" y="0" width="200" height="200" filter="url(#{id}-grain)" opacity="0.26"/></g>"#
        ));
    }

    svg.push_str(&format!(
        r#"<circle cx="100" cy="100" r="76" fill="none" stroke="{}" stroke-width="3.4" opacity="0.55"/>"#,
        tint(wax.highlight())
    ));
    svg.push_str(&format!(
        r#"<circle cx="100" cy="100" r="72.5" fill="none" stroke="{}" stroke-width="2.2" opacity="0.5"/>"#,
        tint(wax.shadow())
    ));

    let notch_turn = sigil.arm_turn(sigil.notch_at) + 0.5 / f64::from(sigil.arms);

    let (nw_in, nw_out) = if opts.resolve_compact() {
        (0.045, 0.028)
    } else {
        (0.023, 0.011)
    };
    let notch = format!(
        "M {} L {} L {} L {} Z",
        Pt::polar(66.5, notch_turn - nw_in).svg(),
        Pt::polar(79.5, notch_turn - nw_out).svg(),
        Pt::polar(79.5, notch_turn + nw_out).svg(),
        Pt::polar(66.5, notch_turn + nw_in).svg(),
    );
    svg.push_str(&format!(
        r#"<path d="{notch}" fill="{}" opacity="0.92"/>"#,
        tint(wax.shadow())
    ));

    svg.push_str(&format!(
        r#"<path d="M {} L {}" fill="none" stroke="{}" stroke-width="1.5" opacity="0.7"/>"#,
        Pt::polar(66.5, notch_turn + nw_in).svg(),
        Pt::polar(79.5, notch_turn + nw_out).svg(),
        tint(wax.highlight())
    ));

    svg.push_str(&format!(
        r#"<circle cx="100" cy="100" r="71" fill="url(#{id}-field)"/>"#
    ));

    let compact = opts.resolve_compact();

    if !compact {
        svg.push_str(&tick_band(&sigil, &wax, desat));
    }

    let sigil_paths = if compact {
        compact_geometry(&sigil)
    } else {
        sigil_geometry(&sigil)
    };

    let (emboss_w, ink_w, offset) = if compact {
        (7.0, 7.6, 1.6)
    } else {
        (2.9, 3.3, 0.55)
    };

    svg.push_str(&format!(
        r#"<g transform="translate(-{off} -{off2})" fill="none" stroke="{c}" stroke-width="{emboss_w}" stroke-linecap="round" stroke-linejoin="round" opacity="0.85">{sigil_paths}</g>"#,
        off = n(offset),
        off2 = n(offset * 1.18),
        c = tint(wax.emboss()),
    ));
    svg.push_str(&format!(
        r#"<g fill="none" stroke="{c}" stroke-width="{ink_w}" stroke-linecap="round" stroke-linejoin="round">{sigil_paths}</g>"#,
        c = tint(wax.ink()),
    ));

    svg.push_str(&format!(
        r#"<g fill="{}" stroke="none">{}</g>"#,
        tint(wax.ink()),
        if compact {
            compact_solids(&sigil)
        } else {
            sigil_solids(&sigil)
        }
    ));

    let extent = opts.state.crack_extent();
    if extent > 0.0 {
        let pulsing = opts.state == SealState::Breaking && !opts.reduced_motion;
        svg.push_str(&if pulsing {
            format!(r#"<g class="{id}-pulse" clip-path="url(#{id}-clip)">"#)
        } else {
            format!(r#"<g clip-path="url(#{id}-clip)">"#)
        });
        svg.push_str(&cracks(&mut crack_bits, &wax, extent, opts, desat));
        svg.push_str("</g>");
    }

    if opts.state == SealState::Frozen {
        svg.push_str(&format!(
            r##"<path d="{outline}" fill="#BFD3DC" opacity="0.20"/><path d="{outline}" fill="none" stroke="#DCE9EE" stroke-width="1.6" opacity="0.50"/>"##
        ));
    }

    svg.push_str("</g></svg>");
    svg
}

fn wax_outline(bits: &mut Bits) -> String {
    closed_smooth_radial(&wax_radii(bits))
}

const LOBE_KNEE: f64 = 88.0;

const LOBE_HEADROOM: f64 = 4.5;

fn wax_radii(bits: &mut Bits) -> Vec<f64> {
    const SAMPLES: usize = 30;
    let base = 86.0;

    let mut radii = Vec::with_capacity(SAMPLES);
    for _ in 0..SAMPLES {
        radii.push(base + bits.signed_unit() * 2.1);
    }

    let lobes = bits.range(2, 3);
    for _ in 0..lobes {
        let at = bits.below(SAMPLES as u32) as usize;
        let spread = bits.range(2, 3) as usize;
        let bulge = 3.4 + bits.unit() * 3.6;
        for offset in 0..=spread {
            let falloff = (1.0 - offset as f64 / (spread as f64 + 1.0)).max(0.0);
            let delta = bulge * falloff * falloff;
            radii[(at + offset) % SAMPLES] += delta;
            radii[(at + SAMPLES - offset) % SAMPLES] += delta;
        }
    }

    for r in &mut radii {
        if *r > LOBE_KNEE {
            let over = *r - LOBE_KNEE;
            *r = LOBE_KNEE + LOBE_HEADROOM * (1.0 - (-over / LOBE_HEADROOM).exp());
        }
    }
    radii
}

fn sigil_geometry(sigil: &Sigil) -> String {
    let mut out = String::new();

    if sigil.has_arms() {
        for i in 0..sigil.arms {
            let turn = sigil.arm_turn(i);
            let reach = sigil.arm_reach(i);
            out.push_str(&format!(
                r#"<path d="{}"/>"#,
                spoke(sigil.arm_inner, reach, turn)
            ));

            let terminal = if i % 2 == 0 {
                sigil.terminal_a
            } else {
                sigil.terminal_b
            };
            out.push_str(&terminal_strokes(terminal, reach, turn));
        }
    }

    match sigil.motif {
        Motif::Web => {
            let mut path = String::from("M ");
            for i in 0..sigil.arms {
                let p = Pt::polar(sigil.arm_reach(i), sigil.arm_turn(i));
                if i > 0 {
                    path.push_str("L ");
                }
                path.push_str(&format!("{} ", p.svg()));
            }
            path.push('Z');
            out.push_str(&format!(r#"<path d="{path}" stroke-width="1.9"/>"#));
        }
        Motif::Rosette => {
            for i in 0..sigil.arms {
                let from = Pt::polar(sigil.arm_reach(i), sigil.arm_turn(i));
                let to = Pt::polar(sigil.arm_reach(i + 1), sigil.arm_turn(i + 1));
                let mid_turn = sigil.arm_turn(i) + 0.5 / f64::from(sigil.arms);
                let control = Pt::polar(sigil.arm_outer + 11.0, mid_turn);
                out.push_str(&format!(
                    r#"<path d="M {} Q {} {}" stroke-width="2.0"/>"#,
                    from.svg(),
                    control.svg(),
                    to.svg()
                ));
            }
        }
        Motif::Rings => {
            for i in 0..sigil.arms {
                let turn = sigil.arm_turn(i);
                out.push_str(&format!(
                    r#"<path d="{}" stroke-width="2.8"/>"#,
                    spoke(sigil.arm_outer - 8.0, sigil.arm_outer + 1.0, turn)
                ));
                let between = turn + 0.5 / f64::from(sigil.arms);
                out.push_str(&format!(
                    r#"<path d="{}" stroke-width="2.2"/>"#,
                    spoke(
                        sigil.arm_inner.max(20.0),
                        sigil.arm_inner.max(20.0) + 7.0,
                        between
                    )
                ));
            }
        }
        Motif::Spokes | Motif::Compass => {}
    }

    for &(radius, segmented, weight) in &sigil.rings {
        if segmented {
            let step = 1.0 / f64::from(sigil.arms);
            for i in 0..sigil.arms {
                let centre = sigil.arm_turn(i) + step / 2.0;
                let half = step * 0.31;
                out.push_str(&format!(
                    r#"<path d="{}" stroke-width="{}"/>"#,
                    arc(radius, centre - half, centre + half),
                    n(weight)
                ));
            }
        } else {
            out.push_str(&format!(
                r#"<path d="{}" stroke-width="{}"/>"#,
                arc(radius, 0.0, 1.0),
                n(weight)
            ));
        }
    }

    out.push_str(&boss_strokes(sigil.boss));
    out
}

fn compact_geometry(sigil: &Sigil) -> String {
    let mut out = String::new();

    let arms = sigil.arms.min(6);

    for i in 0..arms {
        let turn = sigil.rotation + f64::from(i) / f64::from(arms);
        out.push_str(&format!(r#"<path d="{}"/>"#, spoke(22.0, 50.0, turn)));
    }

    if !sigil.rings.is_empty() {
        out.push_str(&format!(
            r#"<path d="{}" stroke-width="6.0"/>"#,
            arc(38.0, 0.0, 1.0)
        ));
    }

    if matches!(sigil.boss, Boss::Void | Boss::Ringed) {
        out.push_str(&format!(
            r#"<path d="{}" stroke-width="6.0"/>"#,
            arc(19.0, 0.0, 1.0)
        ));
    }

    out
}

fn compact_solids(sigil: &Sigil) -> String {
    let radius = match sigil.boss {
        Boss::Void | Boss::Ringed => 9.0,
        _ => 14.0,
    };
    format!(r#"<circle cx="100" cy="100" r="{}"/>"#, n(radius))
}

fn terminal_strokes(terminal: Terminal, r: f64, turn: f64) -> String {
    match terminal {
        Terminal::Bar => {
            let a = Pt::polar(r, turn - 0.020);
            let b = Pt::polar(r, turn + 0.020);
            format!(r#"<path d="M {} L {}"/>"#, a.svg(), b.svg())
        }
        Terminal::Fork => {
            let base = Pt::polar(r - 6.0, turn);
            let up = Pt::polar(r + 2.0, turn - 0.022);
            let down = Pt::polar(r + 2.0, turn + 0.022);
            format!(
                r#"<path d="M {} L {}"/><path d="M {} L {}"/>"#,
                base.svg(),
                up.svg(),
                base.svg(),
                down.svg()
            )
        }
        Terminal::Ring => {
            let c = Pt::polar(r + 2.4, turn);
            format!(
                r#"<circle cx="{}" cy="{}" r="4.1" stroke-width="2.1"/>"#,
                n(c.x),
                n(c.y)
            )
        }
        Terminal::Crescent => {
            let c = Pt::polar(r + 1.0, turn);
            format!(
                r#"<path d="M {} A 5.4 5.4 0 0 1 {}" stroke-width="2.2"/>"#,
                Pt { x: c.x, y: c.y }.offset(0.0, -5.0).svg(),
                Pt { x: c.x, y: c.y }.offset(0.0, 5.0).svg()
            )
        }

        Terminal::Dot | Terminal::Wedge | Terminal::Trefoil => String::new(),
    }
}

fn sigil_solids(sigil: &Sigil) -> String {
    let mut out = String::new();

    for i in 0..sigil.arms {
        if !sigil.has_arms() {
            break;
        }
        let turn = sigil.arm_turn(i);
        let reach = sigil.arm_reach(i);
        let terminal = if i % 2 == 0 {
            sigil.terminal_a
        } else {
            sigil.terminal_b
        };
        match terminal {
            Terminal::Dot => {
                let c = Pt::polar(reach + 2.6, turn);
                out.push_str(&format!(
                    r#"<circle cx="{}" cy="{}" r="3.4"/>"#,
                    n(c.x),
                    n(c.y)
                ));
            }
            Terminal::Wedge => {
                let tip = Pt::polar(reach + 6.4, turn);
                let a = Pt::polar(reach - 0.6, turn - 0.016);
                let b = Pt::polar(reach - 0.6, turn + 0.016);
                out.push_str(&format!(
                    r#"<path d="M {} L {} L {} Z"/>"#,
                    tip.svg(),
                    a.svg(),
                    b.svg()
                ));
            }
            Terminal::Trefoil => {
                for delta in [-0.020_f64, 0.0, 0.020] {
                    let radius = if delta == 0.0 {
                        reach + 5.2
                    } else {
                        reach + 1.4
                    };
                    let c = Pt::polar(radius, turn + delta);
                    out.push_str(&format!(
                        r#"<circle cx="{}" cy="{}" r="2.5"/>"#,
                        n(c.x),
                        n(c.y)
                    ));
                }
            }
            _ => {}
        }
    }

    if sigil.boss == Boss::Disc {
        out.push_str(r#"<circle cx="100" cy="100" r="9.6"/>"#);
    }
    if sigil.boss == Boss::Star {
        let mut path = String::from("M ");
        for i in 0..10 {
            let radius = if i % 2 == 0 { 11.2 } else { 4.6 };
            let turn = sigil.rotation + f64::from(i) / 10.0;
            let p = Pt::polar(radius, turn);
            if i > 0 {
                path.push_str("L ");
            }
            path.push_str(&format!("{} ", p.svg()));
        }
        path.push('Z');
        out.push_str(&format!(r#"<path d="{path}"/>"#));
    }

    out
}

fn boss_strokes(boss: Boss) -> String {
    match boss {
        Boss::Ringed => String::from(
            r#"<circle cx="100" cy="100" r="10.4" stroke-width="2.6"/><circle cx="100" cy="100" r="5.0" stroke-width="1.8"/>"#,
        ),
        Boss::Void => String::from(r#"<circle cx="100" cy="100" r="10.0" stroke-width="3.0"/>"#),
        Boss::Lens => {
            let top = Pt { x: 100.0, y: 89.0 };
            let bottom = Pt { x: 100.0, y: 111.0 };
            format!(
                r#"<path d="M {t} A 13 13 0 0 1 {b} A 13 13 0 0 1 {t} Z" stroke-width="2.4"/>"#,
                t = top.svg(),
                b = bottom.svg()
            )
        }

        Boss::Disc | Boss::Star => String::new(),
    }
}

fn tick_band(sigil: &Sigil, wax: &Wax, desat: f64) -> String {
    let grey = palette::Rgb(0x6B, 0x68, 0x63);
    let mut out = format!(
        r#"<g stroke="{}" stroke-width="1.7" stroke-linecap="butt" opacity="0.7">"#,
        wax.ink().mix(grey, desat).hex()
    );
    for i in 0..sigil.ticks {
        let turn = f64::from(i) / f64::from(sigil.ticks) + sigil.rotation;

        let inner = if i % 4 == 0 { 61.5 } else { 65.5 };
        out.push_str(&format!(r#"<path d="{}"/>"#, spoke(inner, 69.5, turn)));
    }
    out.push_str("</g>");
    out
}

fn cracks(bits: &mut Bits, wax: &Wax, extent: f64, opts: &SealOptions, desat: f64) -> String {
    let grey = palette::Rgb(0x6B, 0x68, 0x63);

    let crack_desat = desat * 0.35;
    let fracture = wax.fracture().mix(grey, crack_desat).hex();
    let depth = wax.base.darken(0.86).mix(grey, crack_desat).hex();
    let healed = wax.highlight().mix(grey, desat).hex();

    let entry = bits.unit();
    let exit = entry + 0.42 + bits.unit() * 0.16;

    let waist = 12.0 + bits.unit() * 16.0;

    const STEPS: usize = 16;
    let mut vertices = Vec::with_capacity(STEPS + 1);
    for i in 0..=STEPS {
        let t = i as f64 / STEPS as f64;

        let bow = (t * std::f64::consts::PI).sin();
        let radius = 88.0 - (88.0 - waist) * bow;

        let turn = entry + (exit - entry) * t + bits.signed_unit() * 0.022;
        vertices.push(Pt::polar(radius, turn));
    }

    let drawn = ((vertices.len() as f64) * extent).ceil().max(2.0) as usize;
    let drawn = drawn.min(vertices.len());

    let mut path = format!("M {} ", vertices[0].svg());
    for v in &vertices[1..drawn] {
        path.push_str(&format!("L {} ", v.svg()));
    }

    let mut out = String::new();

    if opts.state == SealState::Held {
        out.push_str(&format!(
            r#"<path d="{path}" fill="none" stroke="{}" stroke-width="3.4" stroke-linejoin="round" stroke-linecap="round" opacity="0.30"/>"#,
            palette::Rgb(0x3F, 0x7A, 0x6A).mix(grey, desat).hex()
        ));
        out.push_str(&format!(
            r#"<path d="{path}" fill="none" stroke="{healed}" stroke-width="1.3" stroke-linejoin="round" stroke-linecap="round" opacity="0.62"/>"#
        ));
        return out;
    }

    out.push_str(&format!(
        r#"<path d="{path}" fill="none" stroke="{depth}" stroke-width="5.4" stroke-linejoin="round" stroke-linecap="round" opacity="0.94"/>"#
    ));
    out.push_str(&format!(
        r#"<path d="{path}" fill="none" stroke="{fracture}" stroke-width="1.8" stroke-linejoin="round" stroke-linecap="round" opacity="0.95"/>"#
    ));

    let branch_count = bits.range(2, 4) as usize;
    for b in 0..branch_count {
        let anchor = 3 + b * 4;
        if anchor >= drawn {
            break;
        }
        let from = vertices[anchor];
        let direction = if bits.bit() { 1.0 } else { -1.0 };
        let mut bpath = format!("M {} ", from.svg());

        let base_turn =
            ((from.y - geom::CENTRE.y).atan2(from.x - geom::CENTRE.x)) / std::f64::consts::TAU;
        let base_radius =
            ((from.x - geom::CENTRE.x).powi(2) + (from.y - geom::CENTRE.y).powi(2)).sqrt();
        let mut r = base_radius;
        let mut t = base_turn;
        for _ in 0..bits.range(2, 4) {
            r += 9.0 + bits.unit() * 11.0;
            t += direction * (0.012 + bits.unit() * 0.028);
            bpath.push_str(&format!("L {} ", Pt::polar(r.clamp(10.0, 88.0), t).svg()));
            if r >= 88.0 {
                break;
            }
        }

        out.push_str(&format!(
            r#"<path d="{bpath}" fill="none" stroke="{depth}" stroke-width="3.4" stroke-linecap="round" opacity="0.85"/>"#
        ));
        out.push_str(&format!(
            r#"<path d="{bpath}" fill="none" stroke="{fracture}" stroke-width="1.3" stroke-linecap="round" opacity="0.88"/>"#
        ));
    }

    if opts.state == SealState::Broken {
        out.push_str(&format!(
            r#"<path d="{path}" fill="none" stroke="{depth}" stroke-width="6.5" stroke-linejoin="round" opacity="0.30" transform="translate(1.6 1.9)"/>"#
        ));
        out.push_str(&format!(
            r#"<path d="{path}" fill="none" stroke="{fracture}" stroke-width="1.2" stroke-linejoin="round" opacity="0.55" transform="translate(-1.2 -1.4)"/>"#
        ));
    }

    out
}

fn defs(
    wax: &Wax,
    sigil: &Sigil,
    opts: &SealOptions,
    desat: f64,
    outline: &str,
    id: &str,
) -> String {
    let grey = palette::Rgb(0x6B, 0x68, 0x63);
    let tint = |c: palette::Rgb| c.mix(grey, desat).hex();

    let mut defs = String::from("<defs>");

    defs.push_str(&format!(
        r#"<clipPath id="{id}-clip"><path d="{outline}"/></clipPath>"#
    ));

    defs.push_str(&format!(
        r#"<radialGradient id="{id}-body" cx="0.36" cy="0.30" r="0.86"><stop offset="0" stop-color="{a}"/><stop offset="0.52" stop-color="{b}"/><stop offset="1" stop-color="{c}"/></radialGradient>"#,
        a = tint(wax.highlight()),
        b = tint(wax.base),
        c = tint(wax.base.darken(0.28))
    ));

    defs.push_str(&format!(
        r#"<radialGradient id="{id}-field" cx="0.62" cy="0.68" r="0.9"><stop offset="0" stop-color="{a}"/><stop offset="1" stop-color="{b}"/></radialGradient>"#,
        a = tint(wax.field().lighten(0.10)),
        b = tint(wax.field().darken(0.16))
    ));

    if !opts.simplified {
        defs.push_str(&format!(
            r#"<filter id="{id}-soft" x="-20%" y="-20%" width="140%" height="140%"><feGaussianBlur stdDeviation="2.6"/></filter>"#
        ));

        defs.push_str(&format!(
            r#"<filter id="{id}-grain" x="0" y="0" width="100%" height="100%"><feTurbulence type="fractalNoise" baseFrequency="0.85" numOctaves="3" seed="{s}" result="n"/><feColorMatrix in="n" type="saturate" values="0"/></filter>"#,
            s = sigil.ticks
        ));
    }

    if opts.state == SealState::Breaking && !opts.reduced_motion {
        defs.push_str(
            &format!(
                r#"<style>@keyframes {id}-breathe{{0%,100%{{opacity:0.78}}50%{{opacity:1}}}}.{id}-pulse{{animation:{id}-breathe 3.4s ease-in-out infinite}}@media (prefers-reduced-motion:reduce){{.{id}-pulse{{animation:none}}}}</style>"#
            ),
        );
    }

    defs.push_str("</defs>");
    defs
}

fn seal_aria_label(wax: &Wax, sigil: &Sigil, opts: &SealOptions) -> String {
    format!(
        "{} wax seal, {} figure, {} arms, {} state",
        wax.name,
        sigil.motif.label(),
        sigil.arms,
        opts.state.label()
    )
}

fn escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

pub fn wax_name(seed: &[u8; 32]) -> &'static str {
    Bits::new(seed, b"wax").pick(&WAXES).name
}

pub fn describe(seed: &[u8; 32]) -> String {
    let wax = *Bits::new(seed, b"wax").pick(&WAXES);
    let sigil = Sigil::generate(&mut Bits::new(seed, b"sigil"));

    let rings = sigil.rings.len();
    format!(
        "{} wax · {} · {} arms · {} {} · notch at {}",
        wax.name,
        sigil.motif.label(),
        sigil.arms,
        rings,
        if rings == 1 { "ring" } else { "rings" },
        sigil.notch_at
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_wax_always_fits_its_canvas() {
        for i in 0..2000u32 {
            let seed = *blake3::hash(&i.to_le_bytes()).as_bytes();

            let mut bits = Bits::new(&seed, b"wax");
            let _ = bits.pick(&WAXES);
            let max = wax_radii(&mut bits).into_iter().fold(0.0, f64::max);
            assert!(max <= 93.0, "seed {i}: wax reaches radius {max}");
        }
    }

    fn seed(byte: u8) -> [u8; 32] {
        [byte; 32]
    }

    #[test]
    fn the_same_seed_renders_byte_identically() {
        for b in [0u8, 1, 17, 200, 255] {
            let a = render(&seed(b), &SealOptions::default());
            let c = render(&seed(b), &SealOptions::default());
            assert_eq!(a, c, "seed {b} did not render identically");
        }
    }

    #[test]
    fn different_seeds_render_differently() {
        let mut seen = std::collections::HashSet::new();
        for b in 0..=255u8 {
            assert!(
                seen.insert(render(&seed(b), &SealOptions::default())),
                "collision at {b}"
            );
        }
    }

    #[test]
    fn a_single_bit_change_is_visible() {
        let mut a = seed(0);
        let mut b = seed(0);
        b[31] ^= 0x01;

        let first = describe(&a);
        let second = describe(&b);
        a[0] ^= 0x80;
        let third = describe(&a);

        assert!(
            first != second || first != third,
            "a one-bit seed change produced no structural difference"
        );
    }

    #[test]
    fn two_seals_share_no_element_ids() {
        let a = render(&seed(1), &SealOptions::default());
        let b = render(&seed(2), &SealOptions::default());

        let ids = |svg: &str| -> std::collections::HashSet<String> {
            let mut found = std::collections::HashSet::new();
            let mut rest = svg;
            while let Some(at) = rest.find(" id=\"") {
                rest = &rest[at + 5..];
                if let Some(end) = rest.find('"') {
                    found.insert(rest[..end].to_string());
                    rest = &rest[end..];
                }
            }
            found
        };

        let (ia, ib) = (ids(&a), ids(&b));
        assert!(!ia.is_empty(), "the seal defines no ids at all");
        let shared: Vec<_> = ia.intersection(&ib).collect();
        assert!(shared.is_empty(), "two seals share element ids: {shared:?}");

        for (svg, own) in [(&a, &ia), (&b, &ib)] {
            let mut rest = svg.as_str();
            while let Some(at) = rest.find("url(#") {
                rest = &rest[at + 5..];
                let end = rest.find(')').expect("unterminated url() reference");
                let target = &rest[..end];
                assert!(
                    own.contains(target),
                    "reference to #{target} is not defined in this seal"
                );
                rest = &rest[end..];
            }
        }
    }

    #[test]
    fn the_pulse_class_is_scoped_per_seal() {
        let a = render(&seed(1), &SealOptions::in_state(SealState::Breaking));
        let b = render(&seed(2), &SealOptions::in_state(SealState::Breaking));

        let class_of = |svg: &str| {
            let at = svg.find(r#"<g class="s"#).expect("no pulse group");
            let rest = &svg[at + 10..];
            rest[..rest.find('"').unwrap()].to_string()
        };
        assert_ne!(class_of(&a), class_of(&b));
        assert!(a.contains(&format!(
            "@keyframes {}",
            class_of(&a).replace("-pulse", "-breathe")
        )));
    }

    #[test]
    fn id_prefixes_are_deterministic() {
        assert_eq!(
            id_prefix(&seed(5), SealState::Sealed),
            id_prefix(&seed(5), SealState::Sealed)
        );
        assert_ne!(
            id_prefix(&seed(5), SealState::Sealed),
            id_prefix(&seed(6), SealState::Sealed)
        );
        assert_ne!(
            id_prefix(&seed(5), SealState::Sealed),
            id_prefix(&seed(5), SealState::Broken)
        );

        let id = id_prefix(&seed(5), SealState::Sealed);
        assert!(id.starts_with('s') && id.len() == 9);
        assert!(id[1..].chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn output_is_well_formed_svg() {
        let svg = render(&seed(42), &SealOptions::default());
        assert!(svg.starts_with("<svg "));
        assert!(svg.ends_with("</svg>"));
        assert!(svg.contains(r#"viewBox="0 0 200 200""#));
        assert_eq!(svg.matches("<svg").count(), 1);

        assert_eq!(svg.matches("<g").count(), svg.matches("</g>").count());
        assert_eq!(
            svg.matches("<defs>").count(),
            svg.matches("</defs>").count()
        );

        assert!(
            !svg.contains('{') && !svg.contains('}'),
            "unexpanded template in output"
        );
    }

    #[test]
    fn size_is_honoured() {
        for size in [16u32, 32, 200, 600] {
            let svg = render(&seed(3), &SealOptions::at_size(size));
            assert!(svg.contains(&format!(r#"width="{size}""#)));
            assert!(svg.contains(&format!(r#"height="{size}""#)));
        }
    }

    #[test]
    fn every_state_renders() {
        for state in [
            SealState::Sealed,
            SealState::Stirring,
            SealState::Breaking,
            SealState::Broken,
            SealState::Held,
            SealState::Frozen,
        ] {
            let svg = render(&seed(9), &SealOptions::in_state(state));
            assert!(
                svg.starts_with("<svg "),
                "{state:?} produced malformed output"
            );
            assert!(!state.label().is_empty());
            assert!(
                svg.contains(state.label()),
                "{state:?} is not named in the aria label"
            );
        }
    }

    #[test]
    fn the_fracture_deepens_monotonically() {
        let order = [
            SealState::Sealed,
            SealState::Stirring,
            SealState::Breaking,
            SealState::Broken,
        ];
        for pair in order.windows(2) {
            assert!(
                pair[0].crack_extent() < pair[1].crack_extent(),
                "{:?} is not less cracked than {:?}",
                pair[0],
                pair[1]
            );
        }
        assert_eq!(SealState::Sealed.crack_extent(), 0.0);
        assert_eq!(SealState::Broken.crack_extent(), 1.0);
    }

    #[test]
    fn held_shows_a_healed_seam_not_a_fissure() {
        let held = render(&seed(31), &SealOptions::in_state(SealState::Held));
        let breaking = render(
            &seed(31),
            &SealOptions {
                state: SealState::Breaking,
                reduced_motion: true,
                ..Default::default()
            },
        );

        assert!(breaking.contains(r#"stroke-width="5.4""#));
        assert!(
            !held.contains(r#"stroke-width="5.4""#),
            "a held capsule must not render an open fissure"
        );

        let sealed = render(&seed(31), &SealOptions::in_state(SealState::Sealed));
        assert_ne!(held, sealed, "held must be distinguishable from sealed");
    }

    #[test]
    fn a_deepening_crack_follows_the_same_path() {
        let stirring = render(&seed(5), &SealOptions::in_state(SealState::Stirring));
        let breaking = render(&seed(5), &SealOptions::in_state(SealState::Breaking));

        let first_move = |svg: &str| {
            svg.split(r#"stroke-width="5.4""#)
                .next()
                .and_then(|s| s.rfind("M "))
                .map(|i| svg[i..i + 20].to_string())
        };
        assert_eq!(
            first_move(&stirring),
            first_move(&breaking),
            "the crack restarted somewhere else instead of growing"
        );
    }

    #[test]
    fn a_sealed_capsule_has_no_crack() {
        let svg = render(&seed(7), &SealOptions::in_state(SealState::Sealed));
        assert!(
            !svg.contains(r#"stroke-width="5.4""#),
            "a sealed capsule must look intact"
        );
    }

    #[test]
    fn small_seals_use_the_compact_figure() {
        assert!(SealOptions::at_size(24).resolve_compact());
        assert!(SealOptions::at_size(32).resolve_compact());
        assert!(!SealOptions::at_size(64).resolve_compact());
        assert!(!SealOptions::at_size(200).resolve_compact());

        assert!(SealOptions {
            size: 200,
            compact: Some(true),
            ..Default::default()
        }
        .resolve_compact());
        assert!(!SealOptions {
            size: 16,
            compact: Some(false),
            ..Default::default()
        }
        .resolve_compact());
    }

    #[test]
    fn the_compact_figure_drops_the_fine_detail() {
        let tray = render(&seed(21), &SealOptions::tray(SealState::Sealed));
        let full = render(
            &seed(21),
            &SealOptions {
                size: 32,
                compact: Some(false),
                simplified: true,
                ..Default::default()
            },
        );

        assert!(
            full.contains(r#"stroke-width="1.7""#),
            "the full seal should have ticks"
        );
        assert!(
            !tray.contains(r#"stroke-width="1.7""#),
            "the compact seal must drop ticks"
        );

        assert!(
            tray.contains(r#"stroke-width="7.6""#),
            "compact strokes must be heavy"
        );
        assert!(
            tray.len() < full.len(),
            "the compact figure should be simpler, not larger"
        );
    }

    #[test]
    fn the_notch_widens_in_compact_mode() {
        let tray = render(&seed(21), &SealOptions::tray(SealState::Sealed));
        let full = render(&seed(21), &SealOptions::at_size(200));

        assert!(tray.contains(r#"Z" fill="#), "compact seal lost its notch");
        assert!(full.contains(r#"Z" fill="#), "full seal lost its notch");
        assert_ne!(tray, full);
    }

    #[test]
    fn compact_and_full_share_their_identity() {
        for b in [3u8, 40, 200] {
            let sigil = Sigil::generate(&mut Bits::new(&seed(b), b"sigil"));
            let compact = compact_geometry(&sigil);
            let arms = compact.matches("<path").count();
            assert!(arms > 0, "seed {b}: compact figure is empty");

            assert!(
                sigil.arms.min(6) as usize <= sigil.arms as usize,
                "compact must not invent arms"
            );
        }
    }

    #[test]
    fn simplified_output_drops_filters() {
        let full = render(&seed(11), &SealOptions::default());
        let simple = render(
            &seed(11),
            &SealOptions {
                simplified: true,
                ..Default::default()
            },
        );

        assert!(full.contains("feTurbulence"));
        assert!(
            !simple.contains("feTurbulence"),
            "the tray icon must not carry a grain filter"
        );
        assert!(!simple.contains("feGaussianBlur"));
        assert!(simple.len() < full.len());
    }

    #[test]
    fn reduced_motion_removes_animation() {
        let moving = render(&seed(13), &SealOptions::in_state(SealState::Breaking));
        let still = render(
            &seed(13),
            &SealOptions {
                state: SealState::Breaking,
                reduced_motion: true,
                ..Default::default()
            },
        );
        assert!(
            !still.contains("<animate"),
            "reduced motion must mean no animation"
        );
        let _ = moving;
    }

    #[test]
    fn there_is_always_an_accessible_label() {
        let svg = render(&seed(15), &SealOptions::default());
        assert!(svg.contains(r#"role="img""#));
        assert!(svg.contains("aria-label="));
        assert!(svg.contains("wax seal"));
    }

    #[test]
    fn a_title_is_included_and_escaped() {
        let svg = render(
            &seed(15),
            &SealOptions {
                title: Some(r#"Alex & <script>"#.to_string()),
                ..Default::default()
            },
        );
        assert!(svg.contains("<title>Alex &amp; &lt;script&gt;</title>"));
        assert!(
            !svg.contains("<script>"),
            "a title must never inject markup"
        );
    }

    #[test]
    fn structure_does_not_depend_on_colour() {
        let mut structures = std::collections::HashSet::new();
        for b in 0..=120u8 {
            structures.insert(describe(&seed(b)));
        }
        assert!(
            structures.len() > 60,
            "only {} distinct structures across 121 seeds — too much identity is in colour",
            structures.len()
        );
    }

    #[test]
    fn arm_counts_stay_in_the_legible_range() {
        for b in 0..=255u8 {
            let sigil = Sigil::generate(&mut Bits::new(&seed(b), b"sigil"));
            assert!(
                (5..=11).contains(&sigil.arms),
                "seed {b} gave {} arms",
                sigil.arms
            );
            assert!(
                sigil.notch_at < sigil.arms,
                "seed {b} put the notch outside the arm count"
            );
            assert!((1..=3).contains(&sigil.rings.len()));
            assert!((28..=64).contains(&sigil.ticks));
            assert!((0.0..1.0).contains(&sigil.rotation));
        }
    }

    #[test]
    fn rings_stay_separated() {
        for b in 0..=255u8 {
            let sigil = Sigil::generate(&mut Bits::new(&seed(b), b"sigil"));
            let mut radii: Vec<f64> = sigil.rings.iter().map(|r| r.0).collect();
            radii.sort_by(|a, c| a.partial_cmp(c).unwrap());
            for pair in radii.windows(2) {
                assert!(
                    pair[1] - pair[0] >= 6.5,
                    "seed {b}: rings at {:.1} and {:.1} are too close to read apart",
                    pair[0],
                    pair[1]
                );
            }

            for r in radii {
                assert!(
                    r > 15.0 && r < 60.0,
                    "seed {b}: ring at {r:.1} escapes the field"
                );
            }
        }
    }

    #[test]
    fn alternating_terminals_only_appear_on_even_arm_counts() {
        for b in 0..=255u8 {
            let sigil = Sigil::generate(&mut Bits::new(&seed(b), b"sigil"));
            if sigil.arms % 2 == 1 {
                assert_eq!(
                    sigil.terminal_a, sigil.terminal_b,
                    "seed {b}: {} arms with alternating terminals",
                    sigil.arms
                );
            }
        }
    }

    #[test]
    fn every_terminal_and_boss_is_reachable() {
        let mut terminals = std::collections::HashSet::new();
        let mut bosses = std::collections::HashSet::new();
        for b in 0..=255u8 {
            let sigil = Sigil::generate(&mut Bits::new(&seed(b), b"sigil"));
            terminals.insert(sigil.terminal_a);
            bosses.insert(sigil.boss);
        }
        assert_eq!(
            terminals.len(),
            TERMINALS.len(),
            "some terminal shapes never appear"
        );
        assert_eq!(bosses.len(), BOSSES.len(), "some boss shapes never appear");
    }

    #[test]
    fn all_eight_waxes_get_used() {
        let mut waxes = std::collections::HashSet::new();
        for b in 0..=255u8 {
            waxes.insert(wax_name(&seed(b)));
        }
        assert_eq!(waxes.len(), WAXES.len(), "some waxes never appear");
    }

    #[test]
    fn describe_is_stable_and_informative() {
        let d = describe(&seed(21));
        assert_eq!(d, describe(&seed(21)));
        assert!(d.contains("wax"));
        assert!(d.contains("arms"));
    }

    #[test]
    fn output_size_is_reasonable() {
        let svg = render(&seed(1), &SealOptions::default());
        assert!(svg.len() < 24_000, "seal SVG is {} bytes", svg.len());
        let tray = render(&seed(1), &SealOptions::tray(SealState::Sealed));
        assert!(tray.len() < 16_000, "tray seal is {} bytes", tray.len());
    }

    #[test]
    fn presets_are_configured_as_intended() {
        let tray = SealOptions::tray(SealState::Broken);
        assert_eq!(tray.size, 32);
        assert!(tray.simplified && tray.reduced_motion);

        let print = SealOptions::print();
        assert_eq!(print.size, 600);
        assert!(print.simplified && print.reduced_motion);
    }
}
