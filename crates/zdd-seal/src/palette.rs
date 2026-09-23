#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Rgb(pub u8, pub u8, pub u8);

impl Rgb {
    pub fn hex(&self) -> String {
        format!("#{:02x}{:02x}{:02x}", self.0, self.1, self.2)
    }

    pub fn lighten(&self, amount: f64) -> Rgb {
        self.mix(Rgb(255, 255, 255), amount)
    }

    pub fn darken(&self, amount: f64) -> Rgb {
        self.mix(Rgb(0, 0, 0), amount)
    }

    pub fn mix(&self, other: Rgb, amount: f64) -> Rgb {
        let a = amount.clamp(0.0, 1.0);
        let lerp = |x: u8, y: u8| (f64::from(x) + (f64::from(y) - f64::from(x)) * a).round() as u8;
        Rgb(
            lerp(self.0, other.0),
            lerp(self.1, other.1),
            lerp(self.2, other.2),
        )
    }

    pub fn luminance(&self) -> f64 {
        let channel = |c: u8| {
            let s = f64::from(c) / 255.0;
            if s <= 0.039_28 {
                s / 12.92
            } else {
                ((s + 0.055) / 1.055).powf(2.4)
            }
        };
        0.2126 * channel(self.0) + 0.7152 * channel(self.1) + 0.0722 * channel(self.2)
    }
}

#[derive(Debug, Clone, Copy)]
pub struct Wax {
    pub name: &'static str,

    pub base: Rgb,
}

impl Wax {
    pub fn highlight(&self) -> Rgb {
        self.base.lighten(0.30)
    }

    pub fn field(&self) -> Rgb {
        self.base.darken(0.30)
    }

    pub fn ink(&self) -> Rgb {
        self.base.darken(0.58)
    }

    pub fn emboss(&self) -> Rgb {
        self.base.lighten(0.44)
    }

    pub fn shadow(&self) -> Rgb {
        self.base.darken(0.72)
    }

    pub fn fracture(&self) -> Rgb {
        self.base.lighten(0.14).mix(Rgb(120, 110, 100), 0.35)
    }
}

pub const WAXES: [Wax; 8] = [
    Wax {
        name: "oxblood",
        base: Rgb(0xA8, 0x28, 0x1E),
    },
    Wax {
        name: "verdigris",
        base: Rgb(0x12, 0x74, 0x62),
    },
    Wax {
        name: "indigo",
        base: Rgb(0x2C, 0x38, 0x94),
    },
    Wax {
        name: "bronze",
        base: Rgb(0xA3, 0x6E, 0x1E),
    },
    Wax {
        name: "plum",
        base: Rgb(0x7D, 0x21, 0x63),
    },
    Wax {
        name: "moss",
        base: Rgb(0x33, 0x6E, 0x28),
    },
    Wax {
        name: "slate",
        base: Rgb(0x3A, 0x53, 0x6B),
    },
    Wax {
        name: "ember",
        base: Rgb(0xC2, 0x52, 0x14),
    },
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_is_well_formed() {
        assert_eq!(Rgb(0, 0, 0).hex(), "#000000");
        assert_eq!(Rgb(255, 255, 255).hex(), "#ffffff");
        assert_eq!(Rgb(0x8C, 0x2F, 0x26).hex(), "#8c2f26");
    }

    #[test]
    fn lighten_and_darken_move_the_right_way() {
        let c = Rgb(100, 100, 100);
        assert!(c.lighten(0.5).luminance() > c.luminance());
        assert!(c.darken(0.5).luminance() < c.luminance());
        assert_eq!(c.lighten(0.0), c);
        assert_eq!(c.lighten(1.0), Rgb(255, 255, 255));
        assert_eq!(c.darken(1.0), Rgb(0, 0, 0));
    }

    #[test]
    fn amounts_are_clamped() {
        let c = Rgb(100, 100, 100);
        assert_eq!(c.lighten(5.0), Rgb(255, 255, 255));
        assert_eq!(c.darken(-5.0), c);
    }

    #[test]
    fn every_wax_reads_on_both_grounds() {
        const PARCHMENT: Rgb = Rgb(0xE8, 0xE2, 0xD4);
        const INK: Rgb = Rgb(0x0B, 0x0C, 0x0E);

        let contrast = |a: Rgb, b: Rgb| {
            let (hi, lo) = if a.luminance() > b.luminance() {
                (a.luminance(), b.luminance())
            } else {
                (b.luminance(), a.luminance())
            };
            (hi + 0.05) / (lo + 0.05)
        };

        for wax in WAXES {
            let on_parchment = contrast(wax.base, PARCHMENT);
            let on_ink = contrast(wax.highlight(), INK);
            assert!(
                on_parchment >= 3.0,
                "{} has only {on_parchment:.2}:1 against parchment",
                wax.name
            );
            assert!(
                on_ink >= 3.0,
                "{} has only {on_ink:.2}:1 against ink",
                wax.name
            );
        }
    }

    #[test]
    fn tints_are_ordered_from_lit_to_shadowed() {
        for wax in WAXES {
            let steps = [
                ("emboss", wax.emboss().luminance()),
                ("highlight", wax.highlight().luminance()),
                ("base", wax.base.luminance()),
                ("field", wax.field().luminance()),
                ("ink", wax.ink().luminance()),
                ("shadow", wax.shadow().luminance()),
            ];
            for pair in steps.windows(2) {
                assert!(
                    pair[0].1 > pair[1].1,
                    "{}: {} is not lighter than {}",
                    wax.name,
                    pair[0].0,
                    pair[1].0
                );
            }
        }
    }

    #[test]
    fn the_sigil_reads_against_its_field() {
        for wax in WAXES {
            let ratio = wax.field().luminance() / wax.ink().luminance().max(0.001);
            assert!(
                ratio > 1.4,
                "{}: sigil only {ratio:.2}x its field",
                wax.name
            );
        }
    }

    #[test]
    fn waxes_are_distinct_and_named() {
        let mut names = std::collections::HashSet::new();
        let mut colours = std::collections::HashSet::new();
        for wax in WAXES {
            assert!(names.insert(wax.name), "duplicate wax name {}", wax.name);
            assert!(
                colours.insert(wax.base),
                "duplicate wax colour {}",
                wax.name
            );
            assert!(!wax.name.is_empty());
        }
    }
}
