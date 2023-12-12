use std::str::FromStr;

// Manage the + command line option (e.g.: +bufsize=4096 or +short)
#[derive(Debug, Default)]
pub struct PlusArg<'a> {
    pub name: &'a str,
    pub value: Option<&'a str>,
}

// hold the + arguments like +short, +bufsize=4096 or +noaaflag
impl<'a> PlusArg<'a> {
    pub fn new(arg: &'a str) -> Self {
        // safeguards
        if arg.len() == 1 {
            panic!("nothing after +")
        }

        // now we can safely process
        if let Some(pos) = arg.find('=') {
            if pos + 1 == arg.len() {}
            Self {
                name: &arg[1..pos],
                value: Some(&arg[pos + 1..]),
            }
        } else {
            Self {
                name: &arg[1..],
                value: None,
            }
        }
    }
}

// hold all +args found
pub(super) struct PlusArgList<'a>(pub(super) Vec<PlusArg<'a>>);

impl<'a> PlusArgList<'a> {
    pub fn contains(&self, value: &str) -> bool {
        self.0.iter().any(|p| p.name == value)
    }
}

// impl<'a> FromStr for PlusArgList<'a> {
//     type Err = ();

//     fn from_str(s: &str) -> Result<Self, Self::Err> {
//         let split: Vec<_> = s.split_ascii_whitespace().collect();

//         Ok(Self(
//             split
//                 .iter()
//                 .map(|x| PlusArg::new(x))
//                 .collect::<Vec<PlusArg>>(),
//         ))
//     }
// }

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn boolean() {
        let arg = PlusArg::new("+short");
        assert_eq!(arg.name, "short");
        assert!(arg.value.is_none());
    }

    #[test]
    fn string() {
        let arg = PlusArg::new("+bufsize=4096");
        assert_eq!(arg.name, "bufsize");
        assert_eq!(arg.value, Some("4096"));
    }

    #[test]
    #[should_panic]
    fn single_plus() {
        let arg = PlusArg::new("+");
    }
}
