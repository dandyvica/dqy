// Manage the + command line option (e.g.: +bufsize=4096 or +short)
#[derive(Debug, Default)]
pub struct PlusArg<'a> {
    pub name: &'a str,
    pub value: Option<&'a str>,
}

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
