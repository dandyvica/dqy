use std::collections::HashMap;
use std::fmt::Debug;
use std::ops::Deref;
use std::str::FromStr;

// Manage the + command line option (e.g.: +bufsize=4096 or +short)
#[derive(Debug, Default, Clone)]
pub struct PlusArg<'a> {
    pub name: &'a str,
    pub value: Option<&'a str>,
}

// hold the + arguments like +short, +bufsize=4096 or +noaaflag
impl<'a> PlusArg<'a> {
    pub fn new(arg: &'a str) -> Option<Self> {
        // safeguards: nothing after '+'
        if arg.len() == 1 {
            return None;
        }

        // now we can safely process: in that case, the plus arg is like: +bufsize=4096
        if let Some(pos) = arg.find('=') {
            if pos + 1 == arg.len() {}
            Some(Self {
                name: &arg[1..pos],
                value: Some(&arg[pos + 1..]),
            })
        } else {
            Some(Self {
                name: &arg[1..],
                value: None,
            })
        }
    }

    // convert the value to the specified type
    // ex: let size: u16 = value.get()?;
    pub fn get<T: FromStr>(&self) -> Option<T>
    where
        <T as FromStr>::Err: Debug,
    {
        if self.value.is_none() {
            None
        } else {
            let value = str::parse::<T>(self.value.unwrap()).ok();
            value
        }
    }
}

// hold all +args found
#[derive(Debug, Clone)]
pub(super) struct PlusArgList<'a>(HashMap<&'a str, PlusArg<'a>>);

impl<'a> Deref for PlusArgList<'a> {
    /// The resulting type after dereferencing.
    type Target = HashMap<&'a str, PlusArg<'a>>;

    /// Dereferences the value, giving the vector of DNS ip addresses.
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<'a> PlusArgList<'a> {
    pub fn new(arg_list: &[PlusArg<'a>]) -> Self {
        let mut hmap = HashMap::new();

        for arg in arg_list {
            hmap.insert(arg.name, arg.clone());
        }
        Self(hmap)
    }

    // // return true if the list of arguments contains the name passed in argument
    // pub fn contains(&self, name: &str) -> bool {
    //     self.0.contains_key(name)
    // }

    // return the default value if arg name is not found, otherwse the value converted to T
    pub fn get_value<T: FromStr>(&self, name: &str, default: T) -> T
    where
        <T as FromStr>::Err: Debug,
    {
        if let Some(v) = self.get(name) {
            v.get().unwrap_or(default)
        } else {
            default
        }
    }
}

// impl<'a> From<&'a str> for PlusArgList<'a> {
//     // build the list of plus args from a str
//     fn from(s: &'a str) -> Self {
//         let split: Vec<_> = s.split_ascii_whitespace().collect();
//         let v = split
//             .iter()
//             .filter_map(|x| PlusArg::new(x))
//             .collect::<Vec<PlusArg>>();

//         Self(v)
//     }
// }

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn boolean() {
        let arg = PlusArg::new("+short").unwrap();
        assert_eq!(arg.name, "short");
        assert!(arg.value.is_none());
    }

    #[test]
    fn string() {
        let arg = PlusArg::new("+bufsize=4096").unwrap();
        assert_eq!(arg.name, "bufsize");
        assert_eq!(arg.value, Some("4096"));
    }

    #[test]
    fn get() {
        let arg = PlusArg::new("+bufsize=4096").unwrap();
        assert_eq!(arg.get::<u16>(), Some(4096));
    }

    #[test]
    fn single_plus() {
        let arg = PlusArg::new("+");
        assert!(arg.is_none());
    }

    // #[test]
    // fn list() {
    //     let arg = PlusArgList::from("+short +foo +nofoo +bufsize=4096 +");
    //     assert_eq!(arg.len(), 4);
    // }
}
