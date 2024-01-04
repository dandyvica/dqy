use std::collections::HashMap;
use std::fmt::Debug;
use std::ops::Deref;
use std::str::FromStr;

// Manage the + command line option (e.g.: +bufsize=4096 or +short)
#[derive(Debug, Default, Clone)]
pub struct PlusArg<'a> {
    // name of the flag
    name: &'a str,

    // value: "4096" if +bufsize=4096
    value: Option<&'a str>,

    // true if no if present in a boolean flag. E.g: +nocdflag
    no: bool,
}

// hold the + arguments like +short, +bufsize=4096 or +noaaflag
impl<'a> PlusArg<'a> {
    pub fn new(arg: &'a str) -> Self {
        // now we can safely process: in that case, the plus arg is like: +bufsize=4096
        if let Some(pos) = arg.find('=') {
            Self {
                name: &arg[..pos],
                value: Some(&arg[pos + 1..]),
                no: false,
            }
        }
        // or a simple boolean flag like +aaflag or +nocdflag
        else {
            // ex: +nocdflag
            if arg.starts_with("no") {
                Self {
                    name: &arg[2..],
                    value: None,
                    no: true,
                }
            }
            // without no: +cdflag
            else {
                Self {
                    name: arg,
                    value: None,
                    no: false,
                }
            }
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

    // convert value to a vector of T values
    // value is separated with the separator like in: +dau=1,2,3
    pub fn split<T: FromStr>(&self, sep: char) -> Option<Vec<T>> {
        if self.value.is_none() {
            None
        } else {
            let v: Vec<T> = self
                .value
                .unwrap()
                .split(sep)
                .filter_map(|x| T::from_str(x).ok())
                .collect();
            Some(v)
        }
    }

    /// True if the name of the option starts with no like +noaaflag
    pub fn is_no(&self) -> bool {
        self.no
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
    // pub fn new(arg_list: &[PlusArg<'a>]) -> Self {
    //     let mut hmap = HashMap::new();

    //     for arg in arg_list {
    //         hmap.insert(arg.name, arg.clone());
    //     }
    //     Self(hmap)
    // }

    // // return true if the list of arguments contains the name passed in argument
    pub fn contains(&self, name: &str) -> bool {
        self.0.contains_key(name)
    }

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

impl<'a> From<&[PlusArg<'a>]> for PlusArgList<'a> {
    // build the list of plus args from a str separated by a comma
    fn from(arg_list: &[PlusArg<'a>]) -> Self {
        let mut hmap = HashMap::new();

        for arg in arg_list {
            hmap.insert(arg.name, arg.clone());
        }
        Self(hmap)
    }
}

impl<'a> From<&'a str> for PlusArgList<'a> {
    // build the list of plus args from a str separated by a comma
    fn from(s: &'a str) -> Self {
        let split: Vec<_> = s.split(",").map(|s| PlusArg::new(s.trim())).collect();
        PlusArgList::from(split.as_slice())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn boolean() {
        let arg = PlusArg::new("short");
        assert_eq!(arg.name, "short");
        assert!(arg.value.is_none());
        assert!(!arg.is_no());
    }

    #[test]
    fn string() {
        let arg = PlusArg::new("bufsize=4096");
        assert_eq!(arg.name, "bufsize");
        assert_eq!(arg.value, Some("4096"));
    }

    #[test]
    fn get() {
        let arg = PlusArg::new("bufsize=4096");
        assert_eq!(arg.get::<u16>(), Some(4096));
    }

    #[test]
    fn no() {
        let arg = PlusArg::new("noedns");
        assert_eq!(arg.name, "edns");
        assert!(arg.value.is_none());
        assert!(arg.is_no());
    }

    #[test]
    fn from_vec() {
        let v = vec![
            PlusArg::new("short"),
            PlusArg::new("bufsize=4096"),
            PlusArg::new("verbose=1"),
        ];
        let args = PlusArgList::from(v.as_slice());
        assert!(args.contains("short"));
        assert!(args.contains("bufsize"));
        assert!(args.contains("verbose"));
    }

    #[test]
    fn from_str() {
        let args = PlusArgList::from("short,  bufsize=4096,   verbose=1");
        assert!(args.contains("short"));
        assert!(args.contains("bufsize"));
        assert!(args.contains("verbose"));
    }

    #[test]
    fn split() {
        let args = PlusArg::new("+dau=1,2,3,4");
        let v: Vec<u16> = args.split(',').unwrap();
        assert_eq!(v, vec![1_u16, 2, 3, 4]);
    }
}
