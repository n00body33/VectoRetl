use crate::{diagnostic::Formatter, parser::Parser, state};
use std::fmt;
use std::str::FromStr;

#[derive(thiserror::Error, Clone, Debug, PartialEq)]
pub enum Error {
    #[error("unable to create path from alternative string: {0}")]
    Alternative(String),

    #[error("unable to parse path")]
    Parse(String),
}

/// Provide easy access to individual [`Segment`]s of a path.
#[derive(Clone, Debug, Eq, PartialEq, Hash, Ord, PartialOrd)]
pub struct Path {
    segments: Vec<Segment>,
}

impl FromStr for Path {
    type Err = Error;

    /// Parse a string path into a [`Path`] wrapper with easy access to
    /// individual path [`Segment`]s.
    ///
    /// This function fails if the provided path is invalid, as defined by the
    /// parser grammar.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut state = state::Compiler::default();
        let parser = Parser::new(&[], &mut state, false);
        if s.starts_with('.') {
            parser
                .path_from_str(s)
                .map(|(path, _)| path)
                .map_err(|diagnostics| Error::Parse(Formatter::new(s, diagnostics).to_string()))
        } else {
            let s = format!(".{}", s);
            parser
                .path_from_str(&s)
                .map(|(path, _)| path)
                .map_err(|diagnostics| Error::Parse(Formatter::new(&s, diagnostics).to_string()))
        }
    }
}

impl Path {
    /// Create a path from a list of [`Segment`]s.
    ///
    /// Note that the caller is required to uphold the invariant that the list
    /// of segments was generated by the Remap parser.
    ///
    /// Use the `from_str` method if you want to be sure the generated [`Path`]
    /// is valid.
    pub fn new_unchecked(segments: Vec<Segment>) -> Self {
        Self { segments }
    }

    /// Create a "root" path, containing no segments, which when written as a
    /// string is represented as `"."`.
    pub fn root() -> Self {
        Self { segments: vec![] }
    }

    /// Returns `true` if the path points to the _root_ of a given object.
    ///
    /// In its string form, this is represented as `.` (a single dot).
    pub fn is_root(&self) -> bool {
        self.segments.is_empty()
    }

    pub fn segments(&self) -> &[Segment] {
        &self.segments
    }

    /// This is a temporary function to make it easier to interface [`Path`]
    /// with Vector.
    ///
    /// .foo[2]                 => [[".foo[2]"]]
    /// .foo.bar.(baz | qux)    => [[".foo"], [".bar"], [".baz", ".qux"]]
    pub fn to_alternative_components(&self) -> Vec<Vec<String>> {
        let mut segments = vec![];
        let handle_field = |field: &Field| field.as_str().replace('.', "\\.");

        for segment in self.segments() {
            match segment {
                Segment::Field(field) => segments.push(vec![handle_field(field)]),
                Segment::Coalesce(fields) => {
                    segments.push(fields.iter().map(|f| handle_field(f)).collect::<Vec<_>>())
                }
                Segment::Index(_) => segments.last_mut().into_iter().for_each(|vec| {
                    vec.iter_mut()
                        .for_each(|s| s.push_str(&segment.to_string()))
                }),
            }
        }

        segments
    }

    /// Similar to `to_alternative_components`, except that it produces a list of
    /// alternative strings:
    ///
    /// .foo.(bar | baz)[1].(qux | quux)
    ///
    /// // .foo.bar[1].qux
    /// // .foo.bar[1].quux
    /// // .foo.baz[1].qux
    /// // .foo.baz[1].quux
    ///
    /// Coalesced paths to the left take precedence over the ones to the right.
    pub fn to_alternative_strings(&self) -> Vec<String> {
        if self.is_root() {
            return vec![];
        }

        let components = self.to_alternative_components();
        let mut loop_count = components.iter().fold(1, |acc, vec| acc * vec.len());
        let mut paths: Vec<Vec<String>> = Vec::with_capacity(loop_count - 1);
        paths.resize(loop_count, vec![]);

        for fields in components.iter() {
            debug_assert!(!fields.is_empty());

            loop_count /= fields.len();

            let mut paths_index = 0;
            let mut component_index = 0;
            'outer: loop {
                for _ in 0..loop_count {
                    let idx = component_index % fields.len();
                    paths[paths_index].push(fields[idx].clone());

                    if paths_index == paths.len() - 1 {
                        break 'outer;
                    }

                    paths_index += 1;
                }

                component_index += 1;
            }
        }

        paths.into_iter().map(|p| p.join(".")).collect()
    }

    /// A poor-mans way to convert an "alternative" string representation to a
    /// path.
    ///
    /// This will be replaced once better path handling lands.
    pub fn from_alternative_string(path: String) -> Result<Self, Error> {
        let mut segments = vec![];
        let mut chars = path.chars().peekable();
        let mut part = String::new();

        let handle_field = |part: &mut String, segments: &mut Vec<Segment>| -> Result<(), Error> {
            let string = part.replace("\\.", ".");
            let field = Field::from_str(&string)?;
            segments.push(Segment::Field(field));
            part.clear();
            Ok(())
        };

        let mut handle_char = |c: char,
                               chars: &mut std::iter::Peekable<std::str::Chars>,
                               part: &mut String|
         -> Result<(), Error> {
            match c {
                '\\' if chars.peek() == Some(&'.') || chars.peek() == Some(&'[') => {
                    part.push(c);
                    part.push(chars.next().unwrap());
                }
                '[' => {
                    if !part.is_empty() {
                        handle_field(part, &mut segments)?;
                    }

                    for c in chars {
                        if c == ']' {
                            let index = part
                                .parse::<usize>()
                                .map_err(|err| Error::Alternative(err.to_string()))?;

                            segments.push(Segment::Index(index));
                            part.clear();
                            break;
                        }

                        part.push(c);
                    }
                }
                '.' if !part.is_empty() => handle_field(part, &mut segments)?,
                '\0' if !part.is_empty() => handle_field(part, &mut segments)?,
                '.' => {}
                _ => part.push(c),
            }

            Ok(())
        };

        while let Some(c) = chars.next() {
            handle_char(c, &mut chars, &mut part)?;
        }

        if !part.is_empty() {
            handle_char('\0', &mut chars, &mut part)?;
        }

        Ok(Self::new_unchecked(segments))
    }

    /// Appends a new segment to the end of this path.
    pub fn append(&mut self, segment: Segment) {
        self.segments.push(segment);
    }

    /// Returns true if the current path starts with the same segments
    /// as the given path.
    ///
    /// ".noog.norg.nink".starts_with(".noog.norg") == true
    pub fn starts_with(&self, other: &Path) -> bool {
        if self.segments.len() < other.segments.len() {
            return false;
        }

        self.segments
            .iter()
            .take(other.segments.len())
            .zip(other.segments.iter())
            .all(|(me, them)| me == them)
    }
}

impl fmt::Display for Path {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(".")?;

        let mut iter = self.segments.iter().peekable();
        while let Some(segment) = iter.next() {
            segment.fmt(f)?;

            match iter.peek() {
                Some(Segment::Field(_)) | Some(Segment::Coalesce(_)) => f.write_str(".")?,
                _ => {}
            }
        }

        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Hash, Ord, PartialOrd)]
pub enum Segment {
    Field(Field),
    Coalesce(Vec<Field>),
    Index(usize),
}

impl Segment {
    pub fn is_field(&self) -> bool {
        matches!(self, Self::Field(_))
    }

    pub fn is_coalesce(&self) -> bool {
        matches!(self, Self::Coalesce(_))
    }

    pub fn is_index(&self) -> bool {
        matches!(self, Self::Index(_))
    }
}

impl fmt::Display for Segment {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Segment::Field(path) => write!(f, "{}", path),
            Segment::Coalesce(paths) => write!(
                f,
                "({})",
                paths
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join(" | ")
            ),
            Segment::Index(i) => f.write_str(&format!("[{}]", i)),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Hash, Ord, PartialOrd)]
pub enum Field {
    Regular(String),
    Quoted(String),
}

impl Field {
    pub fn as_str(&self) -> &str {
        match self {
            Field::Regular(field) => &field,
            Field::Quoted(field) => &field,
        }
    }
}

impl FromStr for Field {
    type Err = Error;

    /// Parse a string path into a [`Path`] wrapper with easy access to
    /// individual path [`Segment`]s.
    ///
    /// This function fails if the provided path is invalid, as defined by the
    /// parser grammar.
    fn from_str(field: &str) -> Result<Self, Self::Err> {
        let mut state = state::Compiler::default();
        Parser::new(&[], &mut state, false)
            .path_field_from_str(field)
            .map(|(field, _)| field)
            .map_err(|diagnostics| Error::Parse(Formatter::new(field, diagnostics).to_string()))
    }
}

impl fmt::Display for Field {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Field::Regular(path) => f.write_str(path),
            Field::Quoted(path) => {
                f.write_str("\"")?;
                f.write_str(path)?;
                f.write_str("\"")
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Field;
    use super::*;
    use Field::*;
    use Segment::*;

    #[test]
    fn test_starts_with() {
        assert!(Path::from_str(".noog.nork.nink")
            .unwrap()
            .starts_with(&Path::from_str(".noog.nork").unwrap()));

        assert!(!Path::from_str(".noog.nork")
            .unwrap()
            .starts_with(&Path::from_str(".noog.nork.nink").unwrap()));

        assert!(Path::from_str(".noog.nork.nink")
            .unwrap()
            .starts_with(&Path::from_str(".noog.nork.nink").unwrap()));
    }

    #[test]
    fn test_path() {
        let cases = vec![
            (".foo", vec![Field(Regular("foo".to_owned()))]),
            (
                ".foo.bar",
                vec![
                    Field(Regular("foo".to_owned())),
                    Field(Regular("bar".to_owned())),
                ],
            ),
            (
                ".foo.(bar | baz)",
                vec![
                    Field(Regular("foo".to_owned())),
                    Coalesce(vec![Regular("bar".to_owned()), Regular("baz".to_owned())]),
                ],
            ),
            (".foo[2]", vec![Field(Regular("foo".to_owned())), Index(2)]),
            (
                r#".foo."bar baz""#,
                vec![
                    Field(Regular("foo".to_owned())),
                    Field(Quoted("bar baz".to_owned())),
                ],
            ),
            (
                r#".foo.("bar baz" | qux)[0]"#,
                vec![
                    Field(Regular("foo".to_owned())),
                    Coalesce(vec![
                        Quoted("bar baz".to_owned()),
                        Regular("qux".to_owned()),
                    ]),
                    Index(0),
                ],
            ),
            (
                r#".foo.("bar baz" | qux | quux)[0][2].bla"#,
                vec![
                    Field(Regular("foo".to_owned())),
                    Coalesce(vec![
                        Quoted("bar baz".to_owned()),
                        Regular("qux".to_owned()),
                        Regular("quux".to_owned()),
                    ]),
                    Index(0),
                    Index(2),
                    Field(Regular("bla".to_owned())),
                ],
            ),
        ];

        for (string, segments) in cases {
            let path = Path::from_str(string);
            assert_eq!(Ok(segments.clone()), path.map(|p| p.segments().to_owned()));

            let path = Path::new_unchecked(segments).to_string();
            assert_eq!(string.to_string(), path);
        }
    }

    #[test]
    fn test_to_alternate_components() {
        let path = Path::from_str(r#".a.(b | c | d | e).f.(g | h | i).(j | k)"#).unwrap();

        assert_eq!(
            path.to_alternative_components(),
            vec![
                vec!["a".to_owned()],
                vec![
                    "b".to_owned(),
                    "c".to_owned(),
                    "d".to_owned(),
                    "e".to_owned(),
                ],
                vec!["f".to_owned()],
                vec!["g".to_owned(), "h".to_owned(), "i".to_owned(),],
                vec!["j".to_owned(), "k".to_owned(),],
            ]
        );
    }

    #[test]
    fn test_to_alternate_strings() {
        let path = Path::from_str(r#".a.(b | c | d | e).f.(g | h | i).(j | k)"#).unwrap();

        assert_eq!(
            path.to_alternative_strings(),
            vec![
                "a.b.f.g.j",
                "a.b.f.g.k",
                "a.b.f.h.j",
                "a.b.f.h.k",
                "a.b.f.i.j",
                "a.b.f.i.k",
                //
                "a.c.f.g.j",
                "a.c.f.g.k",
                "a.c.f.h.j",
                "a.c.f.h.k",
                "a.c.f.i.j",
                "a.c.f.i.k",
                //
                "a.d.f.g.j",
                "a.d.f.g.k",
                "a.d.f.h.j",
                "a.d.f.h.k",
                "a.d.f.i.j",
                "a.d.f.i.k",
                //
                "a.e.f.g.j",
                "a.e.f.g.k",
                "a.e.f.h.j",
                "a.e.f.h.k",
                "a.e.f.i.j",
                "a.e.f.i.k",
            ]
        );
    }

    #[test]
    fn test_from_alternate_string() {
        let path = "foo.bar\\.baz[2][1].foobar".to_string();

        let path = Path::from_alternative_string(path);
        assert_eq!(
            path.map(|p| p.segments().to_owned()),
            Ok(vec![
                Field(Regular("foo".to_owned())),
                Field(Quoted("bar.baz".to_owned())),
                Index(2),
                Index(1),
                Field(Regular("foobar".to_owned())),
            ]),
        );
    }
}
