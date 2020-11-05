use crate::{ResolveKind, Value};
use std::collections::HashMap;

#[derive(Debug, Default)]
pub struct State {
    variables: HashMap<String, Value>,
}

impl State {
    pub fn variable(&self, key: impl AsRef<str>) -> Option<&Value> {
        self.variables.get(key.as_ref())
    }

    pub fn variables_mut(&mut self) -> &mut HashMap<String, Value> {
        &mut self.variables
    }
}

/// State held by the compiler as it parses the program source.
#[derive(Debug, Default)]
pub struct CompilerState {
    /// The [`ResolveKind`] each variable is expected to have.
    ///
    /// This allows assignment operations to tell the compiler what kinds each
    /// variable will have at runtime, so that the compiler can then check the
    /// variable kinds at compile-time when a variable is called.
    variable_kinds: HashMap<String, ResolveKind>,

    /// The [`ResolveKind`] each path query is expected to have.
    ///
    /// By default, the first time a path is queried, it resolves to `Any`, but
    /// when a path is used to assign a value to, we can potentially narrow down
    /// the list of values the path will resolve to.
    ///
    /// FIXME: this won't work for coalesced paths. We're either going to
    /// disallow those in assignments, which makes this easier to fix, or we're
    /// going to always return `Any` for coalesced paths. Either way, this is a
    /// known bug that we need to fix soon.
    path_query_kinds: HashMap<String, ResolveKind>,
}

impl CompilerState {
    pub fn variable_kind(&self, key: impl AsRef<str>) -> Option<&ResolveKind> {
        self.variable_kinds.get(key.as_ref())
    }

    pub fn variable_kinds_mut(&mut self) -> &mut HashMap<String, ResolveKind> {
        &mut self.variable_kinds
    }

    pub fn path_query_kind(&self, key: impl AsRef<str>) -> Option<&ResolveKind> {
        self.path_query_kinds.get(key.as_ref())
    }

    pub fn path_query_kinds_mut(&mut self) -> &mut HashMap<String, ResolveKind> {
        &mut self.path_query_kinds
    }
}
