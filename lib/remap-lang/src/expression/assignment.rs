use super::Error as E;
use crate::{
    expression::{Path, Variable},
    state,
    value::Kind,
    Expr, Expression, Object, Result, TypeDef, Value,
};

#[derive(thiserror::Error, Clone, Debug, PartialEq)]
pub enum Error {
    #[error("unable to insert value in path: {0}")]
    PathInsertion(String),
}

#[derive(Debug, Clone, PartialEq)]
pub enum Target {
    Path(Path),
    Variable(Variable),
    Infallible { ok: Box<Target>, err: Box<Target> },
}

#[derive(Debug, Clone, PartialEq)]
pub struct Assignment {
    target: Target,
    value: Box<Expr>,
}

impl Assignment {
    pub fn new(target: Target, value: Box<Expr>, state: &mut state::Compiler) -> Self {
        let type_def = value.type_def(state);

        let var_type_def = |state: &mut state::Compiler, var: &Variable, type_def| {
            state
                .variable_types_mut()
                .insert(var.ident().to_owned(), type_def);
        };

        let path_type_def = |state: &mut state::Compiler, path: &Path, type_def| {
            state
                .path_query_types_mut()
                .insert(path.as_ref().clone(), type_def);
        };

        match &target {
            Target::Variable(var) => var_type_def(state, var, type_def),
            Target::Path(path) => path_type_def(state, path, type_def),
            Target::Infallible { ok, err } => {
                // "ok" variable takes on the type definition of the value, but
                // is set to being infallible, as the error will be captured by
                // the "err" variable.
                let type_def = type_def.into_fallible(false);

                match ok.as_ref() {
                    Target::Variable(var) => var_type_def(state, var, type_def),
                    Target::Path(path) => path_type_def(state, path, type_def),
                    _ => unreachable!("nested infallible targets not supported"),
                }

                // "err" variable is either `null` or a string containing the
                // error message.
                let err_type_def = TypeDef {
                    kind: Kind::Bytes | Kind::Null,
                    ..Default::default()
                };

                match err.as_ref() {
                    Target::Variable(var) => var_type_def(state, var, err_type_def),
                    Target::Path(path) => path_type_def(state, path, err_type_def),
                    _ => unreachable!("nested infallible targets not supported"),
                }
            }
        }

        Self { target, value }
    }
}

impl Expression for Assignment {
    fn execute(&self, state: &mut state::Program, object: &mut dyn Object) -> Result<Value> {
        let value = self.value.execute(state, object);

        match &self.target {
            Target::Variable(variable) => {
                state
                    .variables_mut()
                    .insert(variable.ident().to_owned(), value.clone()?);

                value
            }
            Target::Path(path) => {
                object
                    .insert(path.as_ref(), value.clone()?)
                    .map_err(|e| E::Assignment(Error::PathInsertion(e)))?;

                value
            }

            Target::Infallible { ok, err } => {
                let (ok_value, err_value) = match value {
                    Ok(value) => (value, Value::Null),
                    Err(err) => (Value::Null, Value::from(err)),
                };

                match ok.as_ref() {
                    Target::Variable(variable) => {
                        state
                            .variables_mut()
                            .insert(variable.ident().to_owned(), ok_value.clone());
                    }
                    Target::Path(path) => object
                        .insert(path.as_ref(), ok_value.clone())
                        .map_err(|e| E::Assignment(Error::PathInsertion(e)))?,

                    _ => unreachable!("nested infallible targets not supported"),
                }

                match err.as_ref() {
                    Target::Variable(variable) => {
                        state
                            .variables_mut()
                            .insert(variable.ident().to_owned(), err_value.clone());
                    }
                    Target::Path(path) => object
                        .insert(path.as_ref(), err_value.clone())
                        .map_err(|e| E::Assignment(Error::PathInsertion(e)))?,

                    _ => unreachable!("nested infallible targets not supported"),
                };

                if err_value.is_null() {
                    Ok(ok_value)
                } else {
                    Ok(err_value)
                }
            }
        }
    }

    fn type_def(&self, state: &state::Compiler) -> TypeDef {
        let var_type_def = |var: &Variable| {
            state
                .variable_type(var.ident().to_owned())
                .cloned()
                .expect("variable must be assigned via Assignment::new")
        };

        let path_type_def = |path: &Path| {
            state
                .path_query_type(path)
                .cloned()
                .expect("path must be assigned via Assignment::new")
        };

        match &self.target {
            Target::Variable(var) => var_type_def(var),
            Target::Path(path) => path_type_def(path),
            Target::Infallible { ok, err } => {
                let ok_type_def = match ok.as_ref() {
                    Target::Variable(var) => var_type_def(var),
                    Target::Path(path) => path_type_def(path),
                    _ => unreachable!("nested infallible targets not supported"),
                };

                // Technically the parser rejects this invariant, because an
                // expression that is known to be infallible cannot be assigned
                // to an infallible target, since the error will always be
                // `null`.
                if !ok_type_def.is_fallible() {
                    return ok_type_def;
                }

                let err_type_def = match err.as_ref() {
                    Target::Variable(var) => var_type_def(var),
                    Target::Path(path) => path_type_def(path),
                    _ => unreachable!("nested infallible targets not supported"),
                };

                ok_type_def.merge(err_type_def).into_fallible(false)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{expression::Literal, lit, test_type_def, Operator};

    test_type_def![
        variable {
            expr: |state: &mut state::Compiler| {
                let target = Target::Variable(Variable::new("foo".to_owned(), None));
                let value = Box::new(Literal::from(true).into());

                Assignment::new(target, value, state)
            },
            def: TypeDef {
                kind: Kind::Boolean,
                ..Default::default()
            },
        }

        path {
            expr: |state: &mut state::Compiler| {
                let target = Target::Path(Path::from("foo"));
                let value = Box::new(Literal::from("foo").into());

                Assignment::new(target, value, state)
            },
            def: TypeDef {
                kind: Kind::Bytes,
                ..Default::default()
            },
        }

        infallible_ok {
            expr: |state: &mut state::Compiler| {
                let ok = Box::new(Target::Variable(Variable::new("ok".to_owned(), None)));
                let err = Box::new(Target::Variable(Variable::new("err".to_owned(), None)));

                let target = Target::Infallible { ok, err };
                let value = Box::new(lit!(true).into());

                Assignment::new(target, value, state)
            },
            def: TypeDef {
                fallible: false,
                kind: Kind::Boolean,
                ..Default::default()
            },
        }
    ];
}
