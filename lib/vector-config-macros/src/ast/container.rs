use std::collections::HashSet;

use darling::{error::Accumulator, util::Flag, FromAttributes};
use serde_derive_internals::{ast as serde_ast, Ctxt, Derive};
use syn::{
    DeriveInput, ExprPath, GenericArgument, Generics, Ident, PathArguments, PathSegment, Type,
    TypeParam,
};

use super::{
    util::{
        err_serde_failed, get_serde_default_value, try_extract_doc_title_description,
        DarlingResultIterator,
    },
    Data, Field, LazyCustomAttribute, Metadata, Style, Tagging, Variant,
};

const ERR_NO_ENUM_TUPLES: &str = "enum variants cannot be tuples (multiple unnamed fields)";
const ERR_NO_ENUM_VARIANT_DESCRIPTION: &str = "enum variants must have a description i.e. `/// This is a description` or `#[configurable(description = \"This is a description...\")]`";
const ERR_ENUM_UNTAGGED_DUPLICATES: &str = "enum variants must be unique in style/shape when in untagged mode i.e. there cannot be multiple unit variants, or tuple variants with the same fields, etc";
const ERR_NO_UNIT_STRUCTS: &str = "unit structs are not supported by `Configurable`";
const ERR_MISSING_DESC: &str = "all structs/enums must have a description i.e. `/// This is a description` or `#[configurable(description = \"This is a description...\")]`";
const ERR_ASYMMETRIC_SERDE_TYPE_CONVERSION: &str = "any container using `from`/`try_from`/`into` via `#[serde(...)]` must do so symmetrically i.e. the from/into types must match";
const ERR_SERDE_TYPE_CONVERSION_FROM_TRY_FROM: &str = "`#[serde(from)]` and `#[serde(try_from)]` cannot be identical, as it is impossible for an infallible conversion from T to also be fallible";

/// A source data structure annotated with `#[derive(Configurable)]`, parsed into an internal
/// representation.
pub struct Container<'a> {
    original: &'a DeriveInput,
    name: String,
    default_value: Option<ExprPath>,
    data: Data<'a>,
    tagging: Option<Tagging>,
    virtual_newtype: Option<Type>,
    attrs: Attributes,
}

impl<'a> Container<'a> {
    /// Creates a new `Container<'a>` from the raw derive macro input.
    pub fn from_derive_input(input: &'a DeriveInput) -> darling::Result<Container<'a>> {
        // We can't do anything unless `serde` can also handle this container. We specifically only care about
        // deserialization here, because the schema tells us what we can _give_ to Vector.
        let context = Ctxt::new();
        let serde = match serde_ast::Container::from_ast(&context, input, Derive::Deserialize) {
            Some(serde) => {
                // This `serde_derive_internals` helper will panic if `check` isn't _always_ called, so we also have to
                // call it on the success path.
                context
                    .check()
                    .expect("should not have errors if container was parsed successfully");
                Ok(serde)
            }
            None => Err(err_serde_failed(context)),
        }?;

        let mut accumulator = Accumulator::default();

        // Check if we're dealing with a "virtual" newtype.
        //
        // In some cases, types may (de)serialize themselves as another type, which is entirely normal... but
        // they may do this with `serde` helper attributes rather than with a newtype wrapper or manually
        // converting between types.
        //
        // For types doing this, it could be entirely irrelevant to document all of the internal fields, or at
        // least enforce documenting them, because they don't truly represent the actual schema and all that
        // might get used is the documentation on the type having `Configurable` derived.
        //
        // All of that said, we check to see if the `from`, `try_from`, or `into` helper attributes are being
        // used from `serde`, and make sure the transformation is symmetric (it has to
        // deserialize from T and serialize to T, no halfsies) since we can't express a schema that's
        // half-and-half. Assuming it passes this requirement, we track the actual (de)serialized type and use
        // that for our schema generation instead.
        let virtual_newtype = if serde.attrs.type_from().is_some()
            || serde.attrs.type_try_from().is_some()
            || serde.attrs.type_into().is_some()
        {
            // if any of these are set, we start by checking `into`. If it's set, then that's fine, and we
            // continue verifying. Otherwise, it implies that `from`/`try_from` are set, and we only allow
            // symmetric conversions.
            if let Some(into_ty) = serde.attrs.type_into() {
                // Figure out which of `from` and `try_from` are set. Both cannot be set, because either the
                // types are different -- which means asymmetric conversion -- or they're both the same, which
                // would be a logical fallacy since you can't have a fallible conversion from T if you already
                // have an infallible conversion from T.
                //
                // Similar, at least one of them must be set, otherwise that's an asymmetric conversion.
                match (serde.attrs.type_from(), serde.attrs.type_try_from()) {
                    (None, None) => {
                        accumulator.push(
                            darling::Error::custom(ERR_ASYMMETRIC_SERDE_TYPE_CONVERSION)
                                .with_span(&serde.ident),
                        );
                        None
                    }
                    (Some(_), Some(_)) => {
                        accumulator.push(
                            darling::Error::custom(ERR_SERDE_TYPE_CONVERSION_FROM_TRY_FROM)
                                .with_span(&serde.ident),
                        );
                        None
                    }
                    (Some(from_ty), None) | (None, Some(from_ty)) => {
                        if into_ty == from_ty {
                            Some(into_ty.clone())
                        } else {
                            accumulator.push(
                                darling::Error::custom(ERR_ASYMMETRIC_SERDE_TYPE_CONVERSION)
                                    .with_span(&serde.ident),
                            );
                            None
                        }
                    }
                }
            } else {
                accumulator.push(
                    darling::Error::custom(ERR_ASYMMETRIC_SERDE_TYPE_CONVERSION)
                        .with_span(&serde.ident),
                );
                None
            }
        } else {
            None
        };

        // Once we have the `serde` side of things, we need to collect our own specific attributes for the container
        // and map things to our own `Container`.
        Attributes::from_attributes(&input.attrs)
            .and_then(|attrs| attrs.finalize(&input.attrs))
            // We successfully parsed the derive input through both `serde` itself and our own attribute parsing, so
            // build our data container based on whether or not we have a struct, enum, and do any neccessary
            // validation, etc.
            .and_then(|attrs| {
                let tagging: Tagging = serde.attrs.tag().into();

                let (data, is_enum) = match serde.data {
                    serde_ast::Data::Enum(variants) => {
                        let variants = variants
                            .iter()
                            // When an item is marked as being skipped -- `#[serde(skip)]` -- we
                            // want to filter out variants that are skipped entirely, because
                            // otherwise they have to meet all the criteria (doc comment, etc)
                            // despite the fact they won't be part of the configuration schema
                            // anyways, and we can't filter it out after the below step because all
                            // we get is the errors until they can be validated completely.
                            .filter(|variant| {
                                !variant.attrs.skip_deserializing()
                                    && !variant.attrs.skip_serializing()
                            })
                            .map(|variant| {
                                Variant::from_ast(
                                    variant,
                                    tagging.clone(),
                                    virtual_newtype.is_some(),
                                )
                            })
                            .collect_darling_results(&mut accumulator);

                        // Check the generated variants for conformance. We do this at a per-variant and per-enum level.
                        // Not all enum variant styles are compatible with the various tagging types that `serde`
                        // supports, and additionally, we have some of our own constraints that we want to enforce.
                        for variant in &variants {
                            // We don't support tuple variants.
                            if variant.style() == Style::Tuple {
                                accumulator.push(
                                    darling::Error::custom(ERR_NO_ENUM_TUPLES).with_span(variant),
                                );
                            }

                            // All variants must have a description, except for untagged enums.
                            //
                            // This allows untagged enums used for "(de)serialize as A, B, or C"
                            // purposes to avoid needless titles/descriptions when their fields will
                            // implicitly provide that.
                            if variant.description().is_none() && tagging != Tagging::None {
                                accumulator.push(
                                    darling::Error::custom(ERR_NO_ENUM_VARIANT_DESCRIPTION)
                                        .with_span(variant),
                                );
                            }
                        }

                        // If we're in untagged mode, there can be no duplicate variants.
                        if tagging == Tagging::None {
                            for (i, variant) in variants.iter().enumerate() {
                                for (k, other_variant) in variants.iter().enumerate() {
                                    if variant == other_variant && i != k {
                                        accumulator.push(
                                            darling::Error::custom(ERR_ENUM_UNTAGGED_DUPLICATES)
                                                .with_span(variant),
                                        );
                                    }
                                }
                            }
                        }

                        (Data::Enum(variants), true)
                    }
                    serde_ast::Data::Struct(style, fields) => match style {
                        serde_ast::Style::Struct
                        | serde_ast::Style::Tuple
                        | serde_ast::Style::Newtype => {
                            let fields = fields
                                .iter()
                                .map(|field| Field::from_ast(field, virtual_newtype.is_some()))
                                .collect_darling_results(&mut accumulator);

                            (Data::Struct(style.into(), fields), false)
                        }
                        serde_ast::Style::Unit => {
                            // This is a little ugly but we can't drop the accumulator without finishing it, otherwise
                            // it will panic to let us know we didn't assert whether there were errors or not... so add
                            // our error and just return a dummy value.
                            accumulator
                                .push(darling::Error::custom(ERR_NO_UNIT_STRUCTS).with_span(input));
                            (Data::Struct(Style::Unit, Vec::new()), false)
                        }
                    },
                };

                // All containers must have a description: no ifs, ands, or buts.
                //
                // The compile-time errors are a bit too inscrutable otherwise, and inscrutable errors are not very
                // helpful when using procedural macros.
                if attrs.description.is_none() {
                    accumulator
                        .push(darling::Error::custom(ERR_MISSING_DESC).with_span(&serde.ident));
                }

                let original = input;
                let name = serde.attrs.name().deserialize_name();
                let default_value = get_serde_default_value(serde.attrs.default());

                let container = Container {
                    original,
                    name,
                    default_value,
                    data,
                    virtual_newtype,
                    tagging: is_enum.then_some(tagging),
                    attrs,
                };

                accumulator.finish_with(container)
            })
    }

    /// Ident of the container.
    ///
    /// This is simply the name or type of a struct/enum, but is not parsed directly as a type via
    /// `syn`, only an `Ident`.
    pub fn ident(&self) -> &Ident {
        &self.original.ident
    }

    /// Generics for the container, if any.
    pub fn generics(&self) -> &Generics {
        &self.original.generics
    }

    /// Data for the container.
    ///
    /// This would be the fields of a struct, or the variants for an enum.
    pub fn data(&self) -> &Data {
        &self.data
    }

    /// Name of the container when deserializing.
    ///
    /// This may be different than the name of the container itself depending on whether it has been
    /// altered with `serde` helper attributes i.e. `#[serde(rename = "...")]`.
    pub fn name(&self) -> &str {
        self.name.as_str()
    }

    /// Title of the container, if any.
    ///
    /// The title specifically refers to the headline portion of a doc comment. For example, if a
    /// struct has the following doc comment:
    ///
    /// ```text
    /// /// My special struct.
    /// ///
    /// /// Here's why it's special:
    /// /// ...
    /// struct Wrapper(u64);
    /// ```
    ///
    /// then the title would be `My special struct`. If the doc comment only contained `My special
    /// struct.`, then we would consider the title _empty_. See `description` for more details on
    /// detecting titles vs descriptions.
    pub fn title(&self) -> Option<&String> {
        self.attrs.title.as_ref()
    }

    /// Description of the struct, if any.
    ///
    /// The description specifically refers to the body portion of a doc comment, or the headline if
    /// only a headline exists.. For example, if a struct has the following doc comment:
    ///
    /// ```text
    /// /// My special struct.
    /// ///
    /// /// Here's why it's special:
    /// /// ...
    /// struct Wrapper(u64);
    /// ```
    ///
    /// then the title would be everything that comes after `My special struct`. If the doc comment
    /// only contained `My special struct.`, then the description would be `My special struct.`, and
    /// the title would be empty. In this way, the description will always be some port of a doc
    /// comment, depending on the formatting applied.
    ///
    /// This logic was chosen to mimic how Rust's own `rustdoc` tool works, where it will use the
    /// "title" portion as a high-level description for an item, only showing the title and
    /// description together when drilling down to the documentation for that specific item. JSON
    /// Schema supports both title and description for a schema, and so we expose both.
    pub fn description(&self) -> Option<&String> {
        self.attrs.description.as_ref()
    }

    /// Virtual type of this container, if any.
    ///
    /// In some cases, a type may be representable by an entirely different type, and then converted
    /// to the desired type using the common `TryFrom`/`From`/`Into` conversion traits. This is a
    /// common pattern with `serde` to re-use existing conversion logic (such as taking a raw string
    /// and parsing it to see if it's a valid regular expression, and so on) but represents a
    /// divergence between the type we're generating a schema for and the actual type that will be
    /// getting (de)serialized.
    ///
    /// When we detect a container with the right `serde` helper attributes (see the code in
    /// `from_derive_input` for details), we switch to treating this container as, for the purpose
    /// of schema generation, having the type specified by those helper attributes.
    pub fn virtual_newtype(&self) -> Option<Type> {
        self.virtual_newtype.clone()
    }

    /// Tagging mode of this container.
    ///
    /// When the container is an enum, `Some(..)` will be returned, where the value can be any of
    /// the four modes supported by `serde`: external, internal, adjacent, or none (untagged).
    ///
    /// When the container is a struct, `None` is returned.
    pub fn tagging(&self) -> Option<&Tagging> {
        self.tagging.as_ref()
    }

    /// Path to a function to call to generate a default value for the container, if any.
    ///
    /// This will boil down to something like `std::default::Default::default` or
    /// `name_of_in_scope_method_to_call`, where we generate code to actually call that path as a
    /// function to generate the default value we include in the schema for this container.
    pub fn default_value(&self) -> Option<ExprPath> {
        self.default_value.clone()
    }

    /// Whether or not the container is deprecated.
    ///
    /// Applying the `#[configurable(deprecated)]` helper attribute will mark this container as
    /// deprecated from the perspective of the resulting schema. It does not interact with Rust's
    /// standard `#[deprecated]` attribute, neither automatically applying it nor deriving the
    /// deprecation status of a field when it is present.
    pub fn deprecated(&self) -> bool {
        self.attrs.deprecated.is_some()
    }

    /// Metadata (custom attributes) for the container, if any.
    ///
    /// Attributes can take the shape of flags (`#[configurable(metadata(im_a_teapot))]`) or
    /// key/value pairs (`#[configurable(metadata(status = "beta"))]`) to allow rich, semantic
    /// metadata to be attached directly to containers.
    pub fn metadata(&self) -> impl Iterator<Item = LazyCustomAttribute> {
        self.attrs
            .metadata
            .clone()
            .into_iter()
            .flat_map(|metadata| metadata.attributes())
    }

    /// Gets the generic types that are used within fields or variants that are part of the schema.
    ///
    /// In order to ensure we can allow for a maximally flexible `Configurable` trait, we add bounds to generic types that are
    /// present on derived containers so that bounds don't need to be added on the actual container itself, essentially
    /// avoiding declarations like `pub struct Foo<T> where T: Configurable {...}`.
    ///
    /// We contain this logic here as we only care about generic type parameters that are present on fields that will be
    /// included in the schema, so skipped fields shouldn't have bounds added, and so on.
    pub fn generic_field_types(&self) -> Vec<TypeParam> {
        let mut generic_types = Vec::new();

        let field_types = match &self.data {
            Data::Struct(_, fields) => fields
                .iter()
                .filter(|f| f.visible())
                .filter_map(|f| get_generic_type_param_idents(f.ty()))
                .flatten()
                .collect::<HashSet<_>>(),
            Data::Enum(variants) => variants
                .iter()
                .filter(|v| v.visible())
                .flat_map(|v| v.fields().iter())
                .filter_map(|f| get_generic_type_param_idents(f.ty()))
                .flatten()
                .collect::<HashSet<_>>(),
        };

        for type_param in self.original.generics.type_params() {
            if field_types.contains(&type_param.ident) {
                generic_types.push(type_param.clone());
            }
        }

        generic_types
    }
}

#[derive(Debug, Default, FromAttributes)]
#[darling(default, attributes(configurable))]
struct Attributes {
    #[darling(default)]
    title: Option<String>,
    #[darling(default)]
    description: Option<String>,
    #[darling(default)]
    deprecated: Flag,
    #[darling(multiple)]
    metadata: Vec<Metadata>,
}

impl Attributes {
    fn finalize(mut self, forwarded_attrs: &[syn::Attribute]) -> darling::Result<Self> {
        // We additionally attempt to extract a title/description from the forwarded doc attributes, if they exist.
        // Whether we extract both a title and description, or just description, is documented in more detail in
        // `try_extract_doc_title_description` itself.
        let (doc_title, doc_description) = try_extract_doc_title_description(forwarded_attrs);
        self.title = self.title.or(doc_title);
        self.description = self.description.or(doc_description);

        Ok(self)
    }
}

/// Gets the idents for a type that potentially represent generic type parameters.
///
/// We use this function to take the `Type` of a field, and figure out if it has any generic type
/// parameters, such as the `T` in `Vec<T>`. As the type itself might be the generic parameter (just
/// a plain `T`) we potentially return the ident of the type itself unless we can determine that the
/// type path has generic type arguments.
fn get_generic_type_param_idents(ty: &Type) -> Option<Vec<Ident>> {
    match ty {
        Type::Path(tp) => match tp.path.segments.len() {
            0 => unreachable!(
                "A type path with no path segments should not be possible to construct normally."
            ),
            // A single path segment would be something like `String` or `Vec<T>`, so we
            // do need to check for both scenarios.
            1 => match tp.path.segments.first() {
                None => unreachable!("Can only reach match arm if segment length was 1."),
                Some(segment) => get_generic_args_from_path_segment(segment, true),
            },
            _ => {
                let idents = tp
                    .path
                    .segments
                    .iter()
                    .filter_map(|segment| get_generic_args_from_path_segment(segment, false))
                    .flatten()
                    .collect::<Vec<_>>();

                if idents.is_empty() {
                    None
                } else {
                    Some(idents)
                }
            }
        },
        _ => None,
    }
}

fn get_generic_args_from_path_segment(
    segment: &PathSegment,
    return_self: bool,
) -> Option<Vec<Ident>> {
    match &segment.arguments {
        // If the segment has no brackets/parens, return its ident as-is if we should return self.
        // When we're trying to parse a higher-level type path that has multiple segments, we
        // wouldn't want to return the segment's ident, because if we were parsing
        // `std::vec::Vec<T>`, that would lead to us returning `std`, `vec`, and `T`... the first
        // two of which would make no sense, obviously.
        PathArguments::None => {
            if return_self {
                Some(vec![segment.ident.clone()])
            } else {
                None
            }
        }
        PathArguments::AngleBracketed(angle_args) => {
            let args = angle_args
                .args
                .iter()
                .filter_map(|generic| match generic {
                    // We only care about generic type arguments.
                    GenericArgument::Type(gty) => get_generic_type_path_ident(gty),
                    _ => None,
                })
                .collect::<Vec<_>>();

            if args.is_empty() {
                None
            } else {
                Some(args)
            }
        }
        // We don't support parenthesized generic arguments as they only come up in the case of
        // function pointers, and we don't support those with `Configurable`.
        PathArguments::Parenthesized(_) => None,
    }
}

/// Gets the ident of a `Type` when it is a "path" type.
///
/// Path types look like `String` or `std::vec::Vec<T>`, and represent a type you could accept as a
/// generic type argument.
fn get_generic_type_path_ident(ty: &Type) -> Option<Ident> {
    match ty {
        Type::Path(tp) => tp.path.get_ident().cloned(),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use proc_macro2::Ident;
    use quote::format_ident;
    use syn::{parse_quote, Type};

    use super::get_generic_type_param_idents;

    fn literals_to_idents(idents: &[&str]) -> Vec<Ident> {
        idents.iter().map(|raw| format_ident!("{}", raw)).collect()
    }

    #[test]
    fn test_get_generic_type_param_idents() {
        // A "direct" type reference, like a type that's already in scope, is a single ident so we
        // do want to capture that.
        let direct_concrete_type: Type = parse_quote! { String };
        let idents = get_generic_type_param_idents(&direct_concrete_type)
            .expect("idents should have been found");
        assert_eq!(literals_to_idents(&["String"]), idents);

        // Segmented type paths like this can't get represented as idents, which is also why they
        // can't possibly represent a generic type parameter, as a generic type parameter is always
        // a single ident, i.e. `T`.
        let qualified_concrete_type: Type = parse_quote! { std::string::String };
        let idents = get_generic_type_param_idents(&qualified_concrete_type);
        assert_eq!(None, idents);

        // This one is pretty obvious.
        let direct_generic_type: Type = parse_quote! { T };
        let idents = get_generic_type_param_idents(&direct_generic_type)
            .expect("idents should have been found");
        assert_eq!(literals_to_idents(&["T"]), idents);

        // We should always extract the generic type parameter, even for a "direct" type reference.
        let contained_generic_type: Type = parse_quote! { Vec<T> };
        let idents = get_generic_type_param_idents(&contained_generic_type)
            .expect("idents should have been found");
        assert_eq!(literals_to_idents(&["T"]), idents);

        // Similarly, we should always extract the generic type parameter for segmented type paths,
        // since we traverse all segments.
        let qualified_contained_generic_type: Type = parse_quote! { std::vec::Vec<T> };
        let idents = get_generic_type_param_idents(&qualified_contained_generic_type)
            .expect("idents should have been found");
        assert_eq!(literals_to_idents(&["T"]), idents);

        // We don't support parenthesized type parameters, like when using a function pointer type.
        let parenthesized_type: Type = parse_quote! { Something<Fn(bool) -> String> };
        let idents = get_generic_type_param_idents(&parenthesized_type);
        assert_eq!(None, idents);
    }
}
