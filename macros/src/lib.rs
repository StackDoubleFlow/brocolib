//! Procedural macros for brocolib. Internal-only - not meant to be used
//! outside the main crate.

use quote::quote;
use syn::{Data, DeriveInput, Fields, parse_macro_input};

/// Derives `VarRead` (and its companion `VarSize`) for a struct by
/// reading/summing every field in declaration order.
///
/// Every field's type must already implement both traits: anything
/// implementing `BinaryDeserialize` gets them for free via a blanket impl,
/// and the handful of variable-width index types implement them by hand.
/// Since this only reads whichever fields are actually present on the
/// struct at expansion time, version-gated fields (e.g. `#[cfg(...)]` on a
/// single field) are handled automatically - `cfg` stripping runs before
/// derive macros see the item.
///
/// This is an internal derive: it assumes `VarRead`, `VarSize`, and
/// `IndexSizes` are already in scope (by unqualified name) wherever it's
/// invoked, rather than fully-qualifying them, since it's only ever used
/// from within brocolib's own `global_metadata` module.
#[proc_macro_derive(VarRead)]
pub fn derive_var_read(input: proc_macro::TokenStream) -> proc_macro::TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    let name = &input.ident;

    let fields = match &input.data {
        Data::Struct(data) => match &data.fields {
            Fields::Named(fields) => &fields.named,
            _ => {
                return syn::Error::new_spanned(
                    &input,
                    "VarRead can only be derived for structs with named fields",
                )
                .to_compile_error()
                .into();
            }
        },
        _ => {
            return syn::Error::new_spanned(&input, "VarRead can only be derived for structs")
                .to_compile_error()
                .into();
        }
    };

    let field_names = fields.iter().map(|f| f.ident.as_ref().unwrap());
    let field_types = fields.iter().map(|f| &f.ty);

    let expanded = quote! {
        impl VarRead for #name {
            fn var_read(cursor: &mut ::std::io::Cursor<&[u8]>, sizes: &IndexSizes) -> ::std::io::Result<Self> {
                Ok(Self {
                    #(#field_names: VarRead::var_read(cursor, sizes)?,)*
                })
            }
        }

        impl VarSize for #name {
            fn var_size(sizes: &IndexSizes) -> usize {
                0usize #(+ <#field_types as VarSize>::var_size(sizes))*
            }
        }
    };

    expanded.into()
}
