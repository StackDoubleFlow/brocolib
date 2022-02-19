use proc_macro::TokenStream;
use quote::quote;
use syn::{parse_macro_input, Data, DeriveInput, Error, Ident, Type};

#[proc_macro_derive(BinaryDeserialize)]
pub fn derive_binary_deserialize(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);

    match create_binary_deserialize_impl(input) {
        Ok(ts) => ts,
        Err(err) => err.to_compile_error().into(),
    }
}

fn create_binary_deserialize_impl(input: DeriveInput) -> Result<TokenStream, Error> {
    let fields = match input.data {
        Data::Struct(ds) => ds.fields,
        _ => {
            return Err(Error::new_spanned(
                input,
                "only structs can may be derived by BinaryDeserialize",
            ))
        }
    };
    let field_types: Vec<&Type> = fields.iter().map(|f| &f.ty).collect();
    let field_names: Vec<&Ident> = fields.iter().map(|f| f.ident.as_ref().unwrap()).collect();
    let struct_name = input.ident;

    let tokens = quote! {
        impl crate::binary_deserialize::BinaryDeserialize for #struct_name {
            fn read<R>(mut reader: R) -> ::anyhow::Result<Self>
            where
                R: ::std::io::Read,
            {
                Ok(#struct_name {
                    #(
                        #field_names: <#field_types as crate::binary_deserialize::BinaryDeserialize>::read(&mut reader)?
                    ),*
                })
            }
        }
    };
    Ok(tokens.into())
}
