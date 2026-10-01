use proc_macro::TokenStream;
use quote::quote;
use syn::{Data, DeriveInput, Error, Ident, parse_macro_input};

#[proc_macro_derive(MetadataDeserialize)]
pub fn derive_metadata_deserialize(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);

    match create_metadata_deserialize_impl(input) {
        Ok(ts) => ts,
        Err(err) => err.to_compile_error().into(),
    }
}

fn create_metadata_deserialize_impl(input: DeriveInput) -> Result<TokenStream, Error> {
    let fields = match input.data {
        Data::Struct(ds) => ds.fields,
        _ => {
            return Err(Error::new_spanned(
                input,
                "only structs may be derived from MetadataDeserialize",
            ));
        }
    };
    let field_names: Vec<&Ident> = fields.iter().map(|f| f.ident.as_ref().unwrap()).collect();
    let struct_name = input.ident;

    let tokens = quote! {
        impl crate::global_metadata::deserialize::MetadataDeserialize for #struct_name {
            fn deserialize<E, R>(mut reader: R, index_sizes: &crate::global_metadata::SerializedIndexSizes) -> ::std::io::Result<Self>
            where
                E: crate::global_metadata::deserialize::ByteOrder,
                R: ::std::io::Read,
            {
                Ok(Self {
                    #(
                        #field_names: crate::global_metadata::deserialize::deserialize::<E, _, _>(&mut reader, index_sizes)?
                    ),*
                })
            }
        }
    };
    Ok(tokens.into())
}
