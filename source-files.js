var sourcesIndex = JSON.parse('{\
"adler":["",[],["algo.rs","lib.rs"]],\
"bad64":["",[],["arrspec.rs","condition.rs","lib.rs","op.rs","operand.rs","reg.rs","shift.rs","sysreg.rs"]],\
"bad64_sys":["",[],["lib.rs"]],\
"binde":["",[],["lib.rs"]],\
"binde_derive":["",[],["lib.rs"]],\
"binread":["",[["io",[],["error.rs","mod.rs","prelude.rs"]]],["attribute.rs","binread_impls.rs","endian.rs","error.rs","file_ptr.rs","helpers.rs","lib.rs","options.rs","pos_value.rs","private.rs","punctuated.rs","strings.rs"]],\
"binread_derive":["",[["codegen",[["read_options",[],["debug_template.rs","enum.rs","struct.rs"]]],["mod.rs","read_options.rs","sanitization.rs"]],["parser",[["types",[],["assert.rs","cond_endian.rs","condition.rs","enum_error_mode.rs","imports.rs","magic.rs","map.rs","mod.rs","passed_args.rs","read_mode.rs","spanned_value.rs"]]],["attrs.rs","field_level_attrs.rs","keywords.rs","macros.rs","meta_types.rs","mod.rs","top_level_attrs.rs"]]],["lib.rs"]],\
"brocolib":["",[["runtime_metadata",[],["elf.rs","source.rs"]]],["global_metadata.rs","lib.rs","runtime_metadata.rs"]],\
"byteorder":["",[],["io.rs","lib.rs"]],\
"cfg_if":["",[],["lib.rs"]],\
"crc32fast":["",[["specialized",[],["mod.rs","pclmulqdq.rs"]]],["baseline.rs","combine.rs","lib.rs","table.rs"]],\
"cstr_core":["",[],["lib.rs"]],\
"cty":["",[],["lib.rs"]],\
"either":["",[],["lib.rs"]],\
"flate2":["",[["deflate",[],["bufread.rs","mod.rs","read.rs","write.rs"]],["ffi",[],["mod.rs","rust.rs"]],["gz",[],["bufread.rs","mod.rs","read.rs","write.rs"]],["zlib",[],["bufread.rs","mod.rs","read.rs","write.rs"]]],["bufreader.rs","crc.rs","lib.rs","mem.rs","zio.rs"]],\
"memchr":["",[["arch",[["all",[["packedpair",[],["default_rank.rs","mod.rs"]]],["memchr.rs","mod.rs","rabinkarp.rs","shiftor.rs","twoway.rs"]],["generic",[],["memchr.rs","mod.rs","packedpair.rs"]],["x86_64",[["avx2",[],["memchr.rs","mod.rs","packedpair.rs"]],["sse2",[],["memchr.rs","mod.rs","packedpair.rs"]]],["memchr.rs","mod.rs"]]],["mod.rs"]],["memmem",[],["mod.rs","searcher.rs"]]],["cow.rs","ext.rs","lib.rs","macros.rs","memchr.rs","vector.rs"]],\
"miniz_oxide":["",[["deflate",[],["buffer.rs","core.rs","mod.rs","stream.rs"]],["inflate",[],["core.rs","mod.rs","output_buffer.rs","stream.rs"]]],["lib.rs","shared.rs"]],\
"num_derive":["",[],["lib.rs","test.rs"]],\
"num_traits":["",[["ops",[],["bytes.rs","checked.rs","euclid.rs","inv.rs","mod.rs","mul_add.rs","overflowing.rs","saturating.rs","wrapping.rs"]]],["bounds.rs","cast.rs","float.rs","identities.rs","int.rs","lib.rs","macros.rs","pow.rs","real.rs","sign.rs"]],\
"object":["",[["read",[["coff",[],["comdat.rs","file.rs","mod.rs","relocation.rs","section.rs","symbol.rs"]],["elf",[],["comdat.rs","compression.rs","dynamic.rs","file.rs","hash.rs","mod.rs","note.rs","relocation.rs","section.rs","segment.rs","symbol.rs","version.rs"]],["macho",[],["dyld_cache.rs","fat.rs","file.rs","load_command.rs","mod.rs","relocation.rs","section.rs","segment.rs","symbol.rs"]],["pe",[],["data_directory.rs","export.rs","file.rs","import.rs","mod.rs","relocation.rs","resource.rs","rich.rs","section.rs"]]],["any.rs","archive.rs","mod.rs","read_cache.rs","read_ref.rs","traits.rs","util.rs"]]],["archive.rs","common.rs","elf.rs","endian.rs","lib.rs","macho.rs","pe.rs","pod.rs"]],\
"proc_macro2":["",[],["detection.rs","extra.rs","fallback.rs","lib.rs","marker.rs","parse.rs","rcvec.rs","wrapper.rs"]],\
"quote":["",[],["ext.rs","format.rs","ident_fragment.rs","lib.rs","runtime.rs","spanned.rs","to_tokens.rs"]],\
"rustversion":["",[],["attr.rs","bound.rs","constfn.rs","date.rs","error.rs","expand.rs","expr.rs","iter.rs","lib.rs","release.rs","time.rs","token.rs","version.rs"]],\
"static_assertions":["",[],["assert_cfg.rs","assert_eq_align.rs","assert_eq_size.rs","assert_fields.rs","assert_impl.rs","assert_obj_safe.rs","assert_trait.rs","assert_type.rs","const_assert.rs","lib.rs"]],\
"thiserror":["",[],["aserror.rs","display.rs","lib.rs"]],\
"thiserror_impl":["",[],["ast.rs","attr.rs","expand.rs","fmt.rs","generics.rs","lib.rs","prop.rs","valid.rs"]],\
"unicode_ident":["",[],["lib.rs","tables.rs"]]\
}');
createSourceSidebar();