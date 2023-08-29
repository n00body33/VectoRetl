use cargo_toml::Manifest;
use std::fs::File;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::{env, fs, io};

fn get_vector_toml_path() -> PathBuf {
    let path = fs::canonicalize(env::var("CARGO_MANIFEST_DIR").unwrap()).unwrap();

    // Remove the "lib/vector-vrl/web-playground" suffix
    let parent_path = path
        .parent()
        .and_then(|p| p.parent())
        .and_then(|p| p.parent());
    parent_path
        .expect("Failed to find vector repo root")
        .join("Cargo.toml")
        .to_path_buf()
}

fn write_build_constants(manifest: &Manifest, dest_path: &Path) -> io::Result<()> {
    let mut output_file = File::create(dest_path)?;
    output_file.write_all(
        "// AUTOGENERATED CONSTANTS. SEE BUILD.RS AT REPOSITORY ROOT. DO NOT MODIFY.\n".as_ref(),
    )?;

    let create_const_statement =
        |name, value| format!("pub const {}: &str = \"{}\";\n", name, value);
    // TODO: For releases, we should use the manifest.package().version().
    let vector_version_const = create_const_statement("VECTOR_VERSION", "master");
    output_file
        .write_all(vector_version_const.as_bytes())
        .expect("Failed to write Vector version constant");

    let vrl_version = &manifest
        .dependencies
        .get("vrl")
        .unwrap()
        .detail()
        .unwrap()
        .version
        .clone()
        .unwrap();
    let vrl_version_const = create_const_statement("VRL_VERSION", vrl_version);
    output_file
        .write_all(vrl_version_const.as_bytes())
        .expect("Failed to write Vector version constant");
    Ok(())
}

fn main() {
    let manifest =
        Manifest::from_path(get_vector_toml_path()).expect("Failed to load Vector Cargo.toml");
    let dst = Path::new(&env::var("OUT_DIR").unwrap()).join("built.rs");
    write_build_constants(&manifest, &dst).expect("Failed to write constants");
}
