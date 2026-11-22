fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    if std::env::var("CARGO_CFG_TARGET_ENV").as_deref() == Ok("msvc")
        && std::env::var("PROFILE").as_deref() == Ok("debug")
    { println!("cargo:rustc-link-arg=/NODEFAULTLIB:MSVCRTD"); }
}
