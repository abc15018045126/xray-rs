fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    if std::env::var("CARGO_CFG_TARGET_ENV").as_deref() == Ok("msvc")
        && std::env::var("PROFILE").as_deref() == Ok("debug")
    {
        // C dependencies (e.g. ring / libz-ng-sys) request MSVCRTD in dev builds while
        // Rust std links MSVCRT, triggering MSVC linker warning LNK4098.
        println!("cargo:rustc-link-arg=/NODEFAULTLIB:MSVCRTD");
    }
}
