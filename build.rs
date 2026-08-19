fn main() {
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("macos") {
        println!("cargo:rustc-link-arg-cdylib=-install_name");
        println!("cargo:rustc-link-arg-cdylib=@rpath/libreatrust.dylib");
    }
}
