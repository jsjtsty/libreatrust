fn main() {
    println!("cargo:rustc-link-arg-cdylib=-install_name");
    println!("cargo:rustc-link-arg-cdylib=@rpath/libreatrust.dylib");
}
