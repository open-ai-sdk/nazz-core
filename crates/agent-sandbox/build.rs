fn main() {
    println!("cargo:rerun-if-env-changed=CC");
    println!("cargo:rerun-if-changed=src/linux_launcher.c");
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("linux") {
        return;
    }
    let output =
        std::path::PathBuf::from(std::env::var_os("OUT_DIR").unwrap()).join("sandbox-launcher");
    let target = std::env::var("TARGET").unwrap();
    let host = std::env::var("HOST").unwrap();
    let compiler = std::env::var_os("CC").unwrap_or_else(|| {
        assert_eq!(
            target, host,
            "cross-building Linux sandbox requires an explicit target CC"
        );
        "cc".into()
    });
    let status = std::process::Command::new(compiler)
        .args(["-O2", "-Wall", "-Wextra", "-Werror", "-o"])
        .arg(output)
        .arg("src/linux_launcher.c")
        .status()
        .expect("Linux sandbox requires a target C compiler");
    assert!(
        status.success(),
        "Linux sandbox launcher compilation failed"
    );
}
