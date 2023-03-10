fn main() {
    let profile = std::env::var("PROFILE").unwrap();
    let target = std::env::var("TARGET").unwrap();
    let file = format!("../../target/{}/trojan.exe", profile);
    println!("cargo:rerun-if-changed={}", file);
    let new_file = format!("libs/trojan-{}.exe", target);
    std::fs::copy(file, new_file).unwrap();
    tauri_build::build()
}
