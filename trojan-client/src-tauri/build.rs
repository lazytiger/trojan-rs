fn main() {
    let profile = std::env::var("PROFILE").unwrap();
    let target = std::env::var("TARGET").unwrap();
    let exe = if target.contains("windows") {
        ".exe"
    } else {
        ""
    };
    let file = format!("../../target/{}/trojan{}", profile, exe);
    println!("cargo:rerun-if-changed={}", file);
    let new_file = format!("libs/trojan-{}{}", target, exe);
    std::fs::create_dir_all("libs").unwrap();
    std::fs::copy(file, new_file).unwrap();

    if target.contains("windows") {
        let wintun_arch = if target.contains("x86_64") {
            "amd64"
        } else if target.contains("i686") {
            "x86"
        } else if target.contains("aarch64") {
            "arm64"
        } else if target.contains("arm") {
            "arm"
        } else {
            panic!("unsupported target for wintun.dll: {}", target);
        };
        let wintun_file = format!("../../wintun/bin/{}/wintun.dll", wintun_arch);
        println!("cargo:rerun-if-changed={}", wintun_file);
        std::fs::copy(wintun_file, "libs/wintun.dll").unwrap();
    }

    let mut windows = tauri_build::WindowsAttributes::new();
    windows = windows.app_manifest(
        r#"
<assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0">
  <dependency>
    <dependentAssembly>
      <assemblyIdentity
        type="win32"
        name="Microsoft.Windows.Common-Controls"
        version="6.0.0.0"
        processorArchitecture="*"
        publicKeyToken="6595b64144ccf1df"
        language="*"
      />
    </dependentAssembly>
  </dependency>
  <trustInfo xmlns="urn:schemas-microsoft-com:asm.v3">
    <security>
      <requestedPrivileges>
        <requestedExecutionLevel level="requireAdministrator" uiAccess="false" />
      </requestedPrivileges>
    </security>
  </trustInfo>
</assembly>
"#,
    );
    let attrs = tauri_build::Attributes::new().windows_attributes(windows);
    tauri_build::try_build(attrs).expect("failed to run tauri build script");
}
