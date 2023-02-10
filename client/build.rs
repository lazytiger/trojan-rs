use winres::WindowsResource;

fn main() {
    WindowsResource::new()
        .set_icon("res/icon.ico")
        .compile()
        .unwrap();
}
