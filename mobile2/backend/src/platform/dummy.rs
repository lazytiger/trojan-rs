use wry::WebViewBuilder;

pub fn init_logging() {
    env_logger::init();
}

pub fn init_builder(builder: WebViewBuilder) -> WebViewBuilder {
    builder.with_custom_protocol("wry".into(), move |_request| {
        #[cfg(not(target_os = "android"))]
        {
            use std::fs::{canonicalize, read};
            use wry::http::{header::CONTENT_TYPE, Response};

            // Remove url scheme
            let path = _request.uri().path();

            #[cfg(not(target_os = "ios"))]
            let content = read(canonicalize(&path[1..]).unwrap()).unwrap();

            #[cfg(target_os = "ios")]
            let content = {
                let path = core_foundation::bundle::CFBundle::main_bundle()
                    .resources_path()
                    .unwrap()
                    .join(&path);
                read(canonicalize(&path)?)?
            };

            // Return asset contents and mime types based on file extensions
            // If you don't want to do this manually, there are some crates for you.
            // Such as `infer` and `mime_guess`.
            let (data, meta) = if path.ends_with(".html") {
                (content, "text/html")
            } else if path.ends_with(".js") {
                (content, "text/javascript")
            } else if path.ends_with(".png") {
                (content, "image/png")
            } else {
                unimplemented!();
            };

            Response::builder()
                .header(CONTENT_TYPE, meta)
                .body(data.into())
                .unwrap()
        }
    })
}
