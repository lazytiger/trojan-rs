#![windows_subsystem = "windows"]

use eframe::{
    egui::{Context, FontData, FontDefinitions, FontFamily, Vec2},
    Theme,
};

use crate::ui::MainUi;

mod types;
mod ui;

fn setup_custom_fonts(ctx: &Context, data: &'static [u8]) {
    // Start with the default fonts (we will be adding to them rather than replacing them).
    let mut fonts = FontDefinitions::default();

    // Install my own font (maybe supporting non-latin characters).
    // .ttf and .otf files supported.
    fonts
        .font_data
        .insert("my_font".to_owned(), FontData::from_static(data));

    // Put my font first (highest priority) for proportional text:
    fonts
        .families
        .entry(FontFamily::Proportional)
        .or_default()
        .insert(0, "my_font".to_owned());

    // Put my font as last fallback for monospace:
    fonts
        .families
        .entry(FontFamily::Monospace)
        .or_default()
        .push("my_font".to_owned());

    // Tell egui to use these fonts:
    ctx.set_fonts(fonts);
}

fn main() {
    egui_logger::init().unwrap();
    let native_options = eframe::NativeOptions {
        initial_window_size: Some(Vec2::new(473.0, 800.0)),
        resizable: false,
        default_theme: Theme::Light,
        ..Default::default()
    };
    eframe::run_native(
        "Trojan代理",
        native_options,
        Box::new(|ctx| {
            setup_custom_fonts(
                &ctx.egui_ctx,
                include_bytes!("../../res/STSong.ttf").as_ref(),
            );
            let mut style = (*ctx.egui_ctx.style()).clone();
            style
                .text_styles
                .iter_mut()
                .for_each(|(_, font)| font.size = 22.0);
            style.spacing.item_spacing.y = 15.0;
            ctx.egui_ctx.set_style(style);
            Box::new(MainUi::new())
        }),
    );
}
