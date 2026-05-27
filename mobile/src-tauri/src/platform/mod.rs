#[cfg(target_os = "android")]
pub use android::*;
#[cfg(not(any(target_os = "android", target_os = "ios")))]
pub use fallback::*;
#[cfg(target_os = "ios")]
pub use ios::*;

#[cfg(target_os = "android")]
mod android;
#[cfg(not(any(target_os = "android", target_os = "ios")))]
mod fallback;
#[cfg(target_os = "ios")]
mod ios;
