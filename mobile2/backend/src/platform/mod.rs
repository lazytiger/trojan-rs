#[cfg(target_os = "android")]
pub use android::*;
#[cfg(not(target_os = "android"))]
pub use dummy::*;

#[cfg(target_os = "android")]
mod android;

#[cfg(not(target_os = "android"))]
mod dummy;
