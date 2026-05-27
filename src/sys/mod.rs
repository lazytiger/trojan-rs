use cfg_if::cfg_if;

cfg_if! {
    if #[cfg(target_os = "linux")] {
        mod unix;
        pub use self::unix::*;
    } else if #[cfg(windows)] {
        mod windows;
        pub use self::windows::*;
    } else {
        mod unsupported;
        pub use self::unsupported::*;
    }
}
