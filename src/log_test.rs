#[macro_export]
macro_rules! info_t {
    (target: $target:expr, $fmt:expr $(, $($arg:tt)*)?) => {
        println!(concat!("target: {}, info: ", $fmt), $target, $($($arg)*)?);
    };
    ($fmt:expr $(, $($arg:tt)*)?) => {
        println!(concat!("info: ", $fmt), $($($arg)*)?);
    };
}

#[macro_export]
macro_rules! warn_t {
    (target: $target:expr, $fmt:expr $(, $($arg:tt)*)?) => {
        println!(concat!("target: {}, warn: ", $fmt), $target, $($($arg)*)?);
    };
    ($fmt:expr $(, $($arg:tt)*)?) => {
        println!(concat!("warn: ", $fmt), $($($arg)*)?);
    };
}

#[macro_export]
macro_rules! error_t {
    (target: $target:expr, $fmt:expr $(, $($arg:tt)*)?) => {
        println!(concat!("target: {}, error: ", $fmt), $target, $($($arg)*)?);
    };
    ($fmt:expr $(, $($arg:tt)*)?) => {
        println!(concat!("error: ", $fmt), $($($arg)*)?);
    };
}