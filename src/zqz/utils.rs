//! A module containing utilities functions and macros.
use crate::PARAMS;

/// Compute the round and then the modulo
pub(super) fn round_modulo(x: f64) -> f64 {
    let tmp = (x.round()) as i32;
    let i: i32 = tmp % (PARAMS.modulo as i32);
    let res = if i < 0 { i + (PARAMS.modulo as i32) } else { i };
    res as f64
}

/// compute the floor and then the modulo
pub(super) fn floor_modulo(x: f64) -> f64 {
    let tmp = x % (PARAMS.modulo as f64);
    let res = if tmp < 0. {
        tmp + PARAMS.modulo as f64
    } else {
        tmp
    };
    res.floor()
}

/// compute the relu
pub(super) fn relu(x: f64) -> f64 {
    f64::max(0., x)
}

// This macro allows to compute the duration of the execution of the expressions enclosed. Note that
// the variables are not captured.
#[macro_export]
macro_rules! measure_duration{
    ($title: tt, [$($block:tt)+]) => {
        println!("{}", $title);
        let __now = std::time::SystemTime::now();
        $(
           $block
        )+
        let __time = __now.elapsed().unwrap().as_millis() as f64 / 1000.;
        let __s_time = format!("{} s", __time);
        println!("Duration: {}", __s_time.green().bold());
    }
}
