//! Read the executable being run for explicit local installation or update.
use std::fs::File;

pub fn source() -> Result<File, String> {
    File::open("/proc/self/exe").map_err(|_| "cannot read running executable".into())
}
