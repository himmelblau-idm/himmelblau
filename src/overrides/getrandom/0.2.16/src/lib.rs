pub use getrandom::*;

pub fn getrandom(dest: &mut [u8]) -> Result<(), Error> {
    getrandom::fill(dest)
}
