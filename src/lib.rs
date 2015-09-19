pub mod elf;

pub trait Loader {
	fn entry_point(&self) -> u64;
}

