pub mod elf;
pub mod binary;

pub trait Loader {
	fn entry_point(&self) -> Option<u64>;
}

