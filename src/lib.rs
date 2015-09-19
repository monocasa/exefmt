pub mod elf;

pub trait Loader {
	fn entry_point(&self) -> Option<u64>;
}

