#![feature(convert)]

pub mod elf;
pub mod binary;

use std::io;

#[derive(Clone)]
pub struct Segment {
	pub name: String,
	pub load_base: u64,
	pub stream_base: u64,
	pub file_size: u64,
	pub mem_size: u64,
	pub read_only: bool,
	pub executable: bool,
}

pub trait Loader {
	fn entry_point(&self) -> Option<u64>;
	fn get_segments<S>(&self, filter: &Fn(&Segment) -> bool, stream: &mut S) -> Result<Vec<(Segment, Vec<u8>)>, io::Error> 
			where S: io::Read + io::Seek;
}

