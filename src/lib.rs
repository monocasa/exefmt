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
	pub present_when_loaded: bool,
}

pub trait SeekReadStream : io::Seek + io::Read {}

impl<T: io::Seek + io::Read> SeekReadStream for T { }

pub trait Loader {
	fn entry_point(&self) -> Option<u64>;
	fn get_segments(&self, filter: &Fn(&Segment) -> bool, stream: &mut SeekReadStream) -> Result<Vec<(Segment, Vec<u8>)>, io::Error>;
	fn fmt_str(&self) -> String;
}

