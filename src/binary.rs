use std::fs::File;
use std::io::Error;

pub struct Segment {
	pub name: String,
	pub load_base: u64,
	pub stream_base: u64,
	pub file_size: u64,
	pub mem_size: u64,
}

pub struct BinLoader {
	pub segments: Vec<Segment>,
	pub entry: Option<u64>,
}

impl BinLoader {
	pub fn new(file: &mut File) -> Result<BinLoader, Error> {
		let mut bin_ldr = BinLoader {
			segments: Vec::<Segment>::new(),
			entry: None,
		};

		let meta = try!(file.metadata());
		
		bin_ldr.segments.push( Segment {
			name: ".data".to_string(),
			load_base: 0,
			stream_base: 0,
			file_size: meta.len(),
			mem_size: meta.len(),
		} );

		Ok(bin_ldr)
	}
}

