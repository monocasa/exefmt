use std::fs;
use std::io;

use super::{Endianness, Loader, SeekReadStream, Segment};

pub struct BinLoader {
	pub segments: Vec<Segment>,
	pub entry: Option<u64>,
	pub endianness: Option<Endianness>
}

impl BinLoader {
	pub fn new(file: &mut fs::File) -> Result<BinLoader, io::Error> {
		let mut bin_ldr = BinLoader {
			segments: Vec::<Segment>::new(),
			entry: None,
			endianness: None,
		};

		let meta = try!(file.metadata());
		
		bin_ldr.segments.push( Segment {
			name: ".data".to_string(),
			load_base: 0,
			stream_base: 0,
			file_size: meta.len(),
			mem_size: meta.len(),
			read_only: false,
			executable: false,
			present_when_loaded: true,
		} );

		Ok(bin_ldr)
	}
}

impl Loader for BinLoader {
	fn entry_point(&self) -> Option<u64> {
		self.entry
	}

	fn get_segments(&self, filter: &Fn(&Segment) -> bool, stream: &mut SeekReadStream) -> Result<Vec<(Segment, Vec<u8>)>, io::Error> {
		let mut ret = Vec::<(Segment, Vec<u8>)>::new();

		for segment in self.segments.clone() {
			if filter(&segment) {
				let mut data = vec![0u8; segment.file_size as usize];
				try!(stream.seek(io::SeekFrom::Start(segment.stream_base)));
				try!(stream.read(data.as_mut_slice()));
				ret.push((segment, data));
			}
		}

		Ok(ret)
	}

	fn fmt_str(&self) -> String {
		"binary".to_string()
	}

	fn endianness(&self) -> Option<Endianness> {
		self.endianness.clone()
	}
}

