extern crate byteorder;

use super::{SeekReadStream, SymbolTable};

use std::io;

use self::byteorder::{LittleEndian, ReadBytesExt};

#[derive(Clone)]
struct MsfStream {
	len: u32,
	page_size: u32,
	pages: Vec<u16>,
}

impl MsfStream {
	fn new() -> MsfStream {
		MsfStream {
			len: 0,
			page_size: 0,
			pages: Vec::new(),
		}
	}

	fn num_pages(&self) -> usize {
		let stream_size = self.len as usize;
		let page_size = self.page_size as usize;

		if (stream_size % page_size) == 0 {
			stream_size / page_size
		} else {
			(stream_size / page_size) + 1
		}
	}

	fn read_data(&self, rdr: &mut SeekReadStream) -> Result<Vec<u8>, io::Error> {
		let mut cur_page: usize = 0;

		let len = self.len as usize;
		let page_size = self.page_size as usize;

		let mut buffer: Vec<u8> = vec![0; len]; 

		for page in buffer.chunks_mut(page_size) {
			let cur_file_offset = (self.pages[cur_page] as u64) * (page_size as u64);

			try!(rdr.seek(io::SeekFrom::Start(cur_file_offset)));

//			println!("Reading {:4} bytes from {:#x}", page.len(), cur_file_offset);

			try!(rdr.read(page));

			cur_page += 1;
		}

		Ok(buffer)
	}
}

struct MsfHeader {
	signature: [u8; 44],
	page_size: u32,
	start_page: u16,
	file_pages: u16,
	root_stream: MsfStream,
}

const SIGNATURE_2_00: &'static [u8; 44] = &[
	0x4D, 0x69, 0x63, 0x72, 0x6F, 0x73, 0x6F, 0x66,
	0x74, 0x20, 0x43, 0x2F, 0x43, 0x2B, 0x2B, 0x20,
	0x70, 0x72, 0x6F, 0x67, 0x72, 0x61, 0x6D, 0x20,
	0x64, 0x61, 0x74, 0x61, 0x62, 0x61, 0x73, 0x65,
	0x20, 0x32, 0x2E, 0x30, 0x30, 0x0D, 0x0A, 0x1A,
	0x4A, 0x47, 0x00, 0x00,
];

impl MsfHeader {
	fn new() -> MsfHeader {
		MsfHeader {
			signature: [0u8; 44],
			page_size: 0,
			start_page: 0,
			file_pages: 0,
			root_stream: MsfStream::new(),
		}
	}

	fn is_sig_valid(&self) -> bool {
		for ii in 0..44 {
			if self.signature[ii] != SIGNATURE_2_00[ii] {
				return false;
			}
		}

		true
	}
}

struct MsfFile {
	header: MsfHeader,
	streams: Vec<MsfStream>,
}

fn print_buffer(buffer: &[u8]) {
	let mut cur_offset: usize = 0;

	for byte in buffer {
		if (cur_offset % 16) == 0 {
			print!("{:06x}:", cur_offset);
		}

		print!(" {:02x}", byte);
		cur_offset += 1;

		if (cur_offset % 16) == 0 {
			println!("");
		}
	}

	if (cur_offset % 16) != 0 {
		println!("");
	}
}

fn read_directory(root_stream: &MsfStream, rdr: &mut SeekReadStream) -> Result<Vec<MsfStream>, io::Error> {
	let mut directory_data = io::Cursor::new(try!(root_stream.read_data(rdr)));

	let mut streams: Vec<MsfStream> = Vec::new();
	streams.push(root_stream.clone());

	let num_streams = try!(directory_data.read_u16::<LittleEndian>());
	let _ = try!(directory_data.read_u16::<LittleEndian>());

	for _ in 1..num_streams {
		let stream_size = try!(directory_data.read_u32::<LittleEndian>());
		let _ = try!(directory_data.read_u32::<LittleEndian>());

		streams.push(MsfStream {
			len: stream_size,
			page_size: root_stream.page_size,
			pages: Vec::new(),
		});
	}

	for cur_stream_num in 1..num_streams as usize {
		for _ in 0..streams[cur_stream_num].num_pages() {
			streams[cur_stream_num].pages.push(try!(directory_data.read_u16::<LittleEndian>()));
		}
	}

	Ok(streams)
}

impl MsfFile {
	fn read(rdr: &mut SeekReadStream) -> Result<MsfFile, io::Error> {
		let mut header = MsfHeader::new();

		try!(rdr.read(&mut header.signature));

		header.page_size  = try!(rdr.read_u32::<LittleEndian>());
		header.start_page = try!(rdr.read_u16::<LittleEndian>());
		header.file_pages = try!(rdr.read_u16::<LittleEndian>());

		header.root_stream.len = try!(rdr.read_u32::<LittleEndian>());
		header.root_stream.page_size = header.page_size;
		let _ = try!(rdr.read_u32::<LittleEndian>());

		for _ in 0..header.root_stream.num_pages() {
			header.root_stream.pages.push(try!(rdr.read_u16::<LittleEndian>()));
		}

		let streams = try!(read_directory(&header.root_stream, rdr));

		Ok(MsfFile {
			header: header,
			streams: streams,
		})
	}
}

pub fn read(rdr: &mut SeekReadStream) -> Result<SymbolTable, io::Error> {
	let mut symbol_table = SymbolTable::new();

	let msf_file = try!(MsfFile::read(rdr));

	let mut ii = 0;
	for stream in msf_file.streams.iter() {
		let data = try!(stream.read_data(rdr));

		println!("Stream {} contents: ", ii);

		print_buffer(&data);

		ii += 1;
	}

	Ok(symbol_table)
}

