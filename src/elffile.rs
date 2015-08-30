use std::io::Read;

use loader::Loader;

const N_IDENT: usize = 16;

#[derive(Debug)]
pub enum ElfParseErrors {
	ReadError
}

#[derive(Default)]
pub struct ElfFile {
	ident: [u8; N_IDENT],
	entry: u64,
}

impl ElfFile {
	pub fn new() -> ElfFile {
		ElfFile {
			ident: [0u8; N_IDENT],
			entry: 0,
		}
	}

	pub fn read(reader: &mut Read) -> Result<ElfFile, ElfParseErrors> {
		let mut elf = ElfFile::new();

		match reader.read(&mut elf.ident) {
			Ok(bytes_read) => {
				if bytes_read != N_IDENT {
					return Err(ElfParseErrors::ReadError);
				}
			},
			Err(_) =>{
				return Err(ElfParseErrors::ReadError);
			},
		}

		Ok(elf)
	}
}

impl Loader for ElfFile {
	fn entry_point(&self) -> u64 {
		self.entry
	}
}

