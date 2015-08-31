use std::io::Read;

use loader::Loader;

pub const EI_MAG0: usize = 0;
pub const ELFMAG0: u8 = 0x7F;

pub const EI_MAG1: usize = 1;
pub const ELFMAG1: u8 = 0x45;  // 'E'

pub const EI_MAG2: usize = 2;
pub const ELFMAG2: u8 = 0x4C;  // 'L'

pub const EI_MAG3: usize = 3;
pub const ELFMAG3: u8 = 0x46;  // 'F'

pub const EI_CLASS: usize = 4;
pub const ELFCLASSNONE: u8 = 0;
pub const ELFCLASS32:   u8 = 1;
pub const ELFCLASS64:   u8 = 2;

pub const EI_DATA: usize = 5;
pub const ELFDATANONE: u8 = 0;
pub const ELFDATA2LSB: u8 = 1;
pub const ELFDATA2MSB: u8 = 2;

pub const EI_VERSION: usize = 6;
pub const EV_CURRENT: u8 = 1;

pub const EI_NIDENT: usize = 16;

#[derive(Debug)]
pub enum ElfParseErrors {
	ReadError,
	InvalidIdent,
}

#[derive(Default)]
pub struct ElfFile {
	ident: [u8; EI_NIDENT],
	entry: u64,
}

impl ElfFile {
	fn new() -> ElfFile {
		ElfFile {
			ident: [0u8; EI_NIDENT],
			entry: 0,
		}
	}

	fn is_magic_valid(&self) -> bool {
		(self.ident[EI_MAG0] == ELFMAG0) && (self.ident[EI_MAG1] == ELFMAG1) && 
			(self.ident[EI_MAG2] == ELFMAG2) && (self.ident[EI_MAG3] == ELFMAG3)
	}

	fn is_class_valid(&self) -> bool {
		(self.ident[EI_CLASS] == ELFCLASS32) || (self.ident[EI_CLASS] == ELFCLASS64)
	}

	fn is_data_valid(&self) -> bool {
		(self.ident[EI_DATA] == ELFDATA2LSB) || (self.ident[EI_DATA] == ELFDATA2MSB)
	}

	fn is_ver_valid(&self) -> bool {
		self.ident[EI_VERSION] == EV_CURRENT
	}

	fn is_ident_valid(&self) -> bool {
		self.is_magic_valid() && self.is_class_valid() && 
			self.is_data_valid() && self.is_ver_valid()
	}

	pub fn read(reader: &mut Read) -> Result<ElfFile, ElfParseErrors> {
		let mut elf = ElfFile::new();

		match reader.read(&mut elf.ident) {
			Ok(bytes_read) => {
				if bytes_read != EI_NIDENT {
					return Err(ElfParseErrors::ReadError);
				}
			},
			Err(_) =>{
				return Err(ElfParseErrors::ReadError);
			},
		}

		if !elf.is_ident_valid() {
			return Err(ElfParseErrors::InvalidIdent);
		}

		Ok(elf)
	}
}

impl Loader for ElfFile {
	fn entry_point(&self) -> u64 {
		self.entry
	}
}

