extern crate byteorder;

use std::io;

use self::byteorder::{BigEndian, LittleEndian, ReadBytesExt};

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
pub enum ElfParseError {
	UnexpectedEOF,
	InvalidIdent,
	InvalidVersion,
	Io(io::Error),
}

impl From<io::Error> for ElfParseError {
	fn from(err: io::Error) -> ElfParseError{ ElfParseError::Io(err) }
}

impl From<byteorder::Error> for ElfParseError {
	fn from(err: byteorder::Error) -> ElfParseError {
		match err {
			byteorder::Error::UnexpectedEOF => ElfParseError::UnexpectedEOF,
			byteorder::Error::Io(ioerr) => ElfParseError::Io(ioerr),
		}
	}
}

//impl From<byteorder::new::Error> for ElfParseError {
//	fn from(err: byteorder::new::Error) -> ElfParseError {
//		match err {
//			byteorder::new::Error::Io(err) => { ElfParseError::Io(err) }
//			byteorder::new::Error::UnexpectedEOF => { ElfParseError::UnexpectedEOF }
//		}
//	}
//}

#[derive(Default)]
pub struct ElfFile {
	pub e_ident: [u8; EI_NIDENT],
	pub e_type: u16,
	pub e_machine: u16,
	pub e_version: u32,
	pub e_entry: u64,
	pub e_phoff: u64,
	pub e_shoff: u64,
	pub e_flags: u32,
	pub e_ehsize: u16,
	pub e_phentsize: u16,
	pub e_phnum: u16,
	pub e_shentsize: u16,
	pub e_shnum: u16,
	pub e_shstrndx: u16,
}

impl ElfFile {
	fn new() -> ElfFile {
		ElfFile {
			e_ident: [0u8; EI_NIDENT],
			e_type:      0,
			e_machine:   0,
			e_version:   0,
			e_entry:     0,
			e_phoff:     0,
			e_shoff:     0,
			e_flags:     0,
			e_ehsize:    0,
			e_phentsize: 0,
			e_phnum:     0,
			e_shentsize: 0,
			e_shnum:     0,
			e_shstrndx:  0,
		}
	}

	fn is_magic_valid(&self) -> bool {
		(self.e_ident[EI_MAG0] == ELFMAG0) && (self.e_ident[EI_MAG1] == ELFMAG1) && 
			(self.e_ident[EI_MAG2] == ELFMAG2) && (self.e_ident[EI_MAG3] == ELFMAG3)
	}

	fn is_class_valid(&self) -> bool {
		(self.e_ident[EI_CLASS] == ELFCLASS32) || (self.e_ident[EI_CLASS] == ELFCLASS64)
	}

	fn is_data_valid(&self) -> bool {
		(self.e_ident[EI_DATA] == ELFDATA2LSB) || (self.e_ident[EI_DATA] == ELFDATA2MSB)
	}

	fn is_ver_valid(&self) -> bool {
		self.e_ident[EI_VERSION] == EV_CURRENT
	}

	fn is_ident_valid(&self) -> bool {
		self.is_magic_valid() && self.is_class_valid() && 
			self.is_data_valid() && self.is_ver_valid()
	}

	fn read_u16(&self, rdr: &mut io::Read) -> Result<u16, ElfParseError> {
		Ok(match self.e_ident[EI_DATA] {
			ELFDATA2LSB => try!(rdr.read_u16::<LittleEndian>()),
			ELFDATA2MSB => try!(rdr.read_u16::<BigEndian>()),
			_ => {
				return Err(ElfParseError::InvalidIdent);
			},
		})
	}

	fn read_u32(&self, rdr: &mut io::Read) -> Result<u32, ElfParseError> {
		Ok(match self.e_ident[EI_DATA] {
			ELFDATA2LSB => try!(rdr.read_u32::<LittleEndian>()),
			ELFDATA2MSB => try!(rdr.read_u32::<BigEndian>()),
			_ => {
				return Err(ElfParseError::InvalidIdent);
			},
		})
	}

	fn read_u64(&self, rdr: &mut io::Read) -> Result<u64, ElfParseError> {
		Ok(match self.e_ident[EI_DATA] {
			ELFDATA2LSB => try!(rdr.read_u64::<LittleEndian>()),
			ELFDATA2MSB => try!(rdr.read_u64::<BigEndian>()),
			_ => {
				return Err(ElfParseError::InvalidIdent);
			},
		})
	}

	pub fn read(rdr: &mut io::Read) -> Result<ElfFile, ElfParseError> {
		let mut elf = ElfFile::new();

		match rdr.read(&mut elf.e_ident) {
			Ok(bytes_read) => {
				if bytes_read != EI_NIDENT {
					return Err(ElfParseError::UnexpectedEOF);
				}
			},
			Err(err) => {
				return Err(ElfParseError::Io(err));
			},
		}

		if !elf.is_ident_valid() {
			return Err(ElfParseError::InvalidIdent);
		}

		match elf.e_ident[EI_CLASS] {
			ELFCLASS32 => {
				elf.e_type      = try!(elf.read_u16(rdr));
				elf.e_machine   = try!(elf.read_u16(rdr));
				elf.e_version   = try!(elf.read_u32(rdr));
				elf.e_entry     = try!(elf.read_u32(rdr)) as u64;
				elf.e_phoff     = try!(elf.read_u32(rdr)) as u64;
				elf.e_shoff     = try!(elf.read_u32(rdr)) as u64;
				elf.e_flags     = try!(elf.read_u32(rdr));
				elf.e_ehsize    = try!(elf.read_u16(rdr));
				elf.e_phentsize = try!(elf.read_u16(rdr));
				elf.e_phnum     = try!(elf.read_u16(rdr));
				elf.e_shentsize = try!(elf.read_u16(rdr));
				elf.e_shnum     = try!(elf.read_u16(rdr));
				elf.e_shstrndx  = try!(elf.read_u16(rdr));
			},

			ELFCLASS64 => {
				elf.e_type      = try!(elf.read_u16(rdr));
				elf.e_machine   = try!(elf.read_u16(rdr));
				elf.e_version   = try!(elf.read_u32(rdr));
				elf.e_entry     = try!(elf.read_u64(rdr));
				elf.e_phoff     = try!(elf.read_u64(rdr));
				elf.e_shoff     = try!(elf.read_u64(rdr));
				elf.e_flags     = try!(elf.read_u32(rdr));
				elf.e_ehsize    = try!(elf.read_u16(rdr));
				elf.e_phentsize = try!(elf.read_u16(rdr));
				elf.e_phnum     = try!(elf.read_u16(rdr));
				elf.e_shentsize = try!(elf.read_u16(rdr));
				elf.e_shnum     = try!(elf.read_u16(rdr));
				elf.e_shstrndx  = try!(elf.read_u16(rdr));
			},

			_ => {
				return Err(ElfParseError::InvalidIdent);
			},
		}

		if elf.e_version != (EV_CURRENT as u32) {
			return Err(ElfParseError::InvalidVersion);
		}

		Ok(elf)
	}

	pub fn ehdr_class_string(&self) -> String {
		ehdr_class_string(self.e_ident[EI_CLASS])
	}

	pub fn ehdr_data_string(&self) -> String {
		ehdr_data_string(self.e_ident[EI_DATA])
	}

}

impl Loader for ElfFile {
	fn entry_point(&self) -> u64 {
		self.e_entry
	}
}

pub fn ehdr_class_string(e_class: u8) -> String {
	match e_class {
		ELFCLASS32 => "ELF32".to_string(),
		ELFCLASS64 => "ELF64".to_string(),

		_ => format!("Unknown ELF Class {:#x}", e_class),
	}
}

pub fn ehdr_data_string(e_data: u8) -> String {
	match e_data {
		ELFDATA2LSB => "2's complement, little endian".to_string(),
		ELFDATA2MSB => "2's complement, big endian".to_string(),

		_ => format!("Unknown ELF Data {:#x}", e_data),
	}
}

