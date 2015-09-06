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

pub const EI_OSABI: usize = 7;
pub const ELFOSABI_NONE:       u8 = 0;
pub const ELFOSABI_SYSV:       u8 = 0;
pub const ELFOSABI_HPUX:       u8 = 1;
pub const ELFOSABI_NETBSD:     u8 = 2;
pub const ELFOSABI_GNU:        u8 = 3;
pub const ELFOSABI_LINUX:      u8 = ELFOSABI_GNU;
pub const ELFOSABI_HURD:       u8 = 4;
pub const ELFOSABI_SOLARIS:    u8 = 6;
pub const ELFOSABI_AIX:        u8 = 7;
pub const ELFOSABI_IRIX:       u8 = 8;
pub const ELFOSABI_FREEBSD:    u8 = 9;
pub const ELFOSABI_TRU64:      u8 = 10;
pub const ELFOSABI_MODESTO:    u8 = 11;
pub const ELFOSABI_OPENBSD:    u8 = 12;
pub const ELFOSABI_OPENVMS:    u8 = 13;
pub const ELFOSABI_NSK:        u8 = 14;
pub const ELFOSABI_AROS:       u8 = 15;
pub const ELFOSABI_ARM:        u8 = 97;
pub const ELFOSABI_STANDALONE: u8 = 255;

pub const EI_ABIVERSION: usize = 8;

pub const EI_NIDENT: usize = 16;

pub const ET_NONE:   u16 = 0;
pub const ET_REL:    u16 = 1;
pub const ET_EXEC:   u16 = 2;
pub const ET_DYN:    u16 = 3;
pub const ET_CORE:   u16 = 4;
pub const ET_LOOS:   u16 = 0xFE00;
pub const ET_HIOS:   u16 = 0xFEFF;
pub const ET_LOPROC: u16 = 0xFF00;
pub const ET_HIPROC: u16 = 0xFFFF;

pub const EM_NONE:        u16 = 0;
pub const EM_M32:         u16 = 1;
pub const EM_SPARC:       u16 = 2;
pub const EM_386:         u16 = 3;
pub const EM_68K:         u16 = 4;
pub const EM_88K:         u16 = 5;
pub const EM_486:         u16 = 6;
pub const EM_860:         u16 = 7;
pub const EM_MIPS:        u16 = 8;
pub const EM_S370:        u16 = 9;
pub const EM_MIPS_RS3_LE: u16 = 10;
pub const EM_RS6000:      u16 = 11;
pub const EM_UNKNOWN12:   u16 = 12;
pub const EM_UNKNOWN13:   u16 = 13;
pub const EM_UNKNOWN14:   u16 = 14;
pub const EM_PA_RISC:     u16 = 15;
pub const EM_NCUBE:       u16 = 16;
pub const EM_VPP500:      u16 = 17;
pub const EM_SPARC32PLUS: u16 = 18;
pub const EM_960:         u16 = 19;
pub const EM_PPC:         u16 = 20;
pub const EM_PPC64:       u16 = 21;
pub const EM_UNKNOWN22:   u16 = 22;
pub const EM_UNKNOWN23:   u16 = 23;
pub const EM_UNKNOWN24:   u16 = 24;
pub const EM_UNKNOWN25:   u16 = 25;
pub const EM_UNKNOWN26:   u16 = 26;
pub const EM_UNKNOWN27:   u16 = 27;
pub const EM_UNKNOWN28:   u16 = 28;
pub const EM_UNKNOWN29:   u16 = 29;
pub const EM_UNKNOWN30:   u16 = 30;
pub const EM_UNKNOWN31:   u16 = 31;
pub const EM_UNKNOWN32:   u16 = 32;
pub const EM_UNKNOWN33:   u16 = 33;
pub const EM_UNKNOWN34:   u16 = 34;
pub const EM_UNKNOWN35:   u16 = 35;
pub const EM_V800:        u16 = 36;
pub const EM_FR20:        u16 = 37;
pub const EM_RH32:        u16 = 38;
pub const EM_RCE:         u16 = 39;
pub const EM_ARM:         u16 = 40;
pub const EM_ALPHA:       u16 = 41;
pub const EM_SH:          u16 = 42;
pub const EM_SPARCV9:     u16 = 43;
pub const EM_TRICORE:     u16 = 44;
pub const EM_ARC:         u16 = 45;
pub const EM_H8_300:      u16 = 46;
pub const EM_H8_300H:     u16 = 47;
pub const EM_H8S:         u16 = 48;
pub const EM_H8_500:      u16 = 49;
pub const EM_IA_64:       u16 = 50;
pub const EM_MIPS_X:      u16 = 51;
pub const EM_COLDFIRE:    u16 = 52;
pub const EM_68HC12:      u16 = 53;
pub const EM_MMA:         u16 = 54;
pub const EM_PCP:         u16 = 55;
pub const EM_NCPU:        u16 = 56;
pub const EM_NDR1:        u16 = 57;
pub const EM_STARCORE:    u16 = 58;
pub const EM_ME16:        u16 = 59;
pub const EM_ST100:       u16 = 60;
pub const EM_TINYJ:       u16 = 61;
pub const EM_AMD64:       u16 = 62;
pub const EM_X86_64:      u16 = EM_AMD64;
pub const EM_PDSP:        u16 = 63;
pub const EM_UNKNOWN64:   u16 = 64;
pub const EM_UNKNOWN65:   u16 = 65;
pub const EM_FX66:        u16 = 66;
pub const EM_ST9PLUS:     u16 = 67;
pub const EM_ST7:         u16 = 68;
pub const EM_68HC16:      u16 = 69;
pub const EM_68HC11:      u16 = 70;
pub const EM_68HC08:      u16 = 71;
pub const EM_68HC05:      u16 = 72;
pub const EM_SVX:         u16 = 73;
pub const EM_ST19:        u16 = 74;
pub const EM_VAX:         u16 = 75;
pub const EM_CRIS:        u16 = 76;
pub const EM_JAVELIN:     u16 = 77;
pub const EM_FIREPATH:    u16 = 78;
pub const EM_ZSP:         u16 = 79;
pub const EM_MMIX:        u16 = 80;
pub const EM_HUANY:       u16 = 81;
pub const EM_PRISM:       u16 = 82;
pub const EM_AVR:         u16 = 83;
pub const EM_FR30:        u16 = 84;
pub const EM_D10V:        u16 = 85;
pub const EM_D30V:        u16 = 86;
pub const EM_V850:        u16 = 87;
pub const EM_M32R:        u16 = 88;
pub const EM_MN10300:     u16 = 89;
pub const EM_MN10200:     u16 = 90;
pub const EM_PJ:          u16 = 91;
pub const EM_OPENRISC:    u16 = 92;
pub const EM_ARC_A5:      u16 = 93;
pub const EM_XTENSA:      u16 = 94;

pub const EF_MIPS_NOREORDER:     u32 = 0x00000001;
pub const EF_MIPS_PIC:           u32 = 0x00000002;
pub const EF_MIPS_CPIC:          u32 = 0x00000004;
pub const EF_MIPS_XGOT:          u32 = 0x00000008;
pub const EF_MIPS_UCODE:         u32 = 0x00000010;
pub const EF_MIPS_ABI2:          u32 = 0x00000020;
pub const EF_MIPS_OPTIONS_FIRST: u32 = 0x00000080;
pub const EF_MIPS_32BITMODE:     u32 = 0x00000100;
pub const EF_MIPS_FP64:          u32 = 0x00000200;
pub const EF_MIPS_NAN2008:       u32 = 0x00000400;

pub const EF_MIPS_ABI: u32 = 0x0000F000;
pub const EF_MIPS_ABI_O32:    u32 = 0x00001000;
pub const EF_MIPS_ABI_O64:    u32 = 0x00002000;
pub const EF_MIPS_ABI_EABI32: u32 = 0x00003000;
pub const EF_MIPS_ABI_EABI64: u32 = 0x00004000;

pub const EF_MIPS_MACH: u32 = 0x00FF0000;
pub const EF_MIPS_MACH_3900:    u32 = 0x00810000;
pub const EF_MIPS_MACH_4010:    u32 = 0x00820000;
pub const EF_MIPS_MACH_4100:    u32 = 0x00830000;
pub const EF_MIPS_MACH_4650:    u32 = 0x00850000;
pub const EF_MIPS_MACH_4120:    u32 = 0x00870000;
pub const EF_MIPS_MACH_4111:    u32 = 0x00880000;
pub const EF_MIPS_MACH_SB1:     u32 = 0x008A0000;
pub const EF_MIPS_MACH_OCTEON:  u32 = 0x008B0000;
pub const EF_MIPS_MACH_XLR:     u32 = 0x008C0000;
pub const EF_MIPS_MACH_OCTEON2: u32 = 0x008D0000;
pub const EF_MIPS_MACH_OCTEON3: u32 = 0x008E0000;
pub const EF_MIPS_MACH_5400:    u32 = 0x00910000;
pub const EF_MIPS_MACH_5900:    u32 = 0x00920000;
pub const EF_MIPS_MACH_5500:    u32 = 0x00980000;
pub const EF_MIPS_MACH_9000:    u32 = 0x00990000;
pub const EF_MIPS_MACH_LS2E:    u32 = 0x00A00000;
pub const EF_MIPS_MACH_LS2F:    u32 = 0x00A10000;
pub const EF_MIPS_MACH_LS3A:    u32 = 0x00A20000;

pub const EF_MIPS_MICROMIPS:     u32 = 0x02000000;
pub const EF_MIPS_ARCH_ASE_M16:  u32 = 0x04000000;
pub const EF_MIPS_ARCH_ASE_MDMX: u32 = 0x08000000;

pub const EF_MIPS_ARCH: u32 = 0xF0000000;
pub const EF_MIPS_ARCH1:     u32 = 0x00000000;
pub const EF_MIPS_ARCH2:     u32 = 0x10000000;
pub const EF_MIPS_ARCH3:     u32 = 0x20000000;
pub const EF_MIPS_ARCH4:     u32 = 0x30000000;
pub const EF_MIPS_ARCH5:     u32 = 0x40000000;
pub const EF_MIPS_ARCH_32:   u32 = 0x50000000;
pub const EF_MIPS_ARCH_64:   u32 = 0x60000000;
pub const EF_MIPS_ARCH_32R2: u32 = 0x70000000;
pub const EF_MIPS_ARCH_64R2: u32 = 0x80000000;
pub const EF_MIPS_ARCH_32R6: u32 = 0x90000000;
pub const EF_MIPS_ARCH_64R6: u32 = 0xA0000000;

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

	pub fn ehdr_osabi_string(&self) -> String {
		ehdr_osabi_string(self.e_ident[EI_OSABI])
	}

	pub fn ehdr_type_string(&self) -> String {
		ehdr_type_string(self.e_type)
	}

	pub fn ehdr_machine_string(&self) -> String {
		ehdr_machine_string(self.e_machine)
	}

	pub fn ehdr_flags_strings(&self) -> Vec<String> {
		ehdr_flags_strings(self.e_machine, self.e_flags)
	}
}

impl Loader for ElfFile {
	fn entry_point(&self) -> u64 {
		self.e_entry
	}
}

pub fn ehdr_class_string(e_class: u8) -> String {
	let ret = match e_class {
		ELFCLASSNONE => "none",
		ELFCLASS32   => "ELF32",
		ELFCLASS64   => "ELF64",

		_ => return format!("<unknown: {:#x}>", e_class),
	};

	ret.to_string()
}

pub fn ehdr_data_string(e_data: u8) -> String {
	let ret = match e_data {
		ELFDATANONE => "none",
		ELFDATA2LSB => "2's complement, little endian",
		ELFDATA2MSB => "2's complement, big endian",

		_ => return format!("<unknown: {:#x}>", e_data),
	};

	ret.to_string()
}

pub fn ehdr_osabi_string(e_osabi: u8) -> String {
	let ret = match e_osabi {
		ELFOSABI_NONE       => "UNIX - System V",
		ELFOSABI_HPUX       => "UNIX - HP-UX",
		ELFOSABI_NETBSD     => "UNIX - NetBSD",
		ELFOSABI_LINUX      => "UNIX - Linux",
		ELFOSABI_HURD       => "GNU/Hurd",
		ELFOSABI_SOLARIS    => "UNIX - Solaris",
		ELFOSABI_AIX        => "UNIX - AIX",
		ELFOSABI_IRIX       => "UNIX - IRIX",
		ELFOSABI_FREEBSD    => "UNIX - FreeBSD",
		ELFOSABI_TRU64      => "UNIX - TRU64",
		ELFOSABI_MODESTO    => "Novell - Modesto",
		ELFOSABI_OPENBSD    => "UNIX - OpenBSD",
		ELFOSABI_OPENVMS    => "VMS - OpenVMS",
		ELFOSABI_NSK        => "HP - Non-Stop Kernel",
		ELFOSABI_AROS       => "Amiga Research OS",
		ELFOSABI_ARM        => "ARM",
		ELFOSABI_STANDALONE => "Standalone App",

		_ => return format!("<unknown>: {:#x}", e_osabi),
	};

	ret.to_string()
}

pub fn ehdr_type_string(e_type: u16) -> String {
	let ret = match e_type {
		ET_NONE => "NONE (None)",
		ET_CORE => "CORE (Core file)",
		ET_DYN  => "DYN (Shared object file)",
		ET_EXEC => "EXEC (Executable file)",
		ET_REL => "REL (Relocatable file)",

		ET_LOPROC ... ET_HIPROC =>
			return format!("Processor Specific: ({:#x})", e_type),

		ET_LOOS ... ET_HIOS =>
			return format!("OS Specific: ({:#x})", e_type),

		_ => return format!("<unknown {:#x}>", e_type),
	};

	ret.to_string()
}

pub fn ehdr_machine_string(e_machine: u16) -> String {
	let ret = match e_machine {
		EM_NONE  => "None",
		EM_M32   => "WE32100",
		EM_MIPS  => "MIPS R3000",
		EM_SPARC => "Sparc",
		EM_386   => "Intel 80386",
		EM_68K   => "MC68000",
		EM_88K   => "MC88000",

		_ => return format!("<unknown: {:#x}>", e_machine),
	};

	ret.to_string()
}

fn ehdr_mips_flags_strings(e_flags: u32) -> Vec<String> {
	let mut strs = Vec::<String>::new();

	if (e_flags & EF_MIPS_NOREORDER) != 0     { strs.push("noreorder".to_string());     }
	if (e_flags & EF_MIPS_PIC) != 0           { strs.push("pic".to_string());           }
	if (e_flags & EF_MIPS_CPIC) != 0          { strs.push("cpic".to_string());          }
	if (e_flags & EF_MIPS_XGOT) != 0          { strs.push("xgot".to_string());          }
	if (e_flags & EF_MIPS_UCODE) != 0         { strs.push("ugen_reserved".to_string()); }
	if (e_flags & EF_MIPS_OPTIONS_FIRST) != 0 { strs.push("odk first".to_string());     }
	if (e_flags & EF_MIPS_32BITMODE) != 0     { strs.push("32bitmode".to_string());     }
	if (e_flags & EF_MIPS_FP64) != 0          { strs.push("fp64".to_string());          }
	if (e_flags & EF_MIPS_NAN2008) != 0       { strs.push("nan2008".to_string());       }

	if (e_flags & EF_MIPS_ABI) != 0 {
		strs.push( match e_flags & EF_MIPS_ABI {
			EF_MIPS_ABI_O32    => "o32",
			EF_MIPS_ABI_O64    => "o64",
			EF_MIPS_ABI_EABI32 => "eabi32",
			EF_MIPS_ABI_EABI64 => "eabi64",

			_ => "unknown ABI",
		}.to_string());
	}

	if (e_flags & EF_MIPS_MACH) != 0 {
		strs.push( match e_flags & EF_MIPS_MACH {
			EF_MIPS_MACH_3900    => "3900",
			EF_MIPS_MACH_4010    => "4010",
			EF_MIPS_MACH_4100    => "4100",
			EF_MIPS_MACH_4650    => "4650",
			EF_MIPS_MACH_4120    => "4120",
			EF_MIPS_MACH_4111    => "4111",
			EF_MIPS_MACH_SB1     => "sb1",
			EF_MIPS_MACH_OCTEON  => "octeon",
			EF_MIPS_MACH_XLR     => "xlr",
			EF_MIPS_MACH_OCTEON2 => "octeon2",
			EF_MIPS_MACH_OCTEON3 => "octeon2",
			EF_MIPS_MACH_5400    => "5400",
			EF_MIPS_MACH_5900    => "5900",
			EF_MIPS_MACH_5500    => "5500",
			EF_MIPS_MACH_9000    => "9000",
			EF_MIPS_MACH_LS2E    => "loonson-2e",
			EF_MIPS_MACH_LS2F    => "loonson-2f",
			EF_MIPS_MACH_LS3A    => "loonson-3a",

			_ => "unknown CPU",
		}.to_string());
	}

	if (e_flags & EF_MIPS_MICROMIPS) != 0     { strs.push("micromips".to_string()); }
	if (e_flags & EF_MIPS_ARCH_ASE_M16) != 0  { strs.push("mips16".to_string());    }
	if (e_flags & EF_MIPS_ARCH_ASE_MDMX) != 0 { strs.push("mdmx".to_string());      }

	strs.push( match e_flags & EF_MIPS_ARCH {
		EF_MIPS_ARCH1     => "mips1",
		EF_MIPS_ARCH2     => "mips2",
		EF_MIPS_ARCH3     => "mips3",
		EF_MIPS_ARCH4     => "mips4",
		EF_MIPS_ARCH5     => "mips5",
		EF_MIPS_ARCH_32   => "mips32",
		EF_MIPS_ARCH_64   => "mips64",
		EF_MIPS_ARCH_32R2 => "mips32r2",
		EF_MIPS_ARCH_64R2 => "mips64r2",
		EF_MIPS_ARCH_32R6 => "mips32r6",
		EF_MIPS_ARCH_64R6 => "mips64r6",

		_ => "unknown ISA",
	}.to_string());

	strs
}

pub fn ehdr_flags_strings(e_machine: u16, e_flags: u32) -> Vec<String> {
	match e_machine {
		EM_MIPS => ehdr_mips_flags_strings(e_flags),

		_ => Vec::<String>::new(),
	}
}

