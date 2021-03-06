extern crate byteorder;

use std::io;

use self::byteorder::{BigEndian, LittleEndian, ReadBytesExt};

use super::{Endianness, Loader, SeekReadStream, Segment};

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


pub const EM_NONE:         u16 = 0;
pub const EM_M32:          u16 = 1;
pub const EM_SPARC:        u16 = 2;
pub const EM_386:          u16 = 3;
pub const EM_68K:          u16 = 4;
pub const EM_88K:          u16 = 5;
pub const EM_486:          u16 = 6;
pub const EM_860:          u16 = 7;
pub const EM_MIPS:         u16 = 8;
pub const EM_S370:         u16 = 9;
pub const EM_MIPS_RS3_LE:  u16 = 10;

pub const EM_PARISC:       u16 = 15;
pub const EM_NCUBE:        u16 = 16;
pub const EM_VPP500:       u16 = 17;
pub const EM_SPARC32PLUS:  u16 = 18;
pub const EM_960:          u16 = 19;
pub const EM_PPC:          u16 = 20;
pub const EM_PPC64:        u16 = 21;
pub const EM_S390:         u16 = 22;
pub const EM_SPU:          u16 = 23;

pub const EM_V800:         u16 = 36;
pub const EM_FR20:         u16 = 37;
pub const EM_RH32:         u16 = 38;
pub const EM_RCE:          u16 = 39;
pub const EM_MCORE:        u16 = EM_RCE;
pub const EM_ARM:          u16 = 40;
pub const EM_OLD_ALPHA:    u16 = 41;
pub const EM_SH:           u16 = 42;
pub const EM_SPARCV9:      u16 = 43;
pub const EM_TRICORE:      u16 = 44;
pub const EM_ARC:          u16 = 45;
pub const EM_H8_300:       u16 = 46;
pub const EM_H8_300H:      u16 = 47;
pub const EM_H8S:          u16 = 48;
pub const EM_H8_500:       u16 = 49;
pub const EM_IA_64:        u16 = 50;
pub const EM_MIPS_X:       u16 = 51;
pub const EM_COLDFIRE:     u16 = 52;
pub const EM_68HC12:       u16 = 53;
pub const EM_MMA:          u16 = 54;
pub const EM_PCP:          u16 = 55;
pub const EM_NCPU:         u16 = 56;
pub const EM_NDR1:         u16 = 57;
pub const EM_STARCORE:     u16 = 58;
pub const EM_ME16:         u16 = 59;
pub const EM_ST100:        u16 = 60;
pub const EM_TINYJ:        u16 = 61;
pub const EM_AMD64:        u16 = 62;
pub const EM_X86_64:       u16 = EM_AMD64;
pub const EM_PDSP:         u16 = 63;

pub const EM_FX66:         u16 = 66;
pub const EM_ST9PLUS:      u16 = 67;
pub const EM_ST7:          u16 = 68;
pub const EM_68HC16:       u16 = 69;
pub const EM_68HC11:       u16 = 70;
pub const EM_68HC08:       u16 = 71;
pub const EM_68HC05:       u16 = 72;
pub const EM_SVX:          u16 = 73;
pub const EM_ST19:         u16 = 74;
pub const EM_VAX:          u16 = 75;
pub const EM_CRIS:         u16 = 76;
pub const EM_JAVELIN:      u16 = 77;
pub const EM_FIREPATH:     u16 = 78;
pub const EM_ZSP:          u16 = 79;
pub const EM_MMIX:         u16 = 80;
pub const EM_HUANY:        u16 = 81;
pub const EM_PRISM:        u16 = 82;
pub const EM_AVR:          u16 = 83;
pub const EM_FR30:         u16 = 84;
pub const EM_D10V:         u16 = 85;
pub const EM_D30V:         u16 = 86;
pub const EM_V850:         u16 = 87;
pub const EM_M32R:         u16 = 88;
pub const EM_MN10300:      u16 = 89;
pub const EM_MN10200:      u16 = 90;
pub const EM_PJ:           u16 = 91;
pub const EM_OPENRISC:     u16 = 92;
pub const EM_ARC_A5:       u16 = 93;
pub const EM_XTENSA:       u16 = 94;

pub const EM_IP2K:         u16 = 101;

pub const EM_CR:           u16 = 103;

pub const EM_MSP430:       u16 = 105;
pub const EM_BLACKFIN:     u16 = 106;

pub const EM_ALTERA_NIOS2: u16 = 113;
pub const EM_CRX:          u16 = 114;

pub const EM_SCORE:        u16 = 135;

pub const EM_AARCH64:      u16 = 183;

pub const EM_CYGNUS_ARC:     u16 = 0x9040;
pub const EM_CYGNUS_D10V:    u16 = 0x7650;
pub const EM_CYGNUS_D30V:    u16 = 0x7676;
pub const EM_CYGNUS_FRV:     u16 = 0x5441;
pub const EM_CYGNUS_FR30:    u16 = 0x3330;
pub const EM_CYGNUS_M32R:    u16 = 0x9041;
pub const EM_CYGNUS_MN10200: u16 = 0xBEEF;
pub const EM_CYGNUS_MN10300: u16 = 0xDEAD;
pub const EM_CYGNUS_POWERPC: u16 = 0x9025;
pub const EM_CYGNUS_V850:    u16 = 0x9080;

pub const EM_AVR_OLD:     u16 = 0x1057;
pub const EM_ALPHA:       u16 = 0x9026;
pub const EM_DLX:         u16 = 0x5AA5;
pub const EM_IP2K_OLD:    u16 = 0x8217;
pub const EM_IQ2000:      u16 = 0xFEBA;
pub const EM_M32C:        u16 = 0xFEB0;
pub const EM_MS1:         u16 = 0x2530;
pub const EM_OLD_SPARCV9: u16 = 11;
pub const EM_OR32:        u16 = 0x8472;
pub const EM_PJ_OLD:      u16 = 99;
pub const EM_PPC_OLD:     u16 = 17;
pub const EM_S390_OLD:    u16 = 0xA390;
pub const EM_XTENSA_OLD:  u16 = 0xABC7;
pub const EM_XSTORMY16:   u16 = 0xAD45;


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

pub const PF_X: u32 = 0x00000001;
pub const PF_W: u32 = 0x00000002;
pub const PF_R: u32 = 0x00000004;

pub const PT_NULL:    u32 = 0;
pub const PT_LOAD:    u32 = 1;
pub const PT_DYNAMIC: u32 = 2;
pub const PT_INTERP:  u32 = 3;
pub const PT_NOTE:    u32 = 4;
pub const PT_SHLIB:   u32 = 5;
pub const PT_PHDR:    u32 = 6;
pub const PT_TLS:     u32 = 7;

pub const PT_LOOS:   u32 = 0x60000000;
pub const PT_HIOS:   u32 = 0x6fffffff;
pub const PT_LOPROC: u32 = 0x70000000;
pub const PT_HIPROC: u32 = 0x7fffffff;

pub const PT_ARM_EXIDX: u32 = PT_LOPROC + 1;

pub const PT_GNU_EH_FRAME: u32 = PT_LOOS + 0x474e550; //'GNU' + 0.  Cute.
pub const PT_GNU_STACK:    u32 = PT_LOOS + 0x474e551;
pub const PT_GNU_RELRO:    u32 = PT_LOOS + 0x474e552;

pub const PT_HP_TLS:           u32 = PT_LOOS + 0x00;
pub const PT_HP_CORE_NONE:     u32 = PT_LOOS + 0x01;
pub const PT_HP_CORE_VERSION:  u32 = PT_LOOS + 0x02;
pub const PT_HP_CORE_KERNEL:   u32 = PT_LOOS + 0x03;
pub const PT_HP_CORE_COMM:     u32 = PT_LOOS + 0x04;
pub const PT_HP_CORE_PROC:     u32 = PT_LOOS + 0x05;
pub const PT_HP_CORE_LOADABLE: u32 = PT_LOOS + 0x06;
pub const PT_HP_CORE_STACK:    u32 = PT_LOOS + 0x07;
pub const PT_HP_CORE_SHM:      u32 = PT_LOOS + 0x08;
pub const PT_HP_CORE_MMF:      u32 = PT_LOOS + 0x09;
pub const PT_HP_PARALLEL:      u32 = PT_LOOS + 0x10;
pub const PT_HP_FASTBIND:      u32 = PT_LOOS + 0x11;
pub const PT_HP_OPT_ANNOT:     u32 = PT_LOOS + 0x12;
pub const PT_HP_HSL_ANNOT:     u32 = PT_LOOS + 0x13;
pub const PT_HP_STACK:         u32 = PT_LOOS + 0x14;
pub const PT_HP_CORE_UTSNAME:  u32 = PT_LOOS + 0x15;

pub const PT_IA_64_ARCHEXT: u32 = PT_LOPROC + 0;
pub const PT_IA_64_UNWIND:  u32 = PT_LOPROC + 1;

pub const PT_IA_64_HP_OPT_ANOT: u32 = PT_HP_OPT_ANNOT;
pub const PT_IA_64_HP_HSL_ANOT: u32 = PT_HP_HSL_ANNOT;
pub const PT_IA_64_HP_STACK:    u32 = PT_HP_STACK;

pub const PT_MIPS_REGINFO: u32 = PT_LOPROC + 0;
pub const PT_MIPS_RTPROC:  u32 = PT_LOPROC + 1;
pub const PT_MIPS_OPTIONS: u32 = PT_LOPROC + 2;

pub const PT_PARISC_ARCHEXT:   u32 = PT_LOPROC + 0;
pub const PT_PARISC_UNWIND:    u32 = PT_LOPROC + 1;
pub const PT_PARISC_WEAKORDER: u32 = PT_LOPROC + 2;

pub const STB_LOCAL:  u8 = 0;
pub const STB_GLOBAL: u8 = 1;
pub const STB_WEAK:   u8 = 2;
pub const STB_LOOS:   u8 = 10;
pub const STB_HIOS:   u8 = 12;
pub const STB_LOPROC: u8 = 13;
pub const STB_HIPROC: u8 = 15;

pub const STT_NOTYPE:  u8 = 0;
pub const STT_OBJECT:  u8 = 1;
pub const STT_FUNC:    u8 = 2;
pub const STT_SECTION: u8 = 3;
pub const STT_FILE:    u8 = 4;
pub const STT_COMMON:  u8 = 5;
pub const STT_TLS:     u8 = 6;
pub const STT_RELC:    u8 = 8;
pub const STT_SRELC:   u8 = 9;
pub const STT_LOOS:    u8 = 10;
pub const STT_HIOS:    u8 = 12;
pub const STT_LOPROC:  u8 = 13;
pub const STT_HIPROC:  u8 = 15;

pub const STT_REGISTER:         u8 = STT_LOPROC + 0;

pub const STT_ARM_TFUNC:        u8 = STT_LOPROC + 0;

pub const STT_HP_OPAQUE:        u8 = STT_LOOS   + 1;
pub const STT_HP_STUB:          u8 = STT_LOOS   + 2;

pub const STT_PARISC_MILLICODE: u8 = STT_LOPROC + 0;

pub const STV_DEFAULT:   u8 = 0;
pub const STV_INTERNAL:  u8 = 1;
pub const STV_HIDDEN:    u8 = 2;
pub const STV_PROTECTED: u8 = 3;

pub const SHT_NULL:          u32 = 0;
pub const SHT_PROGBITS:      u32 = 1;
pub const SHT_SYMTAB:        u32 = 2;
pub const SHT_STRTAB:        u32 = 3;
pub const SHT_RELA:          u32 = 4;
pub const SHT_HASH:          u32 = 5;
pub const SHT_DYNAMIC:       u32 = 6;
pub const SHT_NOTE:          u32 = 7;
pub const SHT_NOBITS:        u32 = 8;
pub const SHT_REL:           u32 = 9;
pub const SHT_SHLIB:         u32 = 10;
pub const SHT_DYNSYM:        u32 = 11;
pub const SHT_INIT_ARRAY:    u32 = 14;
pub const SHT_FINI_ARRAY:    u32 = 15;
pub const SHT_PREINIT_ARRAY: u32 = 16;
pub const SHT_GROUP:         u32 = 17;
pub const SHT_SYMTAB_SHNDX:  u32 = 18;

pub const SHT_LOOS:   u32 = 0x60000000;
pub const SHT_HIOS:   u32 = 0x6FFFFFFF;
pub const SHT_LOPROC: u32 = 0x70000000;
pub const SHT_HIPROC: u32 = 0x7FFFFFFF;
pub const SHT_LOUSER: u32 = 0x80000000;
pub const SHT_HIUSER: u32 = 0xFFFFFFFF;

pub const SHT_GNU_LIBLIST: u32 = SHT_LOOS + 0xFFFFFF7;
pub const SHT_GNU_VERDEF:  u32 = SHT_LOOS + 0xFFFFFFD;
pub const SHT_GNU_VERNEED: u32 = SHT_LOOS + 0xFFFFFFE;
pub const SHT_GNU_VERSYM:  u32 = SHT_LOOS + 0xFFFFFFF;

pub const SHT_ARM_EXIDX:          u32 = SHT_LOPROC + 1;
pub const SHT_ARM_PREEMPTMAP:     u32 = SHT_LOPROC + 2;
pub const SHT_ARM_ATTRIBUTES:     u32 = SHT_LOPROC + 3;
pub const SHT_ARM_DEBUGOVERLAY:   u32 = SHT_LOPROC + 4;
pub const SHT_ARM_OVERLAYSECTION: u32 = SHT_LOPROC + 5;

pub const SHT_MIPS_LIBLIST:       u32 = SHT_LOPROC + 0x00;
pub const SHT_MIPS_MSYM:          u32 = SHT_LOPROC + 0x01;
pub const SHT_MIPS_CONFLICT:      u32 = SHT_LOPROC + 0x02;
pub const SHT_MIPS_GPTAB:         u32 = SHT_LOPROC + 0x03;
pub const SHT_MIPS_UCODE:         u32 = SHT_LOPROC + 0x04;
pub const SHT_MIPS_DEBUG:         u32 = SHT_LOPROC + 0x05;
pub const SHT_MIPS_REGINFO:       u32 = SHT_LOPROC + 0x06;
pub const SHT_MIPS_PACKAGE:       u32 = SHT_LOPROC + 0x07;
pub const SHT_MIPS_PACKSYM:       u32 = SHT_LOPROC + 0x08;
pub const SHT_MIPS_RELD:          u32 = SHT_LOPROC + 0x09;
pub const SHT_MIPS_IFACE:         u32 = SHT_LOPROC + 0x0B;
pub const SHT_MIPS_CONTENT:       u32 = SHT_LOPROC + 0x0C;
pub const SHT_MIPS_OPTIONS:       u32 = SHT_LOPROC + 0x0D;
pub const SHT_MIPS_SHDR:          u32 = SHT_LOPROC + 0x10;
pub const SHT_MIPS_FDESC:         u32 = SHT_LOPROC + 0x11;
pub const SHT_MIPS_EXTSYM:        u32 = SHT_LOPROC + 0x12;
pub const SHT_MIPS_DENSE:         u32 = SHT_LOPROC + 0x13;
pub const SHT_MIPS_PDESC:         u32 = SHT_LOPROC + 0x14;
pub const SHT_MIPS_LOCSYM:        u32 = SHT_LOPROC + 0x15;
pub const SHT_MIPS_AUXSYM:        u32 = SHT_LOPROC + 0x16;
pub const SHT_MIPS_OPTSYM:        u32 = SHT_LOPROC + 0x17;
pub const SHT_MIPS_LOCSTR:        u32 = SHT_LOPROC + 0x18;
pub const SHT_MIPS_LINE:          u32 = SHT_LOPROC + 0x19;
pub const SHT_MIPS_RFDESC:        u32 = SHT_LOPROC + 0x1A;
pub const SHT_MIPS_DELTASYM:      u32 = SHT_LOPROC + 0x1B;
pub const SHT_MIPS_DELTAINST:     u32 = SHT_LOPROC + 0x1C;
pub const SHT_MIPS_DELTACLASS:    u32 = SHT_LOPROC + 0x1D;
pub const SHT_MIPS_DWARF:         u32 = SHT_LOPROC + 0x1E;
pub const SHT_MIPS_DELTADECL:     u32 = SHT_LOPROC + 0x1F;
pub const SHT_MIPS_SYMBOL_LIB:    u32 = SHT_LOPROC + 0x20;
pub const SHT_MIPS_EVENTS:        u32 = SHT_LOPROC + 0x21;
pub const SHT_MIPS_TRANSLATE:     u32 = SHT_LOPROC + 0x22;
pub const SHT_MIPS_PIXIE:         u32 = SHT_LOPROC + 0x23;
pub const SHT_MIPS_XLATE:         u32 = SHT_LOPROC + 0x24;
pub const SHT_MIPS_XLATE_DEBUG:   u32 = SHT_LOPROC + 0x25;
pub const SHT_MIPS_WHIRL:         u32 = SHT_LOPROC + 0x26;
pub const SHT_MIPS_EH_REGION:     u32 = SHT_LOPROC + 0x27;
pub const SHT_MIPS_XLATE_OLD:     u32 = SHT_LOPROC + 0x28;
pub const SHT_MIPS_PDR_EXCEPTION: u32 = SHT_LOPROC + 0x29;
pub const SHT_MIPS_ABIFLAGS:      u32 = SHT_LOPROC + 0x2A;

pub const SHT_IA_64_EXT:           u32 = SHT_LOPROC + 0;
pub const SHT_IA_64_UNWIND:        u32 = SHT_LOPROC + 1;
pub const SHT_IA_64_LOSPREG:       u32 = SHT_LOPROC + 0x8000000;
pub const SHT_IA_64_HISPREG:       u32 = SHT_LOPROC + 0x8FFFFFF;
pub const SHT_IA_64_PRIORITY_INIT: u32 = SHT_LOPROC + 0x9000000;

pub const SHT_PARISC_EXT:     u32 = SHT_LOPROC + 0;
pub const SHT_PARISC_UNWIND:  u32 = SHT_LOPROC + 1;
pub const SHT_PARISC_DOC:     u32 = SHT_LOPROC + 2;
pub const SHT_PARISC_ANNOT:   u32 = SHT_LOPROC + 3;
pub const SHT_PARISC_DLKM:    u32 = SHT_LOPROC + 4;
pub const SHT_PARISC_SYMEXTN: u32 = SHT_LOPROC + 8;
pub const SHT_PARISC_STUBS:   u32 = SHT_LOPROC + 9;

pub const SHT_X86_64_UNWIND: u32 = SHT_LOPROC + 1;

pub const SHF_WRITE:     u64 = 0x00000001;
pub const SHF_ALLOC:     u64 = 0x00000002;
pub const SHF_EXECINSTR: u64 = 0x00000004;
pub const SHF_TLS:       u64 = 0x00000400;

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
pub struct ElfPhdr {
	pub p_type: u32,
	pub p_flags: u32,
	pub p_offset: u64,
	pub p_vaddr: u64,
	pub p_paddr: u64,
	pub p_filesz: u64,
	pub p_memsz: u64,
	pub p_align: u64
}

impl ElfPhdr {
	pub fn flags_string(&self) -> String {
		phdr_flags_string(self.p_flags)
	}

	pub fn type_string(&self, e_machine: u16) -> String {
		phdr_type_string(self.p_type, e_machine)
	}
}

#[derive(Default)]
pub struct ElfSym {
	pub st_name: u32,
	pub st_info: u8,
	pub st_other: u8,
	pub st_shndx: u16,
	pub st_value: u64,
	pub st_size: u64,
}

impl ElfSym {
	pub fn st_type(&self) -> u8 {
		sym_type_from_info(self.st_info)
	}

	pub fn st_bind(&self) -> u8 {
		sym_bind_from_info(self.st_info)
	}

	pub fn st_visibility(&self) -> u8 {
		sym_visibility_from_other(self.st_other)
	}

	pub fn shndx_string(&self) -> String {
		sym_shndx_string(self.st_shndx)
	}

	pub fn type_string(&self, e_machine: u16) -> String {
		sym_type_string(self.st_type(), e_machine)
	}

	pub fn bind_string(&self) -> String {
		sym_bind_string(self.st_bind())
	}

	pub fn visibility_string(&self) -> String {
		sym_visibility_string(self.st_visibility())
	}
}

#[derive(Default)]
pub struct ElfStrtab {
	pub shnum: u16,
	pub data: Vec<u8>,
}

impl ElfStrtab {
	pub fn read_str(&self, offset: u32) -> Option<String> {
		let mut cur_off = offset as usize;

		if cur_off >= self.data.len() {
			return None;
		}

		let mut value = String::new();

		while (cur_off <= self.data.len()) && (self.data[cur_off] != 0) {
			value.push(self.data[cur_off] as char);
			cur_off += 1;
		}

		Some(value)
	}
}

#[derive(Default)]
pub struct ElfShdr {
	pub sh_name: u32,
	pub sh_type: u32,
	pub sh_flags: u64,
	pub sh_addr: u64,
	pub sh_offset: u64,
	pub sh_size: u64,
	pub sh_link: u32,
	pub sh_info: u32,
	pub sh_addralign: u64,
	pub sh_entsize: u64,
}

impl ElfShdr {
	pub fn type_string(&self, e_machine: u16) -> String {
		shdr_type_string(self.sh_type, e_machine)
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

	pub phdrs: Vec<ElfPhdr>,
	pub shdrs: Vec<ElfShdr>,

	pub strtab: ElfStrtab,
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

			phdrs: Vec::new(),
			shdrs: Vec::new(),

			strtab: ElfStrtab::default(),
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

	fn read_u8(&self, rdr: &mut SeekReadStream) -> Result<u8, ElfParseError> {
		Ok(match rdr.read_u8() {
			Ok(byte) => byte,
			Err(_) => return Err(ElfParseError::InvalidIdent),
		})
	}

	fn read_u16(&self, rdr: &mut SeekReadStream) -> Result<u16, ElfParseError> {
		Ok(match self.e_ident[EI_DATA] {
			ELFDATA2LSB => try!(rdr.read_u16::<LittleEndian>()),
			ELFDATA2MSB => try!(rdr.read_u16::<BigEndian>()),
			_ => {
				return Err(ElfParseError::InvalidIdent);
			},
		})
	}

	fn read_u32(&self, rdr: &mut SeekReadStream) -> Result<u32, ElfParseError> {
		Ok(match self.e_ident[EI_DATA] {
			ELFDATA2LSB => try!(rdr.read_u32::<LittleEndian>()),
			ELFDATA2MSB => try!(rdr.read_u32::<BigEndian>()),
			_ => {
				return Err(ElfParseError::InvalidIdent);
			},
		})
	}

	fn read_u64(&self, rdr: &mut SeekReadStream) -> Result<u64, ElfParseError> {
		Ok(match self.e_ident[EI_DATA] {
			ELFDATA2LSB => try!(rdr.read_u64::<LittleEndian>()),
			ELFDATA2MSB => try!(rdr.read_u64::<BigEndian>()),
			_ => {
				return Err(ElfParseError::InvalidIdent);
			},
		})
	}

	pub fn read(rdr: &mut SeekReadStream) -> Result<ElfFile, ElfParseError> {
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

		for n in 0..elf.e_phnum as u64 {
			let offset = elf.e_phoff + (n * (elf.e_phentsize as u64));
			try!(rdr.seek(io::SeekFrom::Start(offset)));

			let mut phdr = ElfPhdr::default();

			match elf.e_ident[EI_CLASS] {
				ELFCLASS32 => {
					phdr.p_type   = try!(elf.read_u32(rdr));
					phdr.p_offset = try!(elf.read_u32(rdr)) as u64;
					phdr.p_vaddr  = try!(elf.read_u32(rdr)) as u64;
					phdr.p_paddr  = try!(elf.read_u32(rdr)) as u64;
					phdr.p_filesz = try!(elf.read_u32(rdr)) as u64;
					phdr.p_memsz  = try!(elf.read_u32(rdr)) as u64;
					phdr.p_flags  = try!(elf.read_u32(rdr));
					phdr.p_align  = try!(elf.read_u32(rdr)) as u64;
				},

				ELFCLASS64 => {
					phdr.p_type   = try!(elf.read_u32(rdr));
					phdr.p_flags  = try!(elf.read_u32(rdr));
					phdr.p_offset = try!(elf.read_u64(rdr));
					phdr.p_vaddr  = try!(elf.read_u64(rdr));
					phdr.p_paddr  = try!(elf.read_u64(rdr));
					phdr.p_filesz = try!(elf.read_u64(rdr));
					phdr.p_memsz  = try!(elf.read_u64(rdr));
					phdr.p_align  = try!(elf.read_u64(rdr));
				},

				_ => {
					return Err(ElfParseError::InvalidIdent);
				},
			}

			elf.phdrs.push( phdr );
		}

		for n in 0..elf.e_shnum as u64 {
			let offset = elf.e_shoff + (n * (elf.e_shentsize as u64));
			try!(rdr.seek(io::SeekFrom::Start(offset)));

			let mut shdr = ElfShdr::default();

			match elf.e_ident[EI_CLASS] {
				ELFCLASS32 => {
					shdr.sh_name      = try!(elf.read_u32(rdr));
					shdr.sh_type      = try!(elf.read_u32(rdr));
					shdr.sh_flags     = try!(elf.read_u32(rdr)) as u64;
					shdr.sh_addr      = try!(elf.read_u32(rdr)) as u64;
					shdr.sh_offset    = try!(elf.read_u32(rdr)) as u64;
					shdr.sh_size      = try!(elf.read_u32(rdr)) as u64;
					shdr.sh_link      = try!(elf.read_u32(rdr));
					shdr.sh_info      = try!(elf.read_u32(rdr));
					shdr.sh_addralign = try!(elf.read_u32(rdr)) as u64;
					shdr.sh_entsize   = try!(elf.read_u32(rdr)) as u64;
				},

				ELFCLASS64 => {
					shdr.sh_name      = try!(elf.read_u32(rdr));
					shdr.sh_type      = try!(elf.read_u32(rdr));
					shdr.sh_flags     = try!(elf.read_u64(rdr));
					shdr.sh_addr      = try!(elf.read_u64(rdr));
					shdr.sh_offset    = try!(elf.read_u64(rdr));
					shdr.sh_size      = try!(elf.read_u64(rdr));
					shdr.sh_link      = try!(elf.read_u32(rdr));
					shdr.sh_info      = try!(elf.read_u32(rdr));
					shdr.sh_addralign = try!(elf.read_u64(rdr));
					shdr.sh_entsize   = try!(elf.read_u64(rdr));
				},

				_ => {
					return Err(ElfParseError::InvalidIdent);
				},
			}

			elf.shdrs.push( shdr );
		}

		elf.strtab = try!(elf.read_section_as_strtab(elf.e_shstrndx, rdr));

		Ok(elf)
	}

	pub fn read_symbols(&self, rdr: &mut SeekReadStream) -> Result<Vec<(String, u16, Vec<ElfSym>)>, ElfParseError>
	{
		let mut symtabs: Vec<(String, u16, Vec<ElfSym>)> = Vec::new();
		let mut cur_section_num: u16 = 0;

		for shdr in self.shdrs.iter() {
			let mut syms: Vec<ElfSym> = Vec::new();

			if shdr.sh_type != SHT_SYMTAB && shdr.sh_type != SHT_DYNSYM {
				cur_section_num += 1;
				continue;
			}

			let section_data = try!(self.read_section_data(cur_section_num, rdr));
			let section_len = section_data.len() as u64;

			let mut buffer = io::Cursor::new(section_data);

			while buffer.position() != section_len {
				let mut sym = ElfSym::default();

				match self.e_ident[EI_CLASS] {
					ELFCLASS32 => {
						sym.st_name  = try!(self.read_u32(&mut buffer));
						sym.st_value = try!(self.read_u32(&mut buffer)) as u64;
						sym.st_size  = try!(self.read_u32(&mut buffer)) as u64;
						sym.st_info  = try!(self.read_u8(&mut buffer));
						sym.st_other = try!(self.read_u8(&mut buffer));
						sym.st_shndx = try!(self.read_u16(&mut buffer));
					},

					ELFCLASS64 => {
						sym.st_name  = try!(self.read_u32(&mut buffer));
						sym.st_info  = try!(self.read_u8(&mut buffer));
						sym.st_other = try!(self.read_u8(&mut buffer));
						sym.st_shndx = try!(self.read_u16(&mut buffer));
						sym.st_value = try!(self.read_u64(&mut buffer));
						sym.st_size  = try!(self.read_u64(&mut buffer));
					},

					_ => {
						return Err(ElfParseError::InvalidIdent);
					},
				}

				syms.push( sym );
			}

			let cur_section_name = match self.strtab.read_str(shdr.sh_name) {
				Some(name) => name,
				None       => format!(""),
			};

			symtabs.push((cur_section_name, cur_section_num, syms));
			cur_section_num += 1;
		}

		Ok(symtabs)
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

	pub fn read_section_data(&self, shnum: u16, stream: &mut SeekReadStream) -> Result<Vec<u8>, io::Error> {
		let shdr = match self.shdrs.get(shnum as usize) {
			Some(x) => x,
			None    => {
				return Err(io::Error::new(io::ErrorKind::Other, format!("Section number {} out of bounds (max={})", shnum, self.e_shnum)));
			},
		};

		try!(stream.seek(io::SeekFrom::Start(shdr.sh_offset)));

		let mut data = vec![0u8; shdr.sh_size as usize];

		try!(stream.read(data.as_mut_slice()));

		Ok(data)
	}

	pub fn read_section_as_strtab(&self, shnum: u16, stream: &mut SeekReadStream) -> Result<ElfStrtab, io::Error> {
		let data = try!(self.read_section_data(shnum, stream));

		Ok(ElfStrtab{ shnum: shnum, data: data })
	}
}

#[derive(PartialEq)]
pub enum ElfLoadFrom {
	ProgramHeaders,
	SectionHeaders,
}

impl Default for ElfLoadFrom {
	fn default() -> ElfLoadFrom { ElfLoadFrom::ProgramHeaders }
}

pub struct ElfLoader {
	pub elf:       ElfFile,
	pub load_from: ElfLoadFrom,
}


impl ElfLoader {
	pub fn new(elf: ElfFile) -> ElfLoader {
		ElfLoader {
			elf: elf,
			load_from: ElfLoadFrom::default(),
		}
	}
}

impl Loader for ElfLoader {
	fn entry_point(&self) -> Option<u64> {
		Some(self.elf.e_entry)
	}

	#[allow(unused_variables)]
	fn get_segments(&self, filter: &Fn(&Segment) -> bool, stream: &mut SeekReadStream) -> Result<Vec<(Segment, Vec<u8>)>, io::Error> {
		let mut ret_vec: Vec<(Segment, Vec<u8>)> = Vec::new();

		if self.load_from == ElfLoadFrom::SectionHeaders {
			let mut cur_sec_num: u16 = 0;
			for shdr in self.elf.shdrs.iter() {
				let segment = Segment {
					name: match self.elf.strtab.read_str(shdr.sh_name) {
						Some(x) => x,
						None    => format!(""),
					},
					load_base: shdr.sh_addr,
					stream_base: shdr.sh_offset,
					file_size: if shdr.sh_type == SHT_NOBITS { 0 } else { shdr.sh_size },
					mem_size: shdr.sh_size,
					read_only: (shdr.sh_flags & SHF_WRITE) != 0,
					executable: (shdr.sh_flags & SHF_EXECINSTR) != 0,
					present_when_loaded: (shdr.sh_flags & SHF_ALLOC) != 0,
				};

				if filter(&segment) {
					ret_vec.push((segment, try!(self.elf.read_section_data(cur_sec_num, stream))));
				}
				cur_sec_num += 1;
			}
		} else {
			return Err(io::Error::new(io::ErrorKind::Other, "get_segments from ProgramHeader unimplemented"));
		}

		Ok(ret_vec)
	}

	fn get_segment_metadata(&self,) -> Result<Vec<Segment>, io::Error> {
		let mut ret_vec: Vec<Segment> = Vec::new();

		if self.load_from == ElfLoadFrom::ProgramHeaders {
			let mut cur_seg_num: u16 = 0;
			for phdr in self.elf.phdrs.iter() {
				ret_vec.push(Segment {
					name: format!("phdr[{}]", cur_seg_num),
					load_base: phdr.p_paddr,
					stream_base: phdr.p_offset,
					file_size: phdr.p_filesz,
					mem_size: phdr.p_memsz,
					read_only: !((phdr.p_flags & PF_W) != 0),
					executable: (phdr.p_flags & PF_X) != 0,
					present_when_loaded: (phdr.p_type == PT_LOAD),
				});

				cur_seg_num += 1;
			}
		} else {
			return Err(io::Error::new(io::ErrorKind::Other, "get_segment_metadata from SectionHeader unimplemented"));
		}

		Ok(ret_vec)
	}

	fn fmt_str(&self) -> String {
		let fmt = match self.elf.e_ident[EI_CLASS] {
			ELFCLASS32 => "elf32".to_string(),
			ELFCLASS64 => "elf64".to_string(),
			_          => "elfunknownclass".to_string(),
		};

		let machine = match (self.elf.e_machine, self.elf.e_ident[EI_DATA]) {
			(EM_PPC, _) | (EM_PPC64, _) | (EM_PPC_OLD, _) => "powerpc".to_string(),

			(EM_MIPS, ELFDATA2MSB) => "tradbigmips".to_string(),
			(EM_MIPS, ELFDATA2LSB) => "tradlittlemips".to_string(),

			(_, _)  => format!("unknown_machine_{:#x}", self.elf.e_machine),
		};

		fmt + "-" + machine.as_ref()
	}

	fn endianness(&self) -> Option<Endianness> {
		match self.elf.e_ident[EI_DATA] {
			ELFDATA2MSB => Some(Endianness::Big),
			ELFDATA2LSB => Some(Endianness::Little),
			_           => None,
		}
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
		ELFOSABI_GNU        => "UNIX - GNU",
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
		EM_NONE => "None",

		EM_386         => "Intel 80386",
		EM_486         => "Intel 80486",
		EM_68HC05      => "Motorola M68HC05 Microcontroller",
		EM_68HC08      => "Motorola M68HC08 Microcontroller",
		EM_68HC11      => "Motorola M68HC11 Microcontroller",
		EM_68HC12      => "Motorola M68HC12",
		EM_68HC16      => "Motorola M68HC16 Microcontroller",
		EM_68K         => "MC68000",
		EM_88K         => "MC88000",
		EM_960         => "Intel 90860",
		EM_AARCH64     => "AArch64",
		EM_ALPHA       => "Alpha",
		EM_ARC         => "ARC",
		EM_ARM         => "ARM",
		EM_COLDFIRE    => "Motorola Coldfire",
		EM_CRIS        => "Axis Communications 32-bit embedded processor",
		EM_CRX         => "National Semiconductor CRX microprocesor",
		EM_DLX         => "OpenDLX",
		EM_FIREPATH    => "Element 14 64-bit DSP processor",
		EM_FR20        => "Fujuitsu FR20",
		EM_FX66        => "Siemens FX66 microcontroller",
		EM_H8S         => "Renesas H8S",
		EM_H8_300      => "Renesas H8/300",
		EM_H8_300H     => "Renesas H8/300H",
		EM_H8_500      => "Renesas H8/500",
		EM_HUANY       => "Harvard University's machine-independent object format",
		EM_IA_64       => "Intel IA-64",
		EM_IQ2000      => "Vitesse IQ2000",
		EM_JAVELIN     => "Infineon Technologies 32-bit embedded cpu",
		EM_M32         => "WE32100",
		EM_M32C        => "Renesas M32c",
		EM_MCORE       => "MCORE",
		EM_ME16        => "Toyota ME16 processor",
		EM_MIPS        => "MIPS R3000",
		EM_MIPS_RS3_LE => "MIPS R4000 big-endian",
		EM_MIPS_X      => "Stanford MIPS-X",
		EM_MMA         => "Fujitsu Multimedia Accelerator",
		EM_MMIX        => "Donald Knuth's educational 64-bit processor",
		EM_MS1         => "Morpho Technologies MS1 processor",
		EM_NCPU        => "Sony nCPU embedded RISC Processor",
		EM_NDR1        => "Denso NDR1 microprocessor",
		EM_OLD_ALPHA   => "Digital Alpha (old)",
		EM_OLD_SPARCV9 => "Sparc v9 (old)",
		EM_PARISC      => "HPPA",
		EM_PCP         => "Siemens PCP",
		EM_PPC         => "PowerPC",
		EM_PPC64       => "PowerPC64",
		EM_PPC_OLD     => "Power PC (old)",
		EM_PRISM       => "Vitesse Prism",
		EM_RH32        => "TRW RH32",
		EM_SPARC       => "Sparc",
		EM_SPARC32PLUS => "Sparc v8+",
		EM_SPARCV9     => "Sparc v9",
		EM_ST100       => "STMicroelectronics ST100 processor",
		EM_ST19        => "STMicroelectronics ST19 8-bit microcontroller",
		EM_ST7         => "STMicroelectronics ST7 8-bit microcontroller",
		EM_ST9PLUS     => "STMicroelectroings ST9+ 8/16 bit microcontroller",
		EM_STARCORE    => "Motorola Star*Core processor",
		EM_S370        => "IBM System/370",
		EM_SH          => "Renesas / SuperH SH",
		EM_SVX         => "Silicon Graphics SVx",
		EM_TINYJ       => "Advanced Logic Corp. TinyJ embedded processor",
		EM_TRICORE     => "Siemens Tricore",
		EM_V800        => "NEC V800",
		EM_VAX         => "Digital VAX",
		EM_X86_64      => "Advanced Micro Devices X86-64",
		EM_XSTORMY16   => "Sanyo Xstormy16 CPU core",
		EM_ZSP         => "LSI Logic's 16-bit DSP processor",

		EM_CYGNUS_FRV => "Fujitsu FR-V",

		EM_CYGNUS_D10V | EM_D10V => "d10v",
		EM_CYGNUS_D30V | EM_D30V => "d30v",
		EM_CYGNUS_FR30 | EM_FR30 => "Fujitsu FR30",
		EM_CYGNUS_M32R | EM_M32R => "Renesas M32R (formerly Mitsubishi M32r)",
		EM_CYGNUS_V850 | EM_V850 => "NEC v850",

		EM_CYGNUS_MN10200 | EM_MN10200 => "mn10200",
		EM_CYGNUS_MN10300 | EM_MN10300 => "mn10300",

		EM_AVR_OLD    | EM_AVR  => "Atmel AVR 8-bit microcontroller",
		EM_IP2K_OLD   | EM_IP2K => "Ubicom IP2xxx 8-bit microcontrollers",
		EM_PJ_OLD     | EM_PJ   => "picoJava",
		EM_OPENRISC   | EM_OR32 => "OpenRISC",
		EM_S390_OLD   | EM_S390 => "IBM S/390",
		EM_XTENSA_OLD | EM_XTENSA => "Tensilica Xtensa Processor",

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

pub fn phdr_flags_string(p_flags: u32) -> String {
	format!("{}{}{}",
		if (p_flags & PF_R) != 0 { "R" } else { " " },
		if (p_flags & PF_W) != 0 { "W" } else { " " },
		if (p_flags & PF_X) != 0 { "E" } else { " " })
}

pub fn phdr_type_string(p_type: u32, e_machine: u16) -> String {
	match (p_type, e_machine) {
		(PT_NULL,         _) => "NULL",
		(PT_LOAD,         _) => "LOAD",
		(PT_DYNAMIC,      _) => "DYNAMIC",
		(PT_INTERP,       _) => "INTERP",
		(PT_NOTE,         _) => "NOTE",
		(PT_SHLIB,        _) => "SHLIB",
		(PT_PHDR,         _) => "PHDR",
		(PT_TLS,          _) => "TLS",
		(PT_GNU_EH_FRAME, _) => "GNU_EH_FRAME",
		(PT_GNU_STACK,    _) => "GNU_STACK",
		(PT_GNU_RELRO,    _) => "GNU_RELRO",

		(PT_ARM_EXIDX, EM_ARM) => "EXIDX",

		(PT_MIPS_REGINFO, EM_MIPS) | (PT_MIPS_REGINFO, EM_MIPS_RS3_LE) => "REGINFO",
		(PT_MIPS_RTPROC,  EM_MIPS) | (PT_MIPS_RTPROC,  EM_MIPS_RS3_LE) => "RTPROC",
		(PT_MIPS_OPTIONS, EM_MIPS) | (PT_MIPS_OPTIONS, EM_MIPS_RS3_LE) => "OPTIONS",

		(PT_HP_TLS,           EM_PARISC) => "HP_TLS",
		(PT_HP_CORE_NONE,     EM_PARISC) => "HP_CORE_NONE",
		(PT_HP_CORE_VERSION,  EM_PARISC) => "HP_CORE_VERSION",
		(PT_HP_CORE_KERNEL,   EM_PARISC) => "HP_CORE_KERNEL",
		(PT_HP_CORE_COMM,     EM_PARISC) => "HP_CORE_COMM",
		(PT_HP_CORE_PROC,     EM_PARISC) => "HP_CORE_PROC",
		(PT_HP_CORE_LOADABLE, EM_PARISC) => "HP_CORE_LOADABLE",
		(PT_HP_CORE_STACK,    EM_PARISC) => "HP_CORE_STACK",
		(PT_HP_CORE_SHM,      EM_PARISC) => "HP_CORE_SHM",
		(PT_HP_CORE_MMF,      EM_PARISC) => "HP_CORE_MMF",
		(PT_HP_PARALLEL,      EM_PARISC) => "HP_PARALLEL",
		(PT_HP_FASTBIND,      EM_PARISC) => "HP_FASTBIND",
		(PT_HP_OPT_ANNOT,     EM_PARISC) => "HP_OPT_ANNOT",
		(PT_HP_HSL_ANNOT,     EM_PARISC) => "HP_HSL_ANNOT",
		(PT_HP_STACK,         EM_PARISC) => "HP_STACK",
		(PT_HP_CORE_UTSNAME,  EM_PARISC) => "HP_CORE_UTSNAME",
		(PT_PARISC_ARCHEXT,   EM_PARISC) => "PARISC_ARCHEXT",
		(PT_PARISC_UNWIND,    EM_PARISC) => "PARISC_UNWIND",
		(PT_PARISC_WEAKORDER, EM_PARISC) => "PARISC_WEAKORDER",

		(PT_IA_64_ARCHEXT,     EM_IA_64) => "IA_64_ARCHEXT",
		(PT_IA_64_UNWIND,      EM_IA_64) => "IA_64_UNWIND",
		(PT_HP_TLS,            EM_IA_64) => "HP_TLS",
		(PT_IA_64_HP_OPT_ANOT, EM_IA_64) => "HP_OPT_ANNOT",
		(PT_IA_64_HP_HSL_ANOT, EM_IA_64) => "HP_HSL_ANNOT",
		(PT_IA_64_HP_STACK,    EM_IA_64) => "HP_STACK",

		(PT_LOPROC ... PT_HIPROC, _) => return format!("LOPROC+{:x}", p_type - PT_LOPROC),
		(PT_LOOS   ... PT_HIOS,   _) => return format!("LOOS+{:x}", p_type - PT_LOOS),
		(_, _)                       => return format!("<unknown>: {:x}", p_type),
	}.to_string()
}

pub fn sym_bind_from_info(info: u8) -> u8 {
	info >> 4
}

pub fn sym_type_from_info(info: u8) -> u8 {
	info & 0x0F
}

pub fn sym_visibility_from_other(other: u8) -> u8 {
	other & 0x7
}

pub fn sym_shndx_string(st_shndx: u16) -> String {
	match st_shndx {
		0      => "UND".to_string(),
		0xFFF1 => "ABS".to_string(),
		shndx  => format!("{}", shndx),
	}
}

pub fn sym_bind_string(stt_bind: u8) -> String {
	match stt_bind {
		STB_LOCAL                 => "LOCAL",
		STB_GLOBAL                => "GLOBAL",
		STB_WEAK                  => "WEAK",
		STB_LOOS   ... STB_HIOS   => return format!("<OS specific>: {}", stt_bind),
		STB_LOPROC ... STB_HIPROC => return format!("<processor specific>: {}", stt_bind),
		_                         => return format!("<unknown>: {}", stt_bind),
	}.to_string()
}

pub fn sym_type_string(stt_type: u8, e_machine: u16) -> String {
	match (stt_type, e_machine) {
		(STT_NOTYPE,           _)          => "NOTYPE",
		(STT_OBJECT,           _)          => "OBJECT",
		(STT_FUNC,             _)          => "FUNC",
		(STT_SECTION,          _)          => "SECTION",
		(STT_FILE,             _)          => "FILE",
		(STT_COMMON,           _)          => "COMMON",
		(STT_TLS,              _)          => "TLS",
		(STT_RELC,             _)          => "RELC",
		(STT_SRELC,            _)          => "SRELC",
		(STT_ARM_TFUNC,        EM_ARM)     => "THUMB_FUNC",
		(STT_HP_OPAQUE,        EM_PARISC)  => "HP_OPAQUE",
		(STT_HP_STUB,          EM_PARISC)  => "HP_STUB",
		(STT_PARISC_MILLICODE, EM_PARISC)  => "PARISC_MILLI",
		(STT_REGISTER,         EM_SPARCV9) => "REGISTER",
		(STT_LOPROC ... STT_HIPROC, _) => return format!("<processor specific>: {}", stt_type),
		(STT_LOOS   ... STT_HIOS,   _) => return format!("<OS specifc: {}", stt_type),
		(_, _)                         => return format!("<unknown>: {}", stt_type),
	}.to_string()
}

pub fn sym_visibility_string(stt_visibility: u8) -> String {
	match stt_visibility {
		STV_DEFAULT   => "DEFAULT",
		STV_INTERNAL  => "INTERNAL",
		STV_HIDDEN    => "HIDDEN",
		STV_PROTECTED => "PROTECTED",
		_             => return format!("<unknown>: {}", stt_visibility),
	}.to_string()
}

pub fn shdr_type_string(sh_type: u32, e_machine: u16) -> String {
	match (sh_type, e_machine) {
		(SHT_NULL,          _) => "NULL",
		(SHT_PROGBITS,      _) => "PROGBITS",
		(SHT_SYMTAB,        _) => "SYMTAB",
		(SHT_STRTAB,        _) => "STRTAB",
		(SHT_RELA,          _) => "RELA",
		(SHT_HASH,          _) => "HASH",
		(SHT_DYNAMIC,       _) => "DYNAMIC",
		(SHT_NOTE,          _) => "NOTE",
		(SHT_NOBITS,        _) => "NOBITS",
		(SHT_REL,           _) => "REL",
		(SHT_SHLIB,         _) => "SHLIB",
		(SHT_DYNSYM,        _) => "DYNSYM",
		(SHT_INIT_ARRAY,    _) => "INIT_ARRAY",
		(SHT_FINI_ARRAY,    _) => "FINI_ARRAY",
		(SHT_PREINIT_ARRAY, _) => "PREINIT_ARRAY",
		(SHT_GROUP,         _) => "GROUP",
		(SHT_SYMTAB_SHNDX,  _) => "SYMTAB SECTION INDICIES",
		(SHT_GNU_VERDEF,    _) => "VERDEF",
		(SHT_GNU_VERNEED,   _) => "VERNEED",
		(SHT_GNU_VERSYM,    _) => "VERSYM",
		(0x6FFFFFF0,        _) => "VERSYM",
		(0x6FFFFFFC,        _) => "VERDEF",
		(0x7FFFFFFD,        _) => "AUXILIARY",
		(0x7FFFFFFF,        _) => "FILTER",
		(SHT_GNU_LIBLIST,   _) => "GNU_LIBLIST",

		(SHT_ARM_EXIDX,          EM_ARM) => "ARM_EXIDX",
		(SHT_ARM_PREEMPTMAP,     EM_ARM) => "ARM_PREEMPTMAP",
		(SHT_ARM_ATTRIBUTES,     EM_ARM) => "ARM_ATTRIBUTES",
		(SHT_ARM_DEBUGOVERLAY,   EM_ARM) => "ARM_DEBUGOVERLAY",
		(SHT_ARM_OVERLAYSECTION, EM_ARM) => "ARM_OVERLAYSECTION",

		(SHT_IA_64_EXT,           EM_IA_64) => "IA_64_EXT",
		(SHT_IA_64_UNWIND,        EM_IA_64) => "IA_64_UNWIND",
		(SHT_IA_64_PRIORITY_INIT, EM_IA_64) => "IA_64_PRIORITY_INIT",

		(SHT_MIPS_LIBLIST,       EM_MIPS) | (SHT_MIPS_LIBLIST,       EM_MIPS_RS3_LE) => "MIPS_LIBLIST",
		(SHT_MIPS_MSYM,          EM_MIPS) | (SHT_MIPS_MSYM,          EM_MIPS_RS3_LE) => "MIPS_MSYM",
		(SHT_MIPS_CONFLICT,      EM_MIPS) | (SHT_MIPS_CONFLICT,      EM_MIPS_RS3_LE) => "MIPS_CONFLICT",
		(SHT_MIPS_GPTAB,         EM_MIPS) | (SHT_MIPS_GPTAB,         EM_MIPS_RS3_LE) => "MIPS_GPTAB",
		(SHT_MIPS_UCODE,         EM_MIPS) | (SHT_MIPS_UCODE,         EM_MIPS_RS3_LE) => "MIPS_UCODE",
		(SHT_MIPS_DEBUG,         EM_MIPS) | (SHT_MIPS_DEBUG,         EM_MIPS_RS3_LE) => "MIPS_DEBUG",
		(SHT_MIPS_REGINFO,       EM_MIPS) | (SHT_MIPS_REGINFO,       EM_MIPS_RS3_LE) => "MIPS_REGINFO",
		(SHT_MIPS_PACKAGE,       EM_MIPS) | (SHT_MIPS_PACKAGE,       EM_MIPS_RS3_LE) => "MIPS_PACKAGE",
		(SHT_MIPS_PACKSYM,       EM_MIPS) | (SHT_MIPS_PACKSYM,       EM_MIPS_RS3_LE) => "MIPS_PACKSYM",
		(SHT_MIPS_RELD,          EM_MIPS) | (SHT_MIPS_RELD,          EM_MIPS_RS3_LE) => "MIPS_RELD",
		(SHT_MIPS_IFACE,         EM_MIPS) | (SHT_MIPS_IFACE,         EM_MIPS_RS3_LE) => "MIPS_IFACE",
		(SHT_MIPS_CONTENT,       EM_MIPS) | (SHT_MIPS_CONTENT,       EM_MIPS_RS3_LE) => "MIPS_CONTENT",
		(SHT_MIPS_OPTIONS,       EM_MIPS) | (SHT_MIPS_OPTIONS,       EM_MIPS_RS3_LE) => "MIPS_OPTIONS",
		(SHT_MIPS_SHDR,          EM_MIPS) | (SHT_MIPS_SHDR,          EM_MIPS_RS3_LE) => "MIPS_SHDR",
		(SHT_MIPS_FDESC,         EM_MIPS) | (SHT_MIPS_FDESC,         EM_MIPS_RS3_LE) => "MIPS_FDESC",
		(SHT_MIPS_EXTSYM,        EM_MIPS) | (SHT_MIPS_EXTSYM,        EM_MIPS_RS3_LE) => "MIPS_EXTSYM",
		(SHT_MIPS_DENSE,         EM_MIPS) | (SHT_MIPS_DENSE,         EM_MIPS_RS3_LE) => "MIPS_DENSE",
		(SHT_MIPS_PDESC,         EM_MIPS) | (SHT_MIPS_PDESC,         EM_MIPS_RS3_LE) => "MIPS_PDESC",
		(SHT_MIPS_LOCSYM,        EM_MIPS) | (SHT_MIPS_LOCSYM,        EM_MIPS_RS3_LE) => "MIPS_LOCSYM",
		(SHT_MIPS_AUXSYM,        EM_MIPS) | (SHT_MIPS_AUXSYM,        EM_MIPS_RS3_LE) => "MIPS_AUXSYM",
		(SHT_MIPS_OPTSYM,        EM_MIPS) | (SHT_MIPS_OPTSYM,        EM_MIPS_RS3_LE) => "MIPS_OPTSYM",
		(SHT_MIPS_LOCSTR,        EM_MIPS) | (SHT_MIPS_LOCSTR,        EM_MIPS_RS3_LE) => "MIPS_LOCSTR",
		(SHT_MIPS_LINE,          EM_MIPS) | (SHT_MIPS_LINE,          EM_MIPS_RS3_LE) => "MIPS_LINE",
		(SHT_MIPS_RFDESC,        EM_MIPS) | (SHT_MIPS_RFDESC,        EM_MIPS_RS3_LE) => "MIPS_RFDESC",
		(SHT_MIPS_DELTASYM,      EM_MIPS) | (SHT_MIPS_DELTASYM,      EM_MIPS_RS3_LE) => "MIPS_DELTASYM",
		(SHT_MIPS_DELTAINST,     EM_MIPS) | (SHT_MIPS_DELTAINST,     EM_MIPS_RS3_LE) => "MIPS_DELTAINST",
		(SHT_MIPS_DELTACLASS,    EM_MIPS) | (SHT_MIPS_DELTACLASS,    EM_MIPS_RS3_LE) => "MIPS_DELTACLASS",
		(SHT_MIPS_DWARF,         EM_MIPS) | (SHT_MIPS_DWARF,         EM_MIPS_RS3_LE) => "MIPS_DWARF",
		(SHT_MIPS_DELTADECL,     EM_MIPS) | (SHT_MIPS_DELTADECL,     EM_MIPS_RS3_LE) => "MIPS_DELATEDECL",
		(SHT_MIPS_SYMBOL_LIB,    EM_MIPS) | (SHT_MIPS_SYMBOL_LIB,    EM_MIPS_RS3_LE) => "MIPS_SYMBOL_LIB",
		(SHT_MIPS_EVENTS,        EM_MIPS) | (SHT_MIPS_EVENTS,        EM_MIPS_RS3_LE) => "MIPS_EVENTS",
		(SHT_MIPS_TRANSLATE,     EM_MIPS) | (SHT_MIPS_TRANSLATE,     EM_MIPS_RS3_LE) => "MIPS_TRANSLATE",
		(SHT_MIPS_PIXIE,         EM_MIPS) | (SHT_MIPS_PIXIE,         EM_MIPS_RS3_LE) => "MIPS_PIXIE",
		(SHT_MIPS_XLATE,         EM_MIPS) | (SHT_MIPS_XLATE,         EM_MIPS_RS3_LE) => "MIPS_XLATE",
		(SHT_MIPS_XLATE_DEBUG,   EM_MIPS) | (SHT_MIPS_XLATE_DEBUG,   EM_MIPS_RS3_LE) => "MIPS_XLATE_DEBUG",
		(SHT_MIPS_WHIRL,         EM_MIPS) | (SHT_MIPS_WHIRL,         EM_MIPS_RS3_LE) => "MIPS_WHIRL",
		(SHT_MIPS_EH_REGION,     EM_MIPS) | (SHT_MIPS_EH_REGION,     EM_MIPS_RS3_LE) => "MIPS_EH_REGION",
		(SHT_MIPS_XLATE_OLD,     EM_MIPS) | (SHT_MIPS_XLATE_OLD,     EM_MIPS_RS3_LE) => "MIPS_XLATE_OLD",
		(SHT_MIPS_PDR_EXCEPTION, EM_MIPS) | (SHT_MIPS_PDR_EXCEPTION, EM_MIPS_RS3_LE) => "MIPS_PDR_EXCEPTION",
		(SHT_MIPS_ABIFLAGS,      EM_MIPS) | (SHT_MIPS_ABIFLAGS,      EM_MIPS_RS3_LE) => "MIPS_ABIFLAGS",

		(SHT_PARISC_EXT,     EM_PARISC) => "PARISC_EXT",
		(SHT_PARISC_UNWIND,  EM_PARISC) => "PARISC_UNWIND",
		(SHT_PARISC_DOC,     EM_PARISC) => "PARISC_DOC",
		(SHT_PARISC_ANNOT,   EM_PARISC) => "PARISC_ANNOT",
		(SHT_PARISC_SYMEXTN, EM_PARISC) => "PARISC_SYMEXTN",
		(SHT_PARISC_STUBS,   EM_PARISC) => "PARISC_STUBS",
		(SHT_PARISC_DLKM,    EM_PARISC) => "PARISC_DLKM",

		(SHT_X86_64_UNWIND, EM_X86_64) => "X86_64_UNWIND",

		(SHT_LOUSER ... SHT_HIUSER, _) => return format!("LOUSER+{:x}", sh_type - SHT_LOUSER),
		(SHT_LOPROC ... SHT_HIPROC, _) => return format!("LOPROC+{:x}", sh_type - SHT_LOPROC),
		(SHT_LOOS   ... SHT_HIOS,   _) => return format!("LOOS+{:x}", sh_type - SHT_LOOS),
		(_, _)                         => return format!("<unknown>: {:x}", sh_type),
	}.to_string()
}

