pub mod elf;
pub mod binary;
pub mod pdb;

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

#[derive(Clone, PartialEq)]
pub enum Endianness {
	Big,
	Little,
}

pub trait SeekReadStream : io::Seek + io::Read {}

impl<T: io::Seek + io::Read> SeekReadStream for T { }

pub trait Loader {
	fn entry_point(&self) -> Option<u64>;
	fn get_segments(&self, filter: &Fn(&Segment) -> bool, stream: &mut SeekReadStream) -> Result<Vec<(Segment, Vec<u8>)>, io::Error>;
	fn get_segment_metadata(&self) -> Result<Vec<Segment>, io::Error>;
	fn fmt_str(&self) -> String;
	fn endianness(&self) -> Option<Endianness>;
}

#[derive(Clone)]
pub struct Symbol {
	pub name: String,
	pub addr: u64,
}

// TODO:  Algorithmic complexity of this whole thing is wrong.  But I'm 
//   writing it on a flight with no WiFi, and can only reiterate (hah!)
//   Vec's interface from memory.
pub struct SymbolTable {
	symbols: Vec<Symbol>,
}

impl SymbolTable {
	pub fn new() -> SymbolTable {
		SymbolTable {
			symbols: Vec::new(),
		}
	}

	pub fn symbols_for_addr(&self, addr: u64) -> Vec<Symbol> {
		let mut results: Vec<Symbol> = Vec::new();

		for symbol in self.symbols.iter() {
			if symbol.addr == addr {
				results.push(symbol.clone());
			}
		}

		results
	}

	pub fn add_symbol(&mut self, symbol: Symbol) {
		self.symbols.push(symbol);
	}

	//TODO:  Remove when I can look up iter/template/generic syntax
	pub fn symbol_list(&self) -> Vec<Symbol> {
		self.symbols.clone()
	}
}

