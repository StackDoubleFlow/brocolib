use crate::Elf;
use anyhow::Result;
use object::{Object, ObjectSegment};
use std::str;

pub fn vaddr_conv(elf: &Elf, vaddr: u64) -> u64 {
    for segment in elf.segments() {
        if segment.address() <= vaddr {
            let offset = vaddr - segment.address();
            if offset < segment.size() {
                // println!("{:08x} -> {:08x}", vaddr, segment.file_range().0 + offset);
                return segment.file_range().0 + offset;
            }
        }
    }
    panic!("Failed to convert virtual address {:016x}", vaddr);
}

pub fn strlen(data: &[u8], offset: usize) -> usize {
    let mut len = 0;
    while data[offset + len] != 0 {
        len += 1;
    }
    len
}

pub fn get_str(data: &[u8], offset: usize) -> Result<&str> {
    let len = strlen(data, offset);
    let str = str::from_utf8(&data[offset..offset + len])?;
    Ok(str)
}
