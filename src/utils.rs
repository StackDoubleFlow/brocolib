use crate::Elf;
use object::{Object, ObjectSegment};

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
