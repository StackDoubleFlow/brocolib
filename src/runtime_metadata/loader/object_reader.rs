use std::io::Cursor;

use binread::{BinRead, BinReaderExt};
use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use object::{Object, ObjectSection, RelocationEncoding, RelocationTarget};

use crate::runtime_metadata::loader::{Il2CppBinaryError, Result};

pub struct ObjectReader<'data> {
    obj: object::File<'data>,
    rel_data: Vec<u8>,
}

impl<'data> ObjectReader<'data> {
    pub fn new(data: &'data [u8]) -> Result<Self> {
        let obj = object::File::parse(data)?;
        let rel_data = process_relocations(&obj, data.to_vec())?;
        Ok(Self { obj, rel_data })
    }

    pub fn file(&self) -> &object::File<'data> {
        &self.obj
    }

    pub fn find_export(&self, name: &str) -> Result<Option<u64>> {
        Ok(self
            .obj
            .exports()?
            .iter()
            .find(|n| str::from_utf8(n.name()) == Ok(name))
            .map(|n| n.address()))
    }

    pub fn vaddr_conv(&self, vaddr: u64) -> Result<u64> {
        vaddr_conv(&self.obj, vaddr)
    }

    pub fn addr_in_bss(&self, vaddr: u64) -> bool {
        #[cfg(feature = "elf")]
        if matches!(&self.obj, object::File::Elf64(_)) {
            return match self.obj.section_by_name(".bss") {
                Some(bss) => bss.address() <= vaddr && vaddr - bss.address() < bss.size(),
                None => false,
            };
        }

        false
    }

    pub fn data(&self) -> &[u8] {
        &self.rel_data
    }

    pub fn obj_data(&self) -> &'data [u8] {
        match &self.obj {
            #[cfg(feature = "elf")]
            object::File::Elf64(elf) => elf.data(),
            #[cfg(feature = "pe")]
            object::File::Pe64(pe) => pe.data(),
            _ => unreachable!(),
        }
    }

    pub fn strlen(&self, offset: u64) -> usize {
        let mut len = 0;
        while self.rel_data[offset as usize + len] != 0 {
            len += 1;
        }
        len
    }

    pub fn get_str(&self, offset: u64) -> Result<&'data str> {
        let len = self.strlen(offset);
        let str = str::from_utf8(&self.obj_data()[offset as usize..offset as usize + len])?;
        Ok(str)
    }

    pub fn make_cur(&self, vaddr: u64) -> Result<Cursor<&[u8]>> {
        let pos = self.vaddr_conv(vaddr)?;
        let mut cur = Cursor::new(self.rel_data.as_slice());
        cur.set_position(pos);
        Ok(cur)
    }

    pub fn read_u64<'a>(&self, vaddr: u64) -> Result<u64> {
        let offset = self.vaddr_conv(vaddr)? as usize;
        let bytes = &self
            .rel_data
            .get(offset..offset + 8)
            .ok_or(Il2CppBinaryError::BadAddress(vaddr))?;

        let mut arr = [0u8; 8];
        arr.copy_from_slice(bytes);
        Ok(u64::from_le_bytes(arr))
    }

    pub fn read_arr<T>(&self, vaddr: u64, len: usize) -> Result<Vec<T>>
    where
        T: BinRead,
    {
        let mut cur = self.make_cur(vaddr)?;
        let mut vec = Vec::with_capacity(len);
        for _ in 0..len {
            vec.push(cur.read_le()?);
        }
        Ok(vec)
    }

    pub fn read_len_arr<T>(&self, cur: &mut Cursor<&[u8]>) -> Result<Vec<T>>
    where
        T: BinRead,
    {
        let count = cur.read_u32::<LittleEndian>()? as usize;
        let _padding = cur.read_u32::<LittleEndian>()?;
        let addr = cur.read_u64::<LittleEndian>()?;
        self.read_arr(addr, count)
    }

    pub fn read_len_arr_nullable<T>(&self, cur: &mut Cursor<&[u8]>) -> Result<Vec<T>>
    where
        T: BinRead + Default + Clone,
    {
        let count = cur.read_u32::<LittleEndian>()? as usize;
        let _padding = cur.read_u32::<LittleEndian>()?;
        let addr = cur.read_u64::<LittleEndian>()?;
        if self.addr_in_bss(addr) {
            Ok(vec![Default::default(); count])
        } else {
            self.read_arr(addr, count)
        }
    }
}

fn process_relocations<'a>(obj: &impl Object<'a>, obj_data: Vec<u8>) -> Result<Vec<u8>> {
    let mut obj_data = obj_data;

    if let Some(relocations) = obj.dynamic_relocations() {
        for (addr, rel) in relocations {
            if rel.encoding() != RelocationEncoding::Generic
                || rel.target() != RelocationTarget::Absolute
            {
                // TODO: handle more relocation types
                continue;
            }

            let target = rel.addend() as u64;

            let mut cur = Cursor::new(&mut obj_data);
            cur.set_position(vaddr_conv(obj, addr)?);
            cur.write_u64::<LittleEndian>(target)?;
        }
    }

    Ok(obj_data)
}

/// Convert a virtual address to a file offset
pub fn vaddr_conv<'a>(obj: &impl Object<'a>, vaddr: u64) -> Result<u64> {
    // TODO: is this correct for vaddr 0?
    if vaddr == 0 {
        return Ok(0);
    }

    for section in obj.sections() {
        let addr = section.address();
        let size = section.size();
        if addr <= vaddr && vaddr - addr < size {
            if let Some((file_off, _)) = section.file_range() {
                let offset = file_off + (vaddr - addr);
                return Ok(offset);
            }
        }
    }
    Err(Il2CppBinaryError::VAddrConv(vaddr))
}
