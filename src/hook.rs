pub struct Hook;

use byteorder::ByteOrder;
use executable_memory::ExecutableMemory;
use byteorder::{LittleEndian};
use winapi::um::winnt::PAGE_EXECUTE_READWRITE;
use winapi::um::memoryapi::VirtualProtect;
use winapi::ctypes::c_void;

impl Hook {

    pub fn create_trampoline32(original_function: u32) -> ExecutableMemory {
        let mut memory = ExecutableMemory::default();
        let mut shellcode = [0x55, 0x89, 0xE5, 0x57, 0x56, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x83, 0xC0, 0x05, 0xFF, 0xE0];
        LittleEndian::write_u32(&mut shellcode[6..], original_function);
        memory[0..15].copy_from_slice(&shellcode);
        memory
    }

    pub fn place_jump(original_function: u32, hook_function: u32, length: u32) {

        unsafe {
            let mut dw_old_protect: u32 = 0;
            let mut dw_bkup: u32 = 0;
            let mut dw_reladdr: u32 = 0;

            let mut jumpshellcode = [0xE9, 0x00, 0x00, 0x00, 0x00];
            LittleEndian::write_u32(&mut jumpshellcode[1..], hook_function as u32);

            VirtualProtect(original_function as *mut c_void, 5, PAGE_EXECUTE_READWRITE, &mut dw_old_protect);
            dw_reladdr = (hook_function - original_function) - 5;

            *(original_function as *mut u8) = 0xE9;
            *((original_function + 0x1) as *mut u32) = dw_reladdr;

            for n in 5..length {
                *((original_function + n) as *mut u8) = 0x90;
            }

            VirtualProtect(original_function as *mut c_void, 5, dw_old_protect, &mut dw_bkup);
        }
    }
}