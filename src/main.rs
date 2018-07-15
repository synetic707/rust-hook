extern crate byteorder;
extern crate winapi;
extern crate executable_memory;

mod hook;

use hook::Hook;
use executable_memory::ExecutableMemory;

use std::mem;
use std::os::raw::c_void;
use std::process;
use std::io;

extern "C" fn my_cool_function()
{
    println!("I'm cool");
}

extern "C" fn hooked_cool_function()
{

    println!("I'm a hooked function");
}

fn main() {
    let mut input = String::new();

    println!("Press a key to hook cool_function()");
    io::stdin().read_line(&mut input);

    let memory: ExecutableMemory = Hook::create_trampoline32(my_cool_function as u32);
    let function_ptr: extern "C" fn() -> () = unsafe { mem::transmute(memory.as_ptr()) };
    println!("Trampoline: {:02X}", function_ptr as u32);
    println!("Hooked ptr: {:02X}", hooked_cool_function as u32);

    Hook::place_jump(my_cool_function as u32, hooked_cool_function as u32, 5);

    println!("Press a key to call the cool function!");
    io::stdin().read_line(&mut input);

    my_cool_function();

    println!("Press a key to call the original function!");
    io::stdin().read_line(&mut input);

    function_ptr();

    process::Command::new("cmd.exe").arg("/c").arg("pause").status();
}
