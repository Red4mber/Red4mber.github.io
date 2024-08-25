+++
title = "Hell's Gate: Walking the PEB"
date = "2024-08-25"

[taxonomies]
tags = ["programming", "windows" , "malware"]
+++


<img src=/img/hell_gate/walking_peb.png height=350 />

# Introduction

## What is PEB Walking ? 

Remember in the blog post on syscalls when i said i would explain how to make your own `GetProcAddress` function ? 

Well this is it folks, PEB Walking is the way to go.

The `PEB` or `Process Environment Block` is a very useful data structure that contains all kinds of information about our current process. That includes pointers to all the modules currently loaded, and thus their export table, which contains pointers to any function it exports. 

Well this process i just described, of "walking" from pointer to pointer, is what we commonly call PEB Walking. It has, notably been described in this excellent paper from vx_underground :  
> [Hell's Gate](https://vxug.fakedoma.in/papers/VXUG/Exclusive/HellsGate.pdf) <br>
> by smelly__vx ([@RtlMateusz](https://twitter.com/RtlMateusz)) and am0nsec ([@am0nsec](https://twitter.com/am0nsec))

The paper introduces this technique as a way to dynamically resolving Windows syscalls at runtime without relying on any static or hardcoded SSNs, and additionally provides the code to execute these syscalls.

In this post, I'm going to focus on the SSN resolving part of this technique, which can be divided in the following steps:
 - first, we find a pointer to NTDLL 
 - We then parse NTDLL's export table
 - Lastly we parse every syscall to retreive their SSN 
 
 In essence, we are going to write our own `GetModuleHandle` and `GetProcAddress` functions. 

## The First Step: Getting a handle to NTDLL

As I said earlier, the `Process Environment Block` hold the information we need. More specifically, at offset 0x18 in its `PEB_LDR_DATA *Ldr` field, which as you can see is a pointer to a structure named `PEB_LDR_DATA`. 

`PEB_LDR_DATA` holds a records of every loaded modules, which means the PE itself and all the DLLs it has loaded, which will always include NTDLL. <br>
It contains three doubly-linked lists, `InLoadOrderModuleList`, `InMemoryOrderModuleList` and `InInitializationOrderModuleList`, which all contains entries for every loaded modules.<br>
To access this record, we simply need to follow one of these linked lists until we find the module we are looking for.


So, if I summarize everything so far : 
- From the PEB, we read a pointer to PEB_LDR_DATA
- From the PEB_LDR_DATA , read the first element of the InMemoryOrderModuleList linked list
- Flink (forward link) through each element of the list until we find NTDLL.dll's LIST_ENTRY
- Read the pointer to the DLL's base

Here is a quick (and inaccurate) diagram to explain all of this :
<img src=/img/hell_gate/peb_walk.png />

### The code

#### Getting a pointer to the PEB

The address of the PEB is stored in the `Thread Environment Block`, which we can find in the gs register (and the fs register on 32-bit windows).
We can directly read at the offset containing the pointer to the PEB using inline assembly, like so : 
```rust
unsafe fn get_peb_address() -> *const PEB {  
    let peb_ptr;
    asm!("mov {}, gs:[0x60]", out(reg) peb_ptr);  
    peb_ptr  
}
```
Then, we just have to dereference the PEB structure to access any field we want. <br>
Here's code that access the LDR Data Table and start going from link to link : 
```rust
let peb: PEB = *get_peb_address();  
let peb_loader_data =  peb.Ldr;  
let first_entry = (*peb_loader_data).InMemoryOrderModuleList.Flink;  
let second_entry = (*first_entry).Flink;  
let third_entry = (*second_entry).Flink;  
  
let module_base = second_entry.byte_sub(0x10) as *const LDR_DATA_TABLE_ENTRY;  
println!("{}", (*module_base).BaseDllName);  
println!("{}", (*module_base).FullDllName);
```

The most important part here, and the most easy to miss, is the `.byte_sub(0x10)` 
This is because each Flink in the linked list do not point to the *LDR_DATA_TABLE_ENTRY*, but to the next *LIST_ENTRY* in the list. If you look at *LDR_DATA_TABLE_ENTRY* using the `dt` command in WinDgb, you'll see this that the InMemoryOrderLinks field is the second list in the layout, at offset 0x10.
```
+0x000 InLoadOrderLinks : _LIST_ENTRY
+0x010 InMemoryOrderLinks : _LIST_ENTRY
+0x020 InInitializationOrderLinks : _LIST_ENTRY
+0x030 DllBase          : Ptr64 Void
....etc
```
So we need to offset it back by 16 bytes (0x10 in hex) to get the pointer to the start of the structure. 
We use InMemoryOrderLinks and not the other because *InLoadOrderLinks* and *InInitializationOrderLinks* are not defined in Windows crates, so unless you defined *LDR_DATA_TABLE_ENTRY* yourself (or just grabbed my own), you can not use those.

For your convenience, here is a nice function that does everything we just talked about :
```rust
unsafe fn get_module_base_address(module_name: &str) -> Result<*const c_void, &str> {  
    let peb = *get_peb_address();  
    let last_module = (*peb.Ldr).InMemoryOrderModuleList.Blink;  
    let mut module_entry: *mut LIST_ENTRY = (*peb.Ldr).InMemoryOrderModuleList.Flink;  
    let mut module_base: *const LDR_DATA_TABLE_ENTRY;  
  
    loop {  
        module_base = module_entry.byte_sub(0x10) as *const LDR_DATA_TABLE_ENTRY;  
        println!("[?-?] Module : {}", (*module_base).BaseDllName);  
        if (*module_base).BaseDllName.to_string().eq_ignore_ascii_case( module_name ) {  
            println!("[^-^] Module Found at address : {:x?}", (*module_base).DllBase);  
            return Ok((*module_base).DllBase);  
        }  
        if module_entry == last_module {  
            return Err("Module not found !")  
        }  
  
        module_entry = (*module_entry).Flink;  
    }  
}
```
Ta Daaa ~ <br>
That's how you make DIY GetModuleAddress !

## Parsing the PE file 


We may have the address of a loaded NTDLL module, but if we actually want those Syscall numbers, it is time to parse it.
We must first understand its structure, and . 

Here is my best attempt at a diagram: <br>
 (Yes really my best attempt TwT)

<img src=/img/hell_gate/pe_format.png height=550 />

If you want more information, here's a pretty good OSDev wiki article : [here](https://wiki.osdev.org/PE)

And there's the wikipedia article, which features  way better diagram than mine :<br>
[https://en.wikipedia.org/wiki/Portable_Executable](https://en.wikipedia.org/wiki/Portable_Executable)

### The DOS header
For historic reasons, every PE File contains a MS-DOS executable, called the *DOS Stub*.
It contains a DOS Header and an actual MS-DOS program, that would simply output "This program cannot be run in DOS mode." in the case someone ran an exe file in a DOS environment.

Because it is the first bytes of the file, so we can easily read it by casting our pointer to the module to a pointer to the *IMAGE_DOS_HEADER* structure.
We can then easily access it's fields by dereferencing it.
```rust
let dos_header_ptr = base_address as *const IMAGE_DOS_HEADER;  
if (*dos_header_ptr).e_magic != IMAGE_DOS_SIGNATURE { // 0x5A4D  
    return Err("Invalid DOS header".to_string())  
}
```

We are interested in only two fields of this structure:
- *e_magic* which is the DOS Header signature and should always be `0x5A4D` (or "MZ")
- *e_lfanew* at offset 0x3C which contains an offset to the start of the NT Header 


### The NT Headers
The NT Headers, or sometimes called *PE headers* or *COFF headers*, named after *Portable Executable* and *Common Object File Format*, can be found after the *DOS Stub*. <br>
As with the DOS header, the first bytes are a signature, this time 4 bytes long, which should always be `0x00004550` or "PE\\0\\0" (PE followed by two null bytes).<br>
This allows us to be sure we got the right address before dereferencing our structure.

```rust
let base_address = module_handle as *const u8;

// Get the offset to the NT headers from the PE header
let nt_offset = base_address.byte_offset(0x03c);

// Get a reference to the NT headers and check the signature
let nt_header: &IMAGE_NT_HEADERS = &base_address
    .byte_offset(*nt_offset as isize)
    .cast::<IMAGE_NT_HEADERS>()
    .read();
if nt_header.Signature != IMAGE_NT_SIGNATURE {
    return Err(DllParserError::InvalidNtHeader);
}
```


The rest is split in two structures, the *File Header* and the *Optional Header*, which, in the case of Image files, is not at all optional <br>

It's in fact in the Optional header that we'll find the data directory, which is our next target.

#### The data directory

What we're really after is the last field of the optional header, named data directory. It is an array of `IMAGE_DATA_DIRECTORY` elements, each containing an address and a size. 

The address is a *Relative Virtual Address* or RVA, meaning it's really an offset relative to the base of Image, just like the `e_lfanew` field in the DOS Header we saw earlier.

Each element in this array is a different directory, each containing various information such as the exports (index 0) and imports (index 1) the security directory, the exceptions etc....  
```rust
let export_dir: IMAGE_EXPORT_DIRECTORY = base_address
    .offset(nt_header.OptionalHeader.DataDirectory[0].VirtualAddress as isize)
    .cast::<IMAGE_EXPORT_DIRECTORY>()
    .read();
```

This export directory actually contains 3 different arrays 
 - AddressOfNames
 - AddressOfFunctions
 - AddressOfNameOrdinals

 These 3 arrays contains only adresses, but each of these addresses points to data we actually need, one to all the names, the other to function addresses, and the third, more cryptic one serve as an index to get the right address for the right name. 

 It should be easier to understand with some code, so here's the code used in my [Thermite](https://github.com/Red4mber/Thermite) library to search a function's address by it's name : 
 ```rust
// We're searching by name, so we iterate over the list of names
	for (i, name_addr) in address_of_names.iter().enumerate() {
		// Then match over the result of CStr::from_ptr to capture eventual parsing errors
		match CStr::from_ptr((module_handle as usize + *name_addr as usize) as *const i8).to_str() {
			Ok(s) => {
				// If it's ok, we test if our strings match
				if s.eq_ignore_ascii_case(function_name) {
					// if it does, we return the address of the function
					let rva = address_of_functions[address_of_name_ordinals[i] as usize];
					let true_address = (module_handle as usize + rva as usize) as *const u8;
					return Ok(true_address);
				}
			}
			Err(e) => {
				return Err(DllParserError::FunctionNameParsingError(e));
			}
		};
	}
 ```

 
 Anyways I hope i've been clear enough, but if you manage to follow everything you should now be able to build a function like `GetProcAddress`. 

 I really invite you to go and check out the rest of the code in the github repo, as my explanations will never be enough to properly explain this. 

