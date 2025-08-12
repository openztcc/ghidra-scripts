# Exports identified functions as Rust function definitions organized by class
# @category Bryce
# @runtime Jython

import re
from collections import defaultdict

try:
    from typing import TYPE_CHECKING
except ImportError:
    TYPE_CHECKING = False

if TYPE_CHECKING:
    from ghidra.ghidra_builtins import *

def is_identified(function_name):
    """Check if a function has been properly identified (not a default Ghidra name)"""
    return not function_name.startswith("FUN_00") \
        and not function_name.startswith("meth_0x") \
        and not function_name.startswith("virt_") \
        and not function_name.startswith("_") \
        and not function_name.startswith("cls_0x") \
        and not function_name.startswith("entry") \
        and not function_name.startswith("thunk_FUN_")

def get_class_name(function):
    """Get the class name from the function's symbol hierarchy"""
    function_symbol = function.getSymbol()
    parent_symbol = function_symbol.getParentSymbol()
    parent_symbol_name = parent_symbol.getName()
    if parent_symbol_name == "global":
        parent_symbol_name = ""
    return parent_symbol_name

def get_calling_convention(function):
    """Determine the calling convention from function signature"""
    signature = function.getSignature()
    calling_conv = signature.getCallingConventionName()
    
    # Map Ghidra conventions to Rust conventions
    if calling_conv == "__thiscall":
        return "thiscall"
    elif calling_conv == "__stdcall":
        return "stdcall"
    elif calling_conv == "__fastcall":
        return "fastcall"
    elif calling_conv == "__cdecl" or calling_conv == "default":
        return "cdecl"
    else:
        return "cdecl"  # Default to cdecl if unknown

def map_type_to_rust(ghidra_type):
    """Map Ghidra types to Rust types"""
    type_str = str(ghidra_type)
    
    # Basic type mappings
    type_map = {
        "void": "()",
        "bool": "bool",
        "char": "i8",
        "uchar": "u8",
        "byte": "u8",
        "ubyte": "u8",
        "short": "i16",
        "ushort": "u16",
        "int": "i32",
        "uint": "u32",
        "long": "i32",
        "ulong": "u32",
        "longlong": "i64",
        "ulonglong": "u64",
        "float": "f32",
        "double": "f64",
        "undefined": "u8",
        "undefined1": "u8",
        "undefined2": "u16", 
        "undefined4": "u32",
        "undefined8": "u64"
    }
    
    # Handle pointers
    if "*" in type_str:
        # For now, treat all pointers as u32 (32-bit addressing)
        return "u32"
    
    # Check for known types
    for ghidra, rust in type_map.items():
        if ghidra in type_str.lower():
            return rust
    
    # Default to u32 for unknown types
    return "u32"

def get_function_signature_rust(function):
    """Generate Rust function signature from Ghidra function"""
    signature = function.getSignature()
    params = signature.getArguments()
    return_type = signature.getReturnType()
    calling_conv = get_calling_convention(function)
    
    # Map parameter types
    param_types = []
    for param in params:
        rust_type = map_type_to_rust(param.getDataType())
        param_types.append(rust_type)
    
    # Handle 'this' parameter for thiscall
    if calling_conv == "thiscall" and len(param_types) > 0:
        # First parameter is implicit 'this', but we still include it in Rust
        pass
    
    # Map return type
    rust_return = map_type_to_rust(return_type)
    
    # Build the function type string
    if len(param_types) == 0:
        params_str = "()"
    else:
        params_str = "(" + ", ".join(param_types) + ")"
    
    if rust_return == "()":
        fn_type = "unsafe extern \"{}\" fn{}".format(calling_conv, params_str)
    else:
        fn_type = "unsafe extern \"{}\" fn{} -> {}".format(calling_conv, params_str, rust_return)
    
    return fn_type

def sanitize_class_name(class_name):
    """Sanitize class name for use as a Rust module name"""
    # Remove angle brackets and other invalid characters
    class_name = class_name.replace("<", "").replace(">", "")
    
    # Convert to lowercase and replace non-alphanumeric with underscores
    result = ""
    for char in class_name:
        if char.isalnum():
            result += char.lower()
        else:
            result += "_"
    
    # Remove duplicate underscores
    while "__" in result:
        result = result.replace("__", "_")
    result = result.strip("_")
    
    # If it starts with a number, prepend "class_"
    if result and result[0].isdigit():
        result = "class_" + result
    
    return result if result else "unnamed"

def sanitize_rust_name(name, class_name=""):
    """Convert function name to valid Rust constant name"""
    # Remove angle brackets (template parameters)
    name = name.replace("<", "").replace(">", "")
    
    # Remove class prefix if it exists in the function name
    if "::" in name:
        name = name.split("::")[-1]
    
    # If the function name starts with the class name, remove it
    if class_name and name.upper().startswith(class_name.upper()):
        # Remove the class prefix and any following underscore
        name = name[len(class_name):]
        if name.startswith("_"):
            name = name[1:]
    
    # Convert to uppercase with underscores
    result = ""
    for i, char in enumerate(name):
        if i > 0 and char.isupper() and name[i-1].islower():
            result += "_"
        result += char.upper() if char.isalnum() else "_"
    
    # Remove duplicate underscores and trailing underscores
    while "__" in result:
        result = result.replace("__", "_")
    result = result.strip("_")
    
    # If result is empty or starts with a number, prepend "FN_"
    if not result or result[0].isdigit():
        result = "FN_" + result
    
    return result

def main():
    # Get all functions
    function_manager = currentProgram.getFunctionManager()
    functions = function_manager.getFunctions(True)
    
    # Group functions by class
    class_functions = defaultdict(list)
    standalone_functions = []
    
    print("Analyzing functions...")
    function_count = 0
    identified_count = 0
    
    for function in functions:
        function_count += 1
        name = function.getName()
        
        # Skip unidentified functions
        if not is_identified(name):
            continue
            
        identified_count += 1
        
        # Get class name from symbol hierarchy
        class_name = get_class_name(function)
        
        if class_name and class_name != "":
            class_functions[class_name].append(function)
        else:
            standalone_functions.append(function)
    
    print("Found {} identified functions out of {} total".format(identified_count, function_count))
    print("Classes found: {}".format(len(class_functions)))
    
    # Generate Rust code
    rust_code = []
    rust_code.append("// Auto-generated Rust function definitions for Zoo Tycoon")
    rust_code.append("// Generated from Ghidra analysis")
    rust_code.append("")
    rust_code.append("use std::marker::PhantomData;")
    rust_code.append("")
    rust_code.append("pub struct FunctionDef<T> {")
    rust_code.append("    pub address: usize,")
    rust_code.append("    pub function_type: PhantomData<T>,")
    rust_code.append("}")
    rust_code.append("")
    
    # Generate class-organized functions
    for class_name in sorted(class_functions.keys()):
        sanitized_module_name = sanitize_class_name(class_name)
        rust_code.append("// {} class functions".format(class_name))
        rust_code.append("pub mod {} {{".format(sanitized_module_name))
        rust_code.append("    use super::*;")
        rust_code.append("")
        
        for function in sorted(class_functions[class_name], key=lambda f: f.getEntryPoint().getOffset()):
            fn_name = function.getName()
            rust_const_name = sanitize_rust_name(fn_name, class_name)
            
            # Don't prepend class name if the constant name already is unique enough
            if rust_const_name:
                full_const_name = rust_const_name
            else:
                full_const_name = "{}_METHOD".format(class_name.upper())
            
            try:
                fn_signature = get_function_signature_rust(function)
                address = function.getEntryPoint().getOffset()
                
                rust_code.append("    pub const {}: FunctionDef<{}> = FunctionDef{{address: {:#010x}, function_type: PhantomData}};".format(
                    full_const_name, fn_signature, address))
            except Exception as e:
                print("Warning: Could not process function {}: {}".format(fn_name, str(e)))
                continue
        
        rust_code.append("}")
        rust_code.append("")
    
    # Generate standalone functions
    if standalone_functions:
        rust_code.append("// Standalone functions")
        rust_code.append("pub mod standalone {")
        rust_code.append("    use super::*;")
        rust_code.append("")
        
        for function in sorted(standalone_functions, key=lambda f: f.getEntryPoint().getOffset()):
            fn_name = function.getName()
            rust_const_name = sanitize_rust_name(fn_name)
            
            try:
                fn_signature = get_function_signature_rust(function)
                address = function.getEntryPoint().getOffset()
                
                rust_code.append("    pub const {}: FunctionDef<{}> = FunctionDef{{address: {:#010x}, function_type: PhantomData}};".format(
                    rust_const_name, fn_signature, address))
            except Exception as e:
                print("Warning: Could not process function {}: {}".format(fn_name, str(e)))
                continue
        
        rust_code.append("}")
    
    # Write to file
    output_file = str(currentProgram.getExecutablePath()).replace(".exe", "_functions.rs")
    output_file = output_file.replace("\\", "/")
    if "/" in output_file:
        output_file = output_file.split("/")[-1]
    
    print("\nWriting to {}...".format(output_file))
    
    with open(output_file, 'w') as f:
        f.write("\n".join(rust_code))
    
    print("Successfully exported {} identified functions to {}".format(identified_count, output_file))
    print("\nExample usage in Rust:")
    print("  use {}_functions::*;".format(output_file.replace("_functions.rs", "")))
    print("  let mgr_constructor = bfresourcemgr::BFRESOURCEMGR_CONSTRUCTOR;")

if __name__ == "__main__":
    main()