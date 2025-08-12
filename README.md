# Ghidra scripts

A collection of scripts to aid analysis of Zoo Tycoon. Python scripts use Ghidra's built-in Jython interpreter

## Scripts

### ExportASM.py
Exports the assembly code of a function at the current cursor location for use with decomp.me. Features:
- Generates properly formatted assembly with labels for jump targets
- Handles all x86 operand types (registers, immediates, memory references)
- Resolves cross-references and function calls
- Formats output compatible with decomp.me's requirements
- Can be used as a library by other scripts

### function_exporter.py
Comprehensive function analysis and export tool that processes all functions in the binary. Features:
- Categorizes functions as identified/unidentified based on naming patterns
- Determines if functions are pure (no external calls) or impure
- Tracks which functions are called vs uncalled
- Exports assembly (.asm) and decompiled C code (.c) for fully identified functions
- Generates detailed CSV reports with function statistics
- Creates metadata files with function signatures for called functions
- Uses ExportASM module for assembly formatting
- Outputs organized directory structure with categorized functions

### rust_function_exporter.py
Generates Rust FFI function definitions from identified functions in the binary. Features:
- Exports only properly identified functions (excludes default Ghidra names)
- Organizes functions by class into Rust modules
- Automatically detects calling conventions (thiscall, cdecl, stdcall, fastcall)
- Maps Ghidra types to appropriate Rust types
- Generates type-safe function pointers using PhantomData
- Creates constants with function addresses for runtime linking
- Outputs a single .rs file ready for use in Rust projects
- Ideal for creating game modding frameworks or reverse engineering tools

### ida_export.idc
IDA Pro script that exports demangled function names and addresses for importing into Ghidra. Based on [this script](https://gist.github.com/hax0kartik/e358ce447a4537bcef534aa8de84817c) but adds demangling before export. Creates a two-column output file with function names and hex addresses.

### ghidra_function_name_import.py
Imports function names and signatures from IDA Pro exports into Ghidra. Features:
- Reads two-column files (function name, hex address)
- Removes spaces and brackets from function names for compatibility
- Adds function signatures as plate comments
- Handles name conflicts with detailed logging
- Creates comprehensive log file of all operations
- May need multiple runs for very large files

### graph_class_hierarchy.py
Visualizes class inheritance hierarchies as interactive graphs. Features:
- Creates bottom-up (reverse) hierarchy graphs showing parent-child relationships
- Shows parent classes and all their child classes
- Similar to Ghidra's `Data Type Manager -> Display as Graph` but iterates in opposite direction
- Supports multiple starting nodes
- Must be called from command line as it needs class names as parameters
- Useful for understanding object-oriented structures in Zoo Tycoon

```python
from graph_class_hierarchy import class_hierarchy
class_hierarchy(["class", "class2"])
```

### ClassChooser.java (WIP)
Interactive GUI tool for renaming classes in the decompiler view. Features:
- Displays searchable list of all classes from IDA export
- Renames the currently in-scope class in the decompiler
- Automatically renames placeholder classes
- Requires [gson library](https://repo1.maven.org/maven2/com/google/code/gson/gson/2.10.1/gson-2.10.1.jar) - place in ~/ghidra-scripts/

### MethodChooser.java (WIP)
Interactive GUI tool for renaming methods and retyping parameters. Features:
- Shows list of methods for the current class in the decompiler
- Renames the current function to match selected method
- Retypes function parameters based on method signature
- Creates placeholder types (ph_typename) for missing types
- Requires [gson library](https://repo1.maven.org/maven2/com/google/code/gson/gson/2.10.1/gson-2.10.1.jar) - place in ~/ghidra-scripts/