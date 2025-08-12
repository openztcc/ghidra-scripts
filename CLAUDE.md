# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Repository Overview

This is a specialized collection of Ghidra reverse engineering scripts primarily designed for analyzing Zoo Tycoon. The scripts facilitate decompilation workflows, function analysis, and bidirectional integration with IDA Pro.

## Commands

### Running Scripts
Scripts are run directly within Ghidra's Script Manager:
- Python scripts use Ghidra's built-in Jython interpreter (marked with `#@runtime Jython`)
- Java scripts require gson-2.10.1.jar placed in ~/ghidra-scripts/

### Testing
No formal test suite. Scripts are tested manually within Ghidra against Zoo Tycoon binaries.

## Architecture & Key Components

### Core Export Module (ExportASM.py)
The foundation module that provides assembly export functionality. Other scripts import functions from this module rather than duplicating code. Key capabilities:
- Format assembly for decomp.me compatibility
- Generate labels for jump targets
- Handle cross-references and function calls
- Format operands with proper syntax

### Function Analysis Pipeline (function_exporter.py)
Comprehensive analysis tool that:
1. Categorizes functions (identified/unidentified, pure/impure, called/uncalled)
2. Exports assembly and C code for fully identified functions
3. Generates CSV reports and metadata files
4. Uses ExportASM module for assembly formatting

### IDA Pro Integration (ghidra_function_name_import.py + ida_export.idc)
Bidirectional workflow between IDA Pro and Ghidra:
- ida_export.idc exports demangled names from IDA
- ghidra_function_name_import.py imports them into Ghidra
- Handles name conflicts and signature preservation

### Interactive GUI Tools (Java)
ClassChooser.java and MethodChooser.java provide interactive dialogs for renaming during manual analysis. Both are marked as WIP but functional for basic operations.

## Key Development Patterns

### Ghidra API Usage
All scripts heavily utilize:
- `currentProgram` - The loaded binary
- `FunctionManager` - Function operations
- `SymbolTable` - Symbol management
- `DecompInterface` - Decompilation
- `monitor` - Progress tracking for long operations

### Error Handling
Scripts use extensive try-catch blocks and log to separate .log files for debugging.

### File Output Structure
Scripts generate organized outputs:
- `.asm` files for assembly
- `.c` files for decompiled code
- `.csv` for analysis reports
- `.log` for operation logs

## Dependencies

Required:
- Ghidra (10.4+) with built-in Jython support
- gson-2.10.1.jar for Java scripts (place in ~/ghidra-scripts/)

## Important Notes

- All scripts are designed for Windows PE analysis (Zoo Tycoon specifically)
- Address calculations assume Windows executable layout
- Function naming follows Zoo Tycoon's C++ conventions
- Scripts preserve existing analysis while adding new information