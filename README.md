# Ghidra scripts

A collection of scripts to aid analysis of Zoo Tycoon. All Ghidra script require [Ghidrathon](https://github.com/mandiant/Ghidrathon)

## Scripts

### ida_export.idc
This script exports demangled function names from IDA/IDA Pro for importing into Ghidra. Based on [this script](https://gist.github.com/hax0kartik/e358ce447a4537bcef534aa8de84817c) which does not demangle before export.

### ghidra_function_name_import.py
Imports function names from a file containing two columns of function names and addresses. Function names have spaces and brackets and there contents removed. Addresses are in hex format. For very large files the script may need to be run multiple times.