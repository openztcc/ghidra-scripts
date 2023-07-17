# Ghidra scripts

A collection of scripts to aid analysis of Zoo Tycoon. All Python scripts require [Ghidrathon](https://github.com/mandiant/Ghidrathon)

## Scripts

### ida_export.idc
This script exports demangled function names from IDA/IDA Pro for importing into Ghidra. Based on [this script](https://gist.github.com/hax0kartik/e358ce447a4537bcef534aa8de84817c) which does not demangle before export.

### ghidra_function_name_import.py
Imports function names and signatures from a file containing two columns of function names and addresses. Function names have spaces and brackets and there contents removed. Addresses are in hex format. Functions signatures are added as plate comments.
For very large files the script may need to be run multiple times.

### graph_class_hierarchy.py
Given some parent classes, creates a graph with said classes and all child classes. Similar to Ghidras `Data Type Manager -> Display as Graph` but iterates in the opposite direction and can take multiple nodes as starting points. 
Must to be called from the command lines as I haven't figured out a way to get the currently selected types from the `Data Type Manager`

```python
from graph_class_hierarchy import class_hierarchy
class_hierarchy(["class", "class2"])
```

### ClassChooser.java (WIP)
Brings up a list of all classes from the IDA export and allows the user to rename the currently in scope class in the decompiler, it also renames any placeholder classes. The script requires the [gson library](https://repo1.maven.org/maven2/com/google/code/gson/gson/2.10.1/gson-2.10.1.jar), place it in ~/ghidra-scripts/ to make it available to ghidra.

### MethodChooser.java (WIP)
Brings up a list of methods for the current class in scope in the decompiler. The script will rename the current function and retype the parameters. If any parameters types aren't present yet, it will create placeholder types (ph_typename).
The script requires the [gson library](https://repo1.maven.org/maven2/com/google/code/gson/gson/2.10.1/gson-2.10.1.jar), place it in ~/ghidra-scripts/ to make it available to ghidra.