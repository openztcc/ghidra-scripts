#TODO write a description for this script
#@author 
#@category _NEW_
#@keybinding 
#@menupath 
#@toolbar 
#@runtime Jython

import re
from ghidra.program.model.lang import OperandType, Register
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor

try:
    from typing import TYPE_CHECKING
except ImportError:
    TYPE_CHECKING = False

if TYPE_CHECKING:
    from ghidra.ghidra_builtins import *

def is_identified(function_name):
    return not function_name.startswith("FUN_00") \
        and not function_name.startswith("meth_0x") \
        and not function_name.startswith("virt_") \
        and not function_name.startswith("_") \
        and not function_name.startswith("cls_0x") \
        and not function_name.startswith("entry") \
        and not function_name.startswith("~cls_0") \
        and not function_name.startswith("ctor") \
        and not function_name.startswith("lpLocaleEnumProc") \
        and not function_name.startswith("dtor_0x")

def get_functions():
    decomp_interface = DecompInterface()
    decomp_interface.openProgram(currentProgram)

    fm = currentProgram.getFunctionManager()
    functions = fm.getFunctionsNoStubs(True)

    pure_functions = 0
    identified_pure_functions = 0
    more_likely_pure_functions = 0
    unidentified_pure_functions = 0
    uncalled_functions = 0
    uncalled_unidentified_functions = 0
    uncalled_pure_functions = 0
    total_functions = 0
    identified_functions = 0
    unidentified_functions = 0
    probably_empty_functions = 0

    fully_defined = 0
    unidentified_fully_defined = 0
    unidentified_fully_defined_at_least_one_call = 0

    i = 0
    i_bound = 99

    out_file = open("/Users/finnhartshorn/ghidra_scripts/pure_functions.txt", "w")
    out_file.write("Class, Name,Address,Size,Identified,Calling,Called,Pureish,CallersIdentified\n")
    function_out_dir = "/Users/finnhartshorn/Projects/zootycoon/ai-decompile/functions/"

    for function in functions:
        if function.isThunk():
            continue
        elif function.isExternal():
            continue
        total_functions += 1

        function_name = function.getName()
        function_class_name = get_class_name(function)
        identified = is_identified(function_name)
        callers_identified = all([is_identified(caller.getName()) for caller in function.getCalledFunctions(None)])
        called_by = function.getCallingFunctions(None)
        called = function.getCalledFunctions(None)
        if function.getBody().getNumAddresses() == 0 or function_name.startswith("null") or function_name.startswith("caseD_"):
            probably_empty_functions += 1
            continue
        if identified:
            identified_functions += 1
            if callers_identified:
                fully_defined += 1
                file_base = function_out_dir + function_class_name + "_" + function_name
                if function_class_name == " ":
                    file_base = function_out_dir + function_name
                if valid_file_name(file_base) and not excluded_function(function):
                    print("Writing out function: " + function_class_name + " " + function_name)
                    with open(file_base + ".asm", "w") as f:
                        f.write(get_assembly(function))
                    with open(file_base + ".c", "w") as f:
                        f.write(get_c_code(function, decomp_interface))
                else:
                    print("### Skipping function: " + function_class_name + " " + function_name)
            # In future we should be iterating through classes
        else:
            unidentified_functions += 1
            if len(called_by) == 0:
                uncalled_unidentified_functions += 1
            if callers_identified:
                unidentified_fully_defined += 1
                if len(called) > 0:
                    unidentified_fully_defined_at_least_one_call += 1
        
        more_likely_pure = False
        if len(called) == 0:
            pure_functions += 1
            if identified:
                identified_pure_functions += 1
                # print("Function %d: %s %s (%d)" % (i, get_class_name(function), function.getName(), function.getBody().getNumAddresses()))
                # if not function_name.startswith("get") and not function_name.startswith("set") and not function_name.startswith("is") and not function_name.startswith("dtor_") and not function_name.startswith("update") and not function_name.startswith("clear") and not function_name.startswith("force"):
                #     more_likely_pure_functions += 1
                #     more_likely_pure = True
                #     i += 1
                #     if i == i_bound:
                #         decomp_results = decomp_interface.decompileFunction(function, 0, ConsoleTaskMonitor())
                #         if decomp_results.decompileCompleted():
                #             decompiled_code = decomp_results.getDecompiledFunction().getC()
                #             print(decompiled_code)
            elif not identified:
                unidentified_pure_functions += 1
        
        if len(called_by) == 0:
            uncalled_functions += 1
        if len(called) == 0 and len(called_by) == 0:
            uncalled_pure_functions += 1

        out_file.write("\"%s\",\"%s\",0x%s,%d,%r,%d,%d,%r,%r\n" % (function_class_name, function.getName(), function.getEntryPoint().toString(), function.getBody().getNumAddresses(), identified, len(function.getCallingFunctions(None)), len(function.getCalledFunctions(None)), more_likely_pure, callers_identified))


    print("Found %d total functions" % total_functions)
    print("Found %d identified functions" % identified_functions)
    print("Found %d unidentified functions" % unidentified_functions)
    print("Found %d uncalled unidentified functions" % uncalled_unidentified_functions)
    print("Found %d probably empty functions" % probably_empty_functions)
    print("Found %d (potentially) pure functions" % pure_functions)
    print("Found %d more likely identified pure functions" % more_likely_pure_functions)
    print("Found %d identified (potentially) pure functions" % identified_pure_functions)
    print("Found %d unidentified (potentially)pure functions" % unidentified_pure_functions)
    print("Found %d uncalled (potentially) pure functions" % uncalled_pure_functions)
    print("Found %d uncalled functions" % uncalled_functions)
    print("Found %d fully defined functions" % fully_defined)
    print("Found %d unidentified fully defined functions" % unidentified_fully_defined)
    print("Found %d unidentified fully defined functions with at least one call" % unidentified_fully_defined_at_least_one_call)

def excluded_function(function):
    return str(function.body.minAddress) in ["005349b0"]

def valid_file_name(file_name):
    return not " " in file_name \
        and not ">" in file_name \
        and not "<" in file_name \
        and not "." in file_name \
        and not "," in file_name \
        and not "?" in file_name \
        and not file_name.startswith("AI_")

def get_class_name(function):
    # Symbol currentFunctionSymbol = currentFunction.getSymbol();
	# 	Symbol parentSymbol = currentFunctionSymbol.getParentSymbol();
	#	String parentSymbolName;
    function_symbol = function.getSymbol()
    parent_symbol = function_symbol.getParentSymbol()
    parent_symbol_name = parent_symbol.getName()
    if parent_symbol_name == "global":
        parent_symbol_name = ""
    return parent_symbol_name
    

def get_c_code(function, decomp_interface):
    decomp_results = decomp_interface.decompileFunction(function, 0, ConsoleTaskMonitor())
    if decomp_results.decompileCompleted():
        return decomp_results.getDecompiledFunction().getC()
    return ""


def is_code_reference_in_function(instruction, operand_index, function):
    """Check if operand is a code reference within the function body"""
    opType = instruction.getOperandType(operand_index)
    if OperandType.isAddress(opType) and OperandType.isCodeReference(opType):
        opText = instruction.getDefaultOperandRepresentation(operand_index)
        addr = currentProgram.parseAddress(opText)
        return len(addr) > 0 and function.body.contains(addr[0]), addr
    return False, None


def get_label_target_addresses(function, function_start_address):
    """
    Identify instruction addresses within the function that need labels.
    
    These are addresses that are referenced by other instructions within the function,
    such as jump targets or branch targets.
    
    Args:
        function: The function being analyzed
        function_start_address: The starting address of the function body
        
    Returns:
        dict: A dictionary mapping offsets to True for addresses requiring labels
    """
    label_targets = {}
    for instruction in currentProgram.listing.getInstructions(function.body, True):
        opCount = instruction.getNumOperands()
        for operand_index in range(opCount):
            is_in_func, addr = is_code_reference_in_function(instruction, operand_index, function)
            if is_in_func:
                # Calculate offset from function start for the referenced address
                referenced_offset = addr[0].offset - function_start_address.offset
                label_targets[referenced_offset] = True
    return label_targets

def format_operand(instruction, operand_index, function, function_start_address):
    """
    Format a single instruction operand according to assembly syntax rules.
    
    Handles various operand types including registers, dynamic references,
    and code references with appropriate formatting for each.
    
    Args:
        instruction: The instruction containing the operand
        operand_index: The index of the operand in the instruction
        function: The function containing the instruction
        function_start_address: The starting address of the function
        
    Returns:
        str: Formatted representation of the operand
    """
    opText = instruction.getDefaultOperandRepresentation(operand_index)
    opObjects = instruction.getOpObjects(operand_index)
    opType = instruction.getOperandType(operand_index)
    fm = currentProgram.getFunctionManager()
    sm = currentProgram.getSymbolTable()
    address_regex = re.compile(r"(?:^|\[|\s)(0x0{0,2}?[456]\w{5})(?:$|\]|\s])")

    # Handle dynamic addresses with registers (convert to use $ prefix)
    if OperandType.isAddress(opType) and OperandType.isDynamic(opType):
        opText = re.sub(r"\((\w+)\)$", r"($\1)", opText)
    
    # Handle other dynamic operands
    elif OperandType.isDynamic(opType):
        match_obj = re.search(r"\((\w+\))$", opText)
        if match_obj:
            opText = opText[:-len(match_obj.group(0))]
    
    # Add $ prefix to register names
    elif OperandType.isRegister(opType):
        opText = "%" + opText
    
    elif OperandType.isScalar(opType) and isinstance(opObjects[0], Register):
        opText = "$" + opText
    
    # Handle code references (addresses)
    elif OperandType.isAddress(opType) and OperandType.isCodeReference(opType):
        is_in_func, addr = is_code_reference_in_function(instruction, operand_index, function)
        if is_in_func:
            # Format as a local label if reference is within the function
            opText = ".%x" % (addr[0].offset - function_start_address.offset)
        else:
            # External reference, try and find what function it is referencing
            addr = currentProgram.parseAddress(opText)
            f = fm.getFunctionAt(addr[0])
            class_name = get_class_name(f)
            if class_name:
                opText = class_name + "::" + f.getName()
            else:
                opText = f.getName()

    elif OperandType.isAddress(opType):
        m = address_regex.search(opText)
        if m:
            addr = currentProgram.parseAddress(m.group(1))
            if addr is not None and len(addr) > 0:
                f = fm.getReferencedFunction(addr[0])
                if f is not None:
                    class_name = get_class_name(f)
                    ref = f.getName()
                    if class_name:
                        ref = class_name + "::" + ref
                    opText = address_regex.sub(ref, opText)
                else:
                    symbol = sm.getPrimarySymbol(addr[0])
                    if symbol is not None:
                        opText = address_regex.sub(str(symbol), opText)
                    else:
                        print("Unhandled address: " + m.group(1) + " in " + opText)
        else:
            print("Could not find address in: " + opText)
    return opText

def get_class_name(function):
    # Symbol currentFunctionSymbol = currentFunction.getSymbol();
	# 	Symbol parentSymbol = currentFunctionSymbol.getParentSymbol();
	#	String parentSymbolName;
    function_symbol = function.getSymbol()
    parent_symbol = function_symbol.getParentSymbol()
    parent_symbol_name = parent_symbol.getName()
    if parent_symbol_name == "global":
        parent_symbol_name = ""
    return parent_symbol_name


def process_instruction(function, instruction, function_start_address, label_target_addresses):
    """
    Format a complete instruction with its mnemonic and operands.
    
    Handles special cases like delay slots and adds labels where needed.
    
    Args:
        function: The function being analyzed
        instruction: The instruction to process
        function_start_address: The starting address of the function
        label_target_addresses: Dictionary of addresses requiring labels
        
    Returns:
        str: Formatted instruction text with appropriate labels
    """
    # Get the instruction mnemonic and handle delay slot special case
    mnemonic = instruction.getMnemonicString()
    if instruction.isInDelaySlot():
        # Remove leading underscore for delay slot instructions
        mnemonic = re.sub(r"^_", "", mnemonic)

    # Build the instruction string with formatted operands
    formatted_instruction = mnemonic + " "
    opCount = instruction.getNumOperands()

    for operand_index in range(opCount):
        opText = format_operand(instruction, operand_index, function, function_start_address)
        formatted_instruction += opText
        if operand_index < opCount - 1:
            formatted_instruction += ", "

    instruction_offset = instruction.getAddress().offset - function_start_address.offset
    needs_label = label_target_addresses.get(instruction_offset, False)
    eol_comment = instruction.getComment(0)
    formatted_instruction_result = ""
    if needs_label:
        instruction_address = "%x" % instruction_offset
        formatted_instruction_result += ".%s: " % instruction_address
    formatted_instruction_result += "%s" % formatted_instruction
    if eol_comment:
        formatted_instruction_result += "\t\t ; " + eol_comment
    formatted_instruction_result += "\n"

    return formatted_instruction_result

def get_assembly(function):
    if function is None:
        return ""
    
    assembly = ""
    function_start_address = function.body.minAddress
    # print("Functions starts at: " + str(function_start_address))
    label_target_addresses = get_label_target_addresses(function, function_start_address)

    for instruction in currentProgram.listing.getInstructions(function.body, True):
        assembly += process_instruction(function, instruction, function_start_address, label_target_addresses)
    return assembly



get_functions()


#Google AI Playground API Key AIzaSyAZLl7iSPxhDhprBJHbKJu9LcWHHVfjEiU
