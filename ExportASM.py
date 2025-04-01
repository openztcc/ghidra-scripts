# This script dumps the assembly of a function to the console for use in decomp.me
# @category Bryce
# @runtime Jython

import re
from ghidra.program.model.lang import OperandType, Register

try:
    from typing import TYPE_CHECKING
except ImportError:
    TYPE_CHECKING = False

if TYPE_CHECKING:
    from ghidra.ghidra_builtins import *


def get_function():
    fm = currentProgram.getFunctionManager()
    func = fm.getFunctionContaining(currentLocation.address)
    if func is None:
        print("No function found at the current location.")
    elif func.isThunk():
        print("Function is a thunk.")
    elif func.isExternal():
        print("Function is external.")
    else:
        return func
    return None


def is_code_reference_in_function(instruction, operand_index, function):
    """Check if operand is a code reference within the function body"""
    opType = instruction.getOperandType(operand_index)
    if OperandType.isAddress(opType) and OperandType.isCodeReference(opType):
        opText = instruction.getDefaultOperandRepresentation(operand_index)
        addr = currentProgram.parseAddress(opText)
        if len(addr) > 0 and function.body.contains(addr[0]):
            # Check if the address is within the function body
            return True, addr
        else:
            print("Address not in function body: " + str(addr))
            return False, addr
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
            elif addr is not None and len(addr) > 0:
                print("Other Address not in function body: " + str(addr))
                # Do we need to get the name here too?
                # print(instruction, operand_index)
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

def main():
    function = get_function()
    if function is None:
        return

    assembly = ""
    function_start_address = function.body.minAddress
    print("Functions starts at: " + str(function_start_address))
    label_target_addresses = get_label_target_addresses(function, function_start_address)

    for instruction in currentProgram.listing.getInstructions(function.body, True):
        assembly += process_instruction(function, instruction, function_start_address, label_target_addresses)

    print("Assembly for function {}: \n{}".format(function.getName(), assembly))


main()
