// Renames and retypes the function in the decompiler view
//@category _NEW_

import java.util.*;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileWriter;
import java.io.IOException;

import generic.jar.ResourceFile;
import ghidra.app.decompiler.*;
import ghidra.app.decompiler.component.DecompilerUtils;
import ghidra.app.script.*;
import ghidra.app.tablechooser.*;
import ghidra.framework.options.ToolOptions;
import ghidra.framework.plugintool.util.OptionsService;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.*;
import ghidra.program.model.pcode.*;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.util.*;
import ghidra.util.*;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.InvalidInputException;

import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.SymbolType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.data.GenericCallingConvention;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.lang.PrototypeModel;
import ghidra.program.model.data.DataTypeConflictHandler;

import ghidra.util.exception.DuplicateNameException;
import ghidra.util.InvalidNameException;

import docking.widgets.OkDialog;
import docking.widgets.OptionDialog;


public class MethodChooser extends GhidraScript {
	TableChooserDialog tableDialog;

	@Override
	public void run() throws Exception {
		Function currentFunction = getFunctionContaining(currentAddress);
		Symbol currentFunctionSymbol = currentFunction.getSymbol();
		Symbol parentSymbol = currentFunctionSymbol.getParentSymbol();
		String parentSymbolName;
		if (parentSymbol.getSymbolType() != SymbolType.CLASS) {
			// OkDialog.showError("Error", "Function " + currentFunction.getName() + " is not a method of a class.");
			// return;
			parentSymbolName = "";
		} else {
			parentSymbolName = parentSymbol.getName();
			// println(getDataTypes(parentSymbolName)[0].getCategoryPath().toString());
		}
		TableChooserExecutor executor = createTableExecutor(currentFunction);

		if (parentSymbolName != "") {
			tableDialog = createTableChooserDialog("Rename " + parentSymbolName + "::" + currentFunctionSymbol.getName(), executor);
		} else {
			tableDialog = createTableChooserDialog("Rename " + currentFunctionSymbol.getName(), executor);
		}
		configureTableColumns(tableDialog);
		tableDialog.show();
		tableDialog.setMessage("Parsing...");
		MethodParser ida_export = new MethodParser();
		ida_export.parse();
		tableDialog.setMessage("Finished!");

		Map<String, Set<String>> classMethodMaps = ida_export.getClassMethodsMap();

		Set<String> methods = classMethodMaps.get(parentSymbolName);
		if (methods != null) {
			for (String methodName : methods) {
				int bracketIndex = methodName.indexOf('(');
				if (bracketIndex == -1) {
					// addMethod(tableDialog, "0x0", methodName, new String[0]);
					tableDialog.add(new MethodForImport("0x0", methodName, new String[0]));
					continue;
				} 
				// println(methodName);
				String trimmedMethodName = methodName.substring(0, bracketIndex);
				String params = methodName.substring(bracketIndex + 1, methodName.indexOf(')'));
				tableDialog.add(new MethodForImport("0x0", trimmedMethodName, params));
				// addMethod(tableDialog, "0x0", methodName, params);
			}
		}


		// for (Map.Entry<String, ClassStatus> entry : classStatuses.entrySet()) {
		// 	addClass(tableDialog, "0x0", entry.getKey(), entry.getValue());
		// }
	}

	/**
	 * Builds the configurable columns for the TableDialog. More columns could be added.
	 * 
	 * @param tableChooserDialog the dialog 
	 */
	private void configureTableColumns(TableChooserDialog tableChooserDialog) {

		// column to display the note at the address where a
		// this is usually an error condition
		StringColumnDisplay methodNameColumn = new StringColumnDisplay() {
			@Override
			public String getColumnName() {
				return "Method Name";
			}

			@Override
			public String getColumnValue(AddressableRowObject rowObject) {
				MethodForImport entry = (MethodForImport) rowObject;
				String note = entry.getMethodName();
				if (note == null) {
					return "";
				}
				return note;
			}
		};

		StringColumnDisplay paramTypesColumn = new StringColumnDisplay() {
			@Override
			public String getColumnName() {
				return "Parameter Types";
			}

			@Override
			public String getColumnValue(AddressableRowObject rowObject) {
				MethodForImport entry = (MethodForImport) rowObject;
				String note = entry.getParamTypesAsString();
				if (note == null) {
					return "";
				}
				return note;
			}
		};

		tableChooserDialog.addCustomColumn(methodNameColumn);
		tableChooserDialog.addCustomColumn(paramTypesColumn);
	}

	/**
	 * Sample execution task Execution class called whenever the execute button
	 * in the table is called. NOTE: the execute button is not setup, so this is
	 * just and example
	 * 
	 * Useful if you are back tracking constants for malloc or calloc Runs
	 * another script that will create a structure on the return variable of
	 * calloc/malloc. It pulls a little trick when calling the CreateStructure
	 * script by creating an artificial ScriptState. This is a useful technique
	 * for other scripts as well.
	 * 
	 * @return the executor
	 */
	@SuppressWarnings("unused")
	private TableChooserExecutor createTableExecutor(Function function) {

		TableChooserExecutor executor = new TableChooserExecutor() {

			@Override
			public String getButtonName() {
				return "Rename";
			}

			@Override
			public boolean execute(AddressableRowObject rowObject) {
				MethodForImport zooMethod = (MethodForImport) rowObject;

				String methodName = zooMethod.getMethodName(); 
				Address entry = zooMethod.getAddress();
				String paramTypes = zooMethod.getParamTypesAsString();

				println("Renaming method " + function.getName() + " to " + methodName);

				renameMethod(function, methodName, zooMethod.getParamTypes());

				return false; 
			}
		};
		return executor;
	}

	private void addMethod(TableChooserDialog tableChooserDialog, String address, String methodName, String[] paramTypes) {
		tableChooserDialog.add(new MethodForImport(address, methodName, paramTypes));
	}

	class MethodForImport implements AddressableRowObject {
		private Address address;
		private String methodName;
		private String[] paramTypes;

		@Override
		public Address getAddress() {
			return address;
		}

		public String getMethodName() {
			return methodName;
		}

		public String[] getParamTypes() {
			return paramTypes;
		}

		public String getParamTypesAsString() {
			return String.join(", ", paramTypes);
		}

		MethodForImport(Address address, String methodName, String[] paramTypes) {
			this.address = address;
			this.methodName = methodName;
			this.paramTypes = paramTypes;
		}

		MethodForImport(String address, String methodName, String[] paramTypes) {
			this(toAddr(address), methodName, paramTypes);
		}

		MethodForImport(String address, String methodName, String paramTypes) {
			this(toAddr(address), methodName, paramTypes.split(","));
		}
	}

	public class MethodParser {

		private Map<String, ClassStatus> classStatuses = new HashMap<>();
		private Map<String, String> methodSignatures = new HashMap<>();
		private Map<String, String> methodAddresses = new HashMap<>();
		private Map<String, Set<String>> classMethodsMap = new HashMap<>();


		public void parse() {
			String homePath = System.getProperty("user.home");
			File importFile = new File(homePath + File.separator + "ida_export.csv");
			File classLogFile = new File(homePath + File.separator + "class_log.txt");
			createOrReplaceFile(classLogFile);
			File methodLogFile = new File(homePath + File.separator + "method_log.txt");
			createOrReplaceFile(methodLogFile);

			// println("Parsing importFile: " + homePath);

			// Set<String> uniqueClasses = new HashSet<>();

			try (Scanner scanner = new Scanner(importFile)) {
				//Skip header
				scanner.nextLine();
				try {
					FileWriter methodLogFileWriter = new FileWriter(methodLogFile);
					while (scanner.hasNextLine()) {
						String line = scanner.nextLine();
						// println(line);
						String[] parts = line.split(";");

						if (parts.length >= 3) {
							String mangledName = parts[0].trim();
							String methodSignature = parts[1].trim().replaceAll("\\(\\(", "\\(").replaceAll("\\)\\)", "\\)").replaceAll("\\(const\\(", "\\(");
							if (methodSignature.startsWith("std::") || methodSignature.startsWith("Metrowerks::")) {
								continue;
							}
							String address = parts[2].trim();

							// println(methodSignature);
							String methodName = extractMethodName(methodSignature);
							// println(methodName);
							String className = extractClassName(methodSignature);
							// println(className);
							classMethodsMap.computeIfAbsent(className, k -> new HashSet<>()).add(methodName);
							methodLogFileWriter.write(mangledName + " " + className + " " + methodName + " " + methodSignature + " " + address + "\n");

							// uniqueClasses.add(className);
							if (className.length() != 0 && getDataTypes(className).length != 0) {
								classStatuses.put(className, ClassStatus.MATCHED);
							} else if (className.length() != 0) {
								if (getDataTypes("ph_" + className).length != 0) {
									classStatuses.put(className, ClassStatus.IMPORTED);
								} else {
									classStatuses.put(className, ClassStatus.ABSENT);
								}
							}
							// classStatuses.put(className, ClassStatus.ABSENT);
							methodSignatures.put(mangledName, methodSignature);
							methodAddresses.put(mangledName, address);
						} else {
							println("Parsing Error: " + parts.length + " parts");
						}
					}
					methodLogFileWriter.close();
				} catch (IOException e) {
					e.printStackTrace();
				}

			} catch (FileNotFoundException e) {
				e.printStackTrace();
			}

			// Print the unique classes
			// println("Unique Classes:");
			try {
				FileWriter classLogFileWriter = new FileWriter(classLogFile);
				for (Map.Entry<String, ClassStatus> entry : classStatuses.entrySet()) {
					classLogFileWriter.write(entry.getKey() + "\n");
				}
				classLogFileWriter.close();
			} catch (IOException e) {
					e.printStackTrace();
			}
		}

		private static void createOrReplaceFile(File file) {
			try {
				if (file.exists()) {
					file.delete();
				}
				file.createNewFile();
			} catch (IOException e) {
				e.printStackTrace();
			}
		}

		private static String extractMethodName(String methodSignature) {
			int openingParenIndex = methodSignature.indexOf('(');
			if (openingParenIndex == -1) {
				openingParenIndex = methodSignature.length() - 1;
			}
			int lastColonIndex = methodSignature.lastIndexOf("::", openingParenIndex);
			if (lastColonIndex == -1) {
			   return methodSignature;
   			} else {
        		return methodSignature.substring(lastColonIndex + 2);
			}
		}

		private static String extractClassName(String methodSignature) {
			int bracketIndex = methodSignature.indexOf('(');
			if (bracketIndex == -1) {
				return "";
			}
			String beforeBracket = methodSignature.substring(0, bracketIndex);
			int lastColonIndex = beforeBracket.lastIndexOf("::");
			if (lastColonIndex == -1) {
				return "";
			}
			int num_colons = beforeBracket.split(beforeBracket, -1).length-1;
			if (num_colons == 0) {
				return beforeBracket;
			} else if (num_colons == 1) {
				return methodSignature.substring(0, lastColonIndex);
			} else {
				return methodSignature.substring(beforeBracket.indexOf("::"), lastColonIndex);
			}
		}

		public Map<String, ClassStatus> getClassStatuses() {
			return classStatuses;
		}

		public Map<String, Set<String>> getClassMethodsMap() {
			return classMethodsMap;
		}
	}

	public enum ClassStatus {
		IMPORTED,
		MATCHED,
		ABSENT
	}

	public static String convertStatus(ClassStatus status) {
		switch (status) {
			case IMPORTED:
				return "Imported";
			case MATCHED:
				return "Matched";
			case ABSENT:
				return "Absent";
			default:
				return "Unknown";
		}
	}

	public void renameClass(String oldClassName, String newClassName) {
		Namespace ooNamespace = getNamespace(null, "OOAnalyzer");
		DataType[] classDataTypes = getDataTypes(oldClassName);
		DataType[] vtableDataTypes = getDataTypes(oldClassName + "::vtable_" + oldClassName.replaceFirst("^cls_0x", ""));
		List<Symbol> classSymbols = getSymbols(oldClassName, ooNamespace);
		if (getDataTypes(newClassName).length != 0 || getSymbols(newClassName, null).size() != 0) {
			OkDialog.showError("Error", "Class " + newClassName + " already exists");
			return;
		} else if (classDataTypes.length == 0 || classSymbols.size() == 0) {
			OkDialog.showError("Error", "Class " + oldClassName + " does not exist " + classDataTypes.length + " " + classSymbols.size());
			return;
		} else if (classDataTypes.length != 1 || vtableDataTypes.length > 1 || classSymbols.size() != 1) {
			OkDialog.showError("Error", "Multiple classes with name " + oldClassName + " exist " + classDataTypes.length + " " + vtableDataTypes.length + " " + classSymbols.size());
			return;
		} else {
			start();
			try {
				DataType classDataType = classDataTypes[0];
				classDataType.setName(newClassName);
				if (vtableDataTypes.length == 1) {
					DataType vtableDataType = vtableDataTypes[0];
					vtableDataType.setName(newClassName + "::vtable");
				}
				classSymbols.get(0).setName(newClassName, SourceType.USER_DEFINED);
			} catch (Exception e) {
				e.printStackTrace();
				end(false);
			}
			end(true);

			println("Renamed class " + oldClassName + " to " + newClassName);
		}
	}

	public void renameMethod(Function oldFunction, String newFunctionName, String[] newFunctionArgs) {
		println("Renaming method " + oldFunction.getName() + " to " + newFunctionName + " with args " + Arrays.toString(newFunctionArgs));
		int numArgs = newFunctionArgs.length;
		boolean thisFlag = false;
		if (oldFunction.getCallingConventionName().equals("__thiscall")) {
			numArgs++;
			thisFlag = true;
		} 
		if (oldFunction.getParameterCount() != numArgs) {
			OkDialog.showError("Error", "Function " + oldFunction.getName() + " has " + oldFunction.getParameterCount() + " arguments, but " + numArgs + " were provided");
			return;
		}
		start();
		DataType[] paramDataTypes = new DataType[numArgs];
		try {
			oldFunction.setName(newFunctionName, SourceType.USER_DEFINED);
			int indexOffset = 0;
			if (thisFlag) {
				indexOffset = 1;
				paramDataTypes[0] = oldFunction.getParameter(0).getDataType();
			}
			for (int i = 0; i < numArgs-1; i++) {
				paramDataTypes[i] = getDataTypeFromParam(oldFunction.getParameter(i + indexOffset).getDataType(), newFunctionArgs[i]);

				if (paramDataTypes[i] == null) {
					paramDataTypes[i] = getOrCreateDataType(newFunctionArgs[i]);
					if (paramDataTypes[i] == null) {
						// println("Error getting data type from param " + newFunctionArgs[i]);
						end(false);
						return;
					}
				}
				retypeFunctionArg(oldFunction, i + indexOffset, paramDataTypes[i]);
				// oldFunction.getParameter(i).setDataType(paramDataTypes[i], SourceType.USER_DEFINED);
				// paramDataTypes[i] = getDataTypes(newFunctionArgs[i])[0];
				// oldFunction.getParameter(i).setName(newFunctionArgs[i], SourceType.USER_DEFINED);
			}
		} catch (Exception e) {
			println(e.getMessage());
			e.printStackTrace();
			end(false);
		}
		end(true);
	}

	public void retypeFunctionArg(Function function, int argIndex, DataType newDataType) throws ghidra.util.exception.InvalidInputException {
		println("Function args " + function.getParameterCount() + " " + argIndex + " " + newDataType.getName());
		try {
			function.getParameters()[argIndex].setDataType(newDataType, SourceType.USER_DEFINED);
		} catch (Exception e) {
			// if (function.hasCustomVariableStorage()) {
			// 	throw e;
			// }
			println("Retyping function " + function.getName() + " to use custom variable storage");
			function.setCustomVariableStorage(true);
			function.getParameters()[argIndex].setDataType(newDataType, SourceType.IMPORTED);
		}
	}

	public String mapDataTypes(String dataTypeString) {
		return dataTypeString.replaceAll("unsigned ", "u");
	}

	public DataType getOrCreateDataType(String dataTypeString) {
		DataType[] dataTypes = getDataTypes(mapDataTypes(dataTypeString));
		DataTypeManager dataTypeManager = currentProgram.getDataTypeManager();

		if (dataTypes.length == 0) {
			if (dataTypeString.endsWith(" *") || dataTypeString.endsWith(" &") || dataTypeString.endsWith("const &")) {
				String baseType = replaceSuffix(dataTypeString, " *");
				baseType = replaceSuffix(baseType, " &");
				baseType = replaceSuffix(baseType, " const");
				dataTypes = getDataTypes(mapDataTypes(baseType));
				if (dataTypes.length == 0) {
					println("Creating data type ph_" + baseType);
					StructureDataType structure = new StructureDataType(new CategoryPath("/OOAnalyzer"), "ph_" + baseType, 0);
					dataTypeManager.addDataType(structure, DataTypeConflictHandler.REPLACE_HANDLER);
					return new PointerDataType(structure);
				} else {
					return new PointerDataType(dataTypes[0]);
				}
			}
			println("Creating data type ph_" + dataTypeString);
			StructureDataType structure = new StructureDataType(new CategoryPath("/OOAnalyzer"), "ph_" + dataTypeString, 0);
			dataTypeManager.addDataType(structure, DataTypeConflictHandler.REPLACE_HANDLER);
			// return createDataType(mapDataTypes(dataTypeString));
			return structure;
		} else {
			return dataTypes[0];
		}
	}

	public String replaceSuffix(String sourceString, String suffix) {
		if (sourceString.endsWith(suffix)) {
			return sourceString.substring(0, sourceString.length() - suffix.length());
		} else {
			return sourceString;
		}
	}

	public DataType getDataTypeFromParam(DataType oldDataType, String paramName) {
		println("Getting data type from param " + paramName);
		DataType[] dataTypes = getDataTypes(mapDataTypes(paramName));
		if (dataTypes.length >= 1) {
			if (oldDataType == dataTypes[0]) {
				return dataTypes[0];
			} else {
				switch (OptionDialog.showYesNoCancelDialog(null, "Confirm", oldDataType.getName() + " will be changed to " + dataTypes[0].getName())) {
					case 0:
						println("Cancelled");
						return null;
					case 1:
						println("Yes");
						return dataTypes[0];
					case 2:
						println("No");
						return oldDataType;
					default:
						return null;
				}

			}
		} else {
			return null;
		}
}