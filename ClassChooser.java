// Some tests
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
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.SymbolType;
import ghidra.program.model.listing.Function;

import ghidra.util.exception.DuplicateNameException;
import ghidra.util.InvalidNameException;



import docking.widgets.OkDialog;


public class ClassChooser extends GhidraScript {
	TableChooserDialog tableDialog;

	@Override
	public void run() throws Exception {
		Function currentFunction = getFunctionContaining(currentAddress);
		Symbol currentFunctionSymbol = currentFunction.getSymbol();
		Symbol parentSymbol = currentFunctionSymbol.getParentSymbol();
		if (parentSymbol.getSymbolType() != SymbolType.CLASS) {
			OkDialog.showError("Error", "Function " + currentFunction.getName() + " is not a method of a class.");
			return;
		}
		// SymbolTable symbolTable = currentProgram.getSymbolTable();
		// Namespace namespace = currentFunction.getParentNamespace();
		// println("Namespace: " + namespace.getName());

		// Symbol[] symbols = symbolTable.getSymbols(currentFunction.getEntryPoint());
		// for (Symbol symbol : symbols) {
		// 	println(symbol.getName());
		// }

		// DataTypeManager dataTypeManager = currentProgram.getDataTypeManager();

		// try {
        //     DataType[] selectedTypes = askDataTypeChooser("Select Types", "Select types to process:");
        //     if (selectedTypes == null) {
        //         return; // User cancelled the selection
        //     }

        //     println("Selected Types:");
        //     for (DataType selectedType : selectedTypes) {
        //         println(selectedType.getPathName());
        //     }
        // } catch (CancelledException e) {
        //     // User cancelled the selection
        // }

		// TableChooserExecutor executor = null;
		TableChooserExecutor executor = createTableExecutor(parentSymbol);

		tableDialog = createTableChooserDialog("Rename " + parentSymbol.getName(), executor);
		configureTableColumns(tableDialog);
		tableDialog.show();
		tableDialog.setMessage("Parsing...");


		// addClass(tableDialog, "0x1000", "This is a test");

		tableDialog.setMessage("Finished!");
		MethodParser ida_export = new MethodParser();
		ida_export.parse();

		Map<String, ClassStatus> classStatuses = ida_export.getClassStatuses();

		for (Map.Entry<String, ClassStatus> entry : classStatuses.entrySet()) {
			addClass(tableDialog, "0x0", entry.getKey(), entry.getValue());
		}
	}

	/**
	 * Builds the configurable columns for the TableDialog. More columns could be added.
	 * 
	 * @param tableChooserDialog the dialog 
	 */
	private void configureTableColumns(TableChooserDialog tableChooserDialog) {

		// column to display the note at the address where a
		// this is usually an error condition
		StringColumnDisplay classNameColumn = new StringColumnDisplay() {
			@Override
			public String getColumnName() {
				return "Class Name";
			}

			@Override
			public String getColumnValue(AddressableRowObject rowObject) {
				ClassForImport entry = (ClassForImport) rowObject;
				String note = entry.getClassName();
				if (note == null) {
					return "";
				}
				return note;
			}
		};

		StringColumnDisplay classStatusColumn = new StringColumnDisplay() {
			@Override
			public String getColumnName() {
				return "Class Status";
			}

			@Override
			public String getColumnValue(AddressableRowObject rowObject) {
				ClassForImport entry = (ClassForImport) rowObject;
				String note = convertStatus(entry.getClassStatus());
				if (note == null) {
					return "";
				}
				return note;
			}
		};

		tableChooserDialog.addCustomColumn(classNameColumn);
		tableChooserDialog.addCustomColumn(classStatusColumn);
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
	private TableChooserExecutor createTableExecutor(Symbol classSymbol) {

		TableChooserExecutor executor = new TableChooserExecutor() {

			@Override
			public String getButtonName() {
				return "Create Structure";
			}

			@Override
			public boolean execute(AddressableRowObject rowObject) {
				ClassForImport ZooClass = (ClassForImport) rowObject;

				String className = ZooClass.getClassName();
				Address entry = ZooClass.getAddress();



				println("Renaming class " + classSymbol.getName() + " to " + className);
				renameClass(classSymbol.getName(), className);

				return false; // don't remove row from display table
			}
		};
		return executor;
	}

	// class ClassRenamerExecutor extends TableChooserExecutor {
	// 	Symbol classSymbol;

	// 	ClassRenamerExecutor(Symbol classSymbol) {
	// 		this.classSymbol = classSymbol;
	// 	}

	// 	// @Override
	// 	public String getButtonName() {
	// 		return "Create Structure";
	// 	}

	// 	// @Override
	// 	public boolean execute(AddressableRowObject rowObject) {
	// 		ClassForImport ZooClass = (ClassForImport) rowObject;

	// 		String className = ZooClass.getClassName();
	// 		Address entry = ZooClass.getAddress();

	// 		println("Class address: " + entry);
	// 		println("Class name: " + className);

	// 		println("Renaming class " + classSymbol.getName() + " to " + className);

	// 		return false; // don't remove row from display table
	// 	}
	// }

	private void addClass(TableChooserDialog tableChooserDialog, String address, String className, ClassStatus status) {
		tableChooserDialog.add(new ClassForImport(address, className, status));
	}

	class ClassForImport implements AddressableRowObject {
		private Address address;
		private String className;
		private ClassStatus status;

		ClassForImport(Address address, String className, ClassStatus status) {
			this.address = address;
			this.className = className;
			this.status = status;
		}

		ClassForImport(String address, String className, ClassStatus status) {
			this(toAddr(address), className, status);
		}

		@Override
		public Address getAddress() {
			return address;
		}

		public String getClassName() {
			return className;
		}

		public ClassStatus getClassStatus() {
			return status;
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

	public class MethodParser {

		private Map<String, ClassStatus> classStatuses = new HashMap<>();
		private Map<String, String> methodSignatures = new HashMap<>();
		private Map<String, String> methodAddresses = new HashMap<>();


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
							String methodSignature = parts[1].trim().replaceAll("\\(\\(", "\\(").replaceAll("\\)\\)", "\\)");
							if (methodSignature.startsWith("std::") || methodSignature.startsWith("Metrowerks::")) {
								continue;
							}
							String address = parts[2].trim();

							String methodName = extractMethodName(methodSignature);
							String className = extractClassName(methodSignature);
							methodLogFileWriter.write(mangledName + " " + className + " " + methodName + " " + methodSignature + " " + address + "\n");

							// uniqueClasses.add(className);
							if (getDataTypes(className).length != 0) {
								classStatuses.put(className, ClassStatus.MATCHED);
							} else {
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

			// Print the method signatures
			// println("\nMethod Signatures:");
			// for (Map.Entry<String, String> entry : methodSignatures.entrySet()) {
			// 	String mangledName = entry.getKey();
			// 	String methodSignature = entry.getValue();
			// 	println(mangledName + " -> " + methodSignature);
			// }

			// Print the method addresses
			// println("\nMethod Addresses:");
			// for (Map.Entry<String, String> entry : methodAddresses.entrySet()) {
			// 	String mangledName = entry.getKey();
			// 	String address = entry.getValue();
			// 	println(mangledName + " -> " + address);
			// }
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
			int lastSpaceIndex = methodSignature.lastIndexOf("::", openingParenIndex);
			if (openingParenIndex == -1) {
			   return methodSignature.substring(lastSpaceIndex + 1);
   			} else {
        		return methodSignature.substring(lastSpaceIndex + 1, openingParenIndex);
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
}