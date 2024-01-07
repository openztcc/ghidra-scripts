// Renames the class of the current function in the decompiler view
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
import ghidra.program.model.data.DataTypeDependencyException;
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

		TableChooserExecutor executor = createTableExecutor(parentSymbol);

		tableDialog = createTableChooserDialog("Rename " + parentSymbol.getName(), executor);
		configureTableColumns(tableDialog);
		tableDialog.show();
		tableDialog.setMessage("Parsing...");

		MethodParser ida_export = new MethodParser();
		ida_export.parse();

		tableDialog.setMessage("Finished!");
		Map<String, ClassStatus> classStatuses = ida_export.getClassStatuses();

		for (Map.Entry<String, ClassStatus> entry : classStatuses.entrySet()) {
			addClass(tableDialog, "0x0", entry.getKey(), entry.getValue());
		}
	}

	private void configureTableColumns(TableChooserDialog tableChooserDialog) {

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

	@SuppressWarnings("unused")
	private TableChooserExecutor createTableExecutor(Symbol classSymbol) {

		TableChooserExecutor executor = new TableChooserExecutor() {

			@Override
			public String getButtonName() {
				return "Rename Class";
			}

			@Override
			public boolean execute(AddressableRowObject rowObject) {
				ClassForImport ZooClass = (ClassForImport) rowObject;

				String className = ZooClass.getClassName();
				Address entry = ZooClass.getAddress();

				println("Renaming class " + classSymbol.getName() + " to " + className);
				renameClass(classSymbol.getName(), className);

				replacePlaceholders(className);

				return false;
			}
		};
		return executor;
	}

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
		PLACEHOLDER,
		IMPORTED,
		ABSENT
	}

	public static String convertStatus(ClassStatus status) {
		switch (status) {
			case PLACEHOLDER:
				return "Placeholder";
			case IMPORTED:
				return "Imported";
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
								classStatuses.put(className, ClassStatus.IMPORTED);
							} else {
								if (getDataTypes("ph_" + className).length != 0) {
									classStatuses.put(className, ClassStatus.PLACEHOLDER);
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
		DataType[] vftableDataTypes = getDataTypes(oldClassName + "::vftable_" + oldClassName.replaceFirst("^cls_0x", ""));
		List<Symbol> classSymbols = getSymbols(oldClassName, ooNamespace);
		if (getDataTypes(newClassName).length != 0 || getSymbols(newClassName, null).size() != 0) {
			OkDialog.showError("Error", "Class " + newClassName + " already exists");
			return;
		} else if (classDataTypes.length == 0 || classSymbols.size() == 0) {
			OkDialog.showError("Error", "Class " + oldClassName + " does not exist " + classDataTypes.length + " " + classSymbols.size());
			return;
		} else if (classDataTypes.length != 1 || vftableDataTypes.length > 1 || classSymbols.size() != 1) {
			OkDialog.showError("Error", "Multiple classes with name " + oldClassName + " exist " + classDataTypes.length + " " + vftableDataTypes.length + " " + classSymbols.size());
			return;
		} else {
			start();
			try {
				DataType classDataType = classDataTypes[0];
				classDataType.setName(newClassName);
				if (vftableDataTypes.length == 1) {
					DataType vtableDataType = vftableDataTypes[0];
					vtableDataType.setName(newClassName + "::vftable");
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

	public void replacePlaceholders(String className) {
		DataType placeholder = getDataTypes("ph_" + className)[0];
		DataType classDataType = getDataTypes(className)[0];
		if (placeholder == null || classDataType == null) {
			return;
		}
		DataTypeManager dataTypeManager = currentProgram.getDataTypeManager();
		start();
		try {
			dataTypeManager.replaceDataType(placeholder, classDataType, true);
		} catch (DataTypeDependencyException e) {
			e.printStackTrace();
			end(false);
			return;
		}
		end(true);
	}
}