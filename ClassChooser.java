// Some tests
//@category _NEW_

import java.util.*;

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

public class ClassChooser extends GhidraScript {
	TableChooserDialog tableDialog;

	@Override
	public void run() throws Exception {
		// TableChooserExecutor executor = null;
		TableChooserExecutor executor = createTableExecutor();

		tableDialog = createTableChooserDialog("Class Names", executor);
		configureTableColumns(tableDialog);
		tableDialog.show();
		tableDialog.setMessage("Searching...");


		addClass(tableDialog, "0x1000", "This is a test");

		tableDialog.setMessage("Finished!");
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
				return "Note";
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

		tableChooserDialog.addCustomColumn(classNameColumn);
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
	private TableChooserExecutor createTableExecutor() {

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

				println("Class address: " + entry);
				println("Class name: " + className);

				return false; // don't remove row from display table
			}
		};
		return executor;
	}

	private void addClass(TableChooserDialog tableChooserDialog, String address, String className) {
		tableChooserDialog.add(new ClassForImport(address, className));
	}

	class ClassForImport implements AddressableRowObject {
		private Address address;
		private String className;

		ClassForImport(Address address, String className) {
			this.address = address;
			this.className = className;
		}

		ClassForImport(String address, String className) {
			this(toAddr(address), className);
		}

		@Override
		public Address getAddress() {
			return address;
		}

		public String getClassName() {
			return className;
		}
	}
}