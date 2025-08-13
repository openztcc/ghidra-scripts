#Given some parent classes, creates a graph with said classes and all child classes. Similar to Ghidras 'Data Type Manager -> Display as Graph' but iterates in the opposite direction and can take multiple nodes as starting points. 
#Must to be called from the command lines as I haven't figured out a way to get the currently selected types from the 'Data Type Manager'
#@author Finn Hartshorn
#@category _NEW_
#@keybinding 
#@menupath 
#@toolbar 

from ghidra.service.graph import AttributedGraph, EmptyGraphType
from ghidra.app.services import GraphDisplayBroker
from ghidra.service.graph import GraphDisplay
from ghidra.program.model.data import CategoryPath

def class_hierarchy(class_strings):
	already_in_graph = {}


	tool = getState().getTool()
	graph_service = tool.getService(GraphDisplayBroker)
	display = graph_service.getDefaultGraphDisplay(False, monitor)

	graph = AttributedGraph("Test", EmptyGraphType())

	oo_zoo = currentProgram.getDataTypeManager().getCategory(CategoryPath("/OOAnalyzer"))

	nodes_to_process = [oo_zoo.getDataTypesByBaseName(name)[0] for name in class_strings]

	for node in nodes_to_process:
		add_vertex(graph, node.getName(), already_in_graph)


	while nodes_to_process and graph.getVertexCount() < 100:
		current_node = nodes_to_process.pop()

		parents = current_node.getParents()
		# nodes_to_process.extend(parents)
		for parent in parents:
			if parent.getName().startswith("virt_meth") or parent.getName().endswith("*"):
				continue
			elif parent in already_in_graph:
				parent_vertex = already_in_graph[parent.getName()]
			else:
				parent_vertex = add_vertex(graph, parent.getName(), already_in_graph)
				nodes_to_process.append(parent)

			current_vertex = already_in_graph[current_node.getName()]
			
			graph.addEdge(current_vertex, parent_vertex)

	display.setGraph(graph, "Class Graph", False, monitor)





def add_vertex(graph, name, in_dict):
	vertex = graph.addVertex(name, name)
	in_dict[name] = vertex
	return vertex

if __name__ == "__main__":
	class_hierarchy(["cls_0x6354e4"])

	#class_hierarchy(["cls_0x62d4b4", "cls_0x635430"])
	#class_hierarchy(["BFRegistry", "ZTWorldMgr", "ZTGameMgr"])

