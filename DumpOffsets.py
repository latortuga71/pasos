#TODO write a description for this script
#@author 
#@category _NEW_
#@keybinding 
#@menupath 
#@toolbar 


#TODO Add User Code Here

from ghidra.program.model.block import BasicBlockModel
from ghidra.util.task import TaskMonitor

image_base = currentProgram.getImageBase().getOffset()
bbm = BasicBlockModel(currentProgram)
blocks = bbm.getCodeBlocks(TaskMonitor.DUMMY)
block = blocks.next()

print("ImageBase: {}".format(hex(image_base).rstrip("L")))
ghidra_file = askFile("Please select the Offset Output-File", "Save To File")
with open(ghidra_file.getAbsolutePath(), "w") as f:
    while block:
        block_offset_hex = hex(block.minAddress.getOffset() - image_base).rstrip("L")
        #line = "{}".format(block.name)
        #line += ": {}".format(block_offset_hex)
	func_name = block.getName()
	print(func_name)
	if func_name.startswith("LAB_"):
		line = "{}\n".format(block_offset_hex)
		f.write(line)

	
        #print("Min Address: {}".format(block.minAddress))
        #print("Max address: {}".format(block.maxAddress))
        block = blocks.next()

print("Done")
