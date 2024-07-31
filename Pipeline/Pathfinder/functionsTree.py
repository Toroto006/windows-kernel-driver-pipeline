class FuncNode():
    """Represents a node in the function tree"""

    def __init__(self, addr, name=None, depth=0) -> None:
        self.addr = addr
        self.name = name
        self.depth = depth
        self.children = []
    
    def getOrAdd(self, addr):
        for c in self.children:
            if c.addr == addr:
                return c
        
        c = FuncNode(addr, depth=self.depth + 1)
        self.children.append(c)
        return c
    
    def __str__(self) -> str:
        """Prints the tree starting from this node"""
        indent = "  " * self.depth
        s = f"{indent}0x{self.addr:02X}{' ' + self.name if self.name is not None else ''}{' {' if len(self.children) > 0 else ''}\n"
        for c in self.children:
            s += str(c)
        s += f'{indent}}}\n' if len(self.children) > 0 else ''
        return s

def makeFunctionTree(handler_addr, paths, root_name=None):
    root = FuncNode(handler_addr, depth=0)
    root.name = root_name

    for p in paths:
        # First check if the path is relevant to this tree
        if p['path'][0] != handler_addr:
            continue
        
        # Add all intermediate nodes
        current = root.getOrAdd(p['path'][1])
        if len(p['path']) > 2:
            for addr in p['path'][2:]:
                current = current.getOrAdd(addr)

        # Add the leaf node name
        current.name = p['name']
    
    return root

def combinedSubfunctions(tree, depth=0):
    """Returns a list of all subfunctions that have more than one child on any level """
    if len(tree.children) == 0:
        return []
    
    subfunctions = []
    for c in tree.children:
        if len(c.children) > 1:
            subfunctions.append(c)
        subfunctions += combinedSubfunctions(c, depth + 1)
    
    return subfunctions

if __name__ == "__main__":
    ## Test the functionality
    import json
    RESULT_FILE = '.\\ida_ioctl_res.json'
    results = {}
    with open(RESULT_FILE, "r") as f:
        results = json.loads(f.read())

    for handler in results['handler_addrs']:
        tree = makeFunctionTree(handler, results['target_paths'] + results['helper_paths'], results['handler_type'])
        print(tree)
        print(f"{len(combinedSubfunctions(tree))} combined subfunctions:")
        for sub in combinedSubfunctions(tree):
            print(sub)
