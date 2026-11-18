class ASTNode:
    def __init__(self, node_type, line=1, **kwargs):
        self.node_type = node_type
        self.line = line
        self.attributes = kwargs

    def __getattr__(self, name):
        if name in self.attributes:
            return self.attributes[name]
        return None

    def to_dict(self):
        res = {"type": self.node_type, "line": self.line}
        for k, v in self.attributes.items():
            if isinstance(v, ASTNode):
                res[k] = v.to_dict()
            elif isinstance(v, list):
                res[k] = [item.to_dict() if isinstance(item, ASTNode) else item for item in v]
            else:
                res[k] = v
        return res
