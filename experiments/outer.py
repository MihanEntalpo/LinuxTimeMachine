import types

def read_custom_py_module(filename):
    with open(filename, "r") as f:
        code = f.read()
        new_module = types.ModuleType("new_temporary_module")
        exec(code, new_module.__dict__)

    return new_module