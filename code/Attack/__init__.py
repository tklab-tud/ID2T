import glob
import os.path as osp

# Create a list consisting of all attack classes names in this package
__all__ = []
modules = glob.glob(osp.dirname(__file__) + "/*.py")
for m in modules:
    c = str(osp.basename(m)[:-3])
    if (not c.startswith('__') and not c.startswith('Base') and c.endswith('Attack')) or c == "ParameterTypes":
        __all__.append(c)
