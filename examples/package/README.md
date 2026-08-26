# How to use

## 1. Run it unprotected

```bash
python examples/package/demo.py
```

## 2. Protect it as a real, pip-installable wheel

```bash
# Depends on a separately pip-installed gnolly at import time (smaller wheel)
gnolly protect-wheel toolkit dist --name toolkit --version 1.0.0

# OR: fully self-contained, bundles the .so runtime into the wheel
gnolly protect-wheel toolkit dist --name toolkit --version 1.0.0 --bundle-runtime
```

This prints a `GNOLLY_KEY` and writes `dist/toolkit-1.0.0.gnolly.key` next
to the wheel (the key is never bundled inside the .whl itself).
> `dist` is the default in case you don't provide and output dir.

```bash
pip install dist/toolkit-1.0.0-*.whl
GNOLLY_KEY=<hex_key> python -c "
import toolkit
from toolkit.geometry.shapes import Rectangle
print(toolkit.describe(Rectangle(4, 5)))
"
```
> Make sure the local toolkit dir is either renamed or moved. Or else demo.py or commands MAY use the local toolkit/ instead of site-packages toolkit/

