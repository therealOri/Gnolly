# How to use
> [!IMPORTANT]
> 1. Because this will protect every .py file it can in your specified dir and in sub-directories, execution time may very and or be slower because of the very nature of obfuscation. More files protected = more files that need to run their course. Which means it may take longer to run code and import, etc.
>
> 2. If you do NOT `export GNOLLY_KEY=1234567890` (set it as an env var python can access/use), on import it will ask you to paste said key and THEN it will run.
> This may have unintended side affects or bugs depending on how many imports it'll do. (WIP)


## Commands

```bash
# Depends on a separately pip-installed gnolly at import time (smaller wheel)
gnolly protect-wheel toolkit dist --name toolkit --version 1.0.0

# OR: fully self-contained, bundles the .so files into the wheel
gnolly protect-wheel toolkit dist --name toolkit --version 1.0.0 --bundle-runtime
```

This prints a `GNOLLY_KEY` and writes to `dist/toolkit-1.0.0.gnolly.key` next
to the wheel file. (the key is never bundled inside the .whl itself)
> `dist` is the default in case you don't provide and output dir.

<br>

```bash
pip install dist/toolkit-1.0.0-*.whl
GNOLLY_KEY=<hex_key> python -c "
import toolkit
from toolkit.geometry.shapes import Rectangle
print(toolkit.describe(Rectangle(4, 5)))
"
```
> Make sure the local toolkit dir is either renamed or moved. Or else demo.py or commands MAY use the local toolkit/ instead of site-packages toolkit/
__ __
