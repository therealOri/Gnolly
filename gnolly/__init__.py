"""
Gnolly -> Python code protection.
Free, open, and with no paywalls.
"""
__version__ = "1.0.0"

from .pipeline import protect, protect_file
from .crypto   import generate_key

__all__ = ["protect", "protect_file", "generate_key"]
