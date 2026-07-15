#!/bin/bash
# Build and install gnolly with both Cython extensions (_gnolly_core + _gnolly_vm).
# Both .so files are required for protected files to run.
# Make sure you are in a Python 3.11+ environment.
set -e
clear
pip install pycryptodome cython
python setup.py build_ext --inplace
pip install .
python -m gnolly.verify


# Clean up!
rm -rf build
rm -rf ./*.egg-info
rm -f gnolly/*.c
rm -f gnolly/*.so
rm -f gnolly/_gnolly_core.stamp
find . -type d -name "__pycache__" -exec rm -rf {} +
