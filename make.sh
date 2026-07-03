#!/bin/bash
# Build and install gnolly with both Cython extensions (_gnolly_core + _gnolly_vm).
# Both .so files are required for protected files to run.
# Make sure you are in a Python 3.11+ environment.
clear
pip install pycryptodome cython && \
python setup.py build_ext --inplace && \
pip install . && \
python -m gnolly.verify
