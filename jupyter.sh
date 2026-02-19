#!/bin/bash
uv venv --clear
uv pip install -U jupyter pytest
uv pip install -e ./bindings/python
source .venv/bin/activate
cargo install evcxr_jupyter
evcxr_jupyter --install
jupyter lab
