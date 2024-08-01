#!/bin/bash

if [[ $# -ne 1 ]]; then
    echo "Usage: $0 <python_script_dir>"
    echo "Runs tests on all *_test.py files in the given directory."
    exit 1
fi

HOME_DIR=$(dirname "$0")
TARGET_DIR=${1:-.}

PATH=$PATH:/usr/local/bin

if [ ! -d .venv ]; then
    python3 -m venv .venv
fi

source .venv/bin/activate

if ! pip install pytest pytest-cov pytest-mock requests requests-mock gitpython openai pyyaml; then
    echo "Unable to install dependencies."
    exit 1
fi

python3 -m pytest "--cov-config=${HOME_DIR}/pytest.ini" "--cov=$TARGET_DIR" --doctest-modules --cov-report=term "$TARGET_DIR" 