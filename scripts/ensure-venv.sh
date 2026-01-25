#!/bin/sh

if [ -z "$VIRTUAL_ENV" ]; then
    echo "Running in Python virtual environment is required:"
    echo "source ./.venv/bin/activate"
    exit 1
fi
