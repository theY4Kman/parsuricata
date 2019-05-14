#!/usr/bin/env bash
poetry version $1
new_vers=$(cat pyproject.toml | grep "^version = \"*\"" | cut -d'"' -f2)
sed -i "s/__version__ = .*/__version__ = \"${new_vers}\"/g" parsuricata/__init__.py
