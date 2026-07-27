"""
Shared utilities used across all cloudguard-pro Lambda functions.

Importing this module in each Lambda is done via a Lambda Layer at deploy
time (see pulumi/__main__.py). For local testing, tests/ adds this path
directly via conftest.py.
"""
