"""
Root conftest.py.

Two responsibilities:
1. Add the repo root to sys.path so tests can `from lambdas.shared...`
   and `from lambdas.event_ingestor.src...` regardless of where pytest
   is invoked from.
2. Force dummy AWS credentials/region into the environment before any
   boto3 client is constructed, so moto-mocked tests can never
   accidentally make a live AWS call even if a mock decorator is
   missing on a test.
"""

import os
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(REPO_ROOT))

os.environ.setdefault("AWS_ACCESS_KEY_ID", "testing")
os.environ.setdefault("AWS_SECRET_ACCESS_KEY", "testing")
os.environ.setdefault("AWS_SECURITY_TOKEN", "testing")
os.environ.setdefault("AWS_SESSION_TOKEN", "testing")
os.environ.setdefault("AWS_DEFAULT_REGION", "us-east-1")
os.environ.setdefault("AWS_REGION", "us-east-1")
os.environ.setdefault("FINDINGS_TABLE_NAME", "cloudguard-findings-test")
