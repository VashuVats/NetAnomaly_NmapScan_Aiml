import sys
from pathlib import Path

ML_API = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ML_API))
REPO_ROOT = ML_API.parents[1]
FIXTURES = Path(__file__).parent / 'fixtures'
