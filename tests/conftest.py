import os
import sys

import pytest


ROOT_DIR = os.path.dirname(os.path.dirname(__file__))
SRC_DIR = os.path.join(ROOT_DIR, "src")

if SRC_DIR not in sys.path:
    sys.path.insert(0, SRC_DIR)

from crypto.ml_dsa import MLDSA65
from crypto.ml_kem import MLKEM768


@pytest.fixture(scope="session")
def mldsa_keypair():
    return MLDSA65.generate_keypair()


@pytest.fixture(scope="session")
def mlkem_keypair():
    return MLKEM768.generate_keypair()
