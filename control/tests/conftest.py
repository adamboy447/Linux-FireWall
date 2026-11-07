import os
import sys

HERE = os.path.dirname(__file__)
ROOT = os.path.abspath(os.path.join(HERE, "..", ".."))
sys.path.insert(0, os.path.join(ROOT, "control", "src"))

import pytest  # noqa: E402

from myfw_ops.models import Inventory, Policy, load_yaml_model  # noqa: E402


@pytest.fixture
def inv():
    return load_yaml_model(Inventory, open(os.path.join(ROOT, "lab", "inventory.yaml")).read())


@pytest.fixture
def demo_text():
    return open(os.path.join(ROOT, "policies", "demo.yaml")).read()


@pytest.fixture
def demo(demo_text):
    return load_yaml_model(Policy, demo_text)
