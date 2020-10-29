from setuptools import setup

import ed25519


setup(
    name="ed25519.py",
    version=ed25519.__version__,
    py_modules=["ed25519"],
    zip_safe=False,
)
