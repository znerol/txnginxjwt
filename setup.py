from setuptools import find_packages
from setuptools import setup

setup(
    name="TxNginxJWT",
    version="1.0.0",
    package_dir={
        "": "src",
        "twisted": "twisted",
    },
    packages=find_packages("src") + ["twisted.plugins"],
    package_data={
        "twisted.plugins": [
            "twisted/plugins/txnginxjwt_service.py",
        ]
    },
    install_requires=[
        "Twisted",
        "jwcrypto",
        "zope.interface",
    ],
)
