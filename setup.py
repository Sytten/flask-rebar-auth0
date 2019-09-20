#!/usr/bin/env python
from setuptools import setup


with open("README.md", "r") as fh:
    long_description = fh.read()


if __name__ == "__main__":
    setup(
        name="flask-rebar-auth0",
        version="0.1.6",
        author="Emile Fugulin",
        author_email="emilefugulin@hotmail.com",
        description="Flask-Rebar-Auth0 is a simple Flask-Rebar authenticator Auth0",
        long_description=long_description,
        long_description_content_type="text/markdown",
        keywords=["flask", "flask-rebar", "auth0"],
        license="MIT",
        packages=["flask_rebar_auth0"],
        include_package_data=True,
        install_requires=[
            "flask-rebar>=1.0.0,<2",
            "Flask>=0.10,<2",
            "requests>=2.20.0,<3",
            "python-jose>=3.0.1,<4",
            "cryptography>=2.6.1,<3",
        ],
        extras_require={
            "dev": [
                "pytest",
                "pytest-cov",
                "pytest-mock",
                "requests-mock",
                "black",
                "codecov",
            ]
        },
        url="https://github.com/Sytten/flask-rebar-auth0",
        classifiers=[
            "Environment :: Web Environment",
            "Framework :: Flask",
            "Intended Audience :: Developers",
            "License :: OSI Approved :: MIT License",
            "Operating System :: OS Independent",
            "Programming Language :: Python",
            "Programming Language :: Python :: 3",
            "Programming Language :: Python :: 3.5",
            "Programming Language :: Python :: 3.6",
            "Programming Language :: Python :: 3.7",
            "Topic :: Software Development :: Libraries",
            "Topic :: Utilities",
        ],
    )
