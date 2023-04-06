import setuptools

with open("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name="procmon-parser",
    version="0.3.13",
    author="Ely Ronnen",
    author_email="elyronnen@gmail.com",
    description="Parser to Procmon configuration and log files formats",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/eronnen/procmon-parser.git",
    download_url="https://github.com/eronnen/procmon-parser/archive/v0.3.0.tar.gz",
    packages=["procmon_parser"],
    install_requires=[
        "enum34;python_version<'3.4'",
        "construct>=2.10.54",
        "six",
        "ipaddress;python_version<'3'",
    ],
    classifiers=[
        "Intended Audience :: Developers",
        "Intended Audience :: Education",
        "Programming Language :: Python :: 2.7",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires='>=2.7, !=3.0.*, !=3.1.*, !=3.2.*, !=3.3.*, !=3.4.*, !=3.5.*',
)
