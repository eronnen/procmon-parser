import setuptools

with open("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name="procmon-parser",
    version="0.0.1",
    author="Ely Ronnen",
    author_email="elyronnen@gmail.com",
    description="Parser to Process Monitor configuration and log files formats",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/eronnen/procmon-parser.git",
    packages=setuptools.find_packages(),
    install_requires=["construct>=2.9"],
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires='>=3.6',
)
