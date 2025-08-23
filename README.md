# Complete Reverse Engineering of the Microsoft Windows "FileCrypt" driver

This project includes:

1. A complete re-write of `filecrypt.sys`: [FileCrypt Reimagined](https://github.com/NoamGrdn/FileCrypt/tree/master/FileCrypt%20Reimagined) that allows the driver to be built from source and edited.
2. A [technical overview](https://github.com/NoamGrdn/FileCrypt/blob/master/Technical%20Overview.md) of the driver that includes all utilized registries, custom data structures, imported binaries, and more.
3. A funky [web app](https://github.com/NoamGrdn/FileCrypt/tree/master/Interactive%20Visualization) that visualizes the functionality of the driver.
4. A copy of a published article describing this project's research
5. An export file of the Ghidra project (The Ghidra version used in this project can be found in the technical overview).