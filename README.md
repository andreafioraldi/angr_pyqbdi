# angr_pyqbdi

State synchronization between a pyQBDI instrumented process and angr. Based on [angrdbg](https://github.com/andreafioraldi/angrdbg).

This module transfers the instrumented process state in angr to perform symbolic execution and after injects the results in the concrete process to bypass all checks.

You need to run an rpyc server on localhost in the same execution folder of the script to be able to run it.

To start an rpyc server (be sure that you are in a virtualenv with angrdbg installed):
```
$ rpyc_classic.py
```

To start the script:
```
$ export LD_LIBRARY_PATH=/usr/local/lib/
$ LD_PRELOAD=/usr/local/lib/libpyqbdi.so PYQBDI_TOOL=./ais3_crackme.py ./ais3_crackme DUMMYDUMMYDUMMY
```

Example run:
```
 ╭─andrea@malweisse ~/Desktop/angr-qdbi
 ╰─$ LD_PRELOAD=/usr/local/lib/libpyqbdi.so PYQBDI_TOOL=./ais3_crackme.py ./ais3_crackme DUMMYDUMMYDUMMY
 >> symbolizing 0x7ffd8962ff26 : 100
 >> starting exploration...
 >> valid state found
 >> solution:
0x7ffd8962ff26 : 100 = 'ais3{I_tak3_g00d_n0t3s}##\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
Correct! that is the secret key!
```

### differencies with angrgdb and others

The angrdbg API StateShot must not be directly invoked in this module but you must invoke VMShot passing the current pyQBDI vm object as first argument.
