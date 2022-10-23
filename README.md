# RDM880

This is communication protocol implementation library for
[RDM880 RFID module](http://www.seeedstudio.com/wiki/13.56Mhz_RFID_module_-_IOS/IEC_14443_type_a)
written in C++.

## Dependencies

Tools and libraries:

* Git
* C++ Compiler
* CMake
* Boost

Following command could be used to install dependencies on Ubuntu:
`apt-get install git gcc g++ cmake libboost-all-dev`.

## Clone

Following command could be used to clone repository:
`git clone git@bitbucket.org:murzzz/rdm880.git`.

## Build

Following command could be used to build repository:

```sh
cmake -Bbuild -Hrdm880/src
cmake --build build --target all
```

## Run tests

Following command could be used to execute available tests:
`cmake --build build --target check`.

## Build status

[Bitbucket Pipelines](https://bitbucket.org/murzzz/rdm880/addon/pipelines/home)
is used for CI.
