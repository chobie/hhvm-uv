hhvm-uv
=======

interface to libuv for hhvm (experimental). also supports http-parser.

## Install

```
# you need to build hhvm your machine before hphpize.
git clone https://github.com/chobie/hhvm-uv.git --recursive
cd php-uv
make -C libuv CFLAGS=-fPIC
hphpize
cmake -D CMAKE_BUILD_TYPE=Debug . && make

```