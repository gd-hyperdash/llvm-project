# The LLVM Compiler Infrastructure

This is a fork of LLVM which contains various extensions for the ML framework, all of which are licensed under [GLGPL 2.1](ML_LICENSE.txt). ML related sources are explicitly marked.

## Building

[CMake](https://cmake.org/), [Ninja](https://ninja-build.org/) and [LLVM](https://llvm.org/) are required. On windows, [Visual Studio 2022](https://visualstudio.microsoft.com/) is required.

### Linux

Open the terminal and input:

```
export CC=/usr/bin/clang
export CXX=/usr/bin/clang++
mkdir Build
cd Build
cmake -DCMAKE_BUILD_TYPE=Release -DLLVM_ENABLE_PROJECTS="clang;lld" -DLLVM_TARGETS_TO_BUILD="X86;ARM;AArch64" -G"Unix Makefiles" -Wno-dev ../llvm-project/llvm
ninja clang lld llvm-ar llvm-ranlib llvm-strip
```

For development use the following `cmake` command:

```
cmake -DCMAKE_BUILD_TYPE=Debug -DLLVM_USE_SPLIT_DWARF=ON -DLLVM_USE_LINKER=lld -DLLVM_ENABLE_PROJECTS=clang -DLLVM_ENABLE_PLUGINS=OFF -DCLANG_PLUGIN_SUPPORT=OFF -DLLVM_TARGETS_TO_BUILD=X86 -GNinja -Wno-dev ../llvm-project/llvm
```

### Windows

From the X64 Native Tools VS Command Prompt:

```
set CC=clang-cl
set CXX=clang-cl
mkdir Build
cd Build
cmake -DCMAKE_BUILD_TYPE=Release -DCMAKE_CXX_FLAGS="-fuse-ld=lld-link" -DLLVM_ENABLE_PROJECTS="clang;lld" -DLLVM_TARGETS_TO_BUILD="X86;ARM;AArch64" -GNinja -Wno-dev ..\llvm-project\llvm
ninja clang lld llvm-ar llvm-ranlib llvm-strip
```

For development use the following `cmake` command:

```
cmake -DCMAKE_BUILD_TYPE=Debug -DCMAKE_CXX_FLAGS="-fuse-ld=lld-link" -DLLVM_ENABLE_PROJECTS=clang -DLLVM_TARGETS_TO_BUILD=X86 -GNinja -Wno-dev ..\llvm-project\llvm
```

## Contributing

If you want to contribute to the source code feel free to open a [pull request](https://github.com/gd-hyperdash/llvm-project/pulls).