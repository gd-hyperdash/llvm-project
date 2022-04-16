# The LLVM Compiler Infrastructure

This is a fork of LLVM which contains various extensions for the ML framework, all of which are licensed under [GLGPL 2.1](ML_LICENSE.txt). ML related sources are explicitly marked.

## Development

[CMake](https://cmake.org/), [Ninja](https://ninja-build.org/) and [LLVM](https://llvm.org/) are required. On Windows, [Visual Studio 2022](https://visualstudio.microsoft.com/) is required.

### Windows

From the Visual Studio Developer Command Prompt:

```
mkdir LLVMDebug
cd LLVMDebug
cmake -DCMAKE_CXX_FLAGS="-fuse-ld=lld-link" -DLLVM_ENABLE_PROJECTS=clang -DLLVM_TARGETS_TO_BUILD=X86 -GNinja -Wno-dev ..\llvm-project\llvm
ninja clang
```

A dummy Visual Studio project is recommended for file editing:

```
mkdir LLVMVS
cd LLVMVS
cmake -DLLVM_ENABLE_PROJECTS=clang -G "Visual Studio 17 2022" -A x64 -Thost=x64 ..\llvm-project\llvm
```

## Release

To build a release version of the tooling use the following command:

```
mkdir LLVMRelease
cd LLVMRelease
cmake -DCMAKE_BUILD_TYPE=Release -DLLVM_ENABLE_PROJECTS="clang;lld" -DLLVM_TARGETS_TO_BUILD="X86;ARM;AArch64" -GNinja -Wno-dev ..\llvm
ninja clang
```

## Contributing

If you want to contribute to the source code feel free to open a [pull request](https://github.com/gd-hyperdash/llvm-project/pulls).