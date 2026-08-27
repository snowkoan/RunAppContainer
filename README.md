# Run executables in an AppContainer

Run any executable inside an AppContainer, optionally allowing access to specific folders/files and/or registry keys.

See more information in my blog post: https://scorpiosoftware.net/2019/01/15/fun-with-appcontainers/

## Building

RunAppContainer is a native Win32 application and does not use MFC. It requires Visual Studio 2022 with the Desktop development with C++ workload.

Clone the repository with its WIL submodule:

```text
git clone --recursive https://github.com/zodiacon/RunAppContainer.git
```

For an existing clone, initialize the dependency with `git submodule update --init --recursive`, then open `RunAppContainer.sln` and build the desired x86 or x64 configuration.
