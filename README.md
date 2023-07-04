# Credits

Tests were created and tested by Almog Tabo and Nadav Tur. and updated at spring 2023.

# Instructions:

Extract the tests folder to where your source files are, so that you have a test folder where your source file is. The folder tree should look like so (may include additional files):

```
.
├── CMakeLists.txt
├── README.md
├── build_and_run.sh
├── malloc_1.cpp
├── malloc_2.cpp
...
├── setup.sh
└── tests
    ├── CMakeLists.txt
    ├── malloc_1_test.cpp
    ├── malloc_2_test.cpp
    ├── malloc_3_test_basic.cpp
    └── my_stdlib.h
```

run the following command for setup:

```
./setup.py
```

You might be prompted to give your password.

run the following command for testing:

```
./build_and_run.sh
```

You might be prompted to give your password.

run the following command for testing a specific test (using regex):

```
./build_and_run.sh <test_name>
```

Example:

```
./build_and_run.sh "malloc_3.srealloc Max size"
```

# FAQ

Q: I didn't implement part4. What should I do?

A: We automatically identify if malloc_4.cpp exists, and only if it does we run tests on it.

Q: What password should I give when I am prompted?

A: The scripts runs commands with `sudo`, therefor you might need to give your user password in order to execute the command (the default in the vm is `1234`).

Q: Compilation fails when I run `build_and_run.sh` with cmake errors.

A: There might be artifacts (previous files) of cmake from a different test in your project root directory (the directory with the `malloc_<i>.cpp` files). This might fail cmake when we use it.
The solution: remove all cmake files from the root directory (`CMakeFiles` directory, `CMakeCache.txt` file, etc...). This should resolve the issue.

Q: Compilation fails when I run `build_and_run.sh` with g++ errors.

A: We compile your files with `-Wall` and `-Werror` so fix your warnings and run the tests again.
