# CMAKE generated file: DO NOT EDIT!
# Generated by "MinGW Makefiles" Generator, CMake Version 3.28

# Delete rule output on recipe failure.
.DELETE_ON_ERROR:

#=============================================================================
# Special targets provided by cmake.

# Disable implicit rules so canonical targets will work.
.SUFFIXES:

# Disable VCS-based implicit rules.
% : %,v

# Disable VCS-based implicit rules.
% : RCS/%

# Disable VCS-based implicit rules.
% : RCS/%,v

# Disable VCS-based implicit rules.
% : SCCS/s.%

# Disable VCS-based implicit rules.
% : s.%

.SUFFIXES: .hpux_make_needs_suffix_list

# Command-line flag to silence nested $(MAKE).
$(VERBOSE)MAKESILENT = -s

#Suppress display of executed commands.
$(VERBOSE).SILENT:

# A target that is always out of date.
cmake_force:
.PHONY : cmake_force

#=============================================================================
# Set environment variables for the build.

SHELL = cmd.exe

# The CMake executable.
CMAKE_COMMAND = D:\CMake\bin\cmake.exe

# The command to remove a file.
RM = D:\CMake\bin\cmake.exe -E rm -f

# Escaping for special characters.
EQUALS = =

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = D:\Desktop\postgraduate\AES\aes_ecb

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = D:\Desktop\postgraduate\AES\aes_ecb\build

# Include any dependencies generated for this target.
include CMakeFiles/aes_ecb.dir/depend.make
# Include any dependencies generated by the compiler for this target.
include CMakeFiles/aes_ecb.dir/compiler_depend.make

# Include the progress variables for this target.
include CMakeFiles/aes_ecb.dir/progress.make

# Include the compile flags for this target's objects.
include CMakeFiles/aes_ecb.dir/flags.make

CMakeFiles/aes_ecb.dir/main.cpp.obj: CMakeFiles/aes_ecb.dir/flags.make
CMakeFiles/aes_ecb.dir/main.cpp.obj: D:/Desktop/postgraduate/AES/aes_ecb/main.cpp
CMakeFiles/aes_ecb.dir/main.cpp.obj: CMakeFiles/aes_ecb.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green --progress-dir=D:\Desktop\postgraduate\AES\aes_ecb\build\CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building CXX object CMakeFiles/aes_ecb.dir/main.cpp.obj"
	D:\mingw\bin\g++.exe $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -MD -MT CMakeFiles/aes_ecb.dir/main.cpp.obj -MF CMakeFiles\aes_ecb.dir\main.cpp.obj.d -o CMakeFiles\aes_ecb.dir\main.cpp.obj -c D:\Desktop\postgraduate\AES\aes_ecb\main.cpp

CMakeFiles/aes_ecb.dir/main.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green "Preprocessing CXX source to CMakeFiles/aes_ecb.dir/main.cpp.i"
	D:\mingw\bin\g++.exe $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E D:\Desktop\postgraduate\AES\aes_ecb\main.cpp > CMakeFiles\aes_ecb.dir\main.cpp.i

CMakeFiles/aes_ecb.dir/main.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green "Compiling CXX source to assembly CMakeFiles/aes_ecb.dir/main.cpp.s"
	D:\mingw\bin\g++.exe $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S D:\Desktop\postgraduate\AES\aes_ecb\main.cpp -o CMakeFiles\aes_ecb.dir\main.cpp.s

CMakeFiles/aes_ecb.dir/aes.cpp.obj: CMakeFiles/aes_ecb.dir/flags.make
CMakeFiles/aes_ecb.dir/aes.cpp.obj: D:/Desktop/postgraduate/AES/aes_ecb/aes.cpp
CMakeFiles/aes_ecb.dir/aes.cpp.obj: CMakeFiles/aes_ecb.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green --progress-dir=D:\Desktop\postgraduate\AES\aes_ecb\build\CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Building CXX object CMakeFiles/aes_ecb.dir/aes.cpp.obj"
	D:\mingw\bin\g++.exe $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -MD -MT CMakeFiles/aes_ecb.dir/aes.cpp.obj -MF CMakeFiles\aes_ecb.dir\aes.cpp.obj.d -o CMakeFiles\aes_ecb.dir\aes.cpp.obj -c D:\Desktop\postgraduate\AES\aes_ecb\aes.cpp

CMakeFiles/aes_ecb.dir/aes.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green "Preprocessing CXX source to CMakeFiles/aes_ecb.dir/aes.cpp.i"
	D:\mingw\bin\g++.exe $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E D:\Desktop\postgraduate\AES\aes_ecb\aes.cpp > CMakeFiles\aes_ecb.dir\aes.cpp.i

CMakeFiles/aes_ecb.dir/aes.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green "Compiling CXX source to assembly CMakeFiles/aes_ecb.dir/aes.cpp.s"
	D:\mingw\bin\g++.exe $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S D:\Desktop\postgraduate\AES\aes_ecb\aes.cpp -o CMakeFiles\aes_ecb.dir\aes.cpp.s

# Object files for target aes_ecb
aes_ecb_OBJECTS = \
"CMakeFiles/aes_ecb.dir/main.cpp.obj" \
"CMakeFiles/aes_ecb.dir/aes.cpp.obj"

# External object files for target aes_ecb
aes_ecb_EXTERNAL_OBJECTS =

aes_ecb.exe: CMakeFiles/aes_ecb.dir/main.cpp.obj
aes_ecb.exe: CMakeFiles/aes_ecb.dir/aes.cpp.obj
aes_ecb.exe: CMakeFiles/aes_ecb.dir/build.make
aes_ecb.exe: CMakeFiles/aes_ecb.dir/linkLibs.rsp
aes_ecb.exe: CMakeFiles/aes_ecb.dir/objects1.rsp
aes_ecb.exe: CMakeFiles/aes_ecb.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green --bold --progress-dir=D:\Desktop\postgraduate\AES\aes_ecb\build\CMakeFiles --progress-num=$(CMAKE_PROGRESS_3) "Linking CXX executable aes_ecb.exe"
	$(CMAKE_COMMAND) -E cmake_link_script CMakeFiles\aes_ecb.dir\link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
CMakeFiles/aes_ecb.dir/build: aes_ecb.exe
.PHONY : CMakeFiles/aes_ecb.dir/build

CMakeFiles/aes_ecb.dir/clean:
	$(CMAKE_COMMAND) -P CMakeFiles\aes_ecb.dir\cmake_clean.cmake
.PHONY : CMakeFiles/aes_ecb.dir/clean

CMakeFiles/aes_ecb.dir/depend:
	$(CMAKE_COMMAND) -E cmake_depends "MinGW Makefiles" D:\Desktop\postgraduate\AES\aes_ecb D:\Desktop\postgraduate\AES\aes_ecb D:\Desktop\postgraduate\AES\aes_ecb\build D:\Desktop\postgraduate\AES\aes_ecb\build D:\Desktop\postgraduate\AES\aes_ecb\build\CMakeFiles\aes_ecb.dir\DependInfo.cmake "--color=$(COLOR)"
.PHONY : CMakeFiles/aes_ecb.dir/depend

