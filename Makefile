# This Makefile has been tested on Ubuntu 16.10. Use at your own risk
# on anything else! (Or fix it and submit a PR.)

LLVM_VERSION_SUFFIX = -3.9
PYTHON_INCLUDES = /usr/include/python2.7
PYTHON27 = python

BUILD_DIR = $(CURDIR)/build
CLANG = clang++$(LLVM_VERSION_SUFFIX)
CLANGC = clang$(LLVM_VERSION_SUFFIX)
LLVM_CONFIG = llvm-config$(LLVM_VERSION_SUFFIX)
CLANG_LIB_LIST = CodeGen Driver Frontend Index Parse Sema Edit Lex AST Serialization Analysis Basic
LLVM_LIB_LIST = analysis asmparser bitreader codegen core instcombine instrumentation ipo irreader linker mc mcparser object passes profiledata scalaropts support target transformutils vectorize
CLANG_WARNINGS = all unreachable-code empty-body conditional-uninitialized error=conversion no-error=sign-conversion invalid-offsetof newline-eof no-c99-extensions

# Currently, fcd uses some features that are supported by clang-3.7+ (which
# is required anyway) but not g++, so use clang all the way.
# (It may be worth revisiting with later versions of g++)
CC = $(CLANGC)
CXX = $(CLANG)

DIRECTORIES = $(sort $(dir $(wildcard $(CURDIR)/fcd/*/)))
INCLUDES = $(DIRECTORIES:%=-I%) -isystem $(BUILD_DIR)/includes
LLVM_CXXFLAGS = $(subst -I,-isystem ,$(shell $(LLVM_CONFIG) --cxxflags))
LLVM_LIBS = $(shell $(LLVM_CONFIG) --libs $(LLVM_LIB_LIST))
LLVM_LDFLAGS = $(shell $(LLVM_CONFIG) --ldflags)
LLVM_INCLUDEDIR = $(shell $(LLVM_CONFIG) --includedir)
SYSTEM_LIBS = $(shell $(LLVM_CONFIG) --system-libs) -lpython2.7 -lcapstone
CXXFLAGS = $(LLVM_CXXFLAGS) $(INCLUDES) $(CLANG_WARNINGS:%=-W%) --std=gnu++14

# There is no llvm-config equivalent for clang.
CLANG_LIBS = -lclang $(addprefix $(shell $(LLVM_CONFIG) --libdir), $(addprefix "/libclang",$(addsuffix ".a",$(CLANG_LIB_LIST))))

export BUILD_DIR
export CXX
export CLANG
export CXXFLAGS
export INCBIN_TEMPLATE = $(CURDIR)/fcd/cpu/incbin.linux.tpl

all: $(BUILD_DIR) $(BUILD_DIR)/bindings.o $(BUILD_DIR)/systemIncludePaths.o directories
	$(CXX) $(LLVM_LDFLAGS) -Wl,--gc-sections -o $(BUILD_DIR)/fcd $(BUILD_DIR)/*.o $(LLVM_LIBS) $(CLANG_LIBS) $(SYSTEM_LIBS)

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)/includes
	ln -s $(PYTHON_INCLUDES) $(BUILD_DIR)/includes/Python

directories: $(DIRECTORIES)

$(DIRECTORIES): $(BUILD_DIR)
	$(MAKE) -f $(CURDIR)/Makefile.sub -C $@

$(BUILD_DIR)/%.o: $(BUILD_DIR)/%.cpp
	$(CXX) $(CXXFLAGS) -c -o $@ $<

$(BUILD_DIR)/bindings.cpp: fcd/python/bindings.py
	$(CC) -E -o - -I$(LLVM_INCLUDEDIR) $(LLVM_INCLUDEDIR)/llvm-c/Core.h | $(PYTHON27) $< > $@ 2> $@.stderr

$(BUILD_DIR)/systemIncludePaths.cpp: $(BUILD_DIR)
	$(CXX) -E -x c++ -v - < /dev/null 2>&1 | sed -n '/#include <...>/,/End of search/p' > $(@:%.cpp=%.txt)
	echo 'const char* defaultHeaderSearchPathList[] = {' > $@
	grep -v '(framework directory)$$' $(@:%.cpp=%.txt) | sed -n 's/^ \(.*\)/\t"\1",/p' >> $@
	echo '\t0' >> $@
	echo '};' >> $@
	echo 'const char* defaultFrameworkSearchPathList[] = {' >> $@
	sed -n 's/^ \(.*\) (framework directory)/\t"\1",/p' $(@:%.cpp=%.txt) >> $@
	echo '\t0' >> $@
	echo '};' >> $@

clean: $(BUILD_DIR)
	rm -rf $(BUILD_DIR)

.PHONY: all clean directories $(DIRECTORIES)
