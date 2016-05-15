# This Makefile has been tested on Ubuntu 15.10. Use at your own risk
# on anything else! (Or fix it and submit a PR.)

BUILD_DIR = $(CURDIR)/build
CAPSTONE_DIR = /usr/include/capstone
LLVM_VERSION_SUFFIX = -3.7
PYTHON_INCLUDES = /usr/include/python2.7

CLANG = clang++$(LLVM_VERSION_SUFFIX)
LLVM_CONFIG = llvm-config$(LLVM_VERSION_SUFFIX)
LLVM_LIB_LIST = asmparser bitreader instrumentation mc mcparser target analysis codegen core instcombine ipa ipo irreader passes profiledata scalaropts transformutils vectorize support
CLANG_WARNINGS = all unreachable-code empty-body conditional-uninitialized error=conversion no-error=sign-conversion invalid-offsetof newline-eof

# Currently, fcd uses some features that are supported by clang-3.7+ (which
# is required anyway) but not g++, so use clang all the way.
# (It may be worth revisiting with later versions of g++)
CXX = $(CLANG)

DIRECTORIES = $(sort $(dir $(wildcard $(CURDIR)/fcd/*/)))
INCLUDES = $(DIRECTORIES:%=-I%) -isystem $(BUILD_DIR)/includes -isystem $(CAPSTONE_DIR)
LLVM_CXXFLAGS = $(subst -I,-isystem ,$(shell $(LLVM_CONFIG) --cxxflags))
LLVM_LIBS = $(shell $(LLVM_CONFIG) --libs $(LLVM_LIB_LIST))
LLVM_LDFLAGS = $(shell $(LLVM_CONFIG) --ldflags)
SYSTEM_LIBS = $(shell $(LLVM_CONFIG) --system-libs) -lpython2.7 -lcapstone
CXXFLAGS = $(LLVM_CXXFLAGS) $(INCLUDES) $(CLANG_WARNINGS:%=-W%) --std=gnu++14 -fno-rtti

export BUILD_DIR
export CAPSTONE_DIR
export CXX
export CLANG
export CXXFLAGS
export INCBIN_TEMPLATE = $(CURDIR)/fcd/cpu/incbin.linux.tpl

all: $(BUILD_DIR) directories
	$(CXX) $(LLVM_LDFLAGS) -Wl,--gc-sections -o $(BUILD_DIR)/fcd $(BUILD_DIR)/*.o $(LLVM_LIBS) $(SYSTEM_LIBS)

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)/includes
	ln -s $(PYTHON_INCLUDES) $(BUILD_DIR)/includes/Python

directories: $(DIRECTORIES)

$(DIRECTORIES): $(BUILD_DIR)
	$(MAKE) -f $(CURDIR)/Makefile.sub -C $@

clean: $(BUILD_DIR)
	rm -rf $(BUILD_DIR)

.PHONY: all clean directories $(DIRECTORIES)
