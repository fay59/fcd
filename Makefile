BUILD_DIR = $(CURDIR)/build
CAPSTONE_DIR = /usr/include/capstone
LLVM_VERSION_SUFFIX = -3.7
PYTHON_INCLUDES = /usr/include/python2.7

CLANG = clang++$(LLVM_VERSION_SUFFIX)
LLVM_CONFIG = llvm-config$(LLVM_VERSION_SUFFIX)
LLVM_LIB_LIST = asmparser bitreader instrumentation mc mcparser target analysis codegen core instcombine ipa ipo irreader passes profiledata scalaropts support transformutils vectorize
CXX = $(CLANG)

DIRECTORIES = $(sort $(dir $(wildcard $(CURDIR)/fcd/*/)))
INCLUDES = $(DIRECTORIES:%=-I%) -I$(BUILD_DIR)/includes -I$(CAPSTONE_DIR)
LLVM_LIBS = $(shell $(LLVM_CONFIG) --libs $(LLVM_LIB_LIST))
LLVM_LIBDIR = $(shell $(LLVM_CONFIG) --libdir)
LLVM_CXXFLAGS = $(shell $(LLVM_CONFIG) --cxxflags)
CXXFLAGS = $(LLVM_CXXFLAGS) $(INCLUDES) --std=gnu++14 --stdlib=libc++

export BUILD_DIR
export CAPSTONE_DIR
export CXX
export CLANG
export CXXFLAGS
export INCBIN_TEMPLATE = $(CURDIR)/fcd/cpu/incbin.linux.tpl
export LIBDIR
export LIBS

all: $(BUILD_DIR) directories
	$(CXX) $(LIBDIR) $(LIBS) -o $(BUILD_DIR)/fcd $(BUILD_DIR)/*.o

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)/includes
	ln -s $(PYTHON_INCLUDES) $(BUILD_DIR)/includes/Python

directories: $(DIRECTORIES)

$(DIRECTORIES): $(BUILD_DIR)
	$(MAKE) -f $(CURDIR)/Makefile.sub -C $@

clean: $(BUILD_DIR)
	rm -rf $(BUILD_DIR)

.PHONY: all clean directories $(DIRECTORIES)
