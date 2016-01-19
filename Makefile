BUILDDIR = $(CURDIR)/build
CAPSTONE_DIR = /usr/include/capstone
LLVM_VERSION_SUFFIX = -3.7
PYTHON_INCLUDES = /usr/include/python2.7

CLANG = clang++$(LLVM_VERSION_SUFFIX)
LLVM_CONFIG = llvm-config$(LLVM_VERSION_SUFFIX)
LLVM_LIB_LIST = asmparser bitreader instrumentation mc mcparser target analysis codegen core instcombine ipa ipo irreader passes profiledata scalaropts support transformutils vectorize
CC = $(CLANG)

DIRECTORIES = $(sort $(dir $(wildcard $(CURDIR)/fcd/*/)))
INCLUDES = $(DIRECTORIES:%=-I%) -I$(BUILDDIR)/includes -I$(CAPSTONE_DIR)
LLVM_LIBS = $(shell $(LLVM_CONFIG) --libs $(LLVM_LIB_LIST))
LLVM_LIBDIR = $(shell $(LLVM_CONFIG) --libdir)
LLVM_CXXFLAGS = $(shell $(LLVM_CONFIG) --cxxflags)
CXXFLAGS = $(LLVM_CXXFLAGS) $(INCLUDES) --std=gnu++14 --stdlib=libc++

export BUILDDIR
export CC
export CXXFLAGS
export LIBDIR
export LIBS

all: $(BUILDDIR) directories
	$(CC) $(LIBDIR) $(LIBS) -o $(BUILDDIR)/fcd $(BUILDDIR)/*.o

$(BUILDDIR):
	mkdir -p $(BUILDDIR)/includes
	ln -s $(PYTHON_INCLUDES) $(BUILDDIR)/includes/Python

directories: $(DIRECTORIES)
$(DIRECTORIES):
	$(MAKE) -f $(CURDIR)/Makefile.sub -C $@

clean:
	rm -rf $(BUILDDIR)

.PHONY: all clean directories $(DIRECTORIES)
