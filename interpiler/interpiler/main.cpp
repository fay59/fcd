//
//  main.cpp
//  interpiler
//
//  Created by Félix on 2015-04-08.
//  Copyright (c) 2015 Félix Cloutier. All rights reserved.
//

#include <llvm/IR/LLVMContext.h>
#include <llvm/IR/Module.h>
#include <llvm/IRReader/IRReader.h>
#include <llvm/Support/CommandLine.h>
#include <llvm/Support/FileSystem.h>
#include <llvm/Support/raw_ostream.h>
#include <llvm/Support/SourceMgr.h>

#include <iostream>
#include <memory>
#include <string>
#include <vector>

using namespace llvm;
using namespace std;

void interpile(LLVMContext& context, unique_ptr<Module> module, const string& class_name, llvm::raw_ostream& header, llvm::raw_ostream& impl);

namespace args
{
	cl::opt<string> module_file(cl::Positional, cl::Required, cl::desc("<input module>"));
	cl::opt<string> class_name("c", cl::desc("Output class name (defaults to module name)"), cl::value_desc("classname"));
	cl::opt<string> of_name("o", cl::desc("Output files name (defaults to <classname>)"), cl::value_desc("filename"));
	cl::opt<string> of_header_name("oh", cl::desc("Output header file name (defaults to <filename>.h)"), cl::value_desc("header.h"));
	cl::opt<string> of_impl_name("oi", cl::desc("Output implementation file name (defaults to <filename>.cpp)"), cl::value_desc("impl.cpp"));
}

namespace
{
	string file_name(const string& file)
	{
		string::const_iterator nameStart = file.begin();
		for (auto iter = nameStart; iter != file.end(); iter++)
		{
			if (*iter == '/')
			{
				nameStart = iter + 1;
			}
		}
		return string(nameStart, file.end());
	}
	
	string remove_extension(const string& file)
	{
		size_t endIndex = file.find_last_of('.');
		return file.substr(endIndex);
	}
}

int main(int argc, const char * argv[])
{
	LLVMContext context;
	cl::ParseCommandLineOptions(argc, argv);
	
	SMDiagnostic error;
	if (unique_ptr<Module> module = parseIRFile(args::module_file, error, context))
	{
		if (args::class_name == "")
		{
			args::class_name = remove_extension(args::module_file);
		}
		
		if (args::of_name == "")
		{
			args::of_name = static_cast<string&>(args::class_name);
		}
		
		if (args::of_header_name == "")
		{
			args::of_header_name = args::of_name + ".h";
		}
		
		if (args::of_impl_name == "")
		{
			args::of_impl_name = args::of_name + ".cpp";
		}
		
		error_code error;
		raw_fd_ostream header(args::of_header_name, error, sys::fs::F_None);
		if (error)
		{
			cerr << file_name(argv[0]) << ": can't open header output file" << endl;
			return 1;
		}
		else
		{
			raw_fd_ostream impl(args::of_impl_name, error, sys::fs::F_None);
			if (error)
			{
				cerr << file_name(argv[0]) << ": can't open implementation output file" << endl;
				return 1;
			}
			else
			{
				interpile(context, move(module), args::class_name, header, impl);
			}
		}
	}
	else
	{
		cerr << file_name(argv[0]) << ": couldn't read input module: " << error.getMessage().str() << endl;
		return 1;
	}
}
