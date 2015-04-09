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
#include <llvm/Support/SourceMgr.h>

#include <fstream>
#include <iostream>
#include <memory>
#include <string>
#include <vector>

using namespace llvm;
using namespace std;

void interpile(LLVMContext& context, unique_ptr<Module> module, ostream& header, ostream& impl);

namespace args
{
	cl::opt<string> of_name("o", cl::desc("Output files name"), cl::value_desc("filename"));
	cl::opt<string> of_header_name("oh", cl::desc("Output header file name (defaults to <filename>.h)"), cl::value_desc("header.h"));
	cl::opt<string> of_impl_name("oi", cl::desc("Output implementation file name (defaults to <filename>.cpp)"), cl::value_desc("impl.cpp"));
	cl::opt<string> module_file(cl::Positional, cl::Required, cl::desc("<input module>"));
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
		if (args::of_name == "")
		{
			args::of_name = remove_extension(file_name(args::module_file));
		}
		
		if (args::of_header_name == "")
		{
			args::of_header_name = args::of_name + ".h";
		}
		
		if (args::of_impl_name == "")
		{
			args::of_impl_name = args::of_name + ".cpp";
		}
		
		if (ofstream header = ofstream(args::of_header_name, ios::trunc))
		{
			if (ofstream impl = ofstream(args::of_impl_name, ios::trunc))
			{
				interpile(context, move(module), header, impl);
			}
			else
			{
				cerr << file_name(argv[0]) << ": can't open implementation output file" << endl;
				return 1;
			}
		}
		else
		{
			cerr << file_name(argv[0]) << ": can't open header output file" << endl;
			return 1;
		}
	}
	else
	{
		cerr << file_name(argv[0]) << ": " << error.getMessage().str() << endl;
		return 1;
	}
}
