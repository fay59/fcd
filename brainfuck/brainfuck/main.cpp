//
//  main.cpp
//  brainfuck
//
//  Created by Félix on 2015-04-14.
//  Copyright (c) 2015 Félix Cloutier. All rights reserved.
//

#include <fstream>
#include <iomanip>
#include <iostream>
#include <memory>
#include <string>

#include <unistd.h>

#include "exec.h"
#include "parse.h"
#include "print.h"

using namespace std;

namespace
{
	string program_name;

	enum class mode
	{
		print,
		execute,
		compile,
	};

	class options
	{
		fstream maybe_in_file;
		
		options()
		{
			mode = mode::execute;
			input = &cin;
		}
		
	public:
		mode mode;
		istream* input;
		string out_file;
		
		options(const options&) = delete;
		
		options(options&& that)
		: maybe_in_file(move(that.maybe_in_file)), out_file(move(that.out_file))
		{
			mode = that.mode;
			input = that.input == &that.maybe_in_file ? &maybe_in_file : input;
		}
		
		static unique_ptr<options> parse(int argc, const char** argv)
		{
			options result;
			
			const char* optionString = "cep";
			int c = getopt(argc, const_cast<char**>(argv), optionString);
			while (c != -1)
			{
				switch (c)
				{
					case 'e': result.mode = mode::execute; break;
					case 'p': result.mode = mode::print; break;
					case 'c': result.mode = mode::compile; break;
						
					case '?':
						if (optopt != 'h')
						{
							cerr << program_name << ": unknown option -";
							if (isprint(optopt))
							{
								cerr << char(optopt);
							}
							else
							{
								cerr << "\\x" << setfill('0') << setw(2) << hex << optopt;
							}
							cerr << endl;
						}
						return nullptr;
				}
				c = getopt(argc, const_cast<char**>(argv), optionString);
			}
			
			for (int i = optind; i < argc; i++)
			{
				if (result.maybe_in_file.is_open())
				{
					cerr << program_name << ": multiple input files" << endl;
					return nullptr;
				}
				
				result.maybe_in_file.open(argv[i], ios_base::in);
				if (!result.maybe_in_file.is_open())
				{
					cerr << program_name << ": can't open " << argv[i] << endl;
					return nullptr;
				}
				
				result.input = &result.maybe_in_file;
			}
			return make_unique<options>(move(result));
		}
	};
	
	int print_program(brainfuck::scope& program)
	{
		brainfuck::print_visitor printer(cout);
		printer.visit(program);
		return 0;
	}
	
	int execute_program(brainfuck::scope& program)
	{
		brainfuck::to_executable_visitor to_sequence;
		to_sequence.visit(program);
		
		auto sequence = to_sequence.code();
		brainfuck::execute(sequence, brainfuck::execute_one);
		return 0;
	}
	
	int compile_program(brainfuck::scope& program)
	{
		cerr << program_name << ": not implemented" << endl;
		return 3;
	}
}

int main(int argc, const char * argv[])
{
	string argv0 = argv[0];
	program_name = argv0.substr(argv0.find_last_of('/') + 1);
	
	if (auto opts = options::parse(argc, argv))
	{
		istream_iterator<char> program_begin(*opts->input);
		istream_iterator<char> program_end;
		
		if (auto program = brainfuck::scope::parse(program_begin, program_end))
		{
			try
			{
				switch (opts->mode)
				{
					case mode::compile: return compile_program(*program);
					case mode::execute: return execute_program(*program);
					case mode::print: return print_program(*program);
					default: break;
				}
			}
			catch (exception& ex)
			{
				cerr << program_name << ": failed to complete action: " << ex.what() << endl;
			}
		}
		else
		{
			cerr << program_name << ": could not parse program" << endl;
			cerr << "Check that brackets match." << endl;
			return 2;
		}
	}
	
	cerr << "usage: " << program_name << " [-c | -e | -p] [input-file]" << endl;
	cerr << "       " << program_name << "-c: compile source" << endl;
	cerr << "       " << program_name << "-e: execute source" << endl;
	cerr << "       " << program_name << "-p: print source back (removing no-ops)" << endl;
	cerr << "Execution is the default mode." << endl;
	cerr << "Stdin is used if no input file is specified." << endl;
	return 1;
}
