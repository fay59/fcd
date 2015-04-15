//
//  main.cpp
//  brainfuck
//
//  Created by Félix on 2015-04-14.
//  Copyright (c) 2015 Félix Cloutier. All rights reserved.
//

#include <fstream>
#include <iostream>
#include <string>
#include <unistd.h>

#include "exec.h"
#include "parse.h"
#include "print.h"

using namespace std;

int main(int argc, const char * argv[])
{
	string argv0 = argv[0];
	string programName = argv0.substr(argv0.find_last_of('/') + 1);
	
	fstream fileIn;
	istream* input = &cin;
	
	if (argc == 2)
	{
		fileIn.open(argv[1], ios_base::in);
		if (fileIn)
		{
			input = &fileIn;
		}
		else
		{
			cerr << programName << ": can't open " << argv[1] << endl;
			return 1;
		}
	}
	
	if (auto program = brainfuck::scope::parse(istream_iterator<char>(*input), istream_iterator<char>()))
	{
		brainfuck::to_executable_visitor to_sequence;
		to_sequence.visit(*program);
		
		auto sequence = to_sequence.code();
		brainfuck::execute(sequence, brainfuck::execute_one);
		
		return 0;
	}
	cerr << programName << ": could not parse program" << endl;
	cerr << "Check that brackets match." << endl;
	return 2;
}
