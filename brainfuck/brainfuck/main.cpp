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

#include "interp.h"
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
		brainfuck::state state = {
			.fd_in = STDIN_FILENO,
			.fd_out = STDOUT_FILENO,
		};
		brainfuck::interp_visitor interp(state);
		interp.visit(*program);
		return 0;
	}
	cerr << programName << ": could not parse program" << endl;
	cerr << "Check that brackets match." << endl;
	return 2;
}
