//
// pass_typerec.cpp
// Copyright (C) 2015 Félix Cloutier.
// All Rights Reserved.
//
// This file is part of fcd.
// 
// fcd is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
// 
// fcd is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
// 
// You should have received a copy of the GNU General Public License
// along with fcd.  If not, see <http://www.gnu.org/licenses/>.
//

#include "passes.h"

using namespace std;
using namespace llvm;

// The type recovery pass recovers the layout of structures and class hierarchies from an execution stream based on how
// pointers are used. (It also recovers the stack frames of functions, since the stack can easily be treated as a
// pointer to a structure.) It uses two major sources of information.
//
// ## Type Sinks
//
// Type sinks are place in the code where we know for sure what the type of a value is. Our best source is function
// calls to functions that we know about. Our second-best source is when a value is loaded, **transformed** (operated on
// by IR instructions like add, sub, mul, etc) and stored again, and when a value is loaded and interpreted as a
// pointer.
//
// We discard operations that merely load something and store it somewhere else because compilers are starting to
// seriously not care about the type of things that are just moved around. For instance, the Swift compiler will use SSE
// and AVX instructions to do large loads and large stores from one structure to the next, over a whole range of fields.
// These operations must not count as type sinks, and this is why fcd uses the additional "transformed" criteria.
//
// ## The Dominator Tree
//
// Fcd combines the information obtained with type sinks with the dominator tree. This is because, especially in C++,
// functions can accept pointers to base types and do a type switch within the function. Fcd and LLVM do this a lot, and
// languages that support discriminated unions also do. The idea is that if you have a class hierarchy that has a base
// class B and derived classes D1 and D2, if you test the type of your B* and find out that it is a D1*, and branch
// accordingly, the code following that branch is probably aware of that fact, and may directly access fields (or call
// functions that access fields) in ways that are incompatible with the layout of class D2. Logically, the developer
// (and the compiler) know that the pointer is a pointer to a D1 only in blocks that are dominated by the type check.
//
// Note that fcd doesn't try to determine what a "type check" is: it merely looks at parallel branches in the dominator
// tree and doesn't try too hard to unify types in different branches when they don't match. After all, a type check
// could be checking a field, checking another function parameter, or calling a special function, and we want this
// algorithm to work either way.

namespace
{
	
}
