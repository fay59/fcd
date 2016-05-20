//
// type_printer.h
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

#ifndef type_printer_hpp
#define type_printer_hpp

#include "expression_type.h"

#include <llvm/Support/raw_ostream.h>

#include <string>

class CTypePrinter
{
	static void printMiddleIfAny(llvm::raw_ostream& os, const std::string& middle);
	static void print(llvm::raw_ostream& os, const VoidExpressionType&, std::string middle);
	static void print(llvm::raw_ostream& os, const IntegerExpressionType& intTy, std::string middle);
	static void print(llvm::raw_ostream& os, const PointerExpressionType& pointerTy, std::string middle);
	static void print(llvm::raw_ostream& os, const ArrayExpressionType& arrayTy, std::string middle);
	static void print(llvm::raw_ostream& os, const StructExpressionType& structTy, std::string middle);
	static void print(llvm::raw_ostream& os, const FunctionExpressionType& funcTy, std::string middle);
	
public:
	static void declare(llvm::raw_ostream& os, const ExpressionType& type, const std::string& identifier);
	static void print(llvm::raw_ostream& os, const ExpressionType& type, std::string middle = "");
};

#endif /* type_printer_hpp */
