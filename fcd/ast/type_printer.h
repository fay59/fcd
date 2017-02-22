//
// type_printer.h
// Copyright (C) 2015 Félix Cloutier.
// All Rights Reserved.
//
// This file is distributed under the University of Illinois Open Source
// license. See LICENSE.md for details.
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
