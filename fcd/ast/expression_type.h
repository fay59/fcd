//
// expression_type.h
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

#ifndef expression_type_hpp
#define expression_type_hpp

#include "llvm_warnings.h"

SILENCE_LLVM_WARNINGS_BEGIN()
#include <llvm/ADT/StringRef.h>
#include <llvm/Support/raw_ostream.h>
SILENCE_LLVM_WARNINGS_END()

#include <vector>
#include <string>

class ExpressionType
{
public:
	enum Type
	{
		Void,
		Integer,
		Pointer,
		Array,
		Structure,
		Function,
	};
	
private:
	Type type;
	
protected:
	
public:
	ExpressionType(Type type)
	: type(type)
	{
	}
	
	virtual ~ExpressionType() = default;
	
	Type getType() const { return type; }
	
	// Print and debug are only used for debug purposes. Printing declarations is a responsibility of the printer pass.
	void dump() const;
	virtual void print(llvm::raw_ostream& os) const = 0;
};

class VoidExpressionType : public ExpressionType
{
public:
	static bool classof(const ExpressionType* that)
	{
		return that->getType() == Void;
	}
	
	VoidExpressionType()
	: ExpressionType(Void)
	{
	}
	
	virtual void print(llvm::raw_ostream& os) const override;
};

class IntegerExpressionType : public ExpressionType
{
	bool hasSign;
	unsigned short numBits;
	
public:
	static bool classof(const ExpressionType* that)
	{
		return that->getType() == Integer;
	}
	
	IntegerExpressionType(bool hasSign, unsigned short numBits)
	: ExpressionType(Integer), hasSign(hasSign), numBits(numBits)
	{
	}
	
	bool isSigned() const { return hasSign; }
	unsigned short getBits() const { return numBits; }
	virtual void print(llvm::raw_ostream& os) const override;
};

class PointerExpressionType : public ExpressionType
{
	const ExpressionType& nested;
	
public:
	static bool classof(const ExpressionType* that)
	{
		return that->getType() == Pointer;
	}
	
	PointerExpressionType(const ExpressionType& toWhat)
	: ExpressionType(Pointer), nested(toWhat)
	{
	}
	
	const ExpressionType& getNestedType() const { return nested; }
	virtual void print(llvm::raw_ostream& os) const override;
};

class ArrayExpressionType : public ExpressionType
{
	const ExpressionType& nested;
	size_t numElement;
	
public:
	static bool classof(const ExpressionType* that)
	{
		return that->getType() == Array;
	}
	
	ArrayExpressionType(const ExpressionType& nested, size_t size)
	: ExpressionType(Array), nested(nested), numElement(size)
	{
	}
	
	const ExpressionType& getNestedType() const { return nested; }
	size_t size() const { return numElement; }
	virtual void print(llvm::raw_ostream& os) const override;
};

struct ExpressionTypeField
{
	const ExpressionType& type;
	std::string name;
	
	ExpressionTypeField(const ExpressionType& type, std::string name)
	: type(type), name(name)
	{
	}
};

class StructExpressionType : public ExpressionType
{
	std::vector<ExpressionTypeField> fields;
	
public:
	typedef std::vector<ExpressionTypeField>::const_iterator const_iterator;
	
	static bool classof(const ExpressionType* that)
	{
		return that->getType() == Structure;
	}
	
	StructExpressionType()
	: ExpressionType(Structure)
	{
	}
	
	const_iterator begin() const { return fields.begin(); }
	const_iterator end() const { return fields.end(); }
	
	void append(const ExpressionType& type, std::string name)
	{
		fields.emplace_back(type, std::move(name));
	}
	
	virtual void print(llvm::raw_ostream& os) const override;
};

class FunctionExpressionType : public ExpressionType
{
	const ExpressionType& returnType;
	std::vector<ExpressionTypeField> parameters;
	
public:
	typedef std::vector<ExpressionTypeField>::const_iterator const_iterator;
	
	static bool classof(const ExpressionType* that)
	{
		return that->getType() == Structure;
	}
	
	FunctionExpressionType(const ExpressionType& returnType)
	: ExpressionType(Function), returnType(returnType)
	{
	}
	
	const ExpressionType& getReturnType() const { return returnType; }
	const_iterator begin() const { return parameters.begin(); }
	const_iterator end() const { return parameters.end(); }
	
	void append(const ExpressionType& type, std::string name)
	{
		parameters.emplace_back(type, std::move(name));
	}
	
	virtual void print(llvm::raw_ostream& os) const override;
};

#endif /* expression_type_hpp */
