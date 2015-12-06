//
// metadata.cpp
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

#include "metadata.h"

using namespace llvm;
using namespace std;

ConstantInt* md::getVirtualAddress(Function& fn)
{
	if (auto node = fn.getMetadata("fcd.vaddr"))
	if (auto constantMD = dyn_cast<ConstantAsMetadata>(node->getOperand(0)))
	if (auto constantInt = dyn_cast<ConstantInt>(constantMD->getValue()))
	{
		return constantInt;
	}
	return nullptr;
}

MDString* md::getImportName(Function& fn)
{
	if (auto node = fn.getMetadata("fcd.importname"))
	if (auto nameNode = dyn_cast<MDString>(node->getOperand(0)))
	{
		return nameNode;
	}
	return nullptr;
}

bool md::hasRecoveredArguments(Function &fn)
{
	return fn.getMetadata("fcd.recovered") != nullptr;
}

bool md::isPrototype(Function &fn)
{
	return fn.getMetadata("fcd.prototype") != nullptr;
}

void md::setVirtualAddress(Function& fn, uint64_t virtualAddress)
{
	auto& ctx = fn.getContext();
	ConstantInt* cvaddr = ConstantInt::get(Type::getInt64Ty(ctx), virtualAddress);
	MDNode* vaddrNode = MDNode::get(ctx, ConstantAsMetadata::get(cvaddr));
	fn.setMetadata("fcd.vaddr", vaddrNode);
}

void md::setImportName(Function& fn, StringRef name)
{
	auto& ctx = fn.getContext();
	MDNode* nameNode = MDNode::get(ctx, MDString::get(ctx, name));
	fn.setMetadata("fcd.importname", nameNode);
}

void md::setRecoveredArguments(Function &fn)
{
	auto& ctx = fn.getContext();
	Type* i1 = Type::getInt1Ty(ctx);
	MDNode* zeroNode = MDNode::get(ctx, ConstantAsMetadata::get(ConstantInt::getNullValue(i1)));
	fn.setMetadata("fcd.recovered", zeroNode);
}

void md::setPrototype(Function &fn, bool prototype)
{
	if (prototype)
	{
		if (!isPrototype(fn))
		{
			auto& ctx = fn.getContext();
			Type* i1 = Type::getInt1Ty(ctx);
			MDNode* zeroNode = MDNode::get(ctx, ConstantAsMetadata::get(ConstantInt::getNullValue(i1)));
			fn.setMetadata("fcd.prototype", zeroNode);
		}
	}
	else if (isPrototype(fn))
	{
		fn.setMetadata("fcd.prototype", nullptr);
	}
}

void md::copy(Function& from, Function& to)
{
	if (auto address = getVirtualAddress(from))
	{
		setVirtualAddress(to, address->getLimitedValue());
	}
	if (auto name = getImportName(from))
	{
		setImportName(to, name->getString());
	}
}
