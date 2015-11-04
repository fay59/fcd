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

llvm::ConstantInt* md::getVirtualAddress(llvm::Function& fn)
{
	if (auto node = fn.getMetadata("fcd.vaddr"))
	if (auto constantMD = dyn_cast<ConstantAsMetadata>(node->getOperand(0)))
	if (auto constantInt = dyn_cast<ConstantInt>(constantMD->getValue()))
	{
		return constantInt;
	}
	return nullptr;
}

llvm::MDString* md::getImportName(llvm::Function& fn)
{
	if (auto node = fn.getMetadata("fcd.importname"))
	if (auto nameNode = dyn_cast<MDString>(node->getOperand(0)))
	{
		return nameNode;
	}
	return nullptr;
}

void md::setVirtualAddress(llvm::Function& fn, uint64_t virtualAddress)
{
	auto& ctx = fn.getContext();
	ConstantInt* cvaddr = ConstantInt::get(Type::getInt64Ty(ctx), virtualAddress);
	MDNode* vaddrNode = MDNode::get(ctx, ConstantAsMetadata::get(cvaddr));
	fn.setMetadata("fcd.vaddr", vaddrNode);
}

void md::setImportName(llvm::Function& fn, llvm::StringRef name)
{
	auto& ctx = fn.getContext();
	MDNode* nameNode = MDNode::get(ctx, MDString::get(ctx, name));
	fn.setMetadata("fcd.importname", nameNode);
}

void md::copy(llvm::Function& from, llvm::Function& to)
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
