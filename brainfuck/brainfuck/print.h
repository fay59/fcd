//
//  print.h
//  brainfuck
//
//  Created by Félix on 2015-04-14.
//  Copyright (c) 2015 Félix Cloutier. All rights reserved.
//

#ifndef __brainfuck__print__
#define __brainfuck__print__

#include <iostream>
#include "parse.h"

namespace brainfuck
{
	class print_visitor : public statement_visitor
	{
		std::ostream& os;
		
	public:
		explicit print_visitor(std::ostream& os);
		
		using statement_visitor::visit;
		virtual void visit(inst& inst) override;
		virtual void visit(scope& scope) override;
		virtual void visit(loop& loop) override;
	};
}

#endif /* defined(__brainfuck__print__) */
