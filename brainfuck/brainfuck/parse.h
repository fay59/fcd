//
//  parse.h
//  brainfuck
//
//  Created by Félix on 2015-04-14.
//  Copyright (c) 2015 Félix Cloutier. All rights reserved.
//

#ifndef __brainfuck__parse__
#define __brainfuck__parse__

#include <iostream>
#include <memory>
#include <vector>

namespace brainfuck
{
	enum class opcode : char
	{
		inc_ptr = '>',
		dec_ptr = '<',
		inc_value = '+',
		dec_value = '-',
		input = ',',
		output = '.',
		loop_enter = '[',
		loop_exit = ']',
	};
		
	class statement_visitor;

#pragma mark - Statements
	class statement
	{
	protected:
		statement() = default;
		statement(const statement&) = default;
		statement(statement&&) = default;
		
	public:
		virtual void visit(statement_visitor& visitor) = 0;
	};
		
	class inst : public statement
	{
	public:
		opcode opcode;
		
		explicit inst(enum opcode o);
		
		virtual void visit(statement_visitor& visitor) override;
	};

	class scope : public statement
	{
	public:
		template<typename TIterType>
		static std::unique_ptr<scope> parse(TIterType begin, TIterType end, TIterType* endptr = nullptr);
		
		explicit scope(std::vector<std::unique_ptr<statement>> statements);
		
		std::vector<std::unique_ptr<statement>> statements;
		virtual void visit(statement_visitor& visitor) override;
	};

	class loop : public statement
	{
	public:
		std::unique_ptr<scope> body;
		
		explicit loop(std::unique_ptr<scope> scope);
		
		virtual void visit(statement_visitor& visitor) override;
	};
		
#pragma mark -
	class statement_visitor
	{
	public:
		void visit(statement& statement);
		virtual void visit(inst& inst) = 0;
		virtual void visit(scope& scope) = 0;
		virtual void visit(loop& loop) = 0;
	};
		
#pragma mark -
	template<typename TIterType>
	std::unique_ptr<scope> scope::parse(TIterType begin, TIterType end, TIterType* endptr)
	{
		std::unique_ptr<scope> result;
		std::vector<std::unique_ptr<statement>> statements;
		TIterType iter = begin;
		while (iter != end)
		{
			opcode o = static_cast<opcode>(*iter);
			switch (o)
			{
				case opcode::inc_ptr:
				case opcode::dec_ptr:
				case opcode::inc_value:
				case opcode::dec_value:
				case opcode::input:
				case opcode::output:
					statements.push_back(std::make_unique<inst>(o));
					iter++;
					break;
					
				case opcode::loop_enter:
					iter++;
					if (auto body = parse(iter, end, &iter))
					{
						if (iter != end)
						{
							if (*iter == char(opcode::loop_exit))
							{
								statements.push_back(std::make_unique<loop>(std::move(body)));
								iter++;
								break;
							}
						}
					}
					goto parse_end;
					
				case opcode::loop_exit:
					goto loop_end;
					
				default:
					iter++;
					break;
			}
		}
		
	loop_end:
		result.reset(new scope(move(statements)));
		
	parse_end:
		if (endptr != nullptr)
		{
			*endptr = iter;
		}
		
		return result;
	}
}
#endif /* defined(__brainfuck__parse__) */
