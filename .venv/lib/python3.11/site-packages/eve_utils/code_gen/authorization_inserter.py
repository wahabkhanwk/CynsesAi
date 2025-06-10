import itertools
from libcst import *
# from eve_utils.code_gen import insert_import
import eve_utils


class AuthorizationInserter(CSTTransformer):
    def __init__(self):
        pass

    def leave_Module(self, original_node, updated_node):
        addition = SimpleStatementLine(
            body=[
                ImportFrom(
                    module=Attribute(
                        value=Name(
                            value='auth',
                            lpar=[],
                            rpar=[],
                        ),
                        attr=Name(
                            value='es_auth',
                            lpar=[],
                            rpar=[],
                        ),
                        dot=Dot(
                            whitespace_before=SimpleWhitespace(
                                value='',
                            ),
                            whitespace_after=SimpleWhitespace(
                                value='',
                            ),
                        ),
                        lpar=[],
                        rpar=[],
                    ),
                    names=[
                        ImportAlias(
                            name=Name(
                                value='EveAuthorization',
                                lpar=[],
                                rpar=[],
                            ),
                            asname=None,
                            comma=MaybeSentinel.DEFAULT,
                        ),
                    ],
                    relative=[],
                    lpar=None,
                    rpar=None,
                    semicolon=MaybeSentinel.DEFAULT,
                    whitespace_after_from=SimpleWhitespace(
                        value=' ',
                    ),
                    whitespace_before_import=SimpleWhitespace(
                        value=' ',
                    ),
                    whitespace_after_import=SimpleWhitespace(
                        value=' ',
                    ),
                ),
            ])

        new_body = eve_utils.code_gen.insert_import(updated_node.body, addition)

        return updated_node.with_changes(
            body = new_body
        )

    def visit_SimpleStatementLine(self, node):
        if not isinstance(node.body[0], Assign):
            return False
            
        target = node.body[0].targets[0].target
        
        if not isinstance(target, Attribute):
            return False
            
        if not (target.value.value == 'self' and target.attr.value == '_app'):
            return False
            
        return True
        
    def leave_Assign(self, original_node, updated_node):
        addition = Arg(
            value=Name(
                value='EveAuthorization',
                lpar=[],
                rpar=[],
            ),
            keyword=Name(
                value='auth',
                lpar=[],
                rpar=[],
            ),
            equal=AssignEqual(
                whitespace_before=SimpleWhitespace(
                    value='',
                ),
                whitespace_after=SimpleWhitespace(
                    value='',
                ),
            ),
            comma=MaybeSentinel.DEFAULT,
            star='',
            whitespace_after_star=SimpleWhitespace(
                value='',
            ),
            whitespace_after_arg=SimpleWhitespace(
                value='',
            ),
        )
        
        comma = Comma(
            whitespace_before=SimpleWhitespace(
                value='',
            ),
            whitespace_after=SimpleWhitespace(
                value=' ',
            ),
        )       

        new_args = []
        last_arg = updated_node.value.args[-1].with_changes(comma=comma)

        for item in itertools.chain(updated_node.value.args[0:-1], [last_arg, addition]):
            new_args.append(item)

        new_value = updated_node.value.with_changes(args=new_args)

        return updated_node.with_changes(
            value = new_value
        )


