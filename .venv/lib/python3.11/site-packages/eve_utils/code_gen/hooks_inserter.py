import itertools
from libcst import *
import eve_utils


class HooksInserter(CSTTransformer):
    def __init__(self, resource):
        self.resource = resource

    def leave_Module(self, original_node, updated_node):
        addition = SimpleStatementLine(
            body=[
                Import(
                    names=[ImportAlias(name=Attribute(value=Name(value='hooks'), attr=Name(value=f'{self.resource}')))],
                    semicolon=MaybeSentinel.DEFAULT,
                    whitespace_after_import=SimpleWhitespace(
                        value=' ',
                    ),
                ),
            ],
            leading_lines=[],
            trailing_whitespace=TrailingWhitespace(
                whitespace=SimpleWhitespace(
                    value='',
                ),
                comment=None,
                newline=Newline(
                    value=None,
                ),
            ),
        )

        new_body = eve_utils.code_gen.insert_import(updated_node.body, addition)

        return updated_node.with_changes(
            body = new_body
        )

    def leave_FunctionDef(self, original_node, updated_node):
        if not original_node.name.value == 'add_hooks':
            return original_node

        addition = SimpleStatementLine(
            body=[
                Expr(
                    value=Call(
                        func=Attribute(
                            value=Attribute(
                                value=Name(
                                    value='hooks',
                                    lpar=[],
                                    rpar=[],
                                ),
                                attr=Name(
                                    value=f'{self.resource}',
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
                            attr=Name(
                                value='add_hooks',
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
                        args=[
                            Arg(
                                value=Name(
                                    value='app',
                                    lpar=[],
                                    rpar=[],
                                ),
                                keyword=None,
                                equal=MaybeSentinel.DEFAULT,
                                comma=MaybeSentinel.DEFAULT,
                                star='',
                                whitespace_after_star=SimpleWhitespace(
                                    value='',
                                ),
                                whitespace_after_arg=SimpleWhitespace(
                                    value='',
                                ),
                            ),
                        ],
                        lpar=[],
                        rpar=[],
                        whitespace_after_func=SimpleWhitespace(
                            value='',
                        ),
                        whitespace_before_args=SimpleWhitespace(
                            value='',
                        ),
                    ),
                    semicolon=MaybeSentinel.DEFAULT,
                ),
            ],
            leading_lines=[],
            trailing_whitespace=TrailingWhitespace(
                whitespace=SimpleWhitespace(
                    value='',
                ),
                comment=None,
                newline=Newline(
                    value=None,
                ),
            ),
        )

        new_body = []
        for item in itertools.chain(updated_node.body.body, [addition]):  # TODO: if addition is first, prepend with newline
            new_body.append(item)

        return updated_node.with_changes(
            body=updated_node.body.with_changes(
                body=new_body
            )
        )
