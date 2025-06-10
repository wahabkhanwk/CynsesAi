import itertools
from libcst import *
import eve_utils


class DomainDefinitionInserter(CSTTransformer):
    def __init__(self, resource):
        self.resource = resource

    def leave_Module(self, original_node, updated_node):
        addition = SimpleStatementLine(
            body=[
                ImportFrom(
                    module=None,
                    names=[
                        ImportAlias(
                            name=Name(
                                value=f'{self.resource}',
                                lpar=[],
                                rpar=[],
                            ),
                            asname=None,
                            comma=MaybeSentinel.DEFAULT,
                        ),
                    ],
                    relative=[
                        Dot(
                            whitespace_before=SimpleWhitespace(
                                value='',
                            ),
                            whitespace_after=SimpleWhitespace(
                                value='',
                            ),
                        ),
                    ],
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

    def visit_SimpleStatementLine(self, node):
        if not isinstance(node.body[0], Assign):
            return False

        if not node.body[0].targets[0].target.value == 'DOMAIN_DEFINITIONS':
            return False

        return True

    def leave_Dict(self, original_node, updated_node):
        key = SimpleString(
            value=f"'{self.resource}'",
            lpar=[],
            rpar=[],
        )

        value = Attribute(
            value=Name(
                value=f'{self.resource}',
                lpar=[],
                rpar=[],
            ),
            attr=Name(
                value='DEFINITION',
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
        )

        comma = Comma(
            whitespace_before=SimpleWhitespace(
                value='',
            ),
            whitespace_after=ParenthesizedWhitespace(
                first_line=TrailingWhitespace(
                    whitespace=SimpleWhitespace(
                        value='',
                    ),
                    comment=None,
                    newline=Newline(
                        value=None,
                    ),
                ),
                empty_lines=[],
                indent=True,
                last_line=SimpleWhitespace(
                    value='    ',
                ),
            ),
        )

        addition = DictElement(key, value)

        new_elements = []
        last_element = updated_node.elements[-1].with_changes(comma=comma)

        for item in itertools.chain(updated_node.elements[0:-1], [last_element, addition]):
            new_elements.append(item)

        return updated_node.with_changes(
            # elements = sorted(new_elements, key=lambda i:i.key.value)
            elements = new_elements
        )


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


