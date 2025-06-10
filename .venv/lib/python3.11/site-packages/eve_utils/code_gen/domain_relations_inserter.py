import itertools
from libcst import *
import eve_utils

class DomainRelationsInserter(CSTTransformer):
    def __init__(self, parent, child, parents, children, parent_ref):
        self.parent = parent
        self.child = child
        self.parents = parents
        self.children = children
        self.parent_ref = parent_ref

    def visit_SimpleStatementLine(self, node):
        if not isinstance(node.body[0], Assign):
            return False

        if not node.body[0].targets[0].target.value == 'DOMAIN_RELATIONS':
            return False

        return True


    def leave_Assign(self, original_node, updated_node):
        new_elements = []
        if original_node.value.elements:
            for item in original_node.value.elements[:-1]:
                new_elements.append(item)
            new_elements.append(original_node.value.elements[-1].with_changes (comma=eve_utils.code_gen.get_comma()))
        new_elements.append(self.make_domain_relation())

        relations = Dict(elements=new_elements,
                lbrace=LeftCurlyBrace(
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
                ),
                rbrace=RightCurlyBrace(
                    whitespace_before=ParenthesizedWhitespace(
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
                            value='',
                        ),
                    ),
                ),
                lpar=[],
                rpar=[],
            )

        return updated_node.with_changes (value=relations)


    def make_domain_relation(self):
        return DictElement(
            key=SimpleString(
                value=f"'{self.parents}_{self.children}'",
                lpar=[],
                rpar=[],
            ),
            value=Dict(
                elements=[
                    DictElement(
                        key=SimpleString(
                            value="'schema'",
                            lpar=[],
                            rpar=[],
                        ),
                        value=Attribute(
                            value=Name(
                                value=f'{self.children}',
                                lpar=[],
                                rpar=[],
                            ),
                            attr=Name(
                                value='SCHEMA',
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
                        comma=Comma(
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
                                    value='        ',
                                ),
                            ),
                        ),
                        whitespace_before_colon=SimpleWhitespace(
                            value='',
                        ),
                        whitespace_after_colon=SimpleWhitespace(
                            value=' ',
                        ),
                    ),
                    DictElement(
                        key=SimpleString(
                            value="'url'",
                            lpar=[],
                            rpar=[],
                        ),
                        value=SimpleString(
                            value=f'\'{self.parents}/<regex("[a-f0-9]{{24}}"):{self.parent_ref}>/{self.children}\'',
                            lpar=[],
                            rpar=[],
                        ),
                        comma=Comma(
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
                                    value='        ',
                                ),
                            ),
                        ),
                        whitespace_before_colon=SimpleWhitespace(
                            value='',
                        ),
                        whitespace_after_colon=SimpleWhitespace(
                            value=' ',
                        ),
                    ),
                    DictElement(
                        key=SimpleString(
                            value="'resource_title'",
                            lpar=[],
                            rpar=[],
                        ),
                        value=SimpleString(
                            value=f"'{self.children}'",
                            lpar=[],
                            rpar=[],
                        ),
                        comma=Comma(
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
                                    value='        ',
                                ),
                            ),
                        ),
                        whitespace_before_colon=SimpleWhitespace(
                            value='',
                        ),
                        whitespace_after_colon=SimpleWhitespace(
                            value=' ',
                        ),
                    ),
                    DictElement(
                        key=SimpleString(
                            value="'datasource'",
                            lpar=[],
                            rpar=[],
                        ),
                        value=Dict(
                            elements=[
                                DictElement(
                                    key=SimpleString(
                                        value="'source'",
                                        lpar=[],
                                        rpar=[],
                                    ),
                                    value=SimpleString(
                                        value=f"'{self.children}'",
                                        lpar=[],
                                        rpar=[],
                                    ),
                                    comma=MaybeSentinel.DEFAULT,
                                    whitespace_before_colon=SimpleWhitespace(
                                        value='',
                                    ),
                                    whitespace_after_colon=SimpleWhitespace(
                                        value=' ',
                                    ),
                                ),
                            ],
                            lbrace=LeftCurlyBrace(
                                whitespace_after=SimpleWhitespace(
                                    value='',
                                ),
                            ),
                            rbrace=RightCurlyBrace(
                                whitespace_before=SimpleWhitespace(
                                    value='',
                                ),
                            ),
                            lpar=[],
                            rpar=[],
                        ),
                        comma=MaybeSentinel.DEFAULT,
                        whitespace_before_colon=SimpleWhitespace(
                            value='',
                        ),
                        whitespace_after_colon=SimpleWhitespace(
                            value=' ',
                        ),
                    ),
                ],
                lbrace=LeftCurlyBrace(
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
                            value='        ',
                        ),
                    ),
                ),
                rbrace=RightCurlyBrace(
                    whitespace_before=ParenthesizedWhitespace(
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
                ),
                lpar=[],
                rpar=[],
            ),
            comma=MaybeSentinel.DEFAULT,
            whitespace_before_colon=SimpleWhitespace(
                value='',
            ),
            whitespace_after_colon=SimpleWhitespace(
                value=' ',
            )
        )


