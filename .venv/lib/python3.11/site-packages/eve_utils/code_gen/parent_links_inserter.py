from libcst import *


class ParentLinksInserter(CSTTransformer):
    def __init__(self, parent, child, parents, children, parent_ref):
        self.parent = parent
        self.child = child
        self.parents = parents
        self.children = children
        self.parent_ref = parent_ref

    def leave_FunctionDef(self, original_node, updated_node):
        if not original_node.name.value == f'_add_links_to_{self.parent}':
            return original_node

        new_body = []
        for item in original_node.body.body:
            new_body.append(item)
        new_body.append(self.make_children_link())

        return updated_node.with_changes(
            body=updated_node.body.with_changes(
                body=new_body
            )
        )

    def make_children_link(self):
        return SimpleStatementLine(
            body=[
                Assign(
                    targets=[
                        AssignTarget(
                            target=Subscript(
                                value=Subscript(
                                    value=Name(
                                        value=f'{self.parent}',
                                        lpar=[],
                                        rpar=[],
                                    ),
                                    slice=[
                                        SubscriptElement(
                                            slice=Index(
                                                value=SimpleString(
                                                    value="'_links'",
                                                    lpar=[],
                                                    rpar=[],
                                                ),
                                            ),
                                            comma=MaybeSentinel.DEFAULT,
                                        ),
                                    ],
                                    lbracket=LeftSquareBracket(
                                        whitespace_after=SimpleWhitespace(
                                            value='',
                                        ),
                                    ),
                                    rbracket=RightSquareBracket(
                                        whitespace_before=SimpleWhitespace(
                                            value='',
                                        ),
                                    ),
                                    lpar=[],
                                    rpar=[],
                                    whitespace_after_value=SimpleWhitespace(
                                        value='',
                                    ),
                                ),
                                slice=[
                                    SubscriptElement(
                                        slice=Index(
                                            value=SimpleString(
                                                value=f"'{self.children}'",
                                                lpar=[],
                                                rpar=[],
                                            ),
                                        ),
                                        comma=MaybeSentinel.DEFAULT,
                                    ),
                                ],
                                lbracket=LeftSquareBracket(
                                    whitespace_after=SimpleWhitespace(
                                        value='',
                                    ),
                                ),
                                rbracket=RightSquareBracket(
                                    whitespace_before=SimpleWhitespace(
                                        value='',
                                    ),
                                ),
                                lpar=[],
                                rpar=[],
                                whitespace_after_value=SimpleWhitespace(
                                    value='',
                                ),
                            ),
                            whitespace_before_equal=SimpleWhitespace(
                                value=' ',
                            ),
                            whitespace_after_equal=SimpleWhitespace(
                                value=' ',
                            ),
                        ),
                    ],
                    value=Dict(
                        elements=[
                            DictElement(
                                key=SimpleString(
                                    value="'href'",
                                    lpar=[],
                                    rpar=[],
                                ),
                                value=FormattedString(  # ding (make_children_link)
                                    parts=[
                                        FormattedStringText(
                                            value=f'/{self.parents}/',
                                        ),
                                        FormattedStringExpression(
                                            expression=Subscript(
                                                value=Name(
                                                    value=f'{self.parent}',
                                                    lpar=[],
                                                    rpar=[],
                                                ),
                                                slice=[
                                                    SubscriptElement(
                                                        slice=Index(
                                                            value=SimpleString(
                                                                value='"_id"',  ####### ding
                                                                lpar=[],
                                                                rpar=[],
                                                            ),
                                                        ),
                                                        comma=MaybeSentinel.DEFAULT,
                                                    ),
                                                ],
                                                lbracket=LeftSquareBracket(
                                                    whitespace_after=SimpleWhitespace(
                                                        value='',
                                                    ),
                                                ),
                                                rbracket=RightSquareBracket(
                                                    whitespace_before=SimpleWhitespace(
                                                        value='',
                                                    ),
                                                ),
                                                lpar=[],
                                                rpar=[],
                                                whitespace_after_value=SimpleWhitespace(
                                                    value='',
                                                ),
                                            ),
                                            conversion=None,
                                            format_spec=None,
                                            whitespace_before_expression=SimpleWhitespace(
                                                value='',
                                            ),
                                            whitespace_after_expression=SimpleWhitespace(
                                                value='',
                                            ),
                                            equal=None,
                                        ),
                                        FormattedStringText(
                                            value=f'/{self.children}',
                                        ),
                                    ],
                                    start="f'",
                                    end="'",
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
                                            value='    ',
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
                                    value="'title'",
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
                    ),
                    semicolon=MaybeSentinel.DEFAULT,
                ),
            ],
            leading_lines=[],
            trailing_whitespace=TrailingWhitespace(
                whitespace=SimpleWhitespace(
                    value='    ',
                ),
                comment=None,
                newline=Newline(
                    value=None,
                ),
            ),
        )




