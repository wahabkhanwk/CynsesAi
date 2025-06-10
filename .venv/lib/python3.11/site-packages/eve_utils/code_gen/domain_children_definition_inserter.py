from libcst import *
import eve_utils


class DomainChildrenDefinitionInserter(CSTTransformer):
    def __init__(self, parent, child, parents, children, parent_ref):
        self.parent = parent
        self.child = child
        self.parents = parents
        self.children = children
        self.parent_ref = parent_ref

    def visit_SimpleStatementLine(self, node):
        if not isinstance(node.body[0], Assign):
            return False

        if not node.body[0].targets[0].target.value == 'SCHEMA':
            return False

        return True


    def leave_Assign(self, original_node, updated_node):
        new_elements = []
        for item in original_node.value.elements[:-1]:
            new_elements.append(item)
        new_elements.append(original_node.value.elements[-1].with_changes (comma=eve_utils.code_gen.get_comma()))
        new_elements.append(self.make_parent_ref())

        members = Dict(elements=new_elements,
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

        return updated_node.with_changes (value=members)


    def make_parent_ref(self):
        return DictElement(
            key=SimpleString(
                value=f"'{self.parent_ref}'",
                lpar=[],
                rpar=[],
            ),
            value=Dict(
                elements=[
                    DictElement(
                        key=SimpleString(
                            value="'type'",
                            lpar=[],
                            rpar=[],
                        ),
                        value=SimpleString(
                            value="'objectid'",
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
                            value="'data_relation'",
                            lpar=[],
                            rpar=[],
                        ),
                        value=Dict(
                            elements=[
                                DictElement(
                                    key=SimpleString(
                                        value="'resource'",
                                        lpar=[],
                                        rpar=[],
                                    ),
                                    value=SimpleString(
                                        value=f"'{self.parents}'",
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
                                                value='            ',
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
                                        value="'embeddable'",
                                        lpar=[],
                                        rpar=[],
                                    ),
                                    value=Name(
                                        value='True',
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
                                        value='            ',
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
                                        value='        ',
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
            ),
        )
