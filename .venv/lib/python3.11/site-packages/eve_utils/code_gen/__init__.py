from libcst import *
from .domain_definition_inserter import DomainDefinitionInserter
from .hooks_inserter import HooksInserter
from .authorization_inserter import AuthorizationInserter
from .validation_inserter import ValidationInserter
from .child_links_inserter import ChildLinksInserter
from .parent_links_inserter import ParentLinksInserter
from .domain_children_definition_inserter import DomainChildrenDefinitionInserter
from .domain_relations_inserter import DomainRelationsInserter

def get_comma():
    return Comma(
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


def insert_import(original_body, addition):
    rtn = []
    state = 'on-top'
    for item in original_body:
        if state == 'on-top':
            if hasattr(item, 'body') and hasattr(item.body, '__iter__') and type(item.body[0]).__name__ in ['Import', 'ImportFrom', 'Expr']:
                pass
            else:
                state = 'in-position'

        if state == 'in-position':
            rtn.append(addition)  # TODO: if no other appends before, add newline after here
            state = 'on-bottom'

        rtn.append(item)

    return rtn
