import os
import sys
import click
import importlib
from libcst import parse_module
from .singplu import get_pair
from eve_utils.code_gen import ChildLinksInserter, ParentLinksInserter, DomainChildrenDefinitionInserter, DomainRelationsInserter
import eve_utils

def link_already_exist(parents, children):
    rels = parent_child_relations()
    if parents in rels and "children" in rels[parents]:
        if children in rels[parents]["children"]:
            return True
    eve_utils.jump_to_api_folder('src/{project_name}')
    return False


def parent_child_relations():
    try:
        settings = eve_utils.jump_to_api_folder('src/{project_name}/domain')
    except RuntimeError:
        print('This command must be run in an eve_service API folder structure')
        sys.exit(1)

    with open('__init__.py', 'r') as f:
        lines = f.readlines()

    listening = False
    rels = {}
    for line in lines:
        if 'DOMAIN_RELATIONS' in line:
            listening = True
            continue

        if not listening:
            continue

        if line.startswith('}'):
            break

        if line.startswith("    '"):
            rel_name = line.split("'")[1]
            continue

        if line.startswith("        'resource_title':"):
            child = line.split("'")[3]
            parent = rel_name.replace(f"_{child}", "")
            parent, parents = get_pair(parent)
            child, children = get_pair(child)

            if parents not in rels:
                rels[parents] = {}
            if 'children' not in rels[parents]:
                rels[parents]['children'] = set()
            rels[parents]['children'].add(children)

            if children not in rels:
                rels[children] = {}
            if 'parents' not in rels[children]:
                rels[children]['parents'] = set()
            rels[children]['parents'].add(parent)
    return rels


@click.group(name='link', help='Manage parent/child links amongst resources.')
def commands():
    pass


@commands.command(name='create', help='Create a parent/child link between two resources.')
@click.argument('parent', metavar='<parent>')
@click.argument('child', metavar='<child>')
@click.option('--as_parent_ref', '-p', is_flag=True, help='change name of related ref to "parent" (instead of the name of the parent)')
def create(parent, child, as_parent_ref):
    try:
        settings = eve_utils.jump_to_api_folder('src/{project_name}')
    except RuntimeError:
        print('This command must be run in an eve_service API folder structure')
        sys.exit(1)

    parent, parents = singular, plural = get_pair(parent)  # TODO: validate, safe name, etc.
    child, children = singular, plural = get_pair(child)  # TODO: validate, safe name, etc.
    parent_ref = '_parent_ref' if as_parent_ref else f'_{parent}_ref'

    print(f'Creating link rel from {parent} (parent) to {child} (child)')

    if link_already_exist(parents, children):
        print('This link already exist')
        sys.exit(801)
    else:
        _add_to_domain_init(parent, child, parents, children, parent_ref)
        _add_to_domain_child(parent, child, parents, children, parent_ref)
        _add_links_to_parent_hooks(parent, child, parents, children, parent_ref)
        _add_links_to_child_hooks(parent, child, parents, children, parent_ref)


# TODO: refactor/SLAP
@commands.command(name='list', help='List the relationships amongst the resources.')
@click.option('--plant_uml', '-p', is_flag=True, help='output the rels in PlantUML class notation')
def list(plant_uml):
    try:
        settings = eve_utils.jump_to_api_folder('src/{project_name}/domain')
    except RuntimeError:
        print('This command must be run in an eve_service API folder structure')
        sys.exit(1)

    rels = parent_child_relations()

    if plant_uml:
        print('@startuml')
        print('hide <<resource>> circle')
        print('hide members ')
        print()
        for rel in rels:
            print(f'class {rel} <<resource>>')
        print()
        for rel in rels:
            for item in rels[rel].get('children', []):
                print(f'{rel} ||--o{{ {item}')
        print('@enduml')
    else:
        for rel in rels:
            print(rel)
            for item in rels[rel].get('parents', []):
                print(f'- belong to a {item}')
            for item in rels[rel].get('children', []):
                print(f'- have {item}')

@commands.command(name='remove', help='(not yet implemented)')
def remove():
    click.echo('remove')


def _add_links_to_child_hooks(parent, child, parents, children, parent_ref):
    with open(f'hooks/{children}.py', 'r') as source:
        tree = parse_module(source.read())

    inserter = ChildLinksInserter(parent, child, parents, children, parent_ref)
    new_tree = tree.visit(inserter)

    with open(f'hooks/{children}.py', 'w') as source:
        source.write(new_tree.code)


def _add_links_to_parent_hooks(parent, child, parents, children, parent_ref):
    with open(f'hooks/{parents}.py', 'r') as source:
        tree = parse_module(source.read())

    inserter = ParentLinksInserter(parent, child, parents, children, parent_ref)
    new_tree = tree.visit(inserter)

    with open(f'hooks/{parents}.py', 'w') as source:
        source.write(new_tree.code)


def _add_to_domain_init(parent, child, parents, children, parent_ref):
    with open('domain/__init__.py', 'r') as source:
        tree = parse_module(source.read())

    inserter = DomainRelationsInserter(parent, child, parents, children, parent_ref)
    new_tree = tree.visit(inserter)

    with open('domain/__init__.py', 'w') as source:
        source.write(new_tree.code)


def _add_to_domain_child(parent, child, parents, children, parent_ref):
    with open(f'domain/{children}.py', 'r') as source:
        tree = parse_module(source.read())

    inserter = DomainChildrenDefinitionInserter(parent, child, parents, children, parent_ref)
    new_tree = tree.visit(inserter)

    with open(f'domain/{children}.py', 'w') as source:
        source.write(new_tree.code)
