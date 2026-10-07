"""Stable pre-3.12 AST identity for non-generic pinned baseline functions."""
import ast
import copy


def canonical_ast_dump(node):
    normalized = copy.deepcopy(node)
    for item in ast.walk(normalized):
        if 'type_params' in item._fields:
            if getattr(item, 'type_params', ()):
                raise ValueError('generic baseline definitions are not supported')
            item._fields = tuple(field for field in item._fields if field != 'type_params')
    return ast.dump(normalized, include_attributes=False)
