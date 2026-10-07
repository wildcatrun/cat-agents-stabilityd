import ast
import sys
import unittest
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from compat_verifiers.ast_compat import canonical_ast_dump


class BaselineAstCompatibilityTests(unittest.TestCase):
    def test_new_empty_generic_field_keeps_legacy_identity_without_mutating_input(self):
        node = ast.parse('def fixture(x):\n return x + 1\n').body[0]
        legacy = ast.parse('def fixture(x):\n return x + 1\n').body[0]
        legacy._fields = tuple(field for field in legacy._fields if field != 'type_params')
        if 'type_params' not in node._fields:
            node._fields = (*node._fields, 'type_params')
        node.type_params = []
        self.assertEqual(canonical_ast_dump(node), ast.dump(legacy, include_attributes=False))
        self.assertIn('type_params', node._fields)
        changed = ast.parse('def fixture(x):\n return x + 2\n').body[0]
        self.assertNotEqual(canonical_ast_dump(node), canonical_ast_dump(changed))

    def test_new_generic_definition_is_rejected_instead_of_erasing_semantics(self):
        node = ast.parse('def fixture(x):\n return x\n').body[0]
        if 'type_params' not in node._fields:
            node._fields = (*node._fields, 'type_params')
        node.type_params = [ast.Name(id='T', ctx=ast.Load())]
        with self.assertRaises(ValueError):
            canonical_ast_dump(node)
