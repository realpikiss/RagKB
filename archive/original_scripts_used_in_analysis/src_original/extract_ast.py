#!/usr/bin/env python3
"""
Extract AST patterns from C code using Tree-sitter
Cleaned up version focusing on reliable pattern extraction
"""

import tree_sitter_c as tsc
from tree_sitter import Language, Parser

# Configuration imports with fallback
try:
    from .config import AST_TIMEOUT_SECONDS, AST_MAX_DEPTH
    from .utils import timeout_wrapper, clean_error_message
except ImportError:
    from config import AST_TIMEOUT_SECONDS, AST_MAX_DEPTH
    from utils import timeout_wrapper, clean_error_message

# Setup Tree-sitter C parser
C_LANGUAGE = Language(tsc.language())

def extract_ast_patterns(c_code: str, timeout_seconds: int = AST_TIMEOUT_SECONDS):
    """Extract AST patterns with timeout protection"""
    return timeout_wrapper(extract_ast_patterns_internal, (c_code,), timeout_seconds)

def extract_ast_patterns_internal(c_code: str):
    """Internal AST extraction function"""
    try:
        # Parse the code
        parser = Parser()
        parser.language = C_LANGUAGE
        tree = parser.parse(bytes(c_code, "utf8"))
        root_node = tree.root_node
        
        # Extract patterns using proper AST traversal
        patterns = {
            'success': True,
            'node_count': _count_nodes(root_node, max_depth=AST_MAX_DEPTH),
            'depth': _calculate_depth(root_node),
            'patterns': {
                'functions': _extract_functions(root_node),
                'calls': _extract_function_calls(root_node),
                'variables': _extract_variables(root_node),
                'pointers': _extract_pointer_operations(root_node),
                'arrays': _extract_array_operations(root_node),
                'conditions': _extract_conditionals(root_node),
                'loops': _extract_loops(root_node)
            }
        }
        
        return patterns
        
    except Exception as e:
        return {
            'success': False,
            'error': clean_error_message(str(e), 100),
            'node_count': 0,
            'depth': 0,
            'patterns': {}
        }

def _count_nodes(node, current_depth=0, max_depth=AST_MAX_DEPTH):
    """Count AST nodes with depth limit"""
    if current_depth > max_depth:
        return 1
    
    count = 1
    for child in node.children:
        count += _count_nodes(child, current_depth + 1, max_depth)
    return count

def _calculate_depth(node, current_depth=0):
    """Calculate maximum AST depth"""
    if not node.children:
        return current_depth
    
    max_child_depth = 0
    for child in node.children:
        child_depth = _calculate_depth(child, current_depth + 1)
        max_child_depth = max(max_child_depth, child_depth)
    
    return max_child_depth

def _extract_functions(root_node):
    """Extract function definitions from AST"""
    functions = []
    
    def traverse(node):
        if node.type == 'function_definition':
            func_info = _parse_function_definition(node)
            if func_info:
                functions.append(func_info)
        
        for child in node.children:
            traverse(child)
    
    traverse(root_node)
    return functions

def _parse_function_definition(node):
    """Parse function definition node"""
    try:
        func_name = None
        return_type = None
        params = []
        
        # Find function declarator
        for child in node.children:
            if child.type == 'function_declarator':
                # Get function name
                for grandchild in child.children:
                    if grandchild.type == 'identifier':
                        func_name = grandchild.text.decode('utf8')
                    elif grandchild.type == 'parameter_list':
                        # Extract parameters
                        for param in grandchild.children:
                            if param.type == 'parameter_declaration':
                                param_text = param.text.decode('utf8')
                                params.append(param_text.strip())
            
            # Try to get return type (simplified)
            elif child.type in ['primitive_type', 'type_identifier']:
                return_type = child.text.decode('utf8')
        
        if func_name:
            return {
                'name': func_name,
                'return_type': return_type or 'unknown',
                'params': params,
                'line': node.start_point[0] + 1
            }
    except:
        pass
    
    return None

def _extract_function_calls(root_node):
    """Extract function calls from AST"""
    calls = []
    
    def traverse(node):
        if node.type == 'call_expression':
            call_info = _parse_function_call(node)
            if call_info:
                calls.append(call_info)
        
        for child in node.children:
            traverse(child)
    
    traverse(root_node)
    return calls

def _parse_function_call(node):
    """Parse function call node"""
    try:
        func_name = None
        args = []
        
        for child in node.children:
            if child.type == 'identifier':
                func_name = child.text.decode('utf8')
            elif child.type == 'argument_list':
                # Count arguments
                for arg in child.children:
                    if arg.type != ',' and arg.type != '(' and arg.type != ')':
                        args.append(arg.text.decode('utf8'))
        
        if func_name:
            return {
                'function': func_name,
                'args': args,
                'line': node.start_point[0] + 1
            }
    except:
        pass
    
    return None

def _extract_variables(root_node):
    """Extract variable declarations from AST"""
    variables = []
    
    def traverse(node):
        if node.type in ['declaration', 'parameter_declaration']:
            var_info = _parse_variable_declaration(node)
            if var_info:
                variables.extend(var_info)
        
        for child in node.children:
            traverse(child)
    
    traverse(root_node)
    return variables

def _parse_variable_declaration(node):
    """Parse variable declaration node"""
    variables = []
    try:
        var_type = None
        
        # Get type information
        for child in node.children:
            if child.type in ['primitive_type', 'type_identifier']:
                var_type = child.text.decode('utf8')
            elif child.type in ['init_declarator', 'declarator', 'pointer_declarator', 'array_declarator']:
                var_info = _extract_declarator_info(child, var_type)
                if var_info:
                    var_info['line'] = node.start_point[0] + 1
                    variables.append(var_info)
    except:
        pass
    
    return variables

def _extract_declarator_info(node, var_type):
    """Extract variable info from declarator"""
    try:
        for child in node.children:
            if child.type == 'identifier':
                return {
                    'name': child.text.decode('utf8'),
                    'type': var_type or 'unknown',
                    'is_pointer': node.type == 'pointer_declarator',
                    'is_array': node.type == 'array_declarator'
                }
            elif child.type in ['pointer_declarator', 'array_declarator', 'declarator']:
                # Recursive extraction for nested declarators
                return _extract_declarator_info(child, var_type)
    except:
        pass
    
    return None

def _extract_pointer_operations(root_node):
    """Extract pointer operations from AST"""
    pointers = []
    
    def traverse(node):
        if node.type in ['pointer_expression', 'field_expression']:
            pointers.append({
                'operation': node.text.decode('utf8')[:50],  # Limit length
                'type': node.type,
                'line': node.start_point[0] + 1
            })
        
        for child in node.children:
            traverse(child)
    
    traverse(root_node)
    return pointers

def _extract_array_operations(root_node):
    """Extract array operations from AST"""
    arrays = []
    
    def traverse(node):
        if node.type == 'subscript_expression':
            arrays.append({
                'operation': node.text.decode('utf8')[:50],
                'line': node.start_point[0] + 1
            })
        
        for child in node.children:
            traverse(child)
    
    traverse(root_node)
    return arrays

def _extract_conditionals(root_node):
    """Extract conditional statements from AST"""
    conditionals = []
    
    def traverse(node):
        if node.type in ['if_statement', 'conditional_expression', 'switch_statement']:
            conditionals.append({
                'type': node.type,
                'line': node.start_point[0] + 1
            })
        
        for child in node.children:
            traverse(child)
    
    traverse(root_node)
    return conditionals

def _extract_loops(root_node):
    """Extract loop statements from AST"""
    loops = []
    
    def traverse(node):
        if node.type in ['for_statement', 'while_statement', 'do_statement']:
            loops.append({
                'type': node.type,
                'line': node.start_point[0] + 1
            })
        
        for child in node.children:
            traverse(child)
    
    traverse(root_node)
    return loops

# Test function
if __name__ == "__main__":
    test_code = """
    int main(int argc, char* argv[]) {
        int buffer[100];
        char* ptr = malloc(sizeof(char) * 50);
        
        if (argc > 1) {
            strcpy(buffer, argv[1]);
            for (int i = 0; i < 100; i++) {
                buffer[i] = *ptr;
                ptr++;
            }
        }
        
        free(ptr);
        return 0;
    }
    """
    
    result = extract_ast_patterns(test_code)
    print("AST Extraction Test:")
    print(f"Success: {result['success']}")
    if result['success']:
        print(f"Node count: {result['node_count']}")
        print(f"Depth: {result['depth']}")
        patterns = result['patterns']
        print(f"Functions: {len(patterns['functions'])}")
        print(f"Function calls: {len(patterns['calls'])}")
        print(f"Variables: {len(patterns['variables'])}")