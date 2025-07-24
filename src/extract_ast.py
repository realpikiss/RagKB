#!/usr/bin/env python3
"""
Extract AST patterns from C code using Tree-sitter
Enhanced with timeout and error handling
"""

import tree_sitter_c as tsc
from tree_sitter import Language, Parser
import threading
import time
from typing import Dict, List, Any

# Setup Tree-sitter C parser
C_LANGUAGE = Language(tsc.language())

def timeout_function(func, args, timeout_seconds):
    """Execute function with timeout using threading"""
    result = [None]
    exception = [None]
    
    def target():
        try:
            result[0] = func(*args)
        except Exception as e:
            exception[0] = e
    
    thread = threading.Thread(target=target)
    thread.daemon = True
    thread.start()
    thread.join(timeout_seconds)
    
    if thread.is_alive():
        return {'success': False, 'error': 'timeout'}
    elif exception[0]:
        return {'success': False, 'error': str(exception[0])}
    else:
        return result[0]

def extract_ast_patterns_internal(c_code: str) -> Dict[str, Any]:
    """Internal AST extraction function"""
    try:
        # Parse the code
        parser = Parser()
        parser.language = C_LANGUAGE
        
        tree = parser.parse(bytes(c_code, "utf8"))
        root_node = tree.root_node
        
        # Extract patterns
        patterns = {
            'success': True,
            'node_count': 0,
            'functions': [],
            'variables': [],
            'function_calls': [],
            'conditions': [],
            'loops': [],
            'error': None
        }
        
        # Simple pattern extraction without deep recursion
        patterns['node_count'] = count_nodes_safe(root_node, max_depth=10)
        patterns['functions'] = extract_functions_safe(root_node)
        patterns['function_calls'] = extract_function_calls_safe(root_node)
        patterns['variables'] = extract_variables_safe(root_node)
        patterns['conditions'] = extract_conditions_safe(root_node)
        patterns['loops'] = extract_loops_safe(root_node)
        
        return patterns
        
    except Exception as e:
        return {
            'success': False,
            'error': str(e)[:100],
            'node_count': 0,
            'functions': [],
            'variables': [],
            'function_calls': [],
            'conditions': [],
            'loops': []
        }

def extract_ast_patterns(c_code: str, timeout_seconds: int = 5) -> Dict[str, Any]:
    """
    Extract AST patterns with timeout protection using threading
    """
    return timeout_function(extract_ast_patterns_internal, (c_code,), timeout_seconds)

def count_nodes_safe(node, max_depth=10, current_depth=0):
    """Count nodes safely with depth limit"""
    if current_depth > max_depth:
        return 1
    
    count = 1
    for child in node.children:
        count += count_nodes_safe(child, max_depth, current_depth + 1)
    return count

def extract_functions_safe(root_node):
    """Extract functions safely"""
    functions = []
    try:
        def search_functions(node):
            if node.type == 'function_definition':
                func_name = get_function_name_safe(node)
                if func_name:
                    functions.append({
                        'name': func_name,
                        'line': node.start_point[0] + 1
                    })
            for child in node.children:
                search_functions(child)
        
        search_functions(root_node)
    except Exception:
        pass
    return functions

def get_function_name_safe(node):
    """Get function name safely"""
    try:
        for child in node.children:
            if child.type == 'function_declarator':
                for grandchild in child.children:
                    if grandchild.type == 'identifier':
                        return grandchild.text.decode('utf8')
    except Exception:
        pass
    return None

def extract_function_calls_safe(root_node):
    """Extract function calls safely"""
    calls = []
    try:
        def search_calls(node):
            if node.type == 'call_expression':
                func_name = get_call_name_safe(node)
                if func_name:
                    calls.append({
                        'function': func_name,
                        'line': node.start_point[0] + 1
                    })
            for child in node.children:
                search_calls(child)
        
        search_calls(root_node)
    except Exception:
        pass
    return calls

def get_call_name_safe(node):
    """Get call name safely"""
    try:
        for child in node.children:
            if child.type == 'identifier':
                return child.text.decode('utf8')
    except Exception:
        pass
    return None

def extract_variables_safe(root_node):
    """Extract variables safely"""
    variables = []
    try:
        def search_variables(node):
            if node.type == 'declaration':
                # Chercher les déclarations avec initialisation
                for child in node.children:
                    if child.type == 'init_declarator':
                        for grandchild in child.children:
                            if grandchild.type == 'identifier':
                                variables.append({
                                    'name': grandchild.text.decode('utf8'),
                                    'line': node.start_point[0] + 1
                                })
                    # Chercher aussi les déclarations simples
                    elif child.type in ['array_declarator', 'pointer_declarator']:
                        for grandchild in child.children:
                            if grandchild.type == 'identifier':
                                variables.append({
                                    'name': grandchild.text.decode('utf8'),
                                    'line': node.start_point[0] + 1
                                })
            for child in node.children:
                search_variables(child)
        
        search_variables(root_node)
    except Exception:
        pass
    return variables

def extract_conditions_safe(root_node):
    """Extract conditions safely"""
    conditions = []
    try:
        def search_conditions(node):
            if node.type in ['if_statement', 'conditional_expression']:
                conditions.append({
                    'type': node.type,
                    'line': node.start_point[0] + 1
                })
            for child in node.children:
                search_conditions(child)
        
        search_conditions(root_node)
    except Exception:
        pass
    return conditions

def extract_loops_safe(root_node):
    """Extract loops safely"""
    loops = []
    try:
        def search_loops(node):
            if node.type in ['for_statement', 'while_statement', 'do_statement']:
                loops.append({
                    'type': node.type,
                    'line': node.start_point[0] + 1
                })
            for child in node.children:
                search_loops(child)
        
        search_loops(root_node)
    except Exception:
        pass
    return loops 