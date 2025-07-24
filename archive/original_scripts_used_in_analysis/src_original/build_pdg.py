#!/usr/bin/env python3
"""
Build Program Dependence Graph (PDG) from C code
Proper implementation using AST-based analysis 
"""

import networkx as nx
import tree_sitter_c as tsc
from tree_sitter import Language, Parser

# Configuration imports with fallback
try:
    from .config import PDG_TIMEOUT_SECONDS, TRACKED_FUNCTIONS, VULNERABILITY_PATTERNS
    from .utils import timeout_wrapper, clean_error_message
except ImportError:
    from config import PDG_TIMEOUT_SECONDS, TRACKED_FUNCTIONS, VULNERABILITY_PATTERNS
    from utils import timeout_wrapper, clean_error_message

# Setup Tree-sitter C parser
C_LANGUAGE = Language(tsc.language())

def build_simple_pdg(c_code, timeout_seconds=PDG_TIMEOUT_SECONDS):
    """Build a simple PDG with timeout protection"""
    return timeout_wrapper(build_simple_pdg_internal, (c_code,), timeout_seconds)

def build_simple_pdg_internal(c_code):
    """Internal PDG building function"""
    try:
        # Parse the code
        parser = Parser()
        parser.language = C_LANGUAGE
        tree = parser.parse(bytes(c_code, "utf8"))
        root_node = tree.root_node
        
        # Find function definitions
        functions = _find_functions(root_node)
        
        pdg_data = {
            'success': True,
            'functions': {},
            'global_stats': {
                'total_variables': 0,
                'total_dependencies': 0,
                'total_functions': len(functions)
            }
        }
        
        # Build PDG for each function
        for func_name, func_node in functions.items():
            func_pdg = _build_function_pdg(func_node, c_code)
            pdg_data['functions'][func_name] = func_pdg
            
            # Update global stats
            pdg_data['global_stats']['total_variables'] += func_pdg['variable_count']
            pdg_data['global_stats']['total_dependencies'] += func_pdg['dependency_count']
        
        return pdg_data
        
    except Exception as e:
        return {
            'success': False,
            'error': clean_error_message(str(e), 100),
            'functions': {}
        }

def _find_functions(root_node):
    """Find all function definitions in AST"""
    functions = {}
    
    def traverse(node):
        if node.type == 'function_definition':
            func_name = _get_function_name(node)
            if func_name:
                functions[func_name] = node
        
        for child in node.children:
            traverse(child)
    
    traverse(root_node)
    return functions

def _get_function_name(node):
    """Extract function name from function_definition node"""
    try:
        for child in node.children:
            if child.type == 'function_declarator':
                for grandchild in child.children:
                    if grandchild.type == 'identifier':
                        return grandchild.text.decode('utf8')
    except:
        pass
    return None

def _build_function_pdg(func_node, source_code):
    """Build PDG for a single function using AST traversal"""
    
    # Extract variables using AST instead of regex
    variables = _extract_variables_ast(func_node)
    
    # Extract statements with variable usage
    statements = _extract_statements_ast(func_node)
    
    # Build dependency graph
    pdg = nx.DiGraph()
    dependencies = _analyze_dependencies(statements, variables)
    
    # Create nodes for variables
    for var_name, var_info in variables.items():
        pdg.add_node(var_name, **var_info)
    
    # Create edges for dependencies
    for dep in dependencies:
        if dep['source'] in pdg.nodes or dep['target'] in pdg.nodes:
            # Add statement nodes if they don't exist
            if dep['source'] not in pdg.nodes:
                pdg.add_node(dep['source'], type='statement')
            if dep['target'] not in pdg.nodes:
                pdg.add_node(dep['target'], type='statement')
            
            pdg.add_edge(dep['source'], dep['target'], **dep['edge_info'])
    
    # Analyze patterns using AST instead of text analysis
    patterns = _analyze_code_patterns(func_node, statements)
    
    return {
        'variables': variables,
        'statements': statements,
        'dependencies': dependencies,
        'patterns': patterns,
        'variable_count': len(variables),
        'dependency_count': len(dependencies),
        'statement_count': len(statements),
        'vulnerability_indicators': _count_pattern_indicators(patterns)
    }

def _extract_variables_ast(func_node):
    """Extract variables using AST traversal instead of regex"""
    variables = {}
    
    def traverse(node):
        if node.type in ['declaration', 'parameter_declaration']:
            var_info = _parse_variable_declaration_ast(node)
            for var in var_info:
                if var:
                    variables[var['name']] = {
                        'type': var['type'],
                        'declaration_line': var['line'],
                        'is_parameter': node.type == 'parameter_declaration',
                        'is_pointer': var['is_pointer'],
                        'is_array': var['is_array'],
                        'scope': 'function'
                    }
        
        for child in node.children:
            traverse(child)
    
    traverse(func_node)
    return variables

def _parse_variable_declaration_ast(node):
    """Parse variable declaration using AST structure"""
    variables = []
    
    try:
        var_type = None
        
        # Get type information
        for child in node.children:
            if child.type in ['primitive_type', 'type_identifier']:
                var_type = child.text.decode('utf8')
            elif child.type in ['init_declarator', 'declarator', 'pointer_declarator', 'array_declarator']:
                var_info = _extract_declarator_info_ast(child, var_type, node.start_point[0] + 1)
                if var_info:
                    variables.append(var_info)
            elif child.type == 'identifier':  # Direct identifier in parameter declarations
                variables.append({
                    'name': child.text.decode('utf8'),
                    'type': var_type or 'unknown',
                    'is_pointer': False,
                    'is_array': False,
                    'line': node.start_point[0] + 1
                })
    except Exception:
        pass
    
    return variables

def _extract_declarator_info_ast(node, var_type, line_num):
    """Extract variable info from declarator using AST"""
    try:
        # Look for identifier in declarator
        for child in node.children:
            if child.type == 'identifier':
                return {
                    'name': child.text.decode('utf8'),
                    'type': var_type or 'unknown',
                    'is_pointer': node.type == 'pointer_declarator',
                    'is_array': node.type == 'array_declarator',
                    'line': line_num
                }
            elif child.type in ['pointer_declarator', 'array_declarator', 'declarator']:
                # Recursive extraction for nested declarators
                return _extract_declarator_info_ast(child, var_type, line_num)
    except Exception:
        pass
    
    return None

def _extract_statements_ast(func_node):
    """Extract statements with variable usage using AST"""
    statements = []
    
    def traverse(node):
        if node.type in ['expression_statement', 'declaration', 'assignment_expression',
                        'call_expression', 'if_statement', 'while_statement', 'for_statement',
                        'return_statement']:
            
            stmt_info = {
                'id': len(statements),
                'line': node.start_point[0] + 1,
                'text': node.text.decode('utf8')[:200],  # Limit length
                'type': node.type,
                'variables_used': _extract_variable_usage_ast(node),
                'variables_defined': _extract_variable_definitions_ast(node),
                'function_calls': _extract_function_calls_ast(node)
            }
            
            statements.append(stmt_info)
        
        for child in node.children:
            traverse(child)
    
    traverse(func_node)
    return statements

def _extract_variable_usage_ast(node):
    """Extract variables used in a statement using AST"""
    used_vars = []
    
    def traverse(node):
        if node.type == 'identifier':
            var_name = node.text.decode('utf8')
            # Filter out obvious non-variables (function names, keywords)
            if var_name not in ['if', 'while', 'for', 'return', 'int', 'char', 'float', 'double']:
                used_vars.append(var_name)
        
        for child in node.children:
            traverse(child)
    
    traverse(node)
    return list(set(used_vars))  # Remove duplicates

def _extract_variable_definitions_ast(node):
    """Extract variables defined (assigned to) using AST"""
    defined_vars = []
    
    def traverse(node):
        # Look for assignment expressions
        if node.type == 'assignment_expression':
            # Left side of assignment
            left_child = node.children[0] if node.children else None
            if left_child and left_child.type == 'identifier':
                defined_vars.append(left_child.text.decode('utf8'))
        
        # Look for declarations with initialization
        elif node.type == 'init_declarator':
            for child in node.children:
                if child.type == 'identifier':
                    defined_vars.append(child.text.decode('utf8'))
                    break
        
        for child in node.children:
            traverse(child)
    
    traverse(node)
    return defined_vars

def _extract_function_calls_ast(node):
    """Extract function calls from statement using AST"""
    calls = []
    
    def traverse(node):
        if node.type == 'call_expression':
            # Get function name
            for child in node.children:
                if child.type == 'identifier':
                    calls.append(child.text.decode('utf8'))
                    break
        
        for child in node.children:
            traverse(child)
    
    traverse(node)
    return calls

def _analyze_dependencies(statements, variables):
    """Analyze data dependencies between statements"""
    dependencies = []
    
    # For each statement, find dependencies on previous statements
    for i, stmt in enumerate(statements):
        for used_var in stmt['variables_used']:
            # Find the most recent definition of this variable
            for j in range(i-1, -1, -1):
                prev_stmt = statements[j]
                if used_var in prev_stmt['variables_defined']:
                    # Found a dependency
                    dependency = {
                        'source': f"stmt_{prev_stmt['id']}",
                        'target': f"stmt_{stmt['id']}",
                        'variable': used_var,
                        'edge_info': {
                            'type': 'data_dependency',
                            'variable': used_var,
                            'source_line': prev_stmt['line'],
                            'target_line': stmt['line']
                        }
                    }
                    dependencies.append(dependency)
                    break
    
    return dependencies

def _analyze_code_patterns(func_node, statements):
    """Analyze code patterns - observational, not judgmental"""
    patterns = {
        'buffer_operations': [],
        'pointer_operations': [],
        'memory_operations': [],
        'function_calls': []
    }
    
    # Analyze each statement
    for stmt in statements:
        stmt_text = stmt['text'].lower()
        
        # Look for buffer/array operations
        if any(op in stmt_text for op in ['[', 'strcpy', 'strcat', 'memcpy', 'memset']):
            patterns['buffer_operations'].append({
                'line': stmt['line'],
                'statement': stmt['text'][:100],
                'type': 'buffer_operation'
            })
        
        # Look for pointer operations
        if any(op in stmt_text for op in ['->', '*', '&']):
            patterns['pointer_operations'].append({
                'line': stmt['line'],
                'statement': stmt['text'][:100],
                'type': 'pointer_operation'
            })
        
        # Look for memory operations
        if any(op in stmt_text for op in ['malloc', 'free', 'calloc', 'realloc']):
            patterns['memory_operations'].append({
                'line': stmt['line'],
                'statement': stmt['text'][:100],
                'type': 'memory_operation'
            })
        
        # Track function calls from centralized list (observational only)
        for func_call in stmt['function_calls']:
            if func_call in TRACKED_FUNCTIONS:
                patterns['function_calls'].append({
                    'line': stmt['line'],
                    'function': func_call,
                    'statement': stmt['text'][:100]
                })
    
    return patterns

def _count_pattern_indicators(patterns):
    """Count pattern indicators without making security judgments"""
    return {
        'buffer_ops': len(patterns['buffer_operations']),
        'pointer_ops': len(patterns['pointer_operations']),
        'memory_ops': len(patterns['memory_operations']),
        'tracked_funcs': len(patterns['function_calls'])
    }

# Test function
if __name__ == "__main__":
    test_code = """
    int vulnerable_function(char *buffer, int size) {
        char local_buffer[100];
        int *ptr = malloc(size * sizeof(int));
        
        if (size > 100) {
            return -1;
        }
        
        strcpy(local_buffer, buffer);
        *ptr = size;
        
        free(ptr);
        return 0;
    }
    """
    
    result = build_simple_pdg(test_code)
    print("PDG Construction Test:")
    print(f"Success: {result['success']}")
    if result['success']:
        stats = result['global_stats']
        print(f"Functions: {stats['total_functions']}")
        print(f"Total variables: {stats['total_variables']}")
        print(f"Total dependencies: {stats['total_dependencies']}")
        
        for func_name, func_pdg in result['functions'].items():
            print(f"\nFunction '{func_name}':")
            print(f"  Variables: {func_pdg['variable_count']}")
            print(f"  Dependencies: {func_pdg['dependency_count']}")
            print(f"  Pattern indicators: {func_pdg['vulnerability_indicators']}")