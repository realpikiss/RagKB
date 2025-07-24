#!/usr/bin/env python3
"""
Build Program Dependence Graph (PDG) from C code
Simple approach focusing on data dependencies
"""

import networkx as nx
import tree_sitter_c as tsc
from tree_sitter import Language, Parser
import re

# Setup Tree-sitter C parser
C_LANGUAGE = Language(tsc.language())

def build_simple_pdg(c_code):
    """Build a simple PDG from C code"""
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
            'error': str(e),
            'functions': {}
        }

def _find_functions(root_node):
    """Find all function definitions in AST"""
    functions = {}
    
    def _search_functions(node):
        if node.type == 'function_definition':
            func_name = _get_function_name(node)
            if func_name:
                functions[func_name] = node
        
        for child in node.children:
            _search_functions(child)
    
    _search_functions(root_node)
    return functions

def _get_function_name(node):
    """Extract function name from function_definition node"""
    for child in node.children:
        if child.type == 'function_declarator':
            for grandchild in child.children:
                if grandchild.type == 'identifier':
                    return grandchild.text.decode('utf8')
    return None

def _build_function_pdg(func_node, source_code):
    """Build PDG for a single function"""
    
    # Extract variable information
    variables = _extract_variables(func_node)
    
    # Extract statements with variable usage
    statements = _extract_statements(func_node)
    
    # Build dependency graph
    pdg = nx.DiGraph()
    dependencies = _analyze_dependencies(statements, variables)
    
    # Create nodes for variables
    for var_name, var_info in variables.items():
        pdg.add_node(var_name, **var_info)
    
    # Create edges for dependencies
    for dep in dependencies:
        pdg.add_edge(dep['source'], dep['target'], **dep['edge_info'])
    
    # Analyze patterns
    patterns = _analyze_vulnerability_patterns(statements, dependencies)
    
    return {
        'variables': variables,
        'statements': statements,
        'dependencies': dependencies,
        'patterns': patterns,
        'variable_count': len(variables),
        'dependency_count': len(dependencies),
        'statement_count': len(statements),
        'vulnerability_indicators': _count_vulnerability_indicators(patterns)
    }

def _extract_variables(func_node):
    """Extract all variable declarations and usage"""
    variables = {}
    
    def _process_node(node, line_offset=0):
        node_type = node.type
        line_num = node.start_point[0] + 1
        
        # Variable declarations
        if node_type in ['declaration', 'parameter_declaration']:
            var_info = _parse_variable_declaration(node)
            if var_info:
                var_name = var_info['name']
                variables[var_name] = {
                    'type': var_info['type'],
                    'declaration_line': line_num,
                    'is_parameter': node_type == 'parameter_declaration',
                    'is_pointer': var_info['is_pointer'],
                    'is_array': var_info['is_array'],
                    'scope': 'function'
                }
        
        # Recurse through children
        for child in node.children:
            _process_node(child, line_offset)
    
    _process_node(func_node)
    return variables

def _parse_variable_declaration(node):
    """Parse variable declaration node"""
    try:
        text = node.text.decode('utf8')
        
        # Simple regex patterns for C variable declarations
        # This is a simplified parser - a full parser would be more complex
        
        # Find variable name (last identifier before = or ; or ,)
        name_match = re.search(r'\b([a-zA-Z_][a-zA-Z0-9_]*)\s*(?:\[.*?\])?\s*(?:=|;|,)', text)
        var_name = name_match.group(1) if name_match else None
        
        # Determine type
        var_type = 'unknown'
        if 'int' in text:
            var_type = 'int'
        elif 'char' in text:
            var_type = 'char'
        elif 'float' in text:
            var_type = 'float'
        elif 'double' in text:
            var_type = 'double'
        
        # Check for pointer/array
        is_pointer = '*' in text
        is_array = '[' in text and ']' in text
        
        if var_name:
            return {
                'name': var_name,
                'type': var_type,
                'is_pointer': is_pointer,
                'is_array': is_array
            }
        
    except:
        pass
    
    return None

def _extract_statements(func_node):
    """Extract all statements with variable usage"""
    statements = []
    
    def _process_statement(node, stmt_id=0):
        nonlocal statements
        
        line_num = node.start_point[0] + 1
        stmt_text = node.text.decode('utf8')
        
        # Extract variable usage from statement
        used_vars = _extract_variable_usage(stmt_text)
        defined_vars = _extract_variable_definitions(stmt_text)
        
        stmt_info = {
            'id': len(statements),
            'line': line_num,
            'text': stmt_text[:200],  # Limit length
            'type': node.type,
            'variables_used': used_vars,
            'variables_defined': defined_vars,
            'is_assignment': _is_assignment_statement(node),
            'is_function_call': _is_function_call(node),
            'is_control_flow': _is_control_flow_statement(node)
        }
        
        statements.append(stmt_info)
        
        # Process children
        for child in node.children:
            if child.type not in ['{', '}', ';']:
                _process_statement(child)
    
    # Find function body and process statements
    for child in func_node.children:
        if child.type == 'compound_statement':
            for stmt in child.children:
                if stmt.type not in ['{', '}']:
                    _process_statement(stmt)
    
    return statements

def _extract_variable_usage(text):
    """Extract variables used in statement"""
    # Simple regex to find variable names (identifiers)
    # This is simplified - a full implementation would use AST traversal
    var_pattern = r'\b([a-zA-Z_][a-zA-Z0-9_]*)\b'
    variables = re.findall(var_pattern, text)
    
    # Filter out keywords and function names
    c_keywords = {'int', 'char', 'float', 'double', 'if', 'else', 'for', 'while', 'return', 'sizeof'}
    return [var for var in variables if var not in c_keywords]

def _extract_variable_definitions(text):
    """Extract variables defined (assigned to) in statement"""
    # Look for assignment patterns
    assignment_pattern = r'([a-zA-Z_][a-zA-Z0-9_]*)\s*(?:\[.*?\])?\s*='
    matches = re.findall(assignment_pattern, text)
    return matches

def _is_assignment_statement(node):
    """Check if statement is an assignment"""
    return 'assignment' in node.type or '=' in node.text.decode('utf8')

def _is_function_call(node):
    """Check if statement contains function call"""
    return node.type == 'call_expression' or 'call_expression' in [child.type for child in node.children]

def _is_control_flow_statement(node):
    """Check if statement is control flow"""
    return node.type in ['if_statement', 'for_statement', 'while_statement', 'return_statement']

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
                        'source': prev_stmt['id'],
                        'target': stmt['id'],
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

def _analyze_vulnerability_patterns(statements, dependencies):
    """Analyze common vulnerability patterns"""
    patterns = {
        'buffer_operations': [],
        'pointer_operations': [],
        'unchecked_operations': [],
        'dangerous_functions': []
    }
    
    # Simple function call tracking
    tracked_funcs = ['strcpy', 'strcat', 'sprintf', 'gets', 'scanf', 'malloc', 'free']
    
    for stmt in statements:
        stmt_text = stmt['text'].lower()
        
        # Buffer operations
        if any(op in stmt_text for op in ['[', 'strcpy', 'memcpy', 'strcat']):
            patterns['buffer_operations'].append({
                'line': stmt['line'],
                'statement': stmt['text'][:100],
                'type': 'buffer_operation'
            })
        
        # Pointer operations
        if '*' in stmt_text or '->' in stmt_text:
            patterns['pointer_operations'].append({
                'line': stmt['line'],
                'statement': stmt['text'][:100],
                'type': 'pointer_operation'
            })
        
        # Track function calls
        if any(func in stmt_text for func in tracked_funcs):
            found_funcs = [func for func in tracked_funcs if func in stmt_text]
            
            patterns['dangerous_functions'].append({
                'line': stmt['line'],
                'statement': stmt['text'][:100],
                'functions': found_funcs
            })
        
        # Unchecked operations (heuristic)
        if ('=' in stmt_text and 'if' not in stmt_text and 
            any(op in stmt_text for op in ['malloc', 'fopen', 'strcpy'])):
            patterns['unchecked_operations'].append({
                'line': stmt['line'],
                'statement': stmt['text'][:100],
                'type': 'unchecked_operation'
            })
    
    return patterns

def _count_vulnerability_indicators(patterns):
    """Count vulnerability indicators"""
    return {
        'buffer_ops': len(patterns['buffer_operations']),
        'pointer_ops': len(patterns['pointer_operations']),
        'unchecked_ops': len(patterns['unchecked_operations']),
        'dangerous_funcs': len(patterns['dangerous_functions'])
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
            print(f"  Vulnerability indicators: {func_pdg['vulnerability_indicators']}") 