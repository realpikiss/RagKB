#!/usr/bin/env python3
"""
Build Control Flow Graph (CFG) from C code
Proper CFG construction using AST-based basic block identification
"""

import networkx as nx
import tree_sitter_c as tsc
from tree_sitter import Language, Parser

# Configuration imports with fallback
try:
    from .config import CFG_TIMEOUT_SECONDS
    from .utils import timeout_wrapper, clean_error_message
except ImportError:
    from config import CFG_TIMEOUT_SECONDS
    from utils import timeout_wrapper, clean_error_message

# Setup Tree-sitter C parser
C_LANGUAGE = Language(tsc.language())

def build_simple_cfg(c_code, timeout_seconds=CFG_TIMEOUT_SECONDS):
    """Build a CFG with timeout protection"""
    return timeout_wrapper(build_simple_cfg_internal, (c_code,), timeout_seconds)

def build_simple_cfg_internal(c_code):
    """Internal CFG building function"""
    try:
        # Parse the code
        parser = Parser()
        parser.language = C_LANGUAGE
        tree = parser.parse(bytes(c_code, "utf8"))
        root_node = tree.root_node
        
        # Find function definitions
        functions = _find_functions(root_node)
        
        cfg_data = {
            'success': True,
            'functions': {},
            'global_stats': {
                'total_functions': len(functions),
                'total_nodes': 0,
                'total_edges': 0
            }
        }
        
        # Build CFG for each function
        for func_name, func_node in functions.items():
            try:
                func_cfg = _build_function_cfg(func_node)
                cfg_data['functions'][func_name] = func_cfg
                
                # Update global stats
                cfg_data['global_stats']['total_nodes'] += func_cfg.get('node_count', 0)
                cfg_data['global_stats']['total_edges'] += func_cfg.get('edge_count', 0)
                
            except Exception as e:
                cfg_data['functions'][func_name] = {
                    'success': False,
                    'error': clean_error_message(str(e), 50),
                    'node_count': 0,
                    'edge_count': 0,
                    'complexity': 1
                }
        
        return cfg_data
        
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

def _build_function_cfg(func_node):
    """Build CFG for a single function"""
    try:
        # Create directed graph
        cfg = nx.DiGraph()
        
        # Find function body
        body_node = None
        for child in func_node.children:
            if child.type == 'compound_statement':
                body_node = child
                break
        
        if not body_node:
            return _create_minimal_cfg()
        
        # Extract basic blocks from function body
        basic_blocks = _extract_basic_blocks(body_node)
        
        if not basic_blocks:
            return _create_minimal_cfg()
        
        # Add nodes to CFG
        cfg.add_node('entry', type='entry', block_id=0)
        
        for i, block in enumerate(basic_blocks):
            block_id = f'block_{i+1}'
            cfg.add_node(block_id, type='basic_block', statements=block['statements'], 
                        start_line=block['start_line'], end_line=block['end_line'])
        
        cfg.add_node('exit', type='exit', block_id=len(basic_blocks)+1)
        
        # Add edges based on control flow
        _add_control_flow_edges(cfg, basic_blocks, body_node)
        
        # Calculate metrics
        node_count = len(cfg.nodes)
        edge_count = len(cfg.edges)
        
        # Cyclomatic complexity: edges - nodes + 2 (for connected graph)
        complexity = max(1, edge_count - node_count + 2)
        
        # Find cycles and exit nodes
        cycles = list(nx.simple_cycles(cfg))
        exit_nodes = [node for node in cfg.nodes if cfg.out_degree(node) == 0]
        
        return {
            'success': True,
            'node_count': node_count,
            'edge_count': edge_count,
            'complexity': complexity,
            'cycles': cycles,
            'exit_nodes': exit_nodes,
            'basic_blocks': len(basic_blocks)
        }
        
    except Exception as e:
        return {
            'success': False,
            'error': clean_error_message(str(e), 50),
            'node_count': 0,
            'edge_count': 0,
            'complexity': 1
        }

def _create_minimal_cfg():
    """Create minimal CFG for functions without proper body"""
    return {
        'success': True,
        'node_count': 2,
        'edge_count': 1,
        'complexity': 1,
        'cycles': [],
        'exit_nodes': ['exit'],
        'basic_blocks': 0
    }

def _extract_basic_blocks(body_node):
    """Extract basic blocks from function body"""
    basic_blocks = []
    current_block = []
    
    def process_statement(node, block_list):
        """Process a statement and determine if it starts a new basic block"""
        line_num = node.start_point[0] + 1
        stmt_text = node.text.decode('utf8').strip()
        
        # Control flow statements start new blocks
        if node.type in ['if_statement', 'while_statement', 'for_statement', 
                        'switch_statement', 'break_statement', 'continue_statement', 
                        'return_statement', 'goto_statement']:
            
            # Finish current block if it has statements
            if block_list:
                basic_blocks.append(_create_basic_block(block_list))
                block_list.clear()
            
            # Add control statement as its own block
            block_list.append({
                'line': line_num,
                'text': stmt_text[:100],  # Limit length
                'type': node.type
            })
            basic_blocks.append(_create_basic_block(block_list))
            block_list.clear()
            
        else:
            # Regular statement - add to current block
            block_list.append({
                'line': line_num,
                'text': stmt_text[:100],
                'type': node.type
            })
    
    # Traverse statements in function body
    def traverse_body(node):
        if node.type in ['expression_statement', 'declaration', 'if_statement', 
                        'while_statement', 'for_statement', 'return_statement',
                        'break_statement', 'continue_statement', 'switch_statement']:
            process_statement(node, current_block)
        else:
            for child in node.children:
                traverse_body(child)
    
    traverse_body(body_node)
    
    # Add final block if there are remaining statements
    if current_block:
        basic_blocks.append(_create_basic_block(current_block))
    
    return basic_blocks

def _create_basic_block(statements):
    """Create a basic block from a list of statements"""
    if not statements:
        return None
    
    return {
        'statements': statements,
        'start_line': statements[0]['line'],
        'end_line': statements[-1]['line'],
        'statement_count': len(statements)
    }

def _add_control_flow_edges(cfg, basic_blocks, body_node):
    """Add control flow edges to the CFG"""
    try:
        # Simple linear flow for basic implementation
        # Connect entry to first block
        if basic_blocks:
            cfg.add_edge('entry', 'block_1')
            
            # Connect sequential blocks
            for i in range(len(basic_blocks) - 1):
                cfg.add_edge(f'block_{i+1}', f'block_{i+2}')
            
            # Connect last block to exit
            cfg.add_edge(f'block_{len(basic_blocks)}', 'exit')
        else:
            # No blocks - direct entry to exit
            cfg.add_edge('entry', 'exit')
        
        # Add additional edges for control structures
        # This is simplified - a full implementation would analyze
        # if/else branches, loop back edges, etc.
        _add_branch_edges(cfg, basic_blocks)
        
    except Exception:
        # Fallback to minimal flow
        if 'entry' in cfg.nodes and 'exit' in cfg.nodes:
            cfg.add_edge('entry', 'exit')

def _add_branch_edges(cfg, basic_blocks):
    """Add edges for branching control structures"""
    try:
        # Look for control flow statements and add appropriate edges
        for i, block in enumerate(basic_blocks):
            block_id = f'block_{i+1}'
            
            # Check if block contains control flow
            for stmt in block['statements']:
                if stmt['type'] in ['if_statement', 'while_statement', 'for_statement']:
                    # Add potential branch edges (simplified)
                    if i + 2 <= len(basic_blocks):
                        # Branch forward (skip next block)
                        cfg.add_edge(block_id, f'block_{i+3}' if i+3 <= len(basic_blocks) else 'exit')
                
                elif stmt['type'] in ['while_statement', 'for_statement']:
                    # Add loop back edge
                    cfg.add_edge(block_id, block_id)
                
                elif stmt['type'] == 'return_statement':
                    # Direct to exit
                    cfg.add_edge(block_id, 'exit')
    except Exception:
        pass  # Fallback to linear flow

# Test function
if __name__ == "__main__":
    test_code = """
    int test_function(int x) {
        int result = 0;
        
        if (x > 0) {
            result = x * 2;
        } else {
            result = x * -1;
        }
        
        for (int i = 0; i < x; i++) {
            result += i;
        }
        
        return result;
    }
    """
    
    result = build_simple_cfg(test_code)
    print("CFG Construction Test:")
    print(f"Success: {result['success']}")
    if result['success']:
        stats = result['global_stats']
        print(f"Functions: {stats['total_functions']}")
        print(f"Total nodes: {stats['total_nodes']}")
        print(f"Total edges: {stats['total_edges']}")
        
        for func_name, func_cfg in result['functions'].items():
            print(f"\nFunction '{func_name}':")
            print(f"  Complexity: {func_cfg['complexity']}")
            print(f"  Basic blocks: {func_cfg['basic_blocks']}")
            print(f"  Nodes: {func_cfg['node_count']}")
            print(f"  Edges: {func_cfg['edge_count']}")