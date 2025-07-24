#!/usr/bin/env python3
"""
Build Control Flow Graph (CFG) from C code
Enhanced with timeout and error handling
"""

import networkx as nx
import tree_sitter_c as tsc
from tree_sitter import Language, Parser
import threading
import re

# Configuration imports with fallback
try:
    from .config import CFG_TIMEOUT_SECONDS
    from .utils import timeout_wrapper, clean_error_message
except ImportError:
    # Fallback for standalone execution
    from config import CFG_TIMEOUT_SECONDS
    from utils import timeout_wrapper, clean_error_message

# Setup Tree-sitter C parser
C_LANGUAGE = Language(tsc.language())

def build_simple_cfg_internal(c_code):
    """Internal CFG building function"""
    try:
        # Parse the code
        parser = Parser()
        parser.language = C_LANGUAGE
        tree = parser.parse(bytes(c_code, "utf8"))
        root_node = tree.root_node
        
        # Find function definitions
        functions = _find_functions_safe(root_node)
        
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
                func_cfg = _build_function_cfg_safe(func_node, c_code)
                cfg_data['functions'][func_name] = func_cfg
                
                # Update global stats
                cfg_data['global_stats']['total_nodes'] += func_cfg.get('node_count', 0)
                cfg_data['global_stats']['total_edges'] += func_cfg.get('edge_count', 0)
            except Exception as e:
                # Skip problematic functions
                cfg_data['functions'][func_name] = {
                    'success': False,
                    'error': clean_error_message(str(e), 50),
                    'node_count': 0,
                    'edge_count': 0
                }
        
        return cfg_data
        
    except Exception as e:
        return {
            'success': False,
            'error': clean_error_message(str(e), 100),
            'functions': {}
        }

def build_simple_cfg(c_code, timeout_seconds=CFG_TIMEOUT_SECONDS):
    """Build a simple CFG with timeout protection using threading"""
    return timeout_wrapper(build_simple_cfg_internal, (c_code,), timeout_seconds)

def _find_functions_safe(root_node):
    """Find all function definitions safely"""
    functions = {}
    try:
        for node in root_node.children:
            if node.type == 'function_definition':
                func_name = _get_function_name_safe(node)
                if func_name:
                    functions[func_name] = node
    except Exception:
        pass
    return functions

def _get_function_name_safe(node):
    """Extract function name safely"""
    try:
        for child in node.children:
            if child.type == 'function_declarator':
                for grandchild in child.children:
                    if grandchild.type == 'identifier':
                        return grandchild.text.decode('utf8')
    except Exception:
        pass
    return None

def _build_function_cfg_safe(func_node, source_code):
    """Build CFG for a single function safely"""
    try:
        # Create simple CFG
        cfg = nx.DiGraph()
        
        # Add basic nodes
        cfg.add_node('entry', type='entry')
        cfg.add_node('exit', type='exit')
        
        # Extract basic blocks (simplified)
        blocks = _extract_basic_blocks_safe(func_node)
        
        # Add block nodes
        for i, block in enumerate(blocks):
            node_id = f'block_{i}'
            cfg.add_node(node_id, type='block', content=block[:100])
        
        # Add edges (simplified)
        if blocks:
            cfg.add_edge('entry', 'block_0')
            cfg.add_edge(f'block_{len(blocks)-1}', 'exit')
        
        return {
            'success': True,
            'node_count': len(cfg.nodes),
            'edge_count': len(cfg.edges),
            'complexity': len(blocks),
            'cycles': [],
            'exit_nodes': ['exit']
        }
        
    except Exception as e:
        return {
            'success': False,
            'error': str(e)[:50],
            'node_count': 0,
            'edge_count': 0
        }

def _extract_basic_blocks_safe(func_node):
    """Extract basic blocks safely"""
    blocks = []
    try:
        # Simple approach: split by semicolons
        func_text = func_node.text.decode('utf8')
        statements = func_text.split(';')
        blocks = [stmt.strip() for stmt in statements if stmt.strip()]
    except Exception:
        blocks = ['basic_block']
    return blocks 