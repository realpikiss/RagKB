#!/usr/bin/env python3
"""
Create hybrid knowledge base entry
Combine Vul-RAG data with structural representations
"""

from datetime import datetime

def create_hybrid_entry(vulrag_entry, ast_data, cfg_data, pdg_data):
    """Create a hybrid entry combining textual and structural data"""
    
    # Validate inputs
    if not vulrag_entry:
        return None
    
    # Create the hybrid entry structure
    hybrid_entry = {
        # === ORIGINAL VUL-RAG DATA ===
        "original_vulrag": vulrag_entry,
        
        # === STRUCTURAL ENRICHMENT ===
        "structural_analysis": {
            "ast_patterns": _normalize_ast_data(ast_data),
            "cfg_analysis": _normalize_cfg_data(cfg_data), 
            "pdg_analysis": _normalize_pdg_data(pdg_data)
        },
        
        # === HYBRID ANALYSIS ===
        "hybrid_insights": _create_hybrid_insights(vulrag_entry, ast_data, cfg_data, pdg_data),
        
        # === METADATA ===
        "enrichment_metadata": {
            "timestamp": datetime.now().isoformat(),
            "version": "1.0",
            "extraction_success": {
                "ast": ast_data.get('success', False) if ast_data else False,
                "cfg": cfg_data.get('success', False) if cfg_data else False,
                "pdg": pdg_data.get('success', False) if pdg_data else False
            }
        }
    }
    
    return hybrid_entry

def _normalize_ast_data(ast_data):
    """Normalize AST data for the KB"""
    if not ast_data or not ast_data.get('success'):
        return {
            'available': False,
            'error': ast_data.get('error', 'Unknown error') if ast_data else 'No data'
        }
    
    patterns = ast_data.get('patterns', {})
    
    return {
        'available': True,
        'metrics': {
            'node_count': ast_data.get('node_count', 0),
            'depth': ast_data.get('depth', 0),
            'function_count': len(patterns.get('functions', [])),
            'call_count': len(patterns.get('calls', [])),
            'pointer_ops': len(patterns.get('pointers', [])),
            'array_ops': len(patterns.get('arrays', [])),
            'conditions': len(patterns.get('conditions', [])),
            'loops': len(patterns.get('loops', []))
        },
        'patterns': {
            'functions': _simplify_function_patterns(patterns.get('functions', [])),
            'function_patterns': _identify_function_patterns(patterns.get('calls', [])),
            'memory_operations': _identify_memory_ops(patterns),
            'control_structures': _summarize_control_structures(patterns)
        }
    }

def _normalize_cfg_data(cfg_data):
    """Normalize CFG data for the KB"""
    if not cfg_data or not cfg_data.get('success'):
        return {
            'available': False,
            'error': cfg_data.get('error', 'Unknown error') if cfg_data else 'No data'
        }
    
    global_stats = cfg_data.get('global_stats', {})
    functions = cfg_data.get('functions', {})
    
    return {
        'available': True,
        'global_metrics': {
            'total_functions': global_stats.get('total_functions', 0),
            'total_nodes': global_stats.get('total_nodes', 0),
            'total_edges': global_stats.get('total_edges', 0)
        },
        'function_analysis': _analyze_cfg_functions(functions),
        'complexity_indicators': _extract_complexity_indicators(functions)
    }

def _normalize_pdg_data(pdg_data):
    """Normalize PDG data for the KB"""
    if not pdg_data or not pdg_data.get('success'):
        return {
            'available': False,
            'error': pdg_data.get('error', 'Unknown error') if pdg_data else 'No data'
        }
    
    global_stats = pdg_data.get('global_stats', {})
    functions = pdg_data.get('functions', {})
    
    return {
        'available': True,
        'global_metrics': {
            'total_functions': global_stats.get('total_functions', 0),
            'total_variables': global_stats.get('total_variables', 0),
            'total_dependencies': global_stats.get('total_dependencies', 0)
        },
        'vulnerability_patterns': _extract_vulnerability_patterns(functions),
        'dependency_analysis': _analyze_dependencies(functions)
    }

def _create_hybrid_insights(vulrag_entry, ast_data, cfg_data, pdg_data):
    """Create insights that combine textual and structural analysis"""
    
    insights = {
        'code_complexity': 'unknown',
        'vulnerability_alignment': [],
        'structural_evidence': [],
        'risk_indicators': []
    }
    
    # Determine code complexity from multiple sources
    complexity_score = 0
    complexity_factors = []
    
    if ast_data and ast_data.get('success'):
        node_count = ast_data.get('node_count', 0)
        if node_count > 100:
            complexity_score += 2
            complexity_factors.append('high_ast_complexity')
        elif node_count > 50:
            complexity_score += 1
            complexity_factors.append('medium_ast_complexity')
    
    if cfg_data and cfg_data.get('success'):
        functions = cfg_data.get('functions', {})
        for func_name, func_data in functions.items():
            complexity = func_data.get('complexity', 0)
            if complexity > 10:
                complexity_score += 2
                complexity_factors.append('high_cyclomatic_complexity')
            elif complexity > 5:
                complexity_score += 1
                complexity_factors.append('medium_cyclomatic_complexity')
    
    # Map complexity score to category
    if complexity_score >= 3:
        insights['code_complexity'] = 'high'
    elif complexity_score >= 1:
        insights['code_complexity'] = 'medium'
    else:
        insights['code_complexity'] = 'low'
    
    # Find alignment between vulnerability description and structural patterns
    vuln_behavior = vulrag_entry.get('vulnerability_behavior', '')
    if isinstance(vuln_behavior, dict):
        vuln_text = str(vuln_behavior)
    else:
        vuln_text = str(vuln_behavior).lower()
    
    # Check for structural evidence of described vulnerability
    if pdg_data and pdg_data.get('success'):
        functions = pdg_data.get('functions', {})
        for func_name, func_data in functions.items():
            patterns = func_data.get('patterns', {})
            vuln_indicators = func_data.get('vulnerability_indicators', {})
            
            # Ensure vuln_indicators is a dictionary
            if not isinstance(vuln_indicators, dict):
                vuln_indicators = {}
            
            # Buffer overflow indicators
            if 'buffer' in vuln_text and vuln_indicators.get('buffer_ops', 0) > 0:
                insights['vulnerability_alignment'].append('buffer_overflow_evidence')
                insights['structural_evidence'].append(f"Found {vuln_indicators['buffer_ops']} buffer operations")
            
            # Pointer dereference indicators  
            if 'pointer' in vuln_text and vuln_indicators.get('pointer_ops', 0) > 0:
                insights['vulnerability_alignment'].append('pointer_dereference_evidence')
                insights['structural_evidence'].append(f"Found {vuln_indicators['pointer_ops']} pointer operations")
            
            # Function pattern indicators (neutral observation)
            if vuln_indicators.get('dangerous_funcs', 0) > 0:
                insights['structural_evidence'].append(f"Found {vuln_indicators['dangerous_funcs']} tracked function calls")
    
    return insights

def _simplify_function_patterns(functions):
    """Simplify function patterns for storage"""
    simplified = []
    for func in functions:
        simplified.append({
            'name': func.get('name', 'unknown'),
            'param_count': len(func.get('params', [])),
            'return_type': func.get('return_type', 'unknown')
        })
    return simplified

def _identify_function_patterns(calls):
    """Identify function usage patterns (no security judgment)"""
    try:
        
        
        # Simple function pattern tracking
        function_patterns = []
        
        for call in calls:
            func_name = call.get('function', '')
            function_patterns.append({
                'function': func_name,
                'line': call.get('line'),
                'args_count': len(call.get('args', [])) if 'args' in call else 0
            })
        
        return function_patterns
        
    except Exception:
        # Fallback to basic tracking
        function_patterns = []
        
        for call in calls:
            func_name = call.get('function', '')
            function_patterns.append({
                'function': func_name,
                'line': call.get('line')
            })
        
        return function_patterns

def _assess_function_risk(func_name):
    """Assess risk level of function"""
    high_risk = ['gets', 'sprintf', 'strcpy']
    medium_risk = ['strcat', 'scanf', 'malloc']
    
    func_lower = func_name.lower()
    if any(high in func_lower for high in high_risk):
        return 'high'
    elif any(medium in func_lower for medium in medium_risk):
        return 'medium'
    else:
        return 'low'

def _identify_memory_ops(patterns):
    """Identify memory-related operations"""
    memory_ops = []
    
    # Pointer operations
    for ptr_op in patterns.get('pointers', []):
        memory_ops.append({
            'type': 'pointer',
            'operation': ptr_op.get('operation', '')[:50],
            'line': ptr_op.get('line')
        })
    
    # Array operations
    for array_op in patterns.get('arrays', []):
        memory_ops.append({
            'type': 'array',
            'operation': array_op.get('operation', '')[:50],
            'line': array_op.get('line')
        })
    
    return memory_ops

def _summarize_control_structures(patterns):
    """Summarize control flow structures"""
    return {
        'conditionals': len(patterns.get('conditions', [])),
        'loops': len(patterns.get('loops', [])),
        'complexity_estimate': len(patterns.get('conditions', [])) + len(patterns.get('loops', []))
    }

def _analyze_cfg_functions(functions):
    """Analyze CFG function data"""
    analysis = []
    
    for func_name, func_data in functions.items():
        analysis.append({
            'name': func_name,
            'node_count': func_data.get('node_count', 0),
            'edge_count': func_data.get('edge_count', 0),
            'complexity': func_data.get('complexity', 0),
            'has_cycles': len(func_data.get('cycles', [])) > 0,
            'exit_nodes': len(func_data.get('exit_nodes', []))
        })
    
    return analysis

def _extract_complexity_indicators(functions):
    """Extract complexity indicators from CFG"""
    indicators = {
        'high_complexity_functions': [],
        'cyclic_functions': [],
        'multiple_exits': []
    }
    
    for func_name, func_data in functions.items():
        complexity = func_data.get('complexity', 0)
        cycles = func_data.get('cycles', [])
        exit_nodes = func_data.get('exit_nodes', [])
        
        if complexity > 10:
            indicators['high_complexity_functions'].append(func_name)
        
        if len(cycles) > 0:
            indicators['cyclic_functions'].append(func_name)
        
        if len(exit_nodes) > 1:
            indicators['multiple_exits'].append(func_name)
    
    return indicators

def _extract_vulnerability_patterns(functions):
    """Extract vulnerability patterns from PDG"""
    all_patterns = {
        'buffer_operations': [],
        'pointer_operations': [],
        'dangerous_functions': [],
        'unchecked_operations': []
    }
    
    for func_name, func_data in functions.items():
        patterns = func_data.get('patterns', {})
        
        for pattern_type, pattern_list in patterns.items():
            if pattern_type in all_patterns:
                for pattern in pattern_list:
                    pattern_copy = pattern.copy()
                    pattern_copy['function'] = func_name
                    all_patterns[pattern_type].append(pattern_copy)
    
    return all_patterns

def _analyze_dependencies(functions):
    """Analyze data dependencies"""
    dependency_analysis = {
        'total_dependencies': 0,
        'complex_dependencies': [],
        'variable_flow': []
    }
    
    for func_name, func_data in functions.items():
        dependencies = func_data.get('dependencies', [])
        dependency_analysis['total_dependencies'] += len(dependencies)
        
        # Find complex dependency chains
        if len(dependencies) > 5:
            dependency_analysis['complex_dependencies'].append({
                'function': func_name,
                'dependency_count': len(dependencies)
            })
    
    return dependency_analysis

# Test function
if __name__ == "__main__":
    # Mock data for testing
    mock_vulrag = {
        'CVE_id': 'CVE-2024-TEST',
        'vulnerability_behavior': 'Buffer overflow due to unchecked strcpy',
        'code_before_change': 'strcpy(buf, input);',
        'code_after_change': 'strncpy(buf, input, sizeof(buf)-1);',
        'solution': 'Use safe string functions'
    }
    
    mock_ast = {
        'success': True,
        'patterns': {
            'functions': [{'name': 'test_func', 'params': ['char*'], 'return_type': 'int'}],
            'calls': [{'function': 'strcpy', 'line': 5}]
        },
        'node_count': 50,
        'depth': 8
    }
    
    mock_cfg = {
        'success': True,
        'functions': {'test_func': {'complexity': 12, 'node_count': 8}},
        'global_stats': {'total_functions': 1}
    }
    
    mock_pdg = {
        'success': True,
        'functions': {
            'test_func': {
                'patterns': {'dangerous_functions': [{'function': 'strcpy', 'line': 5}]},
                'vulnerability_indicators': {'dangerous_funcs': 1}
            }
        },
        'global_stats': {'total_functions': 1}
    }
    
    result = create_hybrid_entry(mock_vulrag, mock_ast, mock_cfg, mock_pdg)
    print("Hybrid Entry Creation Test:")
    print(f"Original CVE: {result['original_vulrag']['CVE_id']}")
    print(f"AST available: {result['structural_analysis']['ast_patterns']['available']}")
    print(f"Complexity: {result['hybrid_insights']['code_complexity']}")
    print(f"Risk indicators: {result['hybrid_insights']['risk_indicators']}") 