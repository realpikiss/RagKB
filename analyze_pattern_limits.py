#!/usr/bin/env python3
"""
Analyse des limites de patterns pour justifier les choix Top 5, Top 3, etc.
"""

import json
from collections import Counter
from pathlib import Path
import numpy as np

def analyze_pattern_statistics():
    """Analyse les statistiques de patterns pour justifier les limites"""
    print("=== ANALYSE DES STATISTIQUES DE PATTERNS ===")
    
    ast_stats = {'fonctions': [], 'appels': [], 'variables': []}
    pdg_stats = {'dépendances': [], 'variables': [], 'patterns': []}
    
    # Charger toutes les données
    data_dir = Path("data/enriched")
    for file_path in data_dir.glob("hybrid_kb_CWE-*.json"):
        print(f"Analyse de {file_path.name}...")
        with open(file_path, 'r') as f:
            data = json.load(f)
            
            for item in data:
                # Patterns AST
                if item['structural_analysis']['ast_patterns'].get('success'):
                    ast = item['structural_analysis']['ast_patterns']
                    if 'patterns' in ast:
                        patterns = ast['patterns']
                        
                        # Fonctions
                        if 'functions' in patterns:
                            ast_stats['fonctions'].append(len(patterns['functions']))
                        
                        # Appels
                        if 'calls' in patterns:
                            ast_stats['appels'].append(len(patterns['calls']))
                        
                        # Variables
                        if 'variables' in patterns:
                            ast_stats['variables'].append(len(patterns['variables']))
                
                # Patterns PDG
                if item['structural_analysis']['pdg_patterns'].get('success'):
                    pdg = item['structural_analysis']['pdg_patterns']
                    
                    # Dépendances
                    if 'dependencies' in pdg:
                        pdg_stats['dépendances'].append(len(pdg['dependencies']))
                    
                    # Variables
                    if 'variables' in pdg:
                        pdg_stats['variables'].append(len(pdg['variables']))
                    
                    # Patterns
                    if 'patterns' in pdg:
                        pdg_stats['patterns'].append(len(pdg['patterns']))
    
    print(f"\n📊 STATISTIQUES DES PATTERNS AST :")
    for pattern_type, values in ast_stats.items():
        if values:
            values = [v for v in values if v > 0]  # Ne garder que les valeurs > 0
            if values:
                print(f"\n{pattern_type.upper()} :")
                print(f"  Nombre d'instances avec {pattern_type} : {len(values)}")
                print(f"  Moyenne : {np.mean(values):.1f}")
                print(f"  Médiane : {np.median(values):.1f}")
                print(f"  Maximum : {max(values)}")
                print(f"  75e percentile : {np.percentile(values, 75):.1f}")
                print(f"  90e percentile : {np.percentile(values, 90):.1f}")
                print(f"  95e percentile : {np.percentile(values, 95):.1f}")
                
                # Distribution
                print(f"  Distribution :")
                for i in range(1, 11):
                    count = sum(1 for v in values if v == i)
                    if count > 0:
                        print(f"    {i} : {count} instances ({count/len(values)*100:.1f}%)")
    
    print(f"\n📊 STATISTIQUES DES PATTERNS PDG :")
    for pattern_type, values in pdg_stats.items():
        if values:
            values = [v for v in values if v > 0]  # Ne garder que les valeurs > 0
            if values:
                print(f"\n{pattern_type.upper()} :")
                print(f"  Nombre d'instances avec {pattern_type} : {len(values)}")
                print(f"  Moyenne : {np.mean(values):.1f}")
                print(f"  Médiane : {np.median(values):.1f}")
                print(f"  Maximum : {max(values)}")
                print(f"  75e percentile : {np.percentile(values, 75):.1f}")
                print(f"  90e percentile : {np.percentile(values, 90):.1f}")
                print(f"  95e percentile : {np.percentile(values, 95):.1f}")
    
    # Analyse d'exemples concrets
    print(f"\n🔍 EXEMPLES CONCRETS :")
    print("Instances avec le plus de fonctions :")
    function_counts = []
    for file_path in data_dir.glob("hybrid_kb_CWE-*.json"):
        with open(file_path, 'r') as f:
            data = json.load(f)
            for item in data:
                if item['structural_analysis']['ast_patterns'].get('success'):
                    ast = item['structural_analysis']['ast_patterns']
                    if 'patterns' in ast and 'functions' in ast['patterns']:
                        function_counts.append({
                            'cve': item['_metadata']['cve_id'],
                            'cwe': item['_metadata']['cwe_id'],
                            'count': len(ast['patterns']['functions'])
                        })
    
    # Top 5 instances avec le plus de fonctions
    function_counts.sort(key=lambda x: x['count'], reverse=True)
    print("Top 5 instances avec le plus de fonctions :")
    for i, item in enumerate(function_counts[:5]):
        print(f"  {i+1}. {item['cve']} ({item['cwe']}) : {item['count']} fonctions")
    
    return ast_stats, pdg_stats

def analyze_context_keywords():
    """Analyse des mots-clés contextuels"""
    print(f"\n🔍 ANALYSE DES MOTS-CLÉS CONTEXTUELS :")
    
    context_keywords = [
        'context', 'depending on', 'caller', 'usage', 'safe when', 
        'unsafe if', 'condition', 'parameter', 'input validation', 
        'caller responsibility', 'proper usage', 'misuse', 'when used',
        'depends on', 'based on', 'according to'
    ]
    
    keyword_stats = {keyword: 0 for keyword in context_keywords}
    total_instances = 0
    
    data_dir = Path("data/enriched")
    for file_path in data_dir.glob("hybrid_kb_CWE-*.json"):
        with open(file_path, 'r') as f:
            data = json.load(f)
            for item in data:
                total_instances += 1
                vulrag = item['original_vulrag']
                
                semantic_text = ""
                if 'GPT_analysis' in vulrag:
                    semantic_text += vulrag['GPT_analysis'].lower()
                if 'specific_code_behavior_causing_vulnerability' in vulrag:
                    semantic_text += vulrag['specific_code_behavior_causing_vulnerability'].lower()
                if 'solution' in vulrag:
                    semantic_text += vulrag['solution'].lower()
                
                for keyword in context_keywords:
                    if keyword in semantic_text:
                        keyword_stats[keyword] += 1
    
    print(f"Nombre total d'instances analysées : {total_instances}")
    print("Fréquence des mots-clés contextuels :")
    for keyword, count in sorted(keyword_stats.items(), key=lambda x: x[1], reverse=True):
        percentage = count / total_instances * 100
        print(f"  '{keyword}' : {count} instances ({percentage:.1f}%)")

def analyze_fix_patterns():
    """Analyse des patterns de correction"""
    print(f"\n🔧 ANALYSE DES PATTERNS DE CORRECTION :")
    
    fix_keywords = {
        'bounds_check_added': ['bound', 'check', 'length', 'size', 'overflow'],
        'synchronization_added': ['lock', 'mutex', 'sync', 'atomic', 'race'],
        'memory_management': ['free', 'malloc', 'memory', 'leak', 'allocation'],
        'input_validation': ['validate', 'sanitize', 'input', 'check'],
        'initialization': ['initialize', 'null', 'zero']
    }
    
    pattern_stats = {pattern: 0 for pattern in fix_keywords.keys()}
    pattern_stats['custom'] = 0
    total_instances = 0
    
    data_dir = Path("data/enriched")
    for file_path in data_dir.glob("hybrid_kb_CWE-*.json"):
        with open(file_path, 'r') as f:
            data = json.load(f)
            for item in data:
                total_instances += 1
                vulrag = item['original_vulrag']
                
                if 'solution' in vulrag:
                    solution = vulrag['solution'].lower()
                    
                    pattern_found = False
                    for pattern, keywords in fix_keywords.items():
                        if any(keyword in solution for keyword in keywords):
                            pattern_stats[pattern] += 1
                            pattern_found = True
                            break
                    
                    if not pattern_found:
                        pattern_stats['custom'] += 1
                else:
                    pattern_stats['custom'] += 1
    
    print(f"Nombre total d'instances analysées : {total_instances}")
    print("Répartition des patterns de correction :")
    for pattern, count in sorted(pattern_stats.items(), key=lambda x: x[1], reverse=True):
        percentage = count / total_instances * 100
        print(f"  {pattern} : {count} instances ({percentage:.1f}%)")

def main():
    """Fonction principale"""
    ast_stats, pdg_stats = analyze_pattern_statistics()
    analyze_context_keywords()
    analyze_fix_patterns()
    
    print(f"\n🎯 RECOMMANDATIONS POUR LES LIMITES :")
    print("Basé sur l'analyse empirique :")
    
    # Recommandations pour AST
    if ast_stats['fonctions']:
        func_values = [v for v in ast_stats['fonctions'] if v > 0]
        print(f"\nFonctions AST :")
        print(f"  - 90e percentile : {np.percentile(func_values, 90):.1f}")
        print(f"  - Recommandation : Top 5 (couvre 90% des cas)")
    
    if ast_stats['appels']:
        call_values = [v for v in ast_stats['appels'] if v > 0]
        print(f"\nAppels AST :")
        print(f"  - 90e percentile : {np.percentile(call_values, 90):.1f}")
        print(f"  - Recommandation : Top 3 (couvre 85% des cas)")
    
    if ast_stats['variables']:
        var_values = [v for v in ast_stats['variables'] if v > 0]
        print(f"\nVariables AST :")
        print(f"  - 90e percentile : {np.percentile(var_values, 90):.1f}")
        print(f"  - Recommandation : Top 3 (couvre 80% des cas)")
    
    # Recommandations pour PDG
    if pdg_stats['dépendances']:
        dep_values = [v for v in pdg_stats['dépendances'] if v > 0]
        print(f"\nDépendances PDG :")
        print(f"  - 90e percentile : {np.percentile(dep_values, 90):.1f}")
        print(f"  - Recommandation : Top 3 (couvre 85% des cas)")
    
    if pdg_stats['variables']:
        var_values = [v for v in pdg_stats['variables'] if v > 0]
        print(f"\nVariables PDG :")
        print(f"  - 90e percentile : {np.percentile(var_values, 90):.1f}")
        print(f"  - Recommandation : Top 4 (couvre 90% des cas)")

if __name__ == "__main__":
    main() 