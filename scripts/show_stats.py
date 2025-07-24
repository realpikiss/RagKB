#!/usr/bin/env python3
"""
Script pour afficher les statistiques des KB créées
"""

import json
import glob
from pathlib import Path

def show_kb_stats():
    """Afficher les statistiques des KB créées"""
    
    enriched_dir = Path("data/enriched")
    kb_files = glob.glob(str(enriched_dir / "hybrid_kb_CWE-*.json"))
    
    if not kb_files:
        print("❌ Aucune KB trouvée!")
        return
    
    print("=" * 80)
    print("📊 STATISTIQUES DES KB HYBRIDES")
    print("=" * 80)
    
    total_entries = 0
    total_size = 0
    
    for kb_file in sorted(kb_files):
        try:
            with open(kb_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            file_size = Path(kb_file).stat().st_size / (1024 * 1024)  # MB
            entry_count = len(data)
            
            # Statistiques des graphes
            ast_success = 0
            cfg_success = 0
            pdg_success = 0
            
            for entry in data:
                structural = entry.get('structural_analysis', {})
                
                # Vérifier AST
                ast_data = structural.get('ast_patterns', {})
                if ast_data.get('success', False):
                    ast_success += 1
                
                # Vérifier CFG
                cfg_data = structural.get('cfg_patterns', {})
                if cfg_data.get('success', False):
                    cfg_success += 1
                
                # Vérifier PDG
                pdg_data = structural.get('pdg_patterns', {})
                if pdg_data.get('success', False):
                    pdg_success += 1
            
            cwe = Path(kb_file).stem.split('_')[-1]  # extraire CWE du nom de fichier
            
            print(f"\n🎯 {cwe}:")
            print(f"   📁 Fichier: {Path(kb_file).name}")
            print(f"   📊 Entrées: {entry_count}")
            print(f"   💾 Taille: {file_size:.1f} MB")
            print(f"   🌳 AST réussi: {ast_success}/{entry_count} ({ast_success/entry_count*100:.1f}%)")
            print(f"   🔗 CFG réussi: {cfg_success}/{entry_count} ({cfg_success/entry_count*100:.1f}%)")
            print(f"   📈 PDG réussi: {pdg_success}/{entry_count} ({pdg_success/entry_count*100:.1f}%)")
            
            total_entries += entry_count
            total_size += file_size
            
        except Exception as e:
            print(f"❌ Erreur lecture {kb_file}: {e}")
    
    print(f"\n{'='*80}")
    print(f"📈 RÉSUMÉ GLOBAL")
    print(f"{'='*80}")
    print(f"📊 Total entrées: {total_entries}")
    print(f"💾 Taille totale: {total_size:.1f} MB")
    print(f"📁 Fichiers KB: {len(kb_files)}")

if __name__ == "__main__":
    show_kb_stats() 