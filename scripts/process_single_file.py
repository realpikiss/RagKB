#!/usr/bin/env python3
"""
Script simple pour traiter un fichier raw et créer sa KB hybride
"""

import json
import sys
from pathlib import Path

# Ajouter le répertoire src au path
sys.path.append(str(Path(__file__).parent.parent / "src"))

from extract_ast import extract_ast_patterns
from build_cfg import build_simple_cfg  
from build_pdg import build_simple_pdg

def process_single_file(raw_file_path):
    """Traiter un fichier raw et créer sa KB hybride"""
    
    raw_file = Path(raw_file_path)
    if not raw_file.exists():
        print(f"❌ Fichier non trouvé: {raw_file_path}")
        return False
    
    # Extraire le CWE du nom de fichier
    filename = raw_file.stem  # sans extension
    if "CWE-" in filename:
        cwe = filename.split("CWE-")[1].split("_")[0]
        cwe = f"CWE-{cwe}"
    else:
        print(f"❌ CWE non trouvé dans le nom: {filename}")
        return False
    
    print(f"🎯 Traitement de {filename} -> {cwe}")
    
    # Charger les données
    try:
        with open(raw_file, 'r', encoding='utf-8') as f:
            raw_data = json.load(f)
    except Exception as e:
        print(f"❌ Erreur lecture: {e}")
        return False
    
    print(f"✅ {len(raw_data)} entrées chargées")
    
    # Traiter chaque entrée
    enriched_entries = []
    
    for cve_id, entries in raw_data.items():
        print(f"📦 Traitement de {cve_id} ({len(entries)} entrées)")
        
        for i, entry in enumerate(entries):
            print(f"   🔄 Entrée {i+1}/{len(entries)}")
            
            # Extraire le code vulnérable
            vulnerable_code = entry.get('code_before_change', '')
            if not vulnerable_code:
                print(f"      ⚠️ Pas de code vulnérable")
                continue
            
            # Enrichir avec les analyses structurelles
            enriched_entry = {
                'original_vulrag': entry,
                'structural_analysis': {
                    'ast_patterns': extract_ast_patterns(vulnerable_code),
                    'cfg_patterns': build_simple_cfg(vulnerable_code),
                    'pdg_patterns': build_simple_pdg(vulnerable_code)
                },
                '_metadata': {
                    'cve_id': cve_id,
                    'cwe_id': cwe,
                    'source_file': raw_file.name,
                    'instance_idx': i
                }
            }
            
            enriched_entries.append(enriched_entry)
            print(f"      ✅ Enrichie")
    
    # Sauvegarder la KB hybride
    output_dir = Path("data/enriched")
    output_dir.mkdir(exist_ok=True)
    
    output_path = output_dir / f"hybrid_kb_{cwe}.json"
    
    try:
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(enriched_entries, f, indent=2, ensure_ascii=False)
        
        file_size = output_path.stat().st_size / (1024 * 1024)  # MB
        print(f"\n✅ KB hybride créée: {output_path}")
        print(f"   Taille: {file_size:.1f} MB")
        print(f"   Entrées: {len(enriched_entries)}")
        
        return True
        
    except Exception as e:
        print(f"❌ Erreur sauvegarde: {e}")
        return False

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python process_single_file.py <fichier_raw>")
        print("Exemple: python process_single_file.py data/raw/gpt-4o-mini_CWE-119_316.json")
        sys.exit(1)
    
    raw_file = sys.argv[1]
    success = process_single_file(raw_file)
    
    if success:
        print(f"\n🎉 Traitement terminé avec succès!")
    else:
        print(f"\n❌ Échec du traitement")
        sys.exit(1) 