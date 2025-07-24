#!/usr/bin/env python3
"""
Script pour traiter automatiquement tous les fichiers raw
"""

import glob
import subprocess
import sys
from pathlib import Path

def process_all_raw_files():
    """Traiter tous les fichiers raw du dossier data/raw"""
    
    raw_dir = Path("data/raw")
    if not raw_dir.exists():
        print("❌ Dossier data/raw non trouvé!")
        return False
    
    # Trouver tous les fichiers JSON
    raw_files = glob.glob(str(raw_dir / "*.json"))
    
    if not raw_files:
        print("❌ Aucun fichier JSON trouvé dans data/raw!")
        return False
    
    print(f"📁 {len(raw_files)} fichiers trouvés")
    
    # Traiter chaque fichier
    success_count = 0
    failed_files = []
    
    for raw_file in sorted(raw_files):
        print(f"\n{'='*60}")
        print(f"🎯 Traitement de {Path(raw_file).name}")
        print(f"{'='*60}")
        
        try:
            # Lancer le script de traitement
            result = subprocess.run([
                sys.executable, "scripts/process_single_file.py", raw_file
            ], capture_output=True, text=True, timeout=300)  # 5 minutes timeout
            
            if result.returncode == 0:
                print("✅ Succès")
                success_count += 1
            else:
                print(f"❌ Échec: {result.stderr}")
                failed_files.append(raw_file)
                
        except subprocess.TimeoutExpired:
            print("⏰ Timeout (5 minutes)")
            failed_files.append(raw_file)
        except Exception as e:
            print(f"❌ Erreur: {e}")
            failed_files.append(raw_file)
    
    # Résumé
    print(f"\n{'='*60}")
    print(f"📊 RÉSUMÉ FINAL")
    print(f"{'='*60}")
    print(f"✅ Fichiers traités avec succès: {success_count}/{len(raw_files)}")
    
    if failed_files:
        print(f"❌ Fichiers en échec:")
        for failed_file in failed_files:
            print(f"   • {Path(failed_file).name}")
    
    return success_count == len(raw_files)

if __name__ == "__main__":
    print("=" * 60)
    print("🚀 TRAITEMENT AUTOMATIQUE DE TOUS LES FICHIERS")
    print("=" * 60)
    
    success = process_all_raw_files()
    
    if success:
        print(f"\n🎉 Tous les fichiers ont été traités avec succès!")
    else:
        print(f"\n⚠️ Certains fichiers ont échoué")
        sys.exit(1) 