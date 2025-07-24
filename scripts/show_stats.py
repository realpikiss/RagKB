#!/usr/bin/env python3
"""
Script to display statistics for created knowledge bases
"""

import json
import glob
from pathlib import Path
import sys
import os

# Add src directory to path for config import
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'src'))

from config import DATA_ENRICHED_DIR, ENRICHED_FILE_PATTERN, MESSAGES

def show_kb_stats():
    """Display statistics for created knowledge bases"""
    
    kb_files = glob.glob(str(DATA_ENRICHED_DIR / ENRICHED_FILE_PATTERN))
    
    if not kb_files:
        print(MESSAGES['no_files_found'].format(DATA_ENRICHED_DIR))
        return
    
    print("=" * 80)
    print("📊 HYBRID KB STATISTICS")
    print("=" * 80)
    
    total_entries = 0
    total_size = 0
    
    for kb_file in sorted(kb_files):
        try:
            with open(kb_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            file_size = Path(kb_file).stat().st_size / (1024 * 1024)  # MB
            entry_count = len(data)
            
            # Graph statistics
            ast_success = 0
            cfg_success = 0
            pdg_success = 0
            
            for entry in data:
                structural = entry.get('structural_analysis', {})
                
                # Check AST
                ast_data = structural.get('ast_patterns', {})
                if ast_data.get('success', False):
                    ast_success += 1
                
                # Check CFG
                cfg_data = structural.get('cfg_patterns', {})
                if cfg_data.get('success', False):
                    cfg_success += 1
                
                # Check PDG
                pdg_data = structural.get('pdg_patterns', {})
                if pdg_data.get('success', False):
                    pdg_success += 1
            
            cwe = Path(kb_file).stem.split('_')[-1]  # extract CWE from filename
            
            print(f"\n🎯 {cwe}:")
            print(f"   📁 File: {Path(kb_file).name}")
            print(f"   📊 Entries: {entry_count}")
            print(f"   💾 Size: {file_size:.1f} MB")
            print(f"   🌳 AST success: {ast_success}/{entry_count} ({ast_success/entry_count*100:.1f}%)")
            print(f"   🔗 CFG success: {cfg_success}/{entry_count} ({cfg_success/entry_count*100:.1f}%)")
            print(f"   📈 PDG success: {pdg_success}/{entry_count} ({pdg_success/entry_count*100:.1f}%)")
            
            total_entries += entry_count
            total_size += file_size
            
        except Exception as e:
            print(f"❌ Error reading {kb_file}: {e}")
    
    print(f"\n{'='*80}")
    print(f"📈 GLOBAL SUMMARY")
    print(f"{'='*80}")
    print(f"📊 Total entries: {total_entries}")
    print(f"💾 Total size: {total_size:.1f} MB")
    print(f"📁 KB files: {len(kb_files)}")

if __name__ == "__main__":
    show_kb_stats() 