#!/usr/bin/env python3
"""
Simple script to process a single raw file and create its hybrid KB
"""

import json
import sys
from pathlib import Path
import os

# Add src directory to path
sys.path.append(str(Path(__file__).parent.parent / "src"))

from extract_ast import extract_ast_patterns
from build_cfg import build_simple_cfg  
from build_pdg import build_simple_pdg
from config import DATA_ENRICHED_DIR, MESSAGES
from utils import extract_cwe_from_filename, safe_json_load, safe_json_save, get_file_stats

def process_single_file(raw_file_path):
    """Process a single raw file and create its hybrid KB"""
    
    raw_file = Path(raw_file_path)
    if not raw_file.exists():
        print(MESSAGES['file_not_found'].format(raw_file_path))
        return False
    
    # Extract CWE from filename robustly
    cwe = extract_cwe_from_filename(raw_file.name)
    if not cwe.startswith('CWE-'):
        print(MESSAGES['invalid_cwe'].format(cwe))
        return False
    
    print(f"🎯 Processing {raw_file.name} -> {cwe}")
    
    # Load data with secure error handling
    raw_data = safe_json_load(raw_file)
    if not isinstance(raw_data, dict):
        print(f"❌ Read error: {raw_data.get('error', 'Invalid format')}")
        return False
    
    print(f"✅ {len(raw_data)} entries loaded")
    
    # Process each entry
    enriched_entries = []
    
    for cve_id, entries in raw_data.items():
        print(f"📦 Processing {cve_id} ({len(entries)} entries)")
        
        for i, entry in enumerate(entries):
            print(f"   🔄 Entry {i+1}/{len(entries)}")
            
            # Extract vulnerable code
            vulnerable_code = entry.get('code_before_change', '')
            if not vulnerable_code:
                print(f"      ⚠️ No vulnerable code")
                continue
            
            # Enrich with structural analysis
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
            print(f"      ✅ Enriched")
    
    # Save hybrid KB
    output_path = DATA_ENRICHED_DIR / f"hybrid_kb_{cwe}.json"
    
    if safe_json_save(enriched_entries, output_path):
        # Get file statistics
        stats = get_file_stats(output_path)
        if stats.get('exists'):
            print(f"\n✅ Hybrid KB created: {output_path}")
            print(f"   Size: {stats['size_formatted']}")
            print(f"   Entries: {len(enriched_entries)}")
        else:
            print(f"\n✅ Hybrid KB created: {output_path}")
            print(f"   Entries: {len(enriched_entries)}")
        
        return True
    else:
        print(f"❌ Save error: {output_path}")
        return False

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python process_single_file.py <raw_file_path>")
        sys.exit(1)
    
    raw_file_path = sys.argv[1]
    success = process_single_file(raw_file_path)
    
    if not success:
        sys.exit(1) 