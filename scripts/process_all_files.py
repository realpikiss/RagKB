#!/usr/bin/env python3
"""
Script to automatically process all raw files
"""

import glob
import subprocess
import sys
from pathlib import Path
import os

# Add src directory to path for config import
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'src'))

from config import (
    DATA_RAW_DIR, 
    RAW_FILE_PATTERN, 
    BATCH_PROCESSING_TIMEOUT_SECONDS,
    MESSAGES
)

def process_all_raw_files():
    """Process all raw files in the data/raw directory"""
    
    if not DATA_RAW_DIR.exists():
        print(MESSAGES['file_not_found'].format(DATA_RAW_DIR))
        return False
    
    # Find all JSON files
    raw_files = glob.glob(str(DATA_RAW_DIR / RAW_FILE_PATTERN))
    
    if not raw_files:
        print(MESSAGES['no_files_found'].format(DATA_RAW_DIR))
        return False
    
    print(f"📁 {len(raw_files)} files found")
    
    # Process each file
    success_count = 0
    failed_files = []
    
    for raw_file in sorted(raw_files):
        print(f"\n{'='*60}")
        print(f"🎯 Processing {Path(raw_file).name}")
        print(f"{'='*60}")
        
        try:
            # Launch processing script
            result = subprocess.run([
                sys.executable, "scripts/process_single_file.py", raw_file
            ], capture_output=True, text=True, timeout=BATCH_PROCESSING_TIMEOUT_SECONDS)
            
            if result.returncode == 0:
                print("✅ Success")
                success_count += 1
            else:
                print(f"❌ Failed: {result.stderr}")
                failed_files.append(raw_file)
                
        except subprocess.TimeoutExpired:
            print(f"⏰ Timeout ({BATCH_PROCESSING_TIMEOUT_SECONDS} seconds)")
            failed_files.append(raw_file)
        except Exception as e:
            print(f"❌ Error: {e}")
            failed_files.append(raw_file)
    
    # Summary
    print(f"\n{'='*60}")
    print(f"📊 FINAL SUMMARY")
    print(f"{'='*60}")
    print(MESSAGES['batch_complete'].format(success_count))
    
    if failed_files:
        print(f"❌ Failed files:")
        for failed_file in failed_files:
            print(f"   • {Path(failed_file).name}")
    
    return success_count == len(raw_files)

if __name__ == "__main__":
    print("=" * 60)
    print("🚀 AUTOMATIC PROCESSING OF ALL FILES")
    print("=" * 60)
    
    success = process_all_raw_files()
    
    if success:
        print(f"\n🎉 All files processed successfully!")
    else:
        print(f"\n⚠️ Some files failed")
        sys.exit(1) 