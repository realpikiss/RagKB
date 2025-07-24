#!/usr/bin/env python3
"""
Centralized configuration for the Vulnerability Knowledge Base project
Eliminates hard-coded values and centralizes configuration
"""

from pathlib import Path
from typing import List, Dict, Any

# =============================================================================
# FILE PATHS AND DIRECTORIES
# =============================================================================

# Data directories
DATA_RAW_DIR = Path("data/raw")
DATA_ENRICHED_DIR = Path("data/enriched")

# File patterns
RAW_FILE_PATTERN = "*.json"
ENRICHED_FILE_PATTERN = "hybrid_kb_CWE-*.json"

# =============================================================================
# TIMEOUT CONFIGURATION
# =============================================================================

# Timeouts for code analysis
AST_TIMEOUT_SECONDS = 5
CFG_TIMEOUT_SECONDS = 5
PDG_TIMEOUT_SECONDS = 10

# Timeout for batch processing
BATCH_PROCESSING_TIMEOUT_SECONDS = 300  # 5 minutes

# =============================================================================
# AST ANALYSIS CONFIGURATION
# =============================================================================

# Recursion limits
AST_MAX_DEPTH = 10
AST_ERROR_MESSAGE_LENGTH = 100

# =============================================================================
# CFG ANALYSIS CONFIGURATION
# =============================================================================

# Cyclomatic complexity thresholds
CFG_COMPLEXITY_HIGH_THRESHOLD = 10
CFG_COMPLEXITY_MEDIUM_THRESHOLD = 5

# =============================================================================
# PDG ANALYSIS CONFIGURATION
# =============================================================================

# High-risk security functions
HIGH_RISK_FUNCTIONS = [
    'gets',      # Buffer overflow
    'sprintf',   # Format string
    'strcpy',    # Buffer overflow
    'strcat',    # Buffer overflow
    'scanf',     # Format string
    'printf',    # Format string
    'fprintf',   # Format string
    'snprintf',  # Potentially dangerous if misused
    'vsnprintf', # Potentially dangerous if misused
]

# Memory management functions to monitor
MEMORY_MANAGEMENT_FUNCTIONS = [
    'malloc', 'free', 'calloc', 'realloc',
    'new', 'delete', 'new[]', 'delete[]'
]

# String manipulation functions to monitor
STRING_MANIPULATION_FUNCTIONS = [
    'strcpy', 'strcat', 'strncpy', 'strncat',
    'sprintf', 'snprintf', 'vsprintf', 'vsnprintf',
    'gets', 'fgets', 'scanf', 'fscanf'
]

# Combined list of all functions to monitor
TRACKED_FUNCTIONS = (
    HIGH_RISK_FUNCTIONS + 
    MEMORY_MANAGEMENT_FUNCTIONS + 
    STRING_MANIPULATION_FUNCTIONS
)

# =============================================================================
# VULNERABILITY PATTERNS
# =============================================================================

# Regex patterns to detect vulnerabilities
VULNERABILITY_PATTERNS = {
    'buffer_overflow': [
        r'strcpy\s*\([^,]+,\s*[^)]+\)',
        r'strcat\s*\([^,]+,\s*[^)]+\)',
        r'gets\s*\([^)]+\)',
    ],
    'format_string': [
        r'printf\s*\([^,]*"[^"]*%[^"]*"[^)]*\)',
        r'sprintf\s*\([^,]+,\s*[^,]*"[^"]*%[^"]*"[^)]*\)',
        r'fprintf\s*\([^,]+,\s*[^,]*"[^"]*%[^"]*"[^)]*\)',
    ],
    'null_pointer': [
        r'->\s*\w+\s*[^;]*;',  # Pointer access without check
        r'\*\s*\w+\s*[^;]*;',  # Dereferencing without check
    ],
    'memory_leak': [
        r'malloc\s*\([^)]+\)[^;]*;',
        r'calloc\s*\([^)]+\)[^;]*;',
        r'new\s+[^;]+[^;]*;',
    ]
}

# =============================================================================
# MESSAGE CONFIGURATION
# =============================================================================

# Error and information messages
MESSAGES = {
    'processing_start': "Starting file processing: {}",
    'processing_complete': "Processing completed: {}",
    'processing_error': "Error during processing: {}",
    'file_not_found': "File not found: {}",
    'invalid_cwe': "Invalid CWE extracted: {}",
    'timeout_error': "Timeout during analysis: {}",
    'parsing_error': "Parsing error: {}",
    'no_files_found': "No files found in: {}",
    'batch_complete': "Batch processing completed. {} files processed.",
    'batch_error': "Error during batch processing: {}"
}

# =============================================================================
# VALIDATION CONFIGURATION
# =============================================================================

# Valid CWE patterns
VALID_CWE_PATTERNS = [
    r'CWE-\d+',
    r'cwe-\d+',
]

# Supported file extensions
SUPPORTED_EXTENSIONS = ['.json', '.c', '.cpp', '.h', '.hpp']

# =============================================================================
# PERFORMANCE CONFIGURATION
# =============================================================================

# Memory and performance limits
MAX_FILE_SIZE_MB = 50
MAX_NODES_PER_AST = 10000
MAX_FUNCTIONS_PER_FILE = 1000

# =============================================================================
# CONFIGURATION UTILITIES
# =============================================================================

def get_raw_files() -> List[Path]:
    """Get all raw files according to configuration"""
    if not DATA_RAW_DIR.exists():
        return []
    return list(DATA_RAW_DIR.glob(RAW_FILE_PATTERN))

def get_enriched_files() -> List[Path]:
    """Get all enriched files according to configuration"""
    if not DATA_ENRICHED_DIR.exists():
        return []
    return list(DATA_ENRICHED_DIR.glob(ENRICHED_FILE_PATTERN))

def ensure_directories():
    """Create necessary directories if they don't exist"""
    DATA_RAW_DIR.mkdir(parents=True, exist_ok=True)
    DATA_ENRICHED_DIR.mkdir(parents=True, exist_ok=True)

def get_output_path(input_file: Path) -> Path:
    """Generate output path for an input file"""
    cwe = extract_cwe_from_filename(input_file.name)
    return DATA_ENRICHED_DIR / f"hybrid_kb_{cwe}.json"

def extract_cwe_from_filename(filename: str) -> str:
    """Extract CWE from filename with robust error handling"""
    import re
    
    # Try multiple patterns
    for pattern in VALID_CWE_PATTERNS:
        match = re.search(pattern, filename, re.IGNORECASE)
        if match:
            return match.group().upper()
    
    # Fallback: use filename without extension
    return Path(filename).stem 