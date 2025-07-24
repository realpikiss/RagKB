#!/usr/bin/env python3
"""
Common utilities for the Vulnerability Knowledge Base project
Centralizes repeated functions and common patterns
"""

import threading
import time
from typing import Dict, Any, Callable, List
from pathlib import Path
import json
import re

def timeout_wrapper(func: Callable, args: tuple, timeout_seconds: int) -> Dict[str, Any]:
    """
    Generic wrapper to execute a function with timeout
    
    Args:
        func: Function to execute
        args: Function arguments
        timeout_seconds: Timeout in seconds
        
    Returns:
        Function result or error dictionary
    """
    result = [None]
    exception = [None]
    
    def target():
        try:
            result[0] = func(*args)
        except Exception as e:
            exception[0] = e
    
    thread = threading.Thread(target=target)
    thread.daemon = True
    thread.start()
    thread.join(timeout_seconds)
    
    if thread.is_alive():
        return {'success': False, 'error': 'timeout'}
    elif exception[0]:
        return {'success': False, 'error': str(exception[0])}
    else:
        return result[0]

def safe_json_load(file_path: Path) -> Dict[str, Any]:
    """
    Load a JSON file securely
    
    Args:
        file_path: Path to the JSON file
        
    Returns:
        JSON data or error dictionary
    """
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            return json.load(f)
    except FileNotFoundError:
        return {'success': False, 'error': f'File not found: {file_path}'}
    except json.JSONDecodeError as e:
        return {'success': False, 'error': f'JSON error: {str(e)}'}
    except Exception as e:
        return {'success': False, 'error': f'Unexpected error: {str(e)}'}

def safe_json_save(data: Dict[str, Any], file_path: Path) -> bool:
    """
    Save JSON data securely
    
    Args:
        data: Data to save
        file_path: Destination path
        
    Returns:
        True if successful, False otherwise
    """
    try:
        # Create parent directory if necessary
        file_path.parent.mkdir(parents=True, exist_ok=True)
        
        with open(file_path, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        return True
    except Exception as e:
        print(f"Error saving {file_path}: {e}")
        return False

def extract_cwe_from_filename(filename: str) -> str:
    """
    Extract CWE from filename robustly
    
    Args:
        filename: Filename
        
    Returns:
        Extracted CWE or filename without extension
    """
    # Valid CWE patterns
    cwe_patterns = [
        r'CWE-\d+',
        r'cwe-\d+',
    ]
    
    for pattern in cwe_patterns:
        match = re.search(pattern, filename, re.IGNORECASE)
        if match:
            return match.group().upper()
    
    # Fallback: use filename without extension
    return Path(filename).stem

def validate_cwe_format(cwe: str) -> bool:
    """
    Validate CWE format
    
    Args:
        cwe: CWE string to validate
        
    Returns:
        True if valid format, False otherwise
    """
    return bool(re.match(r'^CWE-\d+$', cwe, re.IGNORECASE))

def safe_function_call(func: Callable, *args, **kwargs) -> Dict[str, Any]:
    """
    Call a function securely with error handling
    
    Args:
        func: Function to call
        *args: Positional arguments
        **kwargs: Named arguments
        
    Returns:
        Function result or error dictionary
    """
    try:
        result = func(*args, **kwargs)
        return {'success': True, 'result': result}
    except Exception as e:
        return {'success': False, 'error': str(e)}

def format_file_size(size_bytes: int) -> str:
    """
    Format file size in readable format
    
    Args:
        size_bytes: Size in bytes
        
    Returns:
        Formatted size (e.g., "1.5 MB")
    """
    for unit in ['B', 'KB', 'MB', 'GB']:
        if size_bytes < 1024.0:
            return f"{size_bytes:.1f} {unit}"
        size_bytes /= 1024.0
    return f"{size_bytes:.1f} TB"

def get_file_stats(file_path: Path) -> Dict[str, Any]:
    """
    Get file statistics
    
    Args:
        file_path: Path to the file
        
    Returns:
        File statistics
    """
    try:
        stat = file_path.stat()
        return {
            'size_bytes': stat.st_size,
            'size_formatted': format_file_size(stat.st_size),
            'modified_time': stat.st_mtime,
            'exists': True
        }
    except FileNotFoundError:
        return {'exists': False, 'error': 'File not found'}
    except Exception as e:
        return {'exists': False, 'error': str(e)}

def clean_error_message(error: str, max_length: int = 100) -> str:
    """
    Clean and truncate an error message
    
    Args:
        error: Original error message
        max_length: Maximum length
        
    Returns:
        Cleaned error message
    """
    if not error:
        return "Unknown error"
    
    # Clean problematic characters
    cleaned = str(error).strip()
    cleaned = re.sub(r'\s+', ' ', cleaned)  # Normalize spaces
    
    # Truncate if necessary
    if len(cleaned) > max_length:
        cleaned = cleaned[:max_length-3] + "..."
    
    return cleaned 