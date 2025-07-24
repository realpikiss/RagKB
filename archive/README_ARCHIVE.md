# Archive of Original Scripts Used in Empirical Analysis

## Purpose

This archive preserves the **original scripts and modules** that were used during the 5-phase empirical analysis of the Hybrid Vulnerability Knowledge Base project.

## Why This Archive Exists

For **scientific reproducibility** and **methodological transparency**, we preserve the exact versions of scripts that were used to generate the empirical findings documented in notebooks 01-05.

## What's Archived

### `src_original/` - Original Source Modules

These are the modules that were **actively used** during the empirical analysis phases:

- **`extract_ast.py`** - AST extraction module (refactored version, critical for Phase 2-4)
- **`build_cfg.py`** - CFG construction module (evaluated in Phase 4)
- **`build_pdg.py`** - PDG construction module (validated in Phase 4)
- **`config.py`** - Original configuration (replaced by empirically-derived version)
- **`utils.py`** - Utility functions used across all phases
- **`create_kb.py`** - Knowledge base creation logic (removed from production)
- **`__init__.py`** - Package initialization

### `scripts_original/` - Original Processing Scripts

- **`process_single_file.py`** - Single file processing script
- **`process_all_files.py`** - Batch processing script
- **`show_stats.py`** - Statistics display script

## Analysis Results Summary

Based on the empirical analysis using these original scripts:

### Performance Results (Phase 2)

- **Processing Speed**: 0.003s per instance (5,750x faster than estimated)
- **Success Rate**: 100% across all 2,317 samples
- **Memory Usage**: 0.02 MB per instance

### Architecture Decision (Phase 4)

- **Recommendation**: AST + PDG (skip CFG)
- **Reasoning**: CFG showed 0% complex control flow, PDG showed 66.2% data dependencies
- **Efficiency Gain**: 31% improvement by skipping CFG

### Context Analysis (Phase 3)

- **Optimal Context Window**: 5 lines
- **Context-dependent Functions**: 3,407 identified
- **Approach Validation**: Context-based analysis superior to function blacklists

## Current Status

After the empirical analysis, the production configuration was generated with:

- Empirically-derived timeouts (5s for AST/PDG)
- Validated architecture (AST + PDG only)
- Context-aware patterns (5-line window)
- 100% success rate validation

## Files Generated from This Analysis

The original scripts in this archive were used to generate:

- `vulrag_summary_report.json` (Phase 1)
- `performance_summary_report.json` (Phase 2)
- `context_based_analysis_config.json` (Phase 3)
- `architecture_decision.json` (Phase 4)
- `final_empirical_configuration.json` (Phase 5)

## Scientific Principle

> **All configuration parameters in the final system are empirically justified from measurements made using these archived scripts.**

No arbitrary values remain in the production configuration.

---

**Archive Date**: July 24, 2025
**Project Status**: Empirical analysis completed, production configuration generated
**Total Samples Analyzed**: 2,317 vulnerability instances
**Validation Status**: 100% success rate achieved
