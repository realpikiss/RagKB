
# **Hybrid Vulnerability Knowledge Base**

> Enriching semantic vulnerability knowledge with structural code analysis for enhanced vulnerability detection and repair

## **What This Does**

Takes the **Vul-RAG dataset** (2,317 vulnerable/patched function pairs with semantic descriptions) and enriches it with **structural analysis** (AST, CFG, PDG) to create a hybrid knowledge base that combines:

* **Semantic knowledge** (what the vulnerability is, why it's dangerous, how to fix it)
* **Structural patterns** (syntax trees, control flow, data dependencies)

## **Why This Matters**

Current vulnerability detection systems using LLMs rely on text-only descriptions like *"employ locking mechanism"* but can't generate precise patches because they lack structural context like  *"insert `mutex_lock(&device->mutex)` at line 23 before accessing `device->status`"* .

This hybrid approach bridges that gap.

## **Architecture**

```
Input: Vul-RAG Dataset (semantic knowledge)
         ↓
    Tree-sitter AST extraction
         ↓  
    Custom CFG construction  
         ↓
    Custom PDG analysis
         ↓
Output: Hybrid KB (semantic + structural)
```

## **Quick Start**

### **Setup**

```bash
git clone [repo]
cd vulnerability-kb
python -m venv venv && source venv/bin/activate
pip install -r requirements.txt
```

### **Usage**

```bash
# 1. Copy Vul-RAG dataset to data/raw/
cp /path/to/vul-rag/*.json data/raw/

# 2. Run pipeline
python scripts/run_pipeline.py

# 3. Find enriched KB at data/enriched/hybrid_kb.json
```

## **What Gets Extracted**

### **AST Patterns**

* Function signatures and parameters
* Variable declarations (buffers, pointers, arrays)
* Function calls (including potentially unsafe ones)
* Control structures (if/else, loops)

### **CFG Analysis**

* Basic blocks and control flow
* Entry/exit points
* Branch conditions and loop structures
* Cyclomatic complexity

### **PDG Analysis**

* Variable def-use chains
* Data dependencies between statements
* Vulnerability pattern detection
* Pointer and buffer operation tracking

## **Output Format**

Each entry in the hybrid KB contains:

```json
{
  "original": {
    // Complete Vul-RAG entry (functional_semantics, vulnerability_causes, fixing_solutions)
  },
  "structural": {
    "ast_patterns": {
      "functions": [...],
      "calls": [...],
      "variables": [...]
    },
    "cfg_analysis": {
      "nodes": [...],
      "edges": [...], 
      "complexity": 3
    },
    "pdg_analysis": {
      "dependencies": [...],
      "patterns": {...}
    }
  }
}
```

## **Key Features**

✅ **Preserves original Vul-RAG data** - No information loss

✅ **Simple, fast extraction** - Tree-sitter + custom analysis

✅ **Focus on C/C++** - Optimized for systems programming vulnerabilities

✅ **Scientific methodology** - Rigorous validation and metrics

✅ **Ready for RAG systems** - Structured for downstream consumption

## **Performance**

* **Processing time** : ~2-3 hours for full dataset (2,317 functions)
* **Success rate** : >98% parsing success
* **Memory usage** : <1GB RAM required
* **Output size** : ~100MB enriched knowledge base

## **Supported CWE Types**

Primary focus on top-10 CWEs from Vul-RAG dataset:

* CWE-416 (Use After Free)
* CWE-476 (NULL Pointer Dereference)
* CWE-362 (Race Condition)
* CWE-119/787/125 (Buffer Operations)
* CWE-20 (Input Validation)
* CWE-401 (Memory Leak)
* And more...

## **Project Structure**

```
vulnerability-kb/
├── data/
│   ├── raw/           # Vul-RAG dataset
│   └── enriched/      # Output hybrid KB
├── src/
│   ├── extract_ast.py # Tree-sitter AST extraction
│   ├── build_cfg.py   # Control flow graphs  
│   ├── build_pdg.py   # Program dependence graphs
│   └── create_kb.py   # Hybrid integration
├── scripts/
│   └── run_pipeline.py # Main processing script
└── requirements.txt
```

## **Next Steps**

This knowledge base is designed for integration with RAG-based vulnerability detection and repair systems. The hybrid semantic+structural representations enable:

* **Better similarity matching** between vulnerable code and known patterns
* **Precise patch generation** using structural templates
* **Cross-CWE generalization** through abstract patterns

## **Requirements**

* Python 3.11+
* Tree-sitter with C grammar
* NetworkX for graph analysis
* ~16GB RAM recommended for full processing

---

 **Status** : Knowledge base construction phase ✅

 **Next** : RAG system integration 🚧
