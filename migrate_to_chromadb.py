#!/usr/bin/env python3
"""
Migration of the hybrid knowledge base to ChromaDB
"""

import json
import chromadb
from pathlib import Path
from collections import defaultdict, Counter
import logging
from tqdm import tqdm
import time

# Logging configuration
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class ChromaDBMigrator:
    """Class for migrating data to ChromaDB"""
    
    def __init__(self, db_path="./data/chromadb"):
        """Initialize the ChromaDB migrator"""
        self.db_path = Path(db_path)
        self.client = None
        self.collection = None
        self.migration_stats = {
            'total_instances': 0,
            'successful_migrations': 0,
            'failed_migrations': 0,
            'processing_time': 0,
            'cwe_distribution': Counter(),
            'fix_patterns': Counter(),
            'context_dependent_count': 0
        }
    
    def initialize_chromadb(self):
        """Initialize ChromaDB and create the collection"""
        logger.info("Initializing ChromaDB...")
        
        try:
            # Create the persistent client
            self.client = chromadb.PersistentClient(path=str(self.db_path))
            
            # Create or get the collection
            self.collection = self.client.get_or_create_collection(
                name="vulnrag_hybrid",
                metadata={
                    "description": "Empirically validated hybrid vulnerability knowledge base",
                    "instances": 2317,
                    "source": "hybrid_vulnerability_kb_research",
                    "architecture": "AST + PDG (CFG disabled)",
                    "empirical_validation": True,
                    "created_date": time.strftime("%Y-%m-%d %H:%M:%S")
                }
            )
            
            logger.info(f"✅ ChromaDB collection created: {self.collection.name}")
            logger.info(f"📁 Database: {self.db_path}")
            
            return True
            
        except Exception as e:
            logger.error(f"❌ Error during ChromaDB initialization: {e}")
            return False
    
    def load_hybrid_data(self):
        """Load all hybrid data"""
        logger.info("Loading hybrid data...")
        
        data_dir = Path("data/enriched")
        all_data = []
        
        for file_path in tqdm(list(data_dir.glob("hybrid_kb_CWE-*.json")), desc="Loading files"):
            try:
                with open(file_path, 'r') as f:
                    data = json.load(f)
                    all_data.extend(data)
                    logger.debug(f"Loaded {len(data)} instances from {file_path.name}")
            except Exception as e:
                logger.error(f"❌ Error loading {file_path}: {e}")
        
        self.migration_stats['total_instances'] = len(all_data)
        logger.info(f"✅ {len(all_data)} instances loaded")
        
        return all_data
    
    def summarize_ast_patterns(self, ast_patterns):
        """Converts AST analysis to searchable text summary"""
        if not ast_patterns or not ast_patterns.get('success'):
            return "No AST patterns detected"
        
        summary_parts = []
        
        # Function signatures (optimized based on empirical analysis)
        if ast_patterns.get('patterns', {}).get('functions'):
            functions = ast_patterns['patterns']['functions'][:2]  # Top 2 (99.9% of cases)
            func_names = [f['name'] for f in functions]
            summary_parts.append(f"Functions: {', '.join(func_names)}")
        
        # Dangerous calls (optimized based on empirical analysis)
        if ast_patterns.get('patterns', {}).get('calls'):
            calls = ast_patterns['patterns']['calls'][:10]  # Top 10 (covers 90% of cases)
            call_names = [c['function'] for c in calls]
            summary_parts.append(f"Function calls: {', '.join(call_names)}")
        
        # Variable types (optimized based on empirical analysis)
        if ast_patterns.get('patterns', {}).get('variables'):
            variables = ast_patterns['patterns']['variables'][:8]  # Top 8 (covers 85% of cases)
            var_names = []
            for var in variables:
                if isinstance(var, dict) and 'name' in var:
                    var_names.append(var['name'])
                elif isinstance(var, str):
                    var_names.append(var)
            if var_names:
                summary_parts.append(f"Variables: {', '.join(var_names)}")
        
        return ". ".join(summary_parts) if summary_parts else "Basic AST structure detected"
    
    def summarize_pdg_patterns(self, pdg_patterns):
        """Converts PDG analysis to searchable text summary"""
        if not pdg_patterns or not pdg_patterns.get('success'):
            return "No PDG patterns detected"
        
        summary_parts = []
        
        # Data dependencies (optimized based on empirical analysis)
        if pdg_patterns.get('dependencies'):
            deps = pdg_patterns['dependencies'][:5]  # Top 5 (more dependencies)
            summary_parts.append(f"Data dependencies: {', '.join(deps)}")
        
        # Variable relations (optimized based on empirical analysis)
        if pdg_patterns.get('variables'):
            vars_list = pdg_patterns['variables'][:6]  # Top 6 (covers more cases)
            summary_parts.append(f"Key variables: {', '.join(vars_list)}")
        
        # Pattern types
        if pdg_patterns.get('patterns'):
            patterns = pdg_patterns['patterns']
            pattern_desc = []
            for pattern_type, count in patterns.items():
                pattern_desc.append(f"{pattern_type}: {count}")
            if pattern_desc:
                summary_parts.append(f"Patterns: {', '.join(pattern_desc)}")
        
        return ". ".join(summary_parts) if summary_parts else "Basic PDG structure detected"
    
    def transform_for_chromadb(self, item):
        """Transform an item for ChromaDB"""
        
        try:
            # Create document text
            vulrag = item['original_vulrag']
            structural = item['structural_analysis']
            
            # Ultra-rich semantic text
            semantic_parts = []
            if 'GPT_analysis' in vulrag:
                semantic_parts.append(f"ANALYSIS: {vulrag['GPT_analysis']}")
            if 'specific_code_behavior_causing_vulnerability' in vulrag:
                semantic_parts.append(f"BEHAVIOR: {vulrag['specific_code_behavior_causing_vulnerability']}")
            if 'solution' in vulrag:
                semantic_parts.append(f"SOLUTION: {vulrag['solution']}")
            if 'preconditions_for_vulnerability' in vulrag:
                semantic_parts.append(f"PRECONDITIONS: {vulrag['preconditions_for_vulnerability']}")
            if 'trigger_condition' in vulrag:
                semantic_parts.append(f"TRIGGER_CONDITION: {vulrag['trigger_condition']}")
            if 'GPT_purpose' in vulrag:
                semantic_parts.append(f"FUNCTION_PURPOSE: {vulrag['GPT_purpose']}")
            if 'GPT_function' in vulrag:
                semantic_parts.append(f"FUNCTIONALITIES: {vulrag['GPT_function']}")
            
            # Source code before/after
            if 'code_before_change' in vulrag:
                semantic_parts.append(f"CODE_BEFORE_FIX:\n{vulrag['code_before_change']}")
            if 'code_after_change' in vulrag:
                semantic_parts.append(f"CODE_AFTER_FIX:\n{vulrag['code_after_change']}")
            
            # Modified lines
            if 'modified_lines' in vulrag:
                modified = vulrag['modified_lines']
                added_lines = modified.get('added', [])
                deleted_lines = modified.get('deleted', [])
                if added_lines or deleted_lines:
                    semantic_parts.append(f"MODIFIED_LINES:\nAdded: {added_lines}\nDeleted: {deleted_lines}")
            
            # Structural text with new functions
            structural_parts = []
            if structural['ast_patterns'].get('success'):
                ast_summary = self.summarize_ast_patterns(structural['ast_patterns'])
                structural_parts.append(f"AST_PATTERNS: {ast_summary}")
            
            if structural['pdg_patterns'].get('success'):
                pdg_summary = self.summarize_pdg_patterns(structural['pdg_patterns'])
                structural_parts.append(f"PDG_PATTERNS: {pdg_summary}")
            
            # Combine all parts
            document_text = "\n\n".join(semantic_parts + structural_parts)
            
            # Ultra-rich metadata
            metadata = {
                'cve_id': item['_metadata']['cve_id'],
                'cwe_id': item['_metadata']['cwe_id'],
                'context_dependent': self.determine_context_dependency(item),
                'fix_pattern': self.extract_fix_pattern(vulrag.get('solution', '')),
                'structural_complexity': self.calculate_structural_complexity(structural),
                'empirical_validated': True,
                'dataset_source': 'hybrid_vulnerability_kb',
                'source_file': item['_metadata'].get('source_file', ''),
                'instance_idx': item['_metadata'].get('instance_idx', 0),
                'has_code_before': 'code_before_change' in vulrag,
                'has_code_after': 'code_after_change' in vulrag,
                'has_modified_lines': 'modified_lines' in vulrag,
                'code_length_before': len(vulrag.get('code_before_change', '')),
                'code_length_after': len(vulrag.get('code_after_change', '')),
                'lines_added': len(vulrag.get('modified_lines', {}).get('added', [])),
                'lines_deleted': len(vulrag.get('modified_lines', {}).get('deleted', []))
            }
            
            return {
                'id': f"hybrid_{item['_metadata']['cve_id']}_{item['_metadata']['cwe_id']}_{item['_metadata']['instance_idx']}",
                'document': document_text,
                'metadata': metadata
            }
            
        except Exception as e:
            logger.error(f"❌ Error during transformation: {e}")
            return None
    
    def determine_context_dependency(self, item):
        """Determine if the vulnerability is context-dependent"""
        vulrag = item['original_vulrag']
        semantic_text = ""
        
        if 'GPT_analysis' in vulrag:
            semantic_text += vulrag['GPT_analysis'].lower()
        if 'specific_code_behavior_causing_vulnerability' in vulrag:
            semantic_text += vulrag['specific_code_behavior_causing_vulnerability'].lower()
        if 'solution' in vulrag:
            semantic_text += vulrag['solution'].lower()
        
        # Optimized keywords based on empirical analysis (>5% detection rate)
        context_keywords = [
            'condition',      # 68.1% of instances
            'context',        # 47.3% of instances
            'based on',       # 17.6% of instances
            'parameter',      # 10.1% of instances
            'usage',          # 9.7% of instances
            'misuse'          # 6.8% of instances
        ]
        
        is_context_dependent = any(keyword in semantic_text for keyword in context_keywords)
        
        if is_context_dependent:
            self.migration_stats['context_dependent_count'] += 1
        
        return is_context_dependent
    
    def extract_fix_pattern(self, solution):
        """Extract the fix pattern"""
        if not solution:
            return "unknown"
        
        solution_lower = solution.lower()
        
        if any(keyword in solution_lower for keyword in ['bound', 'check', 'length', 'size', 'overflow']):
            return "bounds_check_added"
        elif any(keyword in solution_lower for keyword in ['lock', 'mutex', 'sync', 'atomic', 'race']):
            return "synchronization_added"
        elif any(keyword in solution_lower for keyword in ['free', 'malloc', 'memory', 'leak', 'allocation']):
            return "memory_management"
        elif any(keyword in solution_lower for keyword in ['validate', 'sanitize', 'input', 'check']):
            return "input_validation"
        elif any(keyword in solution_lower for keyword in ['initialize', 'null', 'zero']):
            return "initialization"
        else:
            return "custom"
    
    def calculate_structural_complexity(self, structural):
        """Calculate structural complexity"""
        ast_complexity = 0
        pdg_complexity = 0
        
        if structural['ast_patterns'].get('success'):
            ast = structural['ast_patterns']
            if 'patterns' in ast:
                patterns = ast['patterns']
                ast_complexity = len(patterns.get('functions', [])) + len(patterns.get('calls', []))
        
        if structural['pdg_patterns'].get('success'):
            pdg = structural['pdg_patterns']
            pdg_complexity = len(pdg.get('dependencies', [])) + len(pdg.get('variables', []))
        
        total_complexity = ast_complexity + pdg_complexity
        
        if total_complexity < 5:
            return "low"
        elif total_complexity < 15:
            return "medium"
        else:
            return "high"
    
    def migrate_data(self, batch_size=100):
        """Migrate data to ChromaDB"""
        logger.info("Starting migration to ChromaDB...")
        
        start_time = time.time()
        
        # Load data
        data = self.load_hybrid_data()
        
        # Process in batches
        total_batches = (len(data) + batch_size - 1) // batch_size
        
        for batch_idx in tqdm(range(0, len(data), batch_size), desc="Migrating batches"):
            batch_data = data[batch_idx:batch_idx + batch_size]
            
            documents = []
            metadatas = []
            ids = []
            
            for item in batch_data:
                transformed = self.transform_for_chromadb(item)
                if transformed:
                    documents.append(transformed['document'])
                    metadatas.append(transformed['metadata'])
                    ids.append(transformed['id'])
                    
                    # Update statistics
                    self.migration_stats['cwe_distribution'][transformed['metadata']['cwe_id']] += 1
                    self.migration_stats['fix_patterns'][transformed['metadata']['fix_pattern']] += 1
                    self.migration_stats['successful_migrations'] += 1
                else:
                    self.migration_stats['failed_migrations'] += 1
            
            # Insert the batch into ChromaDB
            if documents:
                try:
                    self.collection.add(
                        documents=documents,
                        metadatas=metadatas,
                        ids=ids
                    )
                    logger.debug(f"Batch {batch_idx//batch_size + 1}/{total_batches} inserted: {len(documents)} documents")
                except Exception as e:
                    logger.error(f"❌ Error inserting batch {batch_idx//batch_size + 1}: {e}")
                    self.migration_stats['failed_migrations'] += len(documents)
                    self.migration_stats['successful_migrations'] -= len(documents)
        
        self.migration_stats['processing_time'] = time.time() - start_time
        
        logger.info("✅ Migration completed")
        return True
    
    def validate_migration(self):
        """Validate the migration"""
        logger.info("Validating migration...")
        
        try:
            # Count documents in the collection
            count = self.collection.count()
            logger.info(f"📊 Documents in ChromaDB: {count}")
            
            # Simple search test
            results = self.collection.query(
                query_texts=["buffer overflow vulnerability"],
                n_results=3
            )
            logger.info(f"🔍 Search test: {len(results['documents'][0])} results")
            
            # Filter test by CWE
            results = self.collection.query(
                query_texts=["memory management"],
                n_results=3,
                where={"cwe_id": "CWE-416"}
            )
            logger.info(f"🔍 CWE filter test: {len(results['documents'][0])} results")
            
            return True
            
        except Exception as e:
            logger.error(f"❌ Error during validation: {e}")
            return False
    
    def generate_migration_report(self):
        """Generate a migration report"""
        logger.info("Generating migration report...")
        
        report = {
            "migration_summary": {
                "total_instances": self.migration_stats['total_instances'],
                "successful_migrations": self.migration_stats['successful_migrations'],
                "failed_migrations": self.migration_stats['failed_migrations'],
                "success_rate": self.migration_stats['successful_migrations'] / self.migration_stats['total_instances'] if self.migration_stats['total_instances'] > 0 else 0,
                "processing_time_seconds": self.migration_stats['processing_time'],
                "context_dependent_count": self.migration_stats['context_dependent_count']
            },
            "cwe_distribution": dict(self.migration_stats['cwe_distribution']),
            "fix_patterns": dict(self.migration_stats['fix_patterns']),
            "chromadb_info": {
                "database_path": str(self.db_path),
                "collection_name": self.collection.name if self.collection else None,
                "total_documents": self.collection.count() if self.collection else 0
            }
        }
        
        # Save the report
        report_path = Path("results/chromadb_migration_report.json")
        report_path.parent.mkdir(exist_ok=True)
        
        with open(report_path, 'w') as f:
            json.dump(report, f, indent=2)
        
        logger.info(f"📄 Report saved: {report_path}")
        
        # Display the summary
        print("\n" + "="*60)
        print("📊 CHROMADB MIGRATION REPORT")
        print("="*60)
        print(f"✅ Migrated instances: {self.migration_stats['successful_migrations']}/{self.migration_stats['total_instances']}")
        print(f"⏱️  Processing time: {self.migration_stats['processing_time']:.2f} seconds")
        print(f"🎯 Success rate: {report['migration_summary']['success_rate']:.2%}")
        print(f"🔍 Context-dependent vulnerabilities: {self.migration_stats['context_dependent_count']}")
        print(f"📁 Database: {self.db_path}")
        print(f"📊 Documents in ChromaDB: {report['chromadb_info']['total_documents']}")
        
        print(f"\n📈 CWE distribution:")
        for cwe, count in self.migration_stats['cwe_distribution'].most_common():
            print(f"  {cwe}: {count}")
        
        print(f"\n🔧 Fix patterns:")
        for pattern, count in self.migration_stats['fix_patterns'].most_common():
            print(f"  {pattern}: {count}")
        
        return report

def main():
    """Main function"""
    print("🚀 MIGRATION TO CHROMADB")
    print("="*50)
    
    # Initialize the migrator
    migrator = ChromaDBMigrator()
    
    # Initialize ChromaDB
    if not migrator.initialize_chromadb():
        print("❌ Failed to initialize ChromaDB")
        return
    
    # Migrate data
    if not migrator.migrate_data():
        print("❌ Migration failed")
        return
    
    # Validate migration
    if not migrator.validate_migration():
        print("❌ Validation failed")
        return
    
    # Generate report
    report = migrator.generate_migration_report()
    
    print("\n🎉 MIGRATION SUCCESSFULLY COMPLETED!")
    print("="*50)
    print("Your hybrid knowledge base is now available in ChromaDB")
    print("You can now perform semantic searches with metadata filtering")

if __name__ == "__main__":
    main() 