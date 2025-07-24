# Base de Connaissances Hybride pour la Détection de Vulnérabilités

Pipeline pour créer une base de connaissances hybride combinant données textuelles Vul-RAG avec des représentations structurelles (AST, CFG, PDG).

## 🆕 Mise à Jour Récente (Juillet 2025)

✅ **Compatibilité avec les dernières versions :**
- tree-sitter 0.25.0+ (nouvelle ABI interne, support RustRegex)
- networkx 3.5+
- pandas 2.3+
- matplotlib 3.10+
- seaborn 0.13+

✅ **Améliorations apportées :**
- Correction de l'incohérence dans l'utilisation du Parser tree-sitter
- Scripts de test de compatibilité automatisés
- Script de mise à jour d'environnement
- Tests complets de toutes les fonctionnalités

## 🚀 Utilisation Rapide

### Installation
```bash
# Créer l'environnement virtuel
python3 -m venv .venv

# Activer l'environnement virtuel
source .venv/bin/activate  # Sur macOS/Linux
# ou
.venv\Scripts\activate     # Sur Windows

# Installer les dépendances
pip install -r requirements.txt
```

### Méthode Simple (Recommandée)

**Sur macOS/Linux :**
```bash
# Traiter un CWE spécifique
./run.sh --cwe CWE-119

# Traiter tous les CWEs
./run.sh --all
# ou simplement
./run.sh
```

**Sur Windows :**
```cmd
# Traiter un CWE spécifique
run.bat --cwe CWE-119

# Traiter tous les CWEs
run.bat --all
# ou simplement
run.bat
```

### Méthode Manuelle

**Traitement d'un CWE spécifique :**
```bash
# Activer l'environnement virtuel d'abord
source .venv/bin/activate

# Utiliser le script simple
python scripts/process_single_file.py data/raw/gpt-4o-mini_CWE-119_316.json
```

**Traitement de tous les CWEs :**
```bash
# Activer l'environnement virtuel d'abord
source .venv/bin/activate

# Utiliser le script automatique
python scripts/process_all_files.py
```

**Affichage des statistiques :**
```bash
# Activer l'environnement virtuel d'abord
source .venv/bin/activate

# Afficher les statistiques
python scripts/show_stats.py
```

## 📁 Structure

```
vulnerability-kb/
├── 📁 src/                    # Modules Core (Bibliothèques)
│   ├── extract_ast.py        # Extraction AST avec Tree-sitter
│   ├── build_cfg.py          # Construction CFG avec NetworkX
│   ├── build_pdg.py          # Construction PDG avec analyse des dépendances
│   └── create_kb.py          # Création d'entrées KB hybrides
│
├── 📁 scripts/               # Scripts d'Exécution
│   ├── process_single_file.py # Traiter un fichier raw spécifique
│   ├── process_all_files.py   # Traiter tous les fichiers raw
│   └── show_stats.py         # Afficher les statistiques des KB
│
├── 📁 notebooks/             # Notebooks d'Exploration et d'Analyse
│   └── exploration.ipynb     # Exploration des données et visualisations
│
├── 📁 data/                  # Données
│   ├── raw/                  # Données Vul-RAG originales
│   └── enriched/             # KB hybrides générées
│
├── 📄 requirements.txt       # Dépendances Python (versions mises à jour)
├── 🧪 test_compatibility.py # Tests de compatibilité avec les nouvelles versions
└── 🔄 update_environment.py # Script de mise à jour d'environnement
```

📖 **Voir [ARCHITECTURE.md](ARCHITECTURE.md) pour plus de détails sur l'organisation**

## 🧪 Tests et Maintenance

### Tests de Compatibilité
```bash
# Activer l'environnement virtuel
source .venv/bin/activate

# Exécuter tous les tests de compatibilité
python test_compatibility.py
```

### Mise à Jour de l'Environnement
```bash
# Activer l'environnement virtuel
source .venv/bin/activate

# Mettre à jour automatiquement les dépendances et tester
python update_environment.py
```

### Tests d'Architecture
```bash
# Activer l'environnement virtuel
source .venv/bin/activate

# Vérifier l'architecture du projet
python test_architecture.py
```

## 🔧 Fonctionnalités

- **Extraction AST** : Analyse syntaxique avec Tree-sitter
- **Construction CFG** : Graphe de flux de contrôle
- **Construction PDG** : Graphe de dépendances de programme
- **Traitement par batches** : Gestion mémoire optimisée
- **Sauvegarde progressive** : Checkpoints automatiques

## 📊 Sortie

La KB hybride contient :
- Données originales Vul-RAG
- Représentations structurelles (AST, CFG, PDG)
- Métadonnées d'enrichissement
- Statistiques de complexité

## ⚙️ Scripts Disponibles

### 📁 **Scripts d'Exécution (`scripts/`)**
- **`process_single_file.py`** : Traiter un fichier raw spécifique
  ```bash
  python scripts/process_single_file.py data/raw/gpt-4o-mini_CWE-119_316.json
  ```
- **`process_all_files.py`** : Traiter tous les fichiers raw automatiquement
  ```bash
  python scripts/process_all_files.py
  ```
- **`show_stats.py`** : Afficher les statistiques des KB générées
  ```bash
  python scripts/show_stats.py
  ```

### 📁 **Modules Core (`src/`)**
- **`extract_ast.py`** : Extraction AST avec Tree-sitter
- **`build_cfg.py`** : Construction CFG avec NetworkX
- **`build_pdg.py`** : Construction PDG avec analyse des dépendances
- **`create_kb.py`** : Création d'entrées KB hybrides

### 📁 **Notebooks (`notebooks/`)**
- **`exploration.ipynb`** : Exploration des données et visualisations

## 🔧 Dépannage

### Erreur "ModuleNotFoundError"
```bash
# S'assurer que l'environnement virtuel est activé
source .venv/bin/activate

# Réinstaller les dépendances si nécessaire
pip install -r requirements.txt
```

### Erreur "externally-managed-environment"
```bash
# Utiliser l'environnement virtuel
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### Script non exécutable
```bash
# Rendre le script exécutable
chmod +x run.sh
``` 