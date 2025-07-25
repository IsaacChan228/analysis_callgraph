# Multi-Tool Call Graph Comparison Framework

## Overview
This framework provides automated comparison and analysis of call graphs generated by multiple binary analysis tools. It standardizes function names across different tools, performs comprehensive statistical analysis, and generates visualizations to compare the effectiveness and characteristics of each analysis tool.

## Supported Analysis Tools
The framework supports comparison of five major binary analysis tools:

### Required Tools
- **Radare2** - Open-source static analysis framework
- **Ghidra** - NSA's open-source software reverse engineering framework
- **Angr Fast** - Angr symbolic execution engine (fast analysis mode)

### Optional Tools (graceful degradation if unavailable)
- **Angr Emul** - Angr symbolic execution engine (emulation mode)
- **GCC** - GNU Compiler Collection call graph generation

The framework requires at least 2 tools to be successful for meaningful comparison. Optional tools may fail without terminating the analysis.

### Input Format Support
- **DOT format** (.dot) - Standard graph description language used by Radare2 and Angr
- **Ghidra GF format** (.gf) - Ghidra's native graph format
- Automatic format detection and parsing based on file extension and content structure


## Analysis Methodology

### Function Name Standardization
The framework implements comprehensive function name normalization to enable meaningful comparison across tools:
- Removes tool-specific prefixes (`dbg.`, `sym.`, `imp.`, `fcn.`, `reloc.`, `unk.`)
- Strips address suffixes and labels (`.0x[address]`, `@0x[address]`, `_0x[address]`)
- Handles compiler-generated suffixes (`.part.N`, `.isra.N`, `.cold.N`)
- Filters out pure addresses, switch cases, and invalid function names
- Normalizes leading underscores and duplicate definitions

### Graph Analysis and Metrics
The framework performs comprehensive graph-theoretic analysis using NetworkX:
- **Node Analysis**: Function count, unique function identification
- **Edge Analysis**: Call relationship mapping and validation
- **Graph Density**: Measures connectivity (edges / possible_edges)
- **Degree Analysis**: In-degree and out-degree statistics
- **Connected Components**: Strongly connected component identification
- **Jaccard Similarity**: Pairwise tool comparison using intersection/union ratios

### Function Classification System
Functions are automatically classified into two categories using pattern matching:
- **High-Level Functions**: Entry points, main functions, library calls, user-defined functions
- **Low-Level Functions**: Address-based labels, compiler-generated symbols, PLT/GOT entries

Classification patterns include:
```python
high_level_patterns = [
    r'^main$', r'^_start$', r'^entry$',
    r'.*init.*', r'.*setup.*', r'.*process.*',
    r'.*handle.*', r'.*parse.*', r'.*print.*'
]

low_level_patterns = [
    r'^0x[0-9a-f]+$',  # Pure addresses
    r'^sub_[0-9a-f]+$', r'^loc_[0-9a-f]+$',  # Disassembler labels
    r'.*@plt$', r'.*\.plt$',  # PLT entries
    r'^__.*__$'  # System internal functions
]
```

## Technical Implementation

### Core Libraries and Dependencies
- **NetworkX**: Graph creation, analysis, and algorithms
- **Matplotlib**: Visualization generation (charts, heatmaps)
- **Pandas**: Data manipulation and CSV export
- **Python Standard Library**: Regular expressions, file I/O

### Key Components
1. **CallGraphNormalizer**: Handles format parsing and function name standardization
2. **MultiCallGraphComparator**: Main analysis engine and comparison logic
3. **Logger**: Dual output system (console + file logging)

### Error Handling and Robustness
- **Graceful Degradation**: Continues analysis if one tool fails (except critical tools)
- **File Validation**: Checks for file existence, readability, and content validity
- **Format Detection**: Automatic handling of different graph formats
- **Memory Management**: Efficient handling of large function sets


## Installation

### Prerequisites
- Python 3.7 or higher
- pip (Python package installer)

### Quick Installation
1. Clone or download this repository
2. Install required Python packages:

```bash
pip install -r requirements.txt
```

### Verify Installation
Test that all dependencies are properly installed:

```bash
python verify_setup.py
```

## Usage

### Basic Usage
```bash
# Place your call graph files in the graph/ directory:
# Required files:
# - graph/r2.dot (Radare2 output)
# - graph/ghidra.gf (Ghidra export)
# - graph/angr_fast.dot (Angr fast mode)
# 
# Optional files (analysis continues if missing):
# - graph/angr_emul.dot (Angr emulation mode)
# - graph/gcc.dot (GCC generated output)

# Run the analysis
python3 run_analysis.py
```

## Output Generation

### Visualization Outputs
The framework generates multiple high-resolution PNG charts:
- **Function Discovery Comparison**: Bar charts showing total, high-level, and low-level function counts
- **Call Relationship Comparison**: Analysis of call relationship quantities across tools
- **Graph Density Comparison**: Visualization of graph connectivity metrics
- **Similarity Heatmap**: Color-coded Jaccard similarity matrix between all tool pairs

### Data Exports (CSV Format)
- **Statistics Summary**: Comprehensive metrics for each tool
- **Similarity Matrix**: Pairwise comparison coefficients
- **Function Comparison**: Detailed function-by-function analysis
- **Level Analysis**: High-level vs low-level function breakdown
- **Call Relationship Analysis**: Inter-function relationship mapping

### Logging and Reporting
- **Complete Analysis Log**: Detailed execution log with all intermediate results
- **Console Output**: Real-time progress and summary information
- **Error Reporting**: Comprehensive error handling with diagnostic information

## Generated Output Files

### Visualization Files (PNG)
- `result/function_discovery_comparison.png` - Function discovery analysis across tools
- `result/call_relationship_comparison.png` - Call relationship comparison charts
- `result/graph_density_comparison.png` - Graph density and connectivity metrics
- `result/similarity_heatmap.png` - Jaccard similarity matrix heatmap

### Data Export Files (CSV)
- `result/multi_callgraph_comparison_statistics.csv` - Comprehensive tool statistics
- `result/multi_callgraph_comparison_similarity.csv` - Pairwise similarity matrix
- `result/multi_callgraph_comparison_functions.csv` - Function-level comparison
- `result/function_level_analysis_statistics.csv` - High/low-level function statistics
- `result/function_level_analysis_high_level_functions.csv` - High-level function details
- `result/function_level_analysis_low_level_functions.csv` - Low-level function details
- `result/function_level_analysis_high_level_calls.csv` - High-level call relationships

### Log Files
- `analysis_log.txt` - Complete execution log with detailed analysis results
