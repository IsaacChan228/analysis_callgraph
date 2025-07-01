import re
import networkx as nx
from typing import Set, Dict, Tuple
import matplotlib.pyplot as plt
import pandas as pd
import sys

class Logger:
    """Log handler for file output"""
    def __init__(self, filename):
        self.terminal = sys.stdout
        self.log = open(filename, 'w', encoding='utf-8')

    def write(self, message):
        self.terminal.write(message)
        self.log.write(message)
        self.log.flush()

    def flush(self):
        self.terminal.flush()
        self.log.flush()
    
    def close(self):
        self.log.close()

class CallGraphNormalizer:
    """Call graph standardization processor"""
    
    def normalize_function_name(self, name: str) -> str:
        """Standardize function names"""
        if not name:
            return None
        
        # Remove various prefixes
        name = re.sub(r'^(dbg\.|sym\.|fcn\.|reloc\.|imp\.|unk\.)', '', name)
        
        # Remove address suffixes and labels
        name = re.sub(r'\.0x[0-9a-f]+$', '', name)
        name = re.sub(r'@0x[0-9a-f]+$', '', name)
        name = re.sub(r'_0x[0-9a-f]+$', '', name)
        name = re.sub(r'\\n0x[0-9a-f]+$', '', name)  # Angr format
        
        # Remove compiler-generated suffixes
        name = re.sub(r'\.(part|isra|cold)\.[0-9]+', '', name)
        name = re.sub(r'\.(part|isra|cold)$', '', name)
        
        # Remove duplicate definition suffixes
        name = re.sub(r'_[0-9]+$', '', name)
        
        # Remove leading underscores
        name = re.sub(r'^_+', '', name)
        
        # Handle special cases
        if name.startswith('case.') or name.startswith('switch.'):
            return None
        
        # If name becomes empty or contains only digits, return None
        if not name or name.isdigit():
            return None
            
        return name
    
    def extract_from_dot(self, dot_file: str, tool_name: str) -> Tuple[Set[str], Set[Tuple[str, str]]]:
        """Extract standardized functions and call relationships from DOT files"""
        functions = set()
        calls = set()
        
        try:
            with open(dot_file, 'r', encoding='utf-8') as f:
                content = f.read()
        except FileNotFoundError:
            if tool_name.lower() == 'angr_emul':
                print(f"⚠️  Warning: {tool_name} file not found ({dot_file}) - This is expected as Angr_Emul may fail")
                return functions, calls
            else:
                print(f"❌ Fatal Error: Required {tool_name} file not found ({dot_file})")
                print(f"Program will terminate. Please ensure all required graph files exist.")
                raise FileNotFoundError(f"Required graph file missing: {dot_file}")
        except Exception as e:
            if tool_name.lower() == 'angr_emul':
                print(f"⚠️  Warning: Cannot read {tool_name} file ({dot_file}): {e} - Will skip this tool")
                return functions, calls
            else:
                print(f"❌ Fatal Error: Cannot read required {tool_name} file ({dot_file}): {e}")
                print(f"Program will terminate.")
                raise Exception(f"Failed to read required graph file: {dot_file}")
        
        # Check if file content is empty or invalid
        if not content.strip():
            if tool_name.lower() == 'angr_emul':
                print(f"⚠️  Warning: {tool_name} file is empty or has no content - This is acceptable")
                return functions, calls
            else:
                print(f"❌ Fatal Error: Required {tool_name} file is empty or has no content")
                print(f"Program will terminate. Please check the graph file generation process.")
                raise ValueError(f"Required graph file is empty: {dot_file}")
        
        if tool_name.lower() == 'ghidra':
            functions, calls = self._extract_from_ghidra_gf(content)
        else:
            functions, calls = self._extract_from_standard_dot(content)
        
        # Check if data was successfully extracted
        if len(functions) == 0 and len(calls) == 0:
            if tool_name.lower() == 'angr_emul':
                print(f"⚠️  Warning: {tool_name} analysis failed or found no functions and call relationships - Will continue with other tools")
                print(f"    This may be due to:")
                print(f"    - Angr emulation mode execution failure")
                print(f"    - Incorrect file format")
                print(f"    - Binary file too complex")
            else:
                print(f"❌ Fatal Error: Required {tool_name} found no functions and call relationships")
                print(f"    This may be due to:")
                print(f"    - Analysis tool execution failure")
                print(f"    - Incorrect file format")
                print(f"    - Binary file too complex or corrupted")
                print(f"Program will terminate.")
                raise ValueError(f"Required tool {tool_name} found no data")
        
        return functions, calls
    
    def _extract_from_standard_dot(self, content: str) -> Tuple[Set[str], Set[Tuple[str, str]]]:
        """Extract from standard DOT format"""
        functions = set()
        calls = set()
        
        # Extract node definitions
        node_pattern = r'"([^"]+)"\s*\[.*?label="([^"]*)'
        for match in re.finditer(node_pattern, content):
            node_id = match.group(1)
            func_name = match.group(2) if match.group(2) else node_id
            
            # Handle labels containing newlines
            func_name = func_name.split('\\n')[0] if '\\n' in func_name else func_name
            
            normalized = self.normalize_function_name(func_name)
            if normalized:
                functions.add(normalized)
        
        # If no labeled nodes found, try to extract node names directly
        if not functions:
            simple_node_pattern = r'"([^"]+)"\s*\['
            for match in re.finditer(simple_node_pattern, content):
                func_name = match.group(1)
                normalized = self.normalize_function_name(func_name)
                if normalized:
                    functions.add(normalized)
        
        # Extract edges (call relationships)
        edge_pattern = r'"([^"]+)"\s*->\s*"([^"]+)"'
        for match in re.finditer(edge_pattern, content):
            caller = match.group(1)
            callee = match.group(2)
            
            # Find corresponding function names
            caller_func = self._find_function_name_in_content(content, caller)
            callee_func = self._find_function_name_in_content(content, callee)
            
            caller_normalized = self.normalize_function_name(caller_func)
            callee_normalized = self.normalize_function_name(callee_func)
            
            if caller_normalized and callee_normalized:
                calls.add((caller_normalized, callee_normalized))
        
        return functions, calls
    
    def _extract_from_ghidra_gf(self, content: str) -> Tuple[Set[str], Set[Tuple[str, str]]]:
        """Extract from Ghidra GF format"""
        functions = set()
        calls = set()
        
        # Extract node definitions - Ghidra format: "address" [ label="function_name" VertexType="Entry" ];
        node_pattern = r'"([^"]+)"\s*\[\s*label="([^"]+)"'
        for match in re.finditer(node_pattern, content):
            address = match.group(1)
            func_name = match.group(2)
            
            normalized = self.normalize_function_name(func_name)
            if normalized:
                functions.add(normalized)
        
        # Extract edges (call relationships) - Format: "address1" -> "address2";
        edge_pattern = r'"([^"]+)"\s*->\s*"([^"]+)"'
        address_to_func = {}
        
        # First build address to function name mapping
        for match in re.finditer(node_pattern, content):
            address = match.group(1)
            func_name = match.group(2)
            normalized = self.normalize_function_name(func_name)
            if normalized:
                address_to_func[address] = normalized
        
        # Extract call relationships
        for match in re.finditer(edge_pattern, content):
            caller_addr = match.group(1)
            callee_addr = match.group(2)
            
            caller_func = address_to_func.get(caller_addr)
            callee_func = address_to_func.get(callee_addr)
            
            if caller_func and callee_func:
                calls.add((caller_func, callee_func))
        
        return functions, calls
    
    def _find_function_name_in_content(self, content: str, identifier: str) -> str:
        """Find function name corresponding to identifier in content"""
        # Look for corresponding label
        pattern = rf'"{re.escape(identifier)}"\s*\[.*?label="([^"]*)"'
        match = re.search(pattern, content)
        if match:
            label = match.group(1)
            return label.split('\\n')[0] if '\\n' in label else label
        return identifier

class MultiCallGraphComparator:
    """Multi call graph comparison analyzer"""
    
    def __init__(self):
        self.normalizer = CallGraphNormalizer()
        self.tools = {
            'Radare2': 'graph/r2.dot',
            'Ghidra': 'graph/ghidra.gf',
            'Angr_Fast': 'graph/angr_fast.dot', 
            'Angr_Emul': 'graph/angr_emul.dot'
        }
        
    def compare_all_call_graphs(self) -> Dict:
        """Compare all call graph files"""
        print("Starting analysis of all call graphs...")
        
        tool_data = {}
        
        # Extract data from each tool
        for tool_name, file_path in self.tools.items():
            print(f"Standardizing {tool_name} call graph...")
            try:
                functions, calls = self.normalizer.extract_from_dot(file_path, tool_name)
                tool_data[tool_name] = {
                    'functions': functions,
                    'calls': calls,
                    'graph': self._create_graph(functions, calls)
                }
                print(f"{tool_name}: {len(functions)} functions, {len(calls)} call relationships")
            except (FileNotFoundError, ValueError, Exception) as e:
                if tool_name.lower() == 'angr_emul':
                    # Angr_Emul failure is acceptable, create empty data
                    print(f"⚠️  {tool_name} skipped: {str(e)}")
                    tool_data[tool_name] = {
                        'functions': set(),
                        'calls': set(),
                        'graph': self._create_graph(set(), set())
                    }
                    print(f"{tool_name}: 0 functions, 0 call relationships (skipped)")
                else:
                    # Other tool failures terminate the program
                    print(f"💥 Program terminated: {tool_name} is a required tool but analysis failed")
                    raise e
        
        # Verify at least one successful tool (except angr_emul)
        successful_tools = []
        for tool_name, data in tool_data.items():
            if len(data['functions']) > 0 or len(data['calls']) > 0:
                successful_tools.append(tool_name)
        
        if len(successful_tools) < 2:
            error_msg = f"❌ Fatal error: Less than 2 successful tools ({len(successful_tools)} successful)"
            print(error_msg)
            print("At least 2 tools must succeed for meaningful comparison.")
            raise ValueError(error_msg)
        
        print(f"✅ Successfully analyzed {len(successful_tools)} tools: {', '.join(successful_tools)}")
        
        # Calculate union and intersection of all tools
        all_functions = set()
        all_calls = set()
        
        for data in tool_data.values():
            all_functions |= data['functions']
            all_calls |= data['calls']
        
        # Calculate intersection
        common_functions = all_functions.copy()
        common_calls = all_calls.copy()
        
        for data in tool_data.values():
            common_functions &= data['functions']
            common_calls &= data['calls']
        
        return {
            'tool_data': tool_data,
            'all_functions': all_functions,
            'all_calls': all_calls,
            'common_functions': common_functions,
            'common_calls': common_calls
        }
    
    def _create_graph(self, functions: Set[str], calls: Set[Tuple[str, str]]) -> nx.DiGraph:
        """Create NetworkX directed graph"""
        G = nx.DiGraph()
        G.add_nodes_from(functions)
        G.add_edges_from(calls)
        return G
    
    def _classify_functions(self, functions: Set[str]) -> Dict[str, Set[str]]:
        """Classify functions into high-level and low-level categories"""
        high_level = set()
        low_level = set()
        
        # High-level function characteristic patterns
        high_level_patterns = [
            r'^main$', r'^_start$', r'^entry$',
            r'.*main.*', r'.*init.*', r'.*setup.*', r'.*config.*',
            r'.*process.*', r'.*handle.*', r'.*manage.*', r'.*execute.*',
            r'.*parse.*', r'.*format.*', r'.*print.*', r'.*output.*',
            r'.*input.*', r'.*read.*', r'.*write.*', r'.*file.*',
            r'.*error.*', r'.*debug.*', r'.*usage.*', r'.*help.*'
        ]
        
        # Low-level function characteristic patterns
        low_level_patterns = [
            r'^0x[0-9a-f]+$',  # Pure address
            r'^[0-9a-f]{8,}$',  # Long hexadecimal number
            r'^sub_[0-9a-f]+$', r'^loc_[0-9a-f]+$',  # Disassembler-generated labels
            r'^j_.*',  # Jump functions
            r'.*@plt$', r'.*\.plt$',  # PLT entries
            r'.*@got$', r'.*\.got$',  # GOT entries
            r'^__.*__$',  # System internal functions
            r'.*_0x[0-9a-f]+$',  # Address suffixes
            r'^[0-9]+$'  # Pure numbers
        ]
        
        import re
        
        for func in functions:
            if not func:
                continue
                
            # Check if it's a low-level function
            is_low_level = False
            for pattern in low_level_patterns:
                if re.match(pattern, func, re.IGNORECASE):
                    low_level.add(func)
                    is_low_level = True
                    break
            
            # If not low-level, check if it's high-level
            if not is_low_level:
                is_high_level = False
                for pattern in high_level_patterns:
                    if re.match(pattern, func, re.IGNORECASE):
                        high_level.add(func)
                        is_high_level = True
                        break
                
                # Default classification: shorter length with letters as high-level, others as low-level
                if not is_high_level:
                    if len(func) <= 20 and any(c.isalpha() for c in func):
                        high_level.add(func)
                    else:
                        low_level.add(func)
        
        return {
            'high_level': high_level,
            'low_level': low_level
        }
    
    def _filter_calls_by_function_level(self, calls: Set[Tuple[str, str]], 
                                      high_level_funcs: Set[str], 
                                      low_level_funcs: Set[str], 
                                      level: str) -> Set[Tuple[str, str]]:
        """Filter call relationships by function level"""
        target_funcs = high_level_funcs if level == 'high' else low_level_funcs
        filtered_calls = set()
        
        for caller, callee in calls:
            if caller in target_funcs and callee in target_funcs:
                filtered_calls.add((caller, callee))
        
        return filtered_calls
    
    def _calculate_graph_metrics(self, graph: nx.DiGraph) -> Dict:
        """Calculate graph structure metrics"""
        if graph.number_of_nodes() == 0:
            return {
                'nodes': 0,
                'edges': 0,
                'avg_in_degree': 0,
                'avg_out_degree': 0,
                'max_in_degree': 0, 
                'max_out_degree': 0,
                'density': 0,
                'strongly_connected_components': 0
            }
        
        in_degrees = dict(graph.in_degree())
        out_degrees = dict(graph.out_degree())
        
        return {
            'nodes': graph.number_of_nodes(),
            'edges': graph.number_of_edges(),
            'avg_in_degree': sum(in_degrees.values()) / graph.number_of_nodes(),
            'avg_out_degree': sum(out_degrees.values()) / graph.number_of_nodes(),
            'max_in_degree': max(in_degrees.values()) if in_degrees else 0,
            'max_out_degree': max(out_degrees.values()) if out_degrees else 0,
            'density': nx.density(graph),
            'strongly_connected_components': len(list(nx.strongly_connected_components(graph)))
        }
    
    def generate_comparison_report(self, comparison: Dict) -> str:
        """Generate detailed comparison report"""
        tool_data = comparison['tool_data']
        
        report = []
        report.append("=" * 80)
        report.append("Multi-Tool Call Graph Comparison Analysis Report")
        report.append("=" * 80)
        
        # Basic statistics
        report.append("\n1. Basic Statistics")
        report.append("-" * 50)
        report.append(f"{'Tool':<15} {'Functions':<15} {'Calls':<15} {'Graph Density':<15} {'Status':<10}")
        report.append("-" * 75)
        
        failed_tools = []
        for tool_name, data in tool_data.items():
            metrics = self._calculate_graph_metrics(data['graph'])
            func_count = len(data['functions'])
            call_count = len(data['calls'])
            
            # Determine if tool succeeded
            status = "✓ Success" if func_count > 0 or call_count > 0 else "✗ Failed"
            if func_count == 0 and call_count == 0:
                failed_tools.append(tool_name)
            
            report.append(f"{tool_name:<15} {func_count:<15} {call_count:<15} {metrics['density']:<15.4f} {status:<10}")
        
        # Add explanation for failed tools
        if failed_tools:
            report.append(f"\n⚠️  Failed analysis tools: {', '.join(failed_tools)}")
            report.append("   These tools may have failed due to:")
            report.append("   - Tool execution failure or timeout")
            report.append("   - Unsupported binary file format")
            report.append("   - Configuration or environment issues")
        
        # Function discovery comparison
        report.append(f"\n2. Function Discovery Analysis")
        report.append("-" * 50)
        report.append(f"Total unique functions: {len(comparison['all_functions'])}")
        report.append(f"Functions found by all tools: {len(comparison['common_functions'])}")
        
        # Pairwise comparison (only successful tools)
        successful_tools = [tool for tool in tool_data.keys() if tool not in failed_tools]
        if len(successful_tools) >= 2:
            report.append(f"\n3. Pairwise Comparison Analysis (Successful Tools Only)")
            report.append("-" * 50)
            
            for i, tool1 in enumerate(successful_tools):
                for j, tool2 in enumerate(successful_tools[i+1:], i+1):
                    func1 = tool_data[tool1]['functions']
                    func2 = tool_data[tool2]['functions']
                    common = len(func1 & func2)
                    union = len(func1 | func2)
                    jaccard = common / union if union > 0 else 0
                    
                    report.append(f"{tool1} vs {tool2}:")
                    report.append(f"  Common functions: {common}")
                    report.append(f"  Jaccard similarity: {jaccard:.3f}")
        else:
            report.append(f"\n3. Pairwise Comparison Analysis")
            report.append("-" * 50)
            report.append("⚠️  Less than 2 successful tools, cannot perform meaningful comparison")
        
        # Call relationship analysis
        report.append(f"\n4. Call Relationship Analysis")
        report.append("-" * 50)
        report.append(f"Total unique call relationships: {len(comparison['all_calls'])}")
        report.append(f"Call relationships found by all tools: {len(comparison['common_calls'])}")
        
        # Detailed tool characteristic analysis (successful tools only)
        if successful_tools:
            report.append(f"\n5. Tool Characteristic Analysis (Successful Tools Only)")
            report.append("-" * 50)
            
            for tool_name in successful_tools:
                data = tool_data[tool_name]
                # Calculate functions unique to this tool (not found by any other successful tool)
                unique_funcs = data['functions'].copy()
                for other_tool in successful_tools:
                    if other_tool != tool_name:
                        unique_funcs -= tool_data[other_tool]['functions']
                
                report.append(f"\n{tool_name} unique functions ({len(unique_funcs)} total):")
                if len(unique_funcs) > 0:
                    for func in sorted(list(unique_funcs))[:10]:
                        report.append(f"  - {func}")
                    if len(unique_funcs) > 10:
                        report.append(f"  ... and {len(unique_funcs) - 10} more")
                else:
                    report.append("  (No unique functions)")
        
        return "\n".join(report)
    
    def visualize_comparison(self, comparison: Dict):
        """Visualize comparison results"""
        tool_data = comparison['tool_data']
        
        # Identify failed tools
        failed_tools = []
        for tool_name, data in tool_data.items():
            if len(data['functions']) == 0 and len(data['calls']) == 0:
                failed_tools.append(tool_name)
        
        # Prepare high-level and low-level function data
        tool_level_data = {}
        for tool_name, data in tool_data.items():
            classification = self._classify_functions(data['functions'])
            high_level_calls = self._filter_calls_by_function_level(
                data['calls'], classification['high_level'], classification['low_level'], 'high')
            low_level_calls = self._filter_calls_by_function_level(
                data['calls'], classification['high_level'], classification['low_level'], 'low')
            
            tool_level_data[tool_name] = {
                'high_level_funcs': classification['high_level'],
                'low_level_funcs': classification['low_level'],
                'high_level_calls': high_level_calls,
                'low_level_calls': low_level_calls,
                'high_level_graph': self._create_graph(classification['high_level'], high_level_calls),
                'low_level_graph': self._create_graph(classification['low_level'], low_level_calls)
            }
        
        tools = list(tool_data.keys())
        colors = ['#ff7f0e', '#9467bd', '#2ca02c', '#d62728']
        
        # Use gray color for failed tools
        bar_colors = []
        for i, tool in enumerate(tools):
            if tool in failed_tools:
                bar_colors.append('#cccccc')
            else:
                bar_colors.append(colors[i % len(colors)])
        
        # Create three separate charts
        self._create_function_discovery_chart(tool_data, tool_level_data, tools, bar_colors, failed_tools)
        self._create_call_relationship_chart(tool_data, tool_level_data, tools, bar_colors, failed_tools)
        self._create_graph_density_chart(tool_data, tool_level_data, tools, bar_colors, failed_tools)
        self._create_similarity_heatmap(tool_data, failed_tools)
        
        # Export high-level and low-level data to CSV
        self._export_level_data_to_csv(tool_level_data, "function_level_analysis")
    
    def _create_function_discovery_chart(self, tool_data, tool_level_data, tools, bar_colors, failed_tools):
        """Create function discovery comparison chart"""
        fig, (ax1, ax2, ax3) = plt.subplots(1, 3, figsize=(18, 6))
        
        # Total function count comparison
        self._create_bar_chart(ax1, tools, 
                              [len(data['functions']) for data in tool_data.values()],
                              bar_colors, failed_tools, 'Total Function Discovery', 'Number of Functions')
        
        # High-level function count comparison
        self._create_bar_chart(ax2, tools,
                              [len(tool_level_data[t]['high_level_funcs']) for t in tools],
                              bar_colors, failed_tools, 'High-Level Function Discovery', 'Number of Functions')
        
        # Low-level function count comparison
        self._create_bar_chart(ax3, tools,
                              [len(tool_level_data[t]['low_level_funcs']) for t in tools],
                              bar_colors, failed_tools, 'Low-Level Function Discovery', 'Number of Functions')
        
        plt.tight_layout()
        plt.savefig('result/function_discovery_comparison.png', dpi=300, bbox_inches='tight')
        print("Function discovery comparison chart saved as result/function_discovery_comparison.png")
    
    def _create_call_relationship_chart(self, tool_data, tool_level_data, tools, bar_colors, failed_tools):
        """Create call relationship comparison chart"""
        fig, (ax1, ax2, ax3) = plt.subplots(1, 3, figsize=(18, 6))
        
        # Total call relationship comparison
        self._create_bar_chart(ax1, tools,
                              [len(data['calls']) for data in tool_data.values()],
                              bar_colors, failed_tools, 'Total Call Relationships', 'Number of Calls')
        
        # High-level call relationship comparison
        self._create_bar_chart(ax2, tools,
                              [len(tool_level_data[t]['high_level_calls']) for t in tools],
                              bar_colors, failed_tools, 'High-Level Call Relationships', 'Number of Calls')
        
        # Low-level call relationship comparison
        self._create_bar_chart(ax3, tools,
                              [len(tool_level_data[t]['low_level_calls']) for t in tools],
                              bar_colors, failed_tools, 'Low-Level Call Relationships', 'Number of Calls')
        
        plt.tight_layout()
        plt.savefig('result/call_relationship_comparison.png', dpi=300, bbox_inches='tight')
        print("Call relationship comparison chart saved as result/call_relationship_comparison.png")
    
    def _create_graph_density_chart(self, tool_data, tool_level_data, tools, bar_colors, failed_tools):
        """Create graph density comparison chart"""
        fig, (ax1, ax2, ax3) = plt.subplots(1, 3, figsize=(18, 6))
        
        # Total graph density comparison
        densities = [self._calculate_graph_metrics(data['graph'])['density'] for data in tool_data.values()]
        self._create_bar_chart(ax1, tools, densities, bar_colors, failed_tools, 
                              'Total Graph Density', 'Graph Density', format_values=True)
        
        # High-level graph density comparison
        high_densities = [self._calculate_graph_metrics(tool_level_data[t]['high_level_graph'])['density'] for t in tools]
        self._create_bar_chart(ax2, tools, high_densities, bar_colors, failed_tools,
                              'High-Level Graph Density', 'Graph Density', format_values=True)
        
        # Low-level graph density comparison
        low_densities = [self._calculate_graph_metrics(tool_level_data[t]['low_level_graph'])['density'] for t in tools]
        self._create_bar_chart(ax3, tools, low_densities, bar_colors, failed_tools,
                              'Low-Level Graph Density', 'Graph Density', format_values=True)
        
        plt.tight_layout()
        plt.savefig('result/graph_density_comparison.png', dpi=300, bbox_inches='tight')
        print("Graph density comparison chart saved as result/graph_density_comparison.png")
    
    def _export_level_data_to_csv(self, tool_level_data, output_prefix: str):
        """Export high-level and low-level function data to CSV files"""
        tools = list(tool_level_data.keys())
        
        # 1. Export high-level and low-level function statistics
        level_stats_data = []
        for tool_name in tools:
            data = tool_level_data[tool_name]
            high_metrics = self._calculate_graph_metrics(data['high_level_graph'])
            low_metrics = self._calculate_graph_metrics(data['low_level_graph'])
            
            level_stats_data.append({
                'Tool': tool_name,
                'Total Functions': len(data['high_level_funcs']) + len(data['low_level_funcs']),
                'High-Level Functions': len(data['high_level_funcs']),
                'Low-Level Functions': len(data['low_level_funcs']),
                'High-Level Function Ratio (%)': round(len(data['high_level_funcs']) / (len(data['high_level_funcs']) + len(data['low_level_funcs'])) * 100, 2) if (len(data['high_level_funcs']) + len(data['low_level_funcs'])) > 0 else 0,
                'High-Level Calls': len(data['high_level_calls']),
                'Low-Level Calls': len(data['low_level_calls']),
                'High-Level Graph Density': round(high_metrics['density'], 6),
                'Low-Level Graph Density': round(low_metrics['density'], 6),
                'High-Level Strong Components': high_metrics['strongly_connected_components'],
                'Low-Level Strong Components': low_metrics['strongly_connected_components']
            })
        
        level_stats_df = pd.DataFrame(level_stats_data)
        level_stats_df.to_csv(f"result/{output_prefix}_statistics.csv", index=False, encoding='utf-8')
        
        # 2. Export high-level function list
        all_high_level_funcs = set()
        for data in tool_level_data.values():
            all_high_level_funcs |= data['high_level_funcs']
        
        high_level_data = []
        for func in sorted(all_high_level_funcs):
            row = {'Function Name': func, 'Category': 'High-Level'}
            for tool in tools:
                row[tool] = '✓' if func in tool_level_data[tool]['high_level_funcs'] else '✗'
            high_level_data.append(row)
        
        high_level_df = pd.DataFrame(high_level_data)
        high_level_df.to_csv(f"result/{output_prefix}_high_level_functions.csv", index=False, encoding='utf-8')
        
        # 3. Export low-level function list (limit count to avoid oversized files)
        all_low_level_funcs = set()
        for data in tool_level_data.values():
            all_low_level_funcs |= data['low_level_funcs']
        
        # If too many low-level functions, only export first 1000
        sorted_low_funcs = sorted(all_low_level_funcs)
        if len(sorted_low_funcs) > 1000:
            sorted_low_funcs = sorted_low_funcs[:1000]
            print(f"⚠️  Too many low-level functions ({len(all_low_level_funcs)}), only exporting first 1000 to CSV")
        
        low_level_data = []
        for func in sorted_low_funcs:
            row = {'Function Name': func, 'Category': 'Low-Level'}
            for tool in tools:
                row[tool] = '✓' if func in tool_level_data[tool]['low_level_funcs'] else '✗'
            low_level_data.append(row)
        
        low_level_df = pd.DataFrame(low_level_data)
        low_level_df.to_csv(f"result/{output_prefix}_low_level_functions.csv", index=False, encoding='utf-8')
        
        # 4. Export high-level function call relationships
        all_high_level_calls = set()
        for data in tool_level_data.values():
            all_high_level_calls |= data['high_level_calls']
        
        high_call_data = []
        for caller, callee in sorted(all_high_level_calls):
            row = {'Caller': caller, 'Callee': callee, 'Call Type': 'High-High'}
            for tool in tools:
                row[tool] = '✓' if (caller, callee) in tool_level_data[tool]['high_level_calls'] else '✗'
            high_call_data.append(row)
        
        high_call_df = pd.DataFrame(high_call_data)
        high_call_df.to_csv(f"result/{output_prefix}_high_level_calls.csv", index=False, encoding='utf-8')
        
        print(f"High-level/low-level function analysis data exported to:")
        print(f"  - result/{output_prefix}_statistics.csv (statistics summary)")
        print(f"  - result/{output_prefix}_high_level_functions.csv (high-level function list)")
        print(f"  - result/{output_prefix}_low_level_functions.csv (low-level function list)")
        print(f"  - result/{output_prefix}_high_level_calls.csv (high-level call relationships)")
    
    def _create_bar_chart(self, ax, tools, values, colors, failed_tools, title, ylabel, format_values=False):
        """Helper function to create bar charts"""
        bars = ax.bar(tools, values, color=colors)
        ax.set_title(title, fontsize=14, fontweight='bold')
        ax.set_ylabel(ylabel)
        ax.set_xlabel('Tools')
        
        # Add value labels and failure markers
        max_val = max(values) if values else 1
        for i, (bar, value, tool) in enumerate(zip(bars, values, tools)):
            if tool in failed_tools:
                ax.text(bar.get_x() + bar.get_width()/2, bar.get_height() + max_val*0.02,
                       'FAILED', ha='center', va='bottom', fontweight='bold', color='red', fontsize=8)
            
            if format_values:
                label = f'{value:.4f}'
            else:
                label = str(int(value))
                
            ax.text(bar.get_x() + bar.get_width()/2, bar.get_height() + max_val*0.01,
                   label, ha='center', va='bottom', fontweight='bold', fontsize=10)
    
    def _create_similarity_heatmap(self, tool_data, failed_tools):
        """Create similarity heatmap as a separate chart"""
        fig, ax = plt.subplots(1, 1, figsize=(10, 8))
        
        tools = list(tool_data.keys())
        n_tools = len(tools)
        similarity_matrix = [[0 for _ in range(n_tools)] for _ in range(n_tools)]
        
        for i, tool1 in enumerate(tools):
            for j, tool2 in enumerate(tools):
                if i == j:
                    similarity_matrix[i][j] = 1.0
                elif tool1 in failed_tools or tool2 in failed_tools:
                    similarity_matrix[i][j] = -1
                else:
                    func1 = tool_data[tool1]['functions']
                    func2 = tool_data[tool2]['functions']
                    common = len(func1 & func2)
                    union = len(func1 | func2)
                    similarity_matrix[i][j] = common / union if union > 0 else 0
        
        # Create custom colormap to handle failures and improve high similarity visibility
        import matplotlib.colors as mcolors
        import numpy as np
        
        # Replace -1 values with NaN for display
        display_matrix = np.array(similarity_matrix, dtype=float)
        display_matrix[display_matrix == -1] = np.nan
        
        # Use 'viridis' colormap which provides better contrast at high values
        # Or use custom color mapping from light to medium intensity blues, avoiding too dark
        colors = ['#ffffff', '#f0f8ff', '#e6f3ff', '#cce7ff', '#99d6ff', '#66c2ff', '#3399ff', '#0066cc', '#004d99']
        custom_cmap = mcolors.LinearSegmentedColormap.from_list('light_blues', colors, N=256)
        
        im = ax.imshow(display_matrix, cmap=custom_cmap, aspect='auto', vmin=0, vmax=1)
        ax.set_title('Function Discovery Jaccard Similarity', fontsize=16, fontweight='bold')
        ax.set_xticks(range(n_tools))
        ax.set_yticks(range(n_tools))
        ax.set_xticklabels(tools, rotation=45)
        ax.set_yticklabels(tools)
        
        # Add value labels with intelligent color selection for readability
        for i in range(n_tools):
            for j in range(n_tools):
                if similarity_matrix[i][j] == -1:
                    ax.text(j, i, 'N/A', ha='center', va='center', fontweight='bold', color='red')
                else:
                    # Choose text color based on background color
                    value = similarity_matrix[i][j]
                    # Use white text when similarity > 0.5, otherwise use black
                    text_color = 'white' if value > 0.5 else 'black'
                    ax.text(j, i, f'{value:.3f}',
                            ha='center', va='center', fontweight='bold', color=text_color)
        
        # Add colorbar with labels
        cbar = plt.colorbar(im, ax=ax)
        cbar.set_label('Jaccard Similarity', rotation=270, labelpad=20)
        
        plt.tight_layout()
        plt.savefig('result/similarity_heatmap.png', dpi=300, bbox_inches='tight')
        print("Similarity heatmap saved as result/similarity_heatmap.png")
    
    def export_to_csv(self, comparison: Dict, output_prefix: str = "multi_comparison"):
        """Export comparison results to CSV files"""
        tool_data = comparison['tool_data']
        
        # Identify failed tools
        failed_tools = []
        for tool_name, data in tool_data.items():
            if len(data['functions']) == 0 and len(data['calls']) == 0:
                failed_tools.append(tool_name)
        
        # 1. Export basic statistics
        stats_data = []
        for tool_name, data in tool_data.items():
            metrics = self._calculate_graph_metrics(data['graph'])
            status = "Failed" if tool_name in failed_tools else "Success"
            stats_data.append({
                'Tool': tool_name,
                'Status': status,
                'Function Count': len(data['functions']),
                'Call Relationship Count': len(data['calls']),
                'Average In-Degree': round(metrics['avg_in_degree'], 3),
                'Average Out-Degree': round(metrics['avg_out_degree'], 3),
                'Max In-Degree': metrics['max_in_degree'],
                'Max Out-Degree': metrics['max_out_degree'],
                'Graph Density': round(metrics['density'], 6),
                'Strong Components': metrics['strongly_connected_components']
            })
        
        stats_df = pd.DataFrame(stats_data)
        stats_df.to_csv(f"result/{output_prefix}_statistics.csv", index=False, encoding='utf-8')
        
        # 2. Export Jaccard similarity matrix
        tools = list(tool_data.keys())
        similarity_data = []
        
        for tool1 in tools:
            row = {'Tool': tool1}
            for tool2 in tools:
                if tool1 == tool2:
                    row[tool2] = 1.0
                elif tool1 in failed_tools or tool2 in failed_tools:
                    row[tool2] = 'N/A'  # Mark failed tools as N/A
                else:
                    func1 = tool_data[tool1]['functions']
                    func2 = tool_data[tool2]['functions']
                    common = len(func1 & func2)
                    union = len(func1 | func2)
                    jaccard = common / union if union > 0 else 0
                    row[tool2] = round(jaccard, 4)
            similarity_data.append(row)
        
        similarity_df = pd.DataFrame(similarity_data)
        similarity_df.to_csv(f"result/{output_prefix}_similarity.csv", index=False, encoding='utf-8')
        
        # 3. Export function comparison
        all_functions = sorted(comparison['all_functions'])
        func_data = []
        
        for func in all_functions:
            row = {'Function Name': func}
            for tool in tools:
                if tool in failed_tools:
                    row[tool] = 'N/A'  # Mark failed tools as N/A
                else:
                    row[tool] = '✓' if func in tool_data[tool]['functions'] else '✗'
            func_data.append(row)
        
        func_df = pd.DataFrame(func_data)
        func_df.to_csv(f"result/{output_prefix}_functions.csv", index=False, encoding='utf-8')
        
        print(f"Comparison results exported to:")
        print(f"  - result/{output_prefix}_statistics.csv")
        print(f"  - result/{output_prefix}_similarity.csv")
        print(f"  - result/{output_prefix}_functions.csv")
        
        if failed_tools:
            print(f"⚠️  Note: {', '.join(failed_tools)} tool analysis failed, marked as 'N/A' in CSV files")


