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
    
    # Tools that are allowed to fail without terminating the program
    OPTIONAL_TOOLS = {'angr_emul', 'gcc'}
    
    def normalize_function_name(self, name: str) -> str:
        """Standardize function names"""
        if not name:
            return None
        
        # Strip whitespace and normalize
        name = name.strip()
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
        
        # Additional normalization to prevent duplicates
        name = name.strip()  # Remove any remaining whitespace
        
        # Handle special cases
        if name.startswith('case.') or name.startswith('switch.'):
            return None
        
        # If name becomes empty or contains only digits, return None
        if not name or name.isdigit():
            return None
        
        # Convert to lowercase for case-insensitive comparison to reduce duplicates
        # but preserve original case for readability
        normalized_lower = name.lower()
        
        # Filter out common generic names that might cause duplicates
        generic_names = {'unknown', 'unnamed', 'noname', 'func', 'function', 'sub'}
        if normalized_lower in generic_names:
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
            if tool_name.lower() in self.OPTIONAL_TOOLS:
                print(f"⚠️  Warning: {tool_name} file not found ({dot_file}) - This is expected as {tool_name} may fail")
                return functions, calls
            else:
                print(f"❌ Fatal Error: Required {tool_name} file not found ({dot_file})")
                print(f"Program will terminate. Please ensure all required graph files exist.")
                raise FileNotFoundError(f"Required graph file missing: {dot_file}")
        except Exception as e:
            if tool_name.lower() in self.OPTIONAL_TOOLS:
                print(f"⚠️  Warning: Cannot read {tool_name} file ({dot_file}): {e} - Will skip this tool")
                return functions, calls
            else:
                print(f"❌ Fatal Error: Cannot read required {tool_name} file ({dot_file}): {e}")
                print(f"Program will terminate.")
                raise Exception(f"Failed to read required graph file: {dot_file}")
        
        # Check if file content is empty or invalid
        if not content.strip():
            if tool_name.lower() in self.OPTIONAL_TOOLS:
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
            if tool_name.lower() in self.OPTIONAL_TOOLS:
                print(f"⚠️  Warning: {tool_name} analysis failed or found no functions and call relationships - Will continue with other tools")
                print(f"    This may be due to:")
                if tool_name.lower() == 'angr_emul':
                    print(f"    - Angr emulation mode execution failure")
                elif tool_name.lower() == 'gcc':
                    print(f"    - GCC call graph generation failure")
                    print(f"    - Missing compilation flags or debug information")
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
        
        # Explicitly deduplicate and clean the data
        functions, calls = self._deduplicate_data(functions, calls, tool_name)
        
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
    
    def _deduplicate_data(self, functions: Set[str], calls: Set[Tuple[str, str]], tool_name: str) -> Tuple[Set[str], Set[Tuple[str, str]]]:
        """Explicitly deduplicate functions and calls with logging"""
        original_func_count = len(functions)
        original_call_count = len(calls)
        
        # Convert to set to ensure deduplication (even though they should already be sets)
        deduplicated_functions = set(functions)
        deduplicated_calls = set(calls)
        
        # Remove any self-calls (function calling itself) as they might be artifacts
        filtered_calls = set()
        self_call_count = 0
        for caller, callee in deduplicated_calls:
            if caller == callee:
                self_call_count += 1
            else:
                filtered_calls.add((caller, callee))
        
        final_func_count = len(deduplicated_functions)
        final_call_count = len(filtered_calls)
        
        # Log deduplication results if any duplicates were found
        if original_func_count != final_func_count:
            print(f"  🔧 {tool_name}: Removed {original_func_count - final_func_count} duplicate functions")
        
        if original_call_count != final_call_count + self_call_count:
            print(f"  🔧 {tool_name}: Removed {original_call_count - final_call_count - self_call_count} duplicate calls")
        
        if self_call_count > 0:
            print(f"  🔧 {tool_name}: Removed {self_call_count} self-calls")
        
        return deduplicated_functions, filtered_calls

class MultiCallGraphComparator:
    """Multi call graph comparison analyzer"""
    
    def __init__(self):
        self.normalizer = CallGraphNormalizer()
        self.tools = {
            'Radare2': 'graph/r2.dot',
            'Ghidra': 'graph/ghidra.gf',
            'Angr_Fast': 'graph/angr_fast.dot', 
            'Angr_Emul': 'graph/angr_emul.dot',
            'GCC': 'graph/gcc.dot'
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
                if tool_name.lower() in self.normalizer.OPTIONAL_TOOLS:
                    # Optional tool failure is acceptable, create empty data
                    print(f"⚠️  {tool_name} skipped: {str(e)}")
                    tool_data[tool_name] = {
                        'functions': set(),
                        'calls': set(),
                        'graph': self._create_graph(set(), set())
                    }
                    print(f"{tool_name}: 0 functions, 0 call relationships (skipped)")
                else:
                    # Required tool failures terminate the program
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
        
        # Calculate union and intersection of all tools with explicit deduplication
        all_functions = set()
        all_calls = set()
        
        print(f"\n🔍 Aggregating data from all tools:")
        for tool_name, data in tool_data.items():
            before_func_count = len(all_functions)
            before_call_count = len(all_calls)
            
            all_functions |= data['functions']
            all_calls |= data['calls']
            
            func_added = len(all_functions) - before_func_count
            call_added = len(all_calls) - before_call_count
            
            if func_added > 0 or call_added > 0:
                print(f"  + {tool_name}: Added {func_added} unique functions, {call_added} unique calls")
        
        print(f"📊 Total unique functions: {len(all_functions)}")
        print(f"📊 Total unique calls: {len(all_calls)}")
        
        # Calculate intersection with explicit logging
        common_functions = all_functions.copy()
        common_calls = all_calls.copy()
        
        print(f"\n🔍 Finding common elements across tools:")
        for tool_name, data in tool_data.items():
            before_common_func = len(common_functions)
            before_common_call = len(common_calls)
            
            common_functions &= data['functions']
            common_calls &= data['calls']
            
            func_removed = before_common_func - len(common_functions)
            call_removed = before_common_call - len(common_calls)
            
            if func_removed > 0 or call_removed > 0:
                print(f"  - {tool_name}: Filtered out {func_removed} functions, {call_removed} calls not in common")
        
        print(f"📊 Common functions: {len(common_functions)}")
        print(f"📊 Common calls: {len(common_calls)}")
        
        # Final validation - ensure no duplicates in the final results
        print(f"\n✅ Final validation:")
        print(f"  - All functions are unique: {len(all_functions) == len(set(all_functions))}")
        print(f"  - All calls are unique: {len(all_calls) == len(set(all_calls))}")
        print(f"  - Common functions are unique: {len(common_functions) == len(set(common_functions))}")
        print(f"  - Common calls are unique: {len(common_calls) == len(set(common_calls))}")
        
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
            
            # Calculate mixed-level calls
            mixed_level_calls = set()
            for caller, callee in data['calls']:
                caller_is_high = caller in classification['high_level']
                callee_is_high = callee in classification['high_level']
                if (caller_is_high and not callee_is_high) or (not caller_is_high and callee_is_high):
                    mixed_level_calls.add((caller, callee))
            
            tool_level_data[tool_name] = {
                'high_level_funcs': classification['high_level'],
                'low_level_funcs': classification['low_level'],
                'high_level_calls': high_level_calls,
                'low_level_calls': low_level_calls,
                'mixed_level_calls': mixed_level_calls,
                'high_level_graph': self._create_graph(classification['high_level'], high_level_calls),
                'low_level_graph': self._create_graph(classification['low_level'], low_level_calls)
            }
        
        tools = list(tool_data.keys())
        colors = ['#ff7f0e', '#9467bd', '#2ca02c', '#d62728', '#17becf']
        
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
        self._export_level_data_to_csv(tool_data, tool_level_data, "function_level_analysis")
    
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
        fig, ((ax1, ax2), (ax3, ax4)) = plt.subplots(2, 2, figsize=(18, 12))
        
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
        
        # Mixed-level call relationship comparison
        self._create_bar_chart(ax4, tools,
                              [len(tool_level_data[t]['mixed_level_calls']) for t in tools],
                              bar_colors, failed_tools, 'Mixed-Level Call Relationships', 'Number of Calls')
        
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
    
    def _export_level_data_to_csv(self, tool_data, tool_level_data, output_prefix: str):
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
        
        # 2. Export call relationships with level classification
        all_high_level_calls = set()
        all_low_level_calls = set()
        
        for data in tool_level_data.values():
            all_high_level_calls |= data['high_level_calls']
            all_low_level_calls |= data['low_level_calls']
        
        # Combine all calls and classify them
        all_calls_with_level = []
        
        # Add high-level calls
        for caller, callee in sorted(all_high_level_calls):
            row = {'Caller': caller, 'Callee': callee, 'Call Type': 'High-High'}
            for tool in tools:
                row[tool] = 'Y' if (caller, callee) in tool_level_data[tool]['high_level_calls'] else 'N'
            all_calls_with_level.append(row)
        
        # Add low-level calls
        for caller, callee in sorted(all_low_level_calls):
            row = {'Caller': caller, 'Callee': callee, 'Call Type': 'Low-Low'}
            for tool in tools:
                row[tool] = 'Y' if (caller, callee) in tool_level_data[tool]['low_level_calls'] else 'N'
            all_calls_with_level.append(row)
        
        # Check for mixed-level calls (high->low or low->high)
        all_mixed_calls = set()
        for tool_name, level_data in tool_level_data.items():
            original_calls = tool_data[tool_name]['calls']  # Get original calls from tool_data
            for caller, callee in original_calls:
                # Check if this is a mixed-level call
                caller_is_high = caller in level_data['high_level_funcs']
                callee_is_high = callee in level_data['high_level_funcs']
                
                if (caller_is_high and not callee_is_high) or (not caller_is_high and callee_is_high):
                    all_mixed_calls.add((caller, callee, 'Mixed-Level'))
        
        # Add mixed-level calls
        for caller, callee, call_type in sorted(all_mixed_calls):
            row = {'Caller': caller, 'Callee': callee, 'Call Type': call_type}
            for tool in tools:
                # Check if this call exists in the tool's original call data
                row[tool] = 'Y' if (caller, callee) in tool_data[tool]['calls'] else 'N'
            all_calls_with_level.append(row)
        
        calls_df = pd.DataFrame(all_calls_with_level)
        calls_df.to_csv(f"result/{output_prefix}_calls.csv", index=False, encoding='utf-8')
        
        print(f"High-level/low-level function analysis data exported to:")
        print(f"  - result/{output_prefix}_statistics.csv (statistics summary)")
        print(f"  - result/{output_prefix}_calls.csv (call relationships with level classification)")
    
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
        
        # 3. Export function comparison with level classification
        all_functions = sorted(comparison['all_functions'])
        
        # Create combined classification for all functions
        all_high_level_funcs = set()
        all_low_level_funcs = set()
        
        # Collect all function classifications from all tools
        for tool_name, data in tool_data.items():
            if tool_name not in failed_tools:
                classification = self._classify_functions(data['functions'])
                all_high_level_funcs |= classification['high_level']
                all_low_level_funcs |= classification['low_level']
        
        func_data = []
        
        for func in all_functions:
            # Determine function level - if classified as high-level by any tool, mark as high-level
            if func in all_high_level_funcs:
                func_level = 'High-Level'
            elif func in all_low_level_funcs:
                func_level = 'Low-Level'
            else:
                # Fallback classification for unclassified functions
                classification = self._classify_functions({func})
                func_level = 'High-Level' if func in classification['high_level'] else 'Low-Level'
            
            row = {'Function Name': func, 'Level': func_level}
            for tool in tools:
                if tool in failed_tools:
                    row[tool] = 'N/A'  # Mark failed tools as N/A
                else:
                    row[tool] = 'Y' if func in tool_data[tool]['functions'] else 'N'
            func_data.append(row)
        
        func_df = pd.DataFrame(func_data)
        func_df.to_csv(f"result/{output_prefix}_functions.csv", index=False, encoding='utf-8')
        
        print(f"Comparison results exported to:")
        print(f"  - result/{output_prefix}_statistics.csv")
        print(f"  - result/{output_prefix}_similarity.csv")
        print(f"  - result/{output_prefix}_functions.csv")
        
        if failed_tools:
            print(f"⚠️  Note: {', '.join(failed_tools)} tool analysis failed, marked as 'N/A' in CSV files")
    
    def _perform_gcc_coverage_analysis(self, comparison: Dict) -> Dict:
        """Perform GCC-based coverage analysis - calculate percentage of GCC functions/calls found in other tools"""
        tool_data = comparison['tool_data']
        
        # Check if GCC data exists and is valid
        if 'GCC' not in tool_data:
            print("⚠️  Warning: GCC data not found, skipping coverage analysis")
            return None
            
        gcc_data = tool_data['GCC']
        if len(gcc_data['functions']) == 0 and len(gcc_data['calls']) == 0:
            print("⚠️  Warning: GCC data is empty, skipping coverage analysis")
            return None
        
        gcc_functions = gcc_data['functions']
        gcc_calls = gcc_data['calls']
        
        print(f"\n📊 GCC Coverage Analysis:")
        print(f"Using GCC as reference standard:")
        print(f"  - GCC functions: {len(gcc_functions)}")
        print(f"  - GCC calls: {len(gcc_calls)}")
        
        coverage_results = {}
        
        # Analyze each tool's coverage of GCC functions and calls
        for tool_name, data in tool_data.items():
            if tool_name == 'GCC':
                continue  # Skip GCC itself
                
            tool_functions = data['functions']
            tool_calls = data['calls']
            
            # Calculate function coverage
            if len(gcc_functions) > 0:
                common_functions = gcc_functions & tool_functions
                function_coverage = len(common_functions) / len(gcc_functions) * 100
            else:
                function_coverage = 0
                common_functions = set()
            
            # Calculate call coverage
            if len(gcc_calls) > 0:
                common_calls = gcc_calls & tool_calls
                call_coverage = len(common_calls) / len(gcc_calls) * 100
            else:
                call_coverage = 0
                common_calls = set()
            
            coverage_results[tool_name] = {
                'function_coverage': function_coverage,
                'call_coverage': call_coverage,
                'common_functions': common_functions,
                'common_calls': common_calls,
                'gcc_functions_found': len(common_functions),
                'gcc_calls_found': len(common_calls),
                'tool_total_functions': len(tool_functions),
                'tool_total_calls': len(tool_calls)
            }
            
            print(f"  {tool_name}:")
            print(f"    - Function coverage: {function_coverage:.1f}% ({len(common_functions)}/{len(gcc_functions)})")
            print(f"    - Call coverage: {call_coverage:.1f}% ({len(common_calls)}/{len(gcc_calls)})")
        
        return {
            'gcc_functions': gcc_functions,
            'gcc_calls': gcc_calls,
            'coverage_results': coverage_results
        }
    
    def _export_gcc_coverage_to_csv(self, coverage_analysis: Dict, output_prefix: str = "gcc_coverage"):
        """Export GCC coverage analysis to CSV"""
        if not coverage_analysis:
            return
            
        coverage_results = coverage_analysis['coverage_results']
        
        # 1. Export coverage statistics
        stats_data = []
        for tool_name, results in coverage_results.items():
            stats_data.append({
                'Tool': tool_name,
                'GCC Functions Found': results['gcc_functions_found'],
                'Total GCC Functions': len(coverage_analysis['gcc_functions']),
                'Function Coverage (%)': round(results['function_coverage'], 2),
                'GCC Calls Found': results['gcc_calls_found'],
                'Total GCC Calls': len(coverage_analysis['gcc_calls']),
                'Call Coverage (%)': round(results['call_coverage'], 2),
                'Tool Total Functions': results['tool_total_functions'],
                'Tool Total Calls': results['tool_total_calls']
            })
        
        stats_df = pd.DataFrame(stats_data)
        stats_df.to_csv(f"result/{output_prefix}_statistics.csv", index=False, encoding='utf-8')
        
        # 2. Export detailed function coverage
        gcc_functions = sorted(coverage_analysis['gcc_functions'])
        func_coverage_data = []
        
        for func in gcc_functions:
            row = {'Function Name': func, 'In GCC': 'Y'}
            for tool_name, results in coverage_results.items():
                row[tool_name] = 'Y' if func in results['common_functions'] else 'N'
            func_coverage_data.append(row)
        
        func_coverage_df = pd.DataFrame(func_coverage_data)
        func_coverage_df.to_csv(f"result/{output_prefix}_functions.csv", index=False, encoding='utf-8')
        
        # 3. Export detailed call coverage
        gcc_calls = sorted(coverage_analysis['gcc_calls'])
        call_coverage_data = []
        
        for caller, callee in gcc_calls:
            row = {'Caller': caller, 'Callee': callee, 'In GCC': 'Y'}
            for tool_name, results in coverage_results.items():
                row[tool_name] = 'Y' if (caller, callee) in results['common_calls'] else 'N'
            call_coverage_data.append(row)
        
        call_coverage_df = pd.DataFrame(call_coverage_data)
        call_coverage_df.to_csv(f"result/{output_prefix}_calls.csv", index=False, encoding='utf-8')
        
        print(f"\nGCC coverage analysis exported to:")
        print(f"  - result/{output_prefix}_statistics.csv (coverage statistics)")
        print(f"  - result/{output_prefix}_functions.csv (function-level coverage)")
        print(f"  - result/{output_prefix}_calls.csv (call-level coverage)")
    
    def _create_gcc_coverage_chart(self, coverage_analysis: Dict, output_prefix: str = "gcc_coverage"):
        """Create GCC coverage comparison chart"""
        if not coverage_analysis:
            return
            
        coverage_results = coverage_analysis['coverage_results']
        tools = list(coverage_results.keys())
        
        # Prepare data for visualization
        function_coverages = [coverage_results[tool]['function_coverage'] for tool in tools]
        call_coverages = [coverage_results[tool]['call_coverage'] for tool in tools]
        
        # Create chart
        fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(15, 6))
        
        # Colors for different tools (excluding GCC since it's the reference)
        colors = ['#ff7f0e', '#9467bd', '#2ca02c', '#d62728', '#17becf']
        bar_colors = [colors[i % len(colors)] for i in range(len(tools))]
        
        # Function coverage chart
        bars1 = ax1.bar(tools, function_coverages, color=bar_colors)
        ax1.set_title('Function Coverage vs GCC Reference', fontsize=14, fontweight='bold')
        ax1.set_ylabel('Coverage Percentage (%)')
        ax1.set_xlabel('Analysis Tools')
        ax1.set_ylim(0, 100)
        
        # Add percentage labels on bars
        for bar, coverage in zip(bars1, function_coverages):
            height = bar.get_height()
            ax1.text(bar.get_x() + bar.get_width()/2, height + 1,
                    f'{coverage:.1f}%', ha='center', va='bottom', fontweight='bold')
        
        # Call coverage chart
        bars2 = ax2.bar(tools, call_coverages, color=bar_colors)
        ax2.set_title('Call Relationship Coverage vs GCC Reference', fontsize=14, fontweight='bold')
        ax2.set_ylabel('Coverage Percentage (%)')
        ax2.set_xlabel('Analysis Tools')
        ax2.set_ylim(0, 100)
        
        # Add percentage labels on bars
        for bar, coverage in zip(bars2, call_coverages):
            height = bar.get_height()
            ax2.text(bar.get_x() + bar.get_width()/2, height + 1,
                    f'{coverage:.1f}%', ha='center', va='bottom', fontweight='bold')
        
        # Rotate x-axis labels if needed
        ax1.tick_params(axis='x', rotation=45)
        ax2.tick_params(axis='x', rotation=45)
        
        plt.tight_layout()
        plt.savefig(f'result/{output_prefix}_comparison.png', dpi=300, bbox_inches='tight')
        print(f"GCC coverage comparison chart saved as result/{output_prefix}_comparison.png")


