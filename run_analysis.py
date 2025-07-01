#!/usr/bin/env python3
"""
Simplified call graph comparison tool
Run this script to analyze four call graph files in the graph folder
"""

from multi_comparison import MultiCallGraphComparator, Logger
import sys

def main():
    """Main function - simplified version"""
    print("Starting multi-tool call graph comparison analysis...")
    
    # Setup log output
    logger = Logger('analysis_log.txt')
    sys.stdout = logger
    
    try:
        # Create comparator and run analysis
        comparator = MultiCallGraphComparator()
        comparison = comparator.compare_all_call_graphs()
        
        # Generate report
        report = comparator.generate_comparison_report(comparison)
        print(report)
        
        # Generate charts and CSV files
        print("\nGenerating visualization charts...")
        comparator.visualize_comparison(comparison)
        
        print("\nExporting comparison results to CSV files...")
        comparator.export_to_csv(comparison, "multi_callgraph_comparison")
        
        print("\n✅ Analysis complete!")
        print("📁 Output files:")
        print("  - analysis_log.txt (complete log)")
        print("  - result/function_discovery_comparison.png (function discovery comparison)")
        print("  - result/call_relationship_comparison.png (call relationship comparison)")
        print("  - result/graph_density_comparison.png (graph density comparison)")
        print("  - result/similarity_heatmap.png (similarity heatmap)")
        print("  - result/multi_callgraph_comparison_*.csv (basic data)")
        print("  - result/function_level_analysis_*.csv (high-level/low-level data)")
        
    except (FileNotFoundError, ValueError) as e:
        print(f"❌ Fatal error during analysis: {e}")
        print("Program cannot continue. Please check:")
        print("  1. All required graph files exist (except angr_emul.dot)")
        print("  2. Graph files are valid and contain data")
        print("  3. File paths and permissions are correct")
        return 1  # Return error code
        
    except Exception as e:
        print(f"❌ Unexpected error during analysis: {e}")
        print("This may be an internal program error, please check the logs for more information.")
        return 1  # Return error code
        
    finally:
        # Ensure log file is properly closed
        logger.close()
        sys.stdout = sys.__stdout__
        print("📊 Analysis results saved to analysis_log.txt")
    
    return 0  # Success return

if __name__ == "__main__":
    exit_code = main()
    exit(exit_code)
