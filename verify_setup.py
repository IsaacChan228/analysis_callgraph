#!/usr/bin/env python3
"""
Setup verification script for Multi-Tool Call Graph Comparison Framework
Run this script to verify that all required dependencies are properly installed.
"""

import sys
import importlib

def check_package(package_name, min_version=None):
    """Check if a package is installed and optionally verify minimum version"""
    try:
        package = importlib.import_module(package_name)
        version = getattr(package, '__version__', 'Unknown')
        
        if min_version and hasattr(package, '__version__'):
            try:
                from packaging import version as pkg_version
                if pkg_version.parse(package.__version__) < pkg_version.parse(min_version):
                    return False, f"{package_name} {version} (requires >= {min_version})"
            except ImportError:
                # If packaging module is not available, just show version without comparison
                pass
        
        return True, f"{package_name} {version}"
    except ImportError:
        return False, f"{package_name} (not installed)"

def main():
    """Main verification function"""
    print("🔍 Verifying Multi-Tool Call Graph Analysis Framework Setup...")
    print("=" * 60)
    
    # Required packages with minimum versions
    required_packages = [
        ('pandas', '1.5.0'),
        ('numpy', '1.21.0'),
        ('networkx', '2.8.0'),
        ('matplotlib', '3.5.0'),
    ]
    
    # Optional packages
    optional_packages = [
        ('seaborn', '0.11.0'),
        ('scipy', '1.9.0'),
    ]
    
    # Built-in packages (no version check needed)
    builtin_packages = ['re', 'sys', 'typing']
    
    all_good = True
    
    print("📦 Required Packages:")
    for package, min_ver in required_packages:
        success, info = check_package(package, min_ver)
        status = "✅" if success else "❌"
        print(f"  {status} {info}")
        if not success:
            all_good = False
    
    print("\n📦 Built-in Packages:")
    for package in builtin_packages:
        success, info = check_package(package)
        status = "✅" if success else "❌"
        print(f"  {status} {info}")
        if not success:
            all_good = False
    
    print("\n📦 Optional Packages:")
    for package, min_ver in optional_packages:
        success, info = check_package(package, min_ver)
        status = "✅" if success else "⚠️ "
        print(f"  {status} {info}")
    
    print("\n" + "=" * 60)
    
    if all_good:
        print("🎉 All required dependencies are installed!")
        print("✅ Framework is ready to use.")
        print("\n💡 Quick start:")
        print("   1. Place your call graph files in the graph/ directory")
        print("   2. Run: python3 run_analysis.py")
        return 0
    else:
        print("❌ Some required dependencies are missing or outdated.")
        print("\n🔧 To install missing packages:")
        print("   pip install -r requirements.txt")
        return 1

if __name__ == "__main__":
    sys.exit(main())
