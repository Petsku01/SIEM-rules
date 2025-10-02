
# Testing script and quick start guide for YARA Rule Manager
# Run this after saving the main yara_manager.py file


import os
import sys
from pathlib import Path

# Add current directory to path to import yara_manager
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

try:
    from yara_manager import (
        YaraRuleManager, 
        YaraRule, 
        RuleSeverity, 
        RuleStatus,
        YaraRuleValidator
    )
except ImportError:
    print("Error: yara_manager.py not found in current directory")
    print("Please save the main script as yara_manager.py first")
    sys.exit(1)


def test_basic_operations():
    """Test basic CRUD operations"""
    print("="*60)
    print("YARA Rule Manager - Basic Operations Test")
    print("="*60)
    
    # Initialize manager with test database
    manager = YaraRuleManager("test_rules.db")
    
    try:
        # Test 1: Add a simple rule
        print("\n1. Adding a test rule...")
        test_rule = YaraRule(
            name="test_simple_strings",
            content="""rule test_simple_strings {
    meta:
        description = "Test rule for demonstration"
        author = "Test Script"
    strings:
        $test1 = "malware"
        $test2 = "suspicious"
    condition:
        any of them
}""",
            description="Simple test rule",
            author="Test Script",
            severity=RuleSeverity.LOW.value,
            status=RuleStatus.TESTING.value,
            tags=["test", "demo"],
            category="testing"
        )
        
        rule_id = manager.db.add_rule(test_rule)
        print(f"✓ Added rule with ID: {rule_id}")
        
        # Test 2: Retrieve the rule
        print("\n2. Retrieving rule...")
        retrieved = manager.db.get_rule(rule_id=rule_id)
        if retrieved:
            print(f"✓ Retrieved rule: {retrieved.name}")
            print(f"  - Status: {retrieved.status}")
            print(f"  - Tags: {', '.join(retrieved.tags)}")
        
        # Test 3: Search functionality
        print("\n3. Testing search...")
        results = manager.db.search_rules(query="test", tags=["demo"])
        print(f"✓ Found {len(results)} matching rules")
        
        # Test 4: Update the rule
        print("\n4. Updating rule status...")
        retrieved.status = RuleStatus.ACTIVE.value
        retrieved.version = "1.1"
        if manager.db.update_rule(retrieved):
            print("✓ Rule updated successfully")
        
        # Test 5: Statistics
        print("\n5. Getting statistics...")
        stats = manager.db.get_statistics()
        print(f"✓ Total rules in database: {stats['total_rules']}")
        for status, count in stats['by_status'].items():
            print(f"  - {status}: {count}")
        
        # Test 6: Validation
        print("\n6. Testing validation...")
        valid_rule = """rule valid_test {
    strings:
        $a = "test"
    condition:
        $a
}"""
        
        invalid_rule = """rule invalid_test {
    strings:
        $a = "test"
}"""  # Missing condition
        
        is_valid, msg = YaraRuleValidator.validate_syntax(valid_rule)
        print(f"  Valid rule test: {'✓' if is_valid else '✗'} - {msg}")
        
        is_valid, msg = YaraRuleValidator.validate_syntax(invalid_rule)
        print(f"  Invalid rule test: {'✓' if not is_valid else '✗'} - {msg}")
        
        # Test 7: Export
        print("\n7. Testing export...")
        export_dir = Path("test_export")
        export_dir.mkdir(exist_ok=True)
        
        if manager.export_rule(rule_id, str(export_dir / "test_rule.yar")):
            print(f"✓ Exported rule to test_export/test_rule.yar")
        
        # Test 8: Compile
        print("\n8. Testing compilation...")
        compiled = manager.compile_rules("test_compiled.yar", status=RuleStatus.ACTIVE.value)
        print(f"✓ Compiled {compiled} rules to test_compiled.yar")
        
        print("\n" + "="*60)
        print("All tests completed successfully!")
        print("="*60)
        
    except Exception as e:
        print(f"\n✗ Error during testing: {e}")
        import traceback
        traceback.print_exc()
    
    finally:
        manager.close()


def create_sample_rules():
    """Create sample YARA rule files for testing"""
    print("\nCreating sample YARA rule files...")
    
    rules_dir = Path("sample_rules")
    rules_dir.mkdir(exist_ok=True)
    
    # Sample rule 1: Network indicators
    rule1 = """rule network_backdoor_generic {
    meta:
        description = "Generic network backdoor indicators"
        author = "Security Team"
        date = "2024-01-01"
        severity = "high"
    strings:
        $cmd1 = "reverse_tcp"
        $cmd2 = "bind_tcp"
        $port1 = ":4444"
        $port2 = ":5555"
    condition:
        any of ($cmd*) and any of ($port*)
}"""
    
    # Sample rule 2: Suspicious strings
    rule2 = """rule suspicious_registry_modification {
    meta:
        description = "Detects registry modification attempts"
        author = "Security Team"
        severity = "medium"
    strings:
        $reg1 = "RegCreateKeyEx"
        $reg2 = "RegSetValueEx"
        $reg3 = "HKEY_LOCAL_MACHINE"
        $run = "CurrentVersion\\\\Run"
    condition:
        2 of ($reg*) and $run
}"""
    
    # Sample rule 3: Encoding detection
    rule3 = """rule base64_executable {
    meta:
        description = "Detects base64 encoded executables"
        author = "Security Team"
        severity = "high"
    strings:
        $mz = "TVqQAAMAAAAEAAAA"  // Base64 "MZ" header
        $pattern = /[A-Za-z0-9+\/]{100,}={0,2}/
    condition:
        $mz and $pattern
}"""
    
    # Write rules to files
    (rules_dir / "network_detection.yar").write_text(rule1)
    (rules_dir / "registry_monitoring.yar").write_text(rule2)
    (rules_dir / "encoding_detection.yar").write_text(rule3)
    
    print(f"✓ Created 3 sample rules in {rules_dir}/")
    return str(rules_dir)


def quick_start_demo():
    """Complete quick start demonstration"""
    print("\n" + "="*60)
    print("YARA Rule Manager - Quick Start Demo")
    print("="*60)
    
    # Create sample rules
    rules_dir = create_sample_rules()
    
    # Initialize manager
    manager = YaraRuleManager("demo.db")
    
    try:
        # Import rules
        print(f"\nImporting rules from {rules_dir}...")
        results = manager.import_directory(
            rules_dir,
            recursive=True,
            author="Demo Import",
            status=RuleStatus.TESTING.value,
            tags=["demo", "imported"]
        )
        
        print(f"✓ Import complete:")
        print(f"  - Imported: {len(results['imported'])}")
        print(f"  - Failed: {len(results['failed'])}")
        print(f"  - Skipped: {len(results['skipped'])}")
        
        # List rules
        print("\nListing all rules:")
        rules = manager.db.list_all(limit=10)
        for rule in rules:
            print(f"  [{rule.id}] {rule.name} - {rule.status} ({rule.severity})")
        
        # Search example
        print("\nSearching for 'network' rules:")
        results = manager.db.search_rules(query="network")
        for rule in results:
            print(f"  - {rule.name}: {rule.description}")
        
        # Export active rules
        print("\nExporting rules...")
        export_dir = Path("demo_export")
        count = manager.export_all(str(export_dir))
        print(f"✓ Exported {count} rules to {export_dir}/")
        
        # Show statistics
        print("\nDatabase Statistics:")
        stats = manager.db.get_statistics()
        print(f"  Total Rules: {stats['total_rules']}")
        print(f"  By Status: {stats['by_status']}")
        print(f"  By Severity: {stats['by_severity']}")
        
        print("\n" + "="*60)
        print("Demo completed! Check the following:")
        print("  - demo.db: SQLite database with imported rules")
        print("  - sample_rules/: Sample YARA rule files")
        print("  - demo_export/: Exported rule files")
        print("="*60)
        
    finally:
        manager.close()


def main():
    """Main entry point for test script"""
    print("\nYARA Rule Manager Test Suite")
    print("-" * 40)
    print("1. Run basic operations test")
    print("2. Run quick start demo")
    print("3. Run both")
    print("4. Exit")
    
    choice = input("\nSelect option (1-4): ").strip()
    
    if choice == "1":
        test_basic_operations()
    elif choice == "2":
        quick_start_demo()
    elif choice == "3":
        test_basic_operations()
        print("\n" + "="*60 + "\n")
        quick_start_demo()
    elif choice == "4":
        print("Exiting...")
    else:
        print("Invalid choice")
    
    print("\nTo use the CLI, run:")
    print("  python yara_manager.py --help")
    print("\nExample commands:")
    print("  python yara_manager.py import sample_rules/ -r")
    print("  python yara_manager.py list")
    print("  python yara_manager.py search malware")
    print("  python yara_manager.py stats")


if __name__ == "__main__":
    main()
