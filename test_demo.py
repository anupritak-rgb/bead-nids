"""
Test and Demonstration Script

This script demonstrates the Benford analyzer with sample data
without requiring actual malware samples.

Author: Benford Malware Analysis Project
Date: November 2025
"""

import numpy as np
import sys
from benford_analyzer import BenfordAnalyzer


def generate_benign_data(size=1000):
    """
    Generate data that follows Benford's Law.
    
    Examples: File sizes, financial data, population numbers
    """
    # Use exponential distribution which naturally follows Benford
    benign = []
    
    # Simulate file sizes
    for _ in range(size):
        # Random between 1KB and 100MB
        base = np.random.exponential(scale=10000)
        size_bytes = int(base * np.random.uniform(1, 100))
        if size_bytes > 0:
            benign.append(size_bytes)
    
    return benign


def generate_malicious_data(size=1000):
    """
    Generate data that violates Benford's Law.
    
    Examples: Encrypted data, artificially generated data
    """
    # Uniform distribution (like encrypted data)
    malicious = []
    
    for _ in range(size):
        # Uniform random between 1000 and 9999
        value = np.random.randint(1000, 10000)
        malicious.append(value)
    
    return malicious


def generate_ransomware_pattern():
    """
    Simulate ransomware file size patterns.
    
    Before encryption: Natural distribution
    After encryption: Padded to block sizes (artificial spikes)
    """
    # Natural file sizes
    natural = generate_benign_data(500)
    
    # Encrypted + padded to 16-byte blocks (AES)
    block_size = 16
    encrypted = []
    
    for size in natural:
        # Add AES padding
        padded_size = ((size // block_size) + 1) * block_size
        encrypted.append(padded_size)
    
    return natural, encrypted


def test_benford_analyzer():
    """Run comprehensive tests on the Benford analyzer."""
    print("\n" + "="*70)
    print("BENFORD ANALYZER TEST SUITE")
    print("="*70)
    
    analyzer = BenfordAnalyzer()
    
    # Test 1: Benign/Natural Data
    print("\n" + "-"*70)
    print("TEST 1: Natural Data (Should PASS Benford Test)")
    print("-"*70)
    benign = generate_benign_data(1000)
    print(f"Generated {len(benign)} benign data points")
    results1 = analyzer.analyze(benign, verbose=True)
    
    if results1['compliant']:
        print("✅ TEST 1 PASSED: Data conforms to Benford's Law (as expected)")
    else:
        print("⚠️ TEST 1: Unexpected result (may occur due to randomness)")
    
    # Test 2: Encrypted/Random Data
    print("\n" + "-"*70)
    print("TEST 2: Encrypted/Random Data (Should FAIL Benford Test)")
    print("-"*70)
    malicious = generate_malicious_data(1000)
    print(f"Generated {len(malicious)} random/encrypted data points")
    results2 = analyzer.analyze(malicious, verbose=True)
    
    if not results2['compliant']:
        print("✅ TEST 2 PASSED: Data violates Benford's Law (as expected)")
    else:
        print("⚠️ TEST 2: Unexpected result (may occur due to randomness)")
    
    # Test 3: Real-world Example - Powers of 2 (common in computing)
    print("\n" + "-"*70)
    print("TEST 3: Powers of 2 (Common File/Memory Sizes)")
    print("-"*70)
    powers_of_two = [2**i for i in range(1, 25)] * 10  # Repeat for better stats
    print(f"Testing {len(powers_of_two)} power-of-2 values")
    results3 = analyzer.analyze(powers_of_two, verbose=True)
    
    # Test 4: Mixed Data (Partially Encrypted - Like Intermittent Ransomware)
    print("\n" + "-"*70)
    print("TEST 4: Mixed Natural + Random (Intermittent Encryption)")
    print("-"*70)
    mixed = generate_benign_data(500) + generate_malicious_data(500)
    print(f"Testing {len(mixed)} mixed data points (50% benign, 50% malicious)")
    results4 = analyzer.analyze(mixed, verbose=True)
    
    # Test 5: Ransomware File Size Pattern
    print("\n" + "-"*70)
    print("TEST 5: Ransomware Encryption Pattern Simulation")
    print("-"*70)
    natural, encrypted = generate_ransomware_pattern()
    
    print("\n[*] BEFORE Encryption (Natural files):")
    results5a = analyzer.analyze(natural, verbose=True)
    
    print("\n[*] AFTER Encryption (Block-padded files):")
    results5b = analyzer.analyze(encrypted, verbose=True)
    
    print("\n📊 COMPARISON:")
    print(f"  Before Encryption - Compliant: {results5a['compliant']}")
    print(f"  After Encryption  - Compliant: {results5b['compliant']}")
    print(f"  MAD Increase: {results5b['mad'] - results5a['mad']:.4f}")
    
    if results5a['compliant'] and not results5b['compliant']:
        print("✅ TEST 5 PASSED: Ransomware pattern detected!")
    
    # Summary
    print("\n" + "="*70)
    print("TEST SUITE SUMMARY")
    print("="*70)
    print(f"\nTest 1 (Natural Data):       {'PASS ✅' if results1['compliant'] else 'UNEXPECTED ⚠️'}")
    print(f"Test 2 (Encrypted Data):     {'PASS ✅' if not results2['compliant'] else 'UNEXPECTED ⚠️'}")
    print(f"Test 3 (Powers of 2):        Informational")
    print(f"Test 4 (Mixed Data):         Informational")
    print(f"Test 5 (Ransomware Pattern): {'DETECTED ✅' if not results5b['compliant'] else 'NOT DETECTED ⚠️'}")
    print("\n✨ All tests completed!")
    
    # Generate visualizations
    print("\n" + "="*70)
    print("GENERATING VISUALIZATIONS")
    print("="*70)
    
    try:
        print("\n[*] Generating visualization for benign data...")
        analyzer.visualize(benign, save_path="output/visualizations/test_benign.png",
                          title="Test 1: Natural/Benign Data Distribution")
        
        print("[*] Generating visualization for malicious data...")
        analyzer.visualize(malicious, save_path="output/visualizations/test_malicious.png",
                          title="Test 2: Encrypted/Random Data Distribution")
        
        print("[*] Generating visualization for ransomware pattern...")
        analyzer.visualize(encrypted, save_path="output/visualizations/test_ransomware.png",
                          title="Test 5: Ransomware Encrypted Files")
        
        print("\n✅ Visualizations saved to output/visualizations/")
        
    except Exception as e:
        print(f"[!] Visualization error: {str(e)}")
        print("[!] This is normal if matplotlib cannot display in your environment")


def demo_statistical_metrics():
    """Demonstrate different statistical metrics."""
    print("\n" + "="*70)
    print("STATISTICAL METRICS DEMONSTRATION")
    print("="*70)
    
    analyzer = BenfordAnalyzer()
    
    # Create data with known characteristics
    perfect_benford = []
    for digit in range(1, 10):
        count = int(analyzer.benford_probs[digit-1] * 1000)
        perfect_benford.extend([digit * 100] * count)
    
    print("\n[*] Testing with theoretically perfect Benford data...")
    results = analyzer.analyze(perfect_benford, verbose=False)
    
    print(f"\nStatistical Metrics:")
    print(f"  Chi-Square Statistic: {results['chi_square_statistic']:.6f}")
    print(f"  Chi-Square P-Value:   {results['chi_square_p_value']:.6f}")
    print(f"  KS Statistic:         {results['ks_statistic']:.6f}")
    print(f"  KS P-Value:           {results['ks_p_value']:.6f}")
    print(f"  MAD:                  {results['mad']:.6f}")
    print(f"  KL Divergence:        {results['kl_divergence']:.6f}")
    print(f"\n  Compliant: {results['compliant']}")
    print("\n📝 Note: Even 'perfect' data may show small deviations due to rounding")


if __name__ == "__main__":
    print("""
╔═══════════════════════════════════════════════════════════════════╗
║                                                                   ║
║   BENFORD'S LAW ANALYZER - TEST & DEMONSTRATION                  ║
║                                                                   ║
║   This script demonstrates the analyzer with synthetic data      ║
║   No malware samples required!                                   ║
║                                                                   ║
╚═══════════════════════════════════════════════════════════════════╝
    """)
    
    print("\nSelect test mode:")
    print("  1. Run full test suite")
    print("  2. Statistical metrics demo")
    print("  3. Both")
    
    if len(sys.argv) > 1:
        choice = sys.argv[1]
    else:
        choice = input("\nEnter choice (1-3) [default: 3]: ").strip() or "3"
    
    try:
        if choice == "1":
            test_benford_analyzer()
        elif choice == "2":
            demo_statistical_metrics()
        elif choice == "3":
            test_benford_analyzer()
            demo_statistical_metrics()
        else:
            print(f"[!] Invalid choice: {choice}")
            sys.exit(1)
            
        print("\n✨ Demo completed successfully!")
        print("\nNext steps:")
        print("  • Try analyzing real PE files: python main.py --mode pe --file <file>")
        print("  • Check output/visualizations/ for generated charts")
        print("  • Read README.md for more examples\n")
        
    except KeyboardInterrupt:
        print("\n\n[!] Demo interrupted by user")
        sys.exit(130)
    except Exception as e:
        print(f"\n[!] Error during demo: {str(e)}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
