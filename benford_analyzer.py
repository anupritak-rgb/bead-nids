"""
Benford's Law Analyzer Module

This module implements Benford's Law analysis for detecting anomalies
in numerical data distributions, particularly useful for malware detection.

Author: Benford Malware Analysis Project
Date: November 2025
"""

import numpy as np
from scipy import stats
import matplotlib.pyplot as plt
import os
from typing import List, Dict, Tuple, Optional


class BenfordAnalyzer:
    """
    Analyzer for Benford's Law compliance.
    
    Benford's Law states that in many naturally occurring datasets,
    the leading digit is more likely to be small. Specifically:
    - Digit 1 appears ~30.1% of the time
    - Digit 2 appears ~17.6% of the time
    - ...
    - Digit 9 appears ~4.6% of the time
    
    Encrypted or artificially generated data typically violates this law.
    """
    
    def __init__(self):
        """Initialize the Benford analyzer with theoretical probabilities."""
        # Theoretical Benford probabilities for digits 1-9
        self.benford_probs = np.array([
            np.log10(1 + 1/d) for d in range(1, 10)
        ])
        
        # Thresholds for compliance testing
        self.mad_threshold = 0.015  # Mean Absolute Deviation threshold
        self.chi_square_alpha = 0.05  # Significance level for chi-square test
        self.ks_alpha = 0.05  # Significance level for KS test
        
    def extract_first_digits(self, data: List[float]) -> np.ndarray:
        """
        Extract the first significant digit from each number.
        
        Args:
            data: List of numerical values
            
        Returns:
            Array of first digits (1-9)
        """
        first_digits = []
        
        for value in data:
            # Convert to absolute value and skip zeros
            abs_value = abs(float(value))
            if abs_value == 0:
                continue
                
            # Get first digit by converting to string and finding first non-zero digit
            str_value = f"{abs_value:.10e}"  # Scientific notation
            for char in str_value:
                if char.isdigit() and char != '0':
                    first_digits.append(int(char))
                    break
                    
        return np.array(first_digits)
    
    def calculate_observed_frequencies(self, first_digits: np.ndarray) -> np.ndarray:
        """
        Calculate observed frequencies for each digit (1-9).
        
        Args:
            first_digits: Array of first digits
            
        Returns:
            Array of observed probabilities for digits 1-9
        """
        if len(first_digits) == 0:
            return np.zeros(9)
            
        counts = np.zeros(9)
        for digit in range(1, 10):
            counts[digit-1] = np.sum(first_digits == digit)
            
        return counts / len(first_digits)
    
    def calculate_mad(self, observed: np.ndarray, expected: np.ndarray) -> float:
        """
        Calculate Mean Absolute Deviation (MAD).
        
        MAD = mean(|observed - expected|)
        
        Args:
            observed: Observed frequencies
            expected: Expected (Benford) frequencies
            
        Returns:
            MAD value (lower is better)
        """
        return np.mean(np.abs(observed - expected))
    
    def chi_square_test(self, observed: np.ndarray, expected: np.ndarray, 
                       n_samples: int) -> Tuple[float, float]:
        """
        Perform chi-square goodness of fit test.
        
        Args:
            observed: Observed frequencies
            expected: Expected (Benford) frequencies
            n_samples: Number of data points
            
        Returns:
            Tuple of (chi_square_statistic, p_value)
        """
        expected_counts = expected * n_samples
        observed_counts = observed * n_samples
        
        # Avoid division by zero
        expected_counts = np.where(expected_counts == 0, 1e-10, expected_counts)
        
        chi_square_stat = np.sum((observed_counts - expected_counts)**2 / expected_counts)
        
        # Degrees of freedom = number of categories - 1
        df = len(observed) - 1
        p_value = 1 - stats.chi2.cdf(chi_square_stat, df)
        
        return chi_square_stat, p_value
    
    def ks_test(self, observed: np.ndarray, expected: np.ndarray) -> Tuple[float, float]:
        """
        Perform Kolmogorov-Smirnov test.
        
        Args:
            observed: Observed frequencies
            expected: Expected (Benford) frequencies
            
        Returns:
            Tuple of (ks_statistic, p_value)
        """
        # Calculate cumulative distributions
        observed_cdf = np.cumsum(observed)
        expected_cdf = np.cumsum(expected)
        
        # KS statistic is maximum difference between CDFs
        ks_stat = np.max(np.abs(observed_cdf - expected_cdf))
        
        # For Benford's Law, we can use a simplified p-value calculation
        # In practice, you might want to use scipy.stats.kstest for more accuracy
        n = len(observed)
        p_value = 2 * np.exp(-2 * n * ks_stat**2)
        
        return ks_stat, p_value
    
    def kl_divergence(self, observed: np.ndarray, expected: np.ndarray) -> float:
        """
        Calculate Kullback-Leibler divergence.
        
        KL(P||Q) = sum(P * log(P/Q))
        
        Args:
            observed: Observed distribution (P)
            expected: Expected distribution (Q)
            
        Returns:
            KL divergence value (0 = identical, higher = more different)
        """
        # Avoid log(0) by adding small epsilon
        epsilon = 1e-10
        observed = np.where(observed == 0, epsilon, observed)
        expected = np.where(expected == 0, epsilon, expected)
        
        return np.sum(observed * np.log(observed / expected))
    
    def analyze(self, data: List[float], verbose: bool = False) -> Dict:
        """
        Perform comprehensive Benford's Law analysis.
        
        Args:
            data: List of numerical values to analyze
            verbose: Whether to print detailed results
            
        Returns:
            Dictionary containing analysis results
        """
        # Extract first digits
        first_digits = self.extract_first_digits(data)
        
        if len(first_digits) == 0:
            return {
                'error': 'No valid data points',
                'compliant': False
            }
        
        # Calculate observed frequencies
        observed_freqs = self.calculate_observed_frequencies(first_digits)
        
        # Calculate various metrics
        mad = self.calculate_mad(observed_freqs, self.benford_probs)
        chi_sq_stat, chi_sq_p = self.chi_square_test(
            observed_freqs, self.benford_probs, len(first_digits)
        )
        ks_stat, ks_p = self.ks_test(observed_freqs, self.benford_probs)
        kl_div = self.kl_divergence(observed_freqs, self.benford_probs)
        
        # Determine compliance (passes if MAD below threshold AND chi-square p-value above alpha)
        compliant = (mad <= self.mad_threshold) and (chi_sq_p >= self.chi_square_alpha)
        
        results = {
            'n_samples': len(first_digits),
            'observed_frequencies': observed_freqs,
            'expected_frequencies': self.benford_probs,
            'mad': mad,
            'chi_square_statistic': chi_sq_stat,
            'chi_square_p_value': chi_sq_p,
            'ks_statistic': ks_stat,
            'ks_p_value': ks_p,
            'kl_divergence': kl_div,
            'compliant': compliant
        }
        
        if verbose:
            self._print_results(results)
        
        return results
    
    def _print_results(self, results: Dict):
        """Print analysis results in a formatted way."""
        print(f"\n📊 Benford's Law Analysis Results")
        print(f"{'─' * 50}")
        print(f"Samples analyzed: {results['n_samples']}")
        print(f"\nDigit Distribution:")
        print(f"{'Digit':<10} {'Observed':<15} {'Expected':<15} {'Difference'}")
        print(f"{'─' * 50}")
        
        for digit in range(1, 10):
            obs = results['observed_frequencies'][digit-1]
            exp = results['expected_frequencies'][digit-1]
            diff = obs - exp
            print(f"{digit:<10} {obs:>6.2%}{' '*8} {exp:>6.2%}{' '*8} {diff:>+7.2%}")
        
        print(f"\n{'─' * 50}")
        print(f"Statistical Metrics:")
        print(f"  MAD (Mean Absolute Deviation): {results['mad']:.6f}")
        print(f"    → Threshold: {self.mad_threshold} (lower is better)")
        print(f"    → Status: {'✓ PASS' if results['mad'] <= self.mad_threshold else '✗ FAIL'}")
        
        print(f"\n  Chi-Square Test:")
        print(f"    → Statistic: {results['chi_square_statistic']:.4f}")
        print(f"    → P-Value: {results['chi_square_p_value']:.4f}")
        print(f"    → Status: {'✓ PASS' if results['chi_square_p_value'] >= self.chi_square_alpha else '✗ FAIL'} "
              f"(α = {self.chi_square_alpha})")
        
        print(f"\n  Kolmogorov-Smirnov Test:")
        print(f"    → Statistic: {results['ks_statistic']:.4f}")
        print(f"    → P-Value: {results['ks_p_value']:.4f}")
        
        print(f"\n  KL Divergence: {results['kl_divergence']:.6f}")
        print(f"    → (0 = perfect match, higher = more deviation)")
        
        print(f"\n{'─' * 50}")
        print(f"Overall Compliance: {'✅ COMPLIANT' if results['compliant'] else '❌ NON-COMPLIANT'}")
        print(f"{'─' * 50}")
    
    def visualize(self, data: List[float], save_path: Optional[str] = None,
                 title: str = "Benford's Law Analysis") -> None:
        """
        Create a visualization comparing observed vs expected distributions.
        
        Args:
            data: List of numerical values to analyze
            save_path: Path to save the plot (optional)
            title: Title for the plot
        """
        # Perform analysis
        results = self.analyze(data, verbose=False)
        
        if 'error' in results:
            print(f"Cannot visualize: {results['error']}")
            return
        
        # Create figure with subplots
        fig, axes = plt.subplots(2, 2, figsize=(14, 10))
        fig.suptitle(title, fontsize=16, fontweight='bold')
        
        # Plot 1: Bar chart comparison
        ax1 = axes[0, 0]
        x = np.arange(1, 10)
        width = 0.35
        
        ax1.bar(x - width/2, results['observed_frequencies'], width, 
               label='Observed', alpha=0.8, color='steelblue')
        ax1.bar(x + width/2, results['expected_frequencies'], width,
               label='Expected (Benford)', alpha=0.8, color='coral')
        
        ax1.set_xlabel('First Digit', fontsize=11)
        ax1.set_ylabel('Frequency', fontsize=11)
        ax1.set_title('Observed vs Expected Distribution', fontsize=12, fontweight='bold')
        ax1.set_xticks(x)
        ax1.legend()
        ax1.grid(True, alpha=0.3)
        
        # Plot 2: Deviation from Benford
        ax2 = axes[0, 1]
        deviations = results['observed_frequencies'] - results['expected_frequencies']
        colors = ['green' if abs(d) < 0.02 else 'orange' if abs(d) < 0.05 else 'red' 
                 for d in deviations]
        
        ax2.bar(x, deviations, color=colors, alpha=0.7)
        ax2.axhline(y=0, color='black', linestyle='-', linewidth=0.8)
        ax2.set_xlabel('First Digit', fontsize=11)
        ax2.set_ylabel('Deviation from Expected', fontsize=11)
        ax2.set_title('Deviation Analysis', fontsize=12, fontweight='bold')
        ax2.set_xticks(x)
        ax2.grid(True, alpha=0.3)
        
        # Plot 3: Cumulative Distribution
        ax3 = axes[1, 0]
        observed_cdf = np.cumsum(results['observed_frequencies'])
        expected_cdf = np.cumsum(results['expected_frequencies'])
        
        ax3.plot(x, observed_cdf, 'o-', label='Observed CDF', linewidth=2, markersize=6)
        ax3.plot(x, expected_cdf, 's-', label='Expected CDF', linewidth=2, markersize=6)
        ax3.set_xlabel('First Digit', fontsize=11)
        ax3.set_ylabel('Cumulative Probability', fontsize=11)
        ax3.set_title('Cumulative Distribution Function', fontsize=12, fontweight='bold')
        ax3.set_xticks(x)
        ax3.legend()
        ax3.grid(True, alpha=0.3)
        
        # Plot 4: Statistics Summary
        ax4 = axes[1, 1]
        ax4.axis('off')
        
        stats_text = f"""
        📊 Statistical Summary
        {'─' * 35}
        
        Samples: {results['n_samples']:,}
        
        MAD: {results['mad']:.6f}
        Status: {'✓ Pass' if results['mad'] <= self.mad_threshold else '✗ Fail'} (threshold: {self.mad_threshold})
        
        Chi-Square: {results['chi_square_statistic']:.4f}
        P-Value: {results['chi_square_p_value']:.4f}
        Status: {'✓ Pass' if results['chi_square_p_value'] >= self.chi_square_alpha else '✗ Fail'} (α = {self.chi_square_alpha})
        
        KS Statistic: {results['ks_statistic']:.4f}
        P-Value: {results['ks_p_value']:.4f}
        
        KL Divergence: {results['kl_divergence']:.6f}
        
        {'─' * 35}
        Overall: {'✅ COMPLIANT' if results['compliant'] else '❌ NON-COMPLIANT'}
        """
        
        ax4.text(0.1, 0.5, stats_text, fontsize=10, family='monospace',
                verticalalignment='center')
        
        plt.tight_layout()
        
        # Save or show
        if save_path:
            os.makedirs(os.path.dirname(save_path), exist_ok=True)
            plt.savefig(save_path, dpi=300, bbox_inches='tight')
            print(f"✅ Visualization saved to: {save_path}")
        else:
            plt.show()
        
        plt.close()


if __name__ == "__main__":
    # Quick self-test
    print("Benford Analyzer Module - Self Test")
    print("=" * 50)
    
    analyzer = BenfordAnalyzer()
    
    # Test with sample data that follows Benford's Law
    benford_data = [1, 12, 123, 2, 234, 3, 34, 4, 45, 5, 56, 1234, 12345]
    results = analyzer.analyze(benford_data, verbose=True)
    
    print("\n✨ Self-test completed!")
