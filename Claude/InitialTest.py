"""
Aristocrat Cipher Cracker
A comprehensive tool for breaking monoalphabetic substitution ciphers
using frequency analysis, pattern matching, and dictionary attacks.
"""

import re
from collections import Counter, defaultdict
from typing import Dict, List, Tuple, Set
import string

class AristocratCracker:
    """Main cipher cracking class with multiple solving strategies."""
    
    # English letter frequencies (approximate percentages)
    ENGLISH_FREQ = {
        'E': 12.70, 'T': 9.06, 'A': 8.17, 'O': 7.51, 'I': 6.97,
        'N': 6.75, 'S': 6.33, 'H': 6.09, 'R': 5.99, 'D': 4.25,
        'L': 4.03, 'C': 2.78, 'U': 2.76, 'M': 2.41, 'W': 2.36,
        'F': 2.23, 'G': 2.02, 'Y': 1.97, 'P': 1.93, 'B': 1.29,
        'V': 0.98, 'K': 0.77, 'J': 0.15, 'X': 0.15, 'Q': 0.10, 'Z': 0.07
    }
    
    # Common English words for pattern matching
    COMMON_WORDS = {
        'THE', 'AND', 'FOR', 'ARE', 'BUT', 'NOT', 'YOU', 'ALL',
        'CAN', 'HER', 'WAS', 'ONE', 'OUR', 'OUT', 'DAY', 'HAD'
    }
    
    # Common bigrams and trigrams
    COMMON_BIGRAMS = ['TH', 'HE', 'IN', 'ER', 'AN', 'RE', 'ON', 'AT', 'EN', 'ND']
    COMMON_TRIGRAMS = ['THE', 'AND', 'ING', 'HER', 'HAT', 'HIS', 'THA', 'ERE', 'FOR', 'ENT']
    
    def __init__(self, ciphertext: str):
        """Initialize with ciphertext."""
        self.ciphertext = ciphertext.upper()
        self.cipher_letters = [c for c in self.ciphertext if c.isalpha()]
        self.mapping = {}
        self.reverse_mapping = {}
        
    def analyze_frequency(self) -> List[Tuple[str, int, float]]:
        """Analyze letter frequencies in ciphertext."""
        letter_counts = Counter(self.cipher_letters)
        total = len(self.cipher_letters)
        
        freq_analysis = []
        for letter, count in letter_counts.most_common():
            percentage = (count / total) * 100
            freq_analysis.append((letter, count, percentage))
        
        return freq_analysis
    
    def get_word_patterns(self) -> Dict[str, List[str]]:
        """Extract word patterns from ciphertext."""
        words = re.findall(r'[A-Z]+', self.ciphertext)
        patterns = defaultdict(list)
        
        for word in words:
            pattern = self._get_pattern(word)
            patterns[pattern].append(word)
        
        return dict(patterns)
    
    def _get_pattern(self, word: str) -> str:
        """Convert word to pattern (e.g., 'HELLO' -> '0.1.2.2.3')."""
        char_map = {}
        pattern = []
        next_id = 0
        
        for char in word:
            if char not in char_map:
                char_map[char] = next_id
                next_id += 1
            pattern.append(str(char_map[char]))
        
        return '.'.join(pattern)
    
    def suggest_mapping_by_frequency(self) -> Dict[str, str]:
        """Suggest initial mapping based on frequency analysis."""
        freq_analysis = self.analyze_frequency()
        cipher_letters_sorted = [letter for letter, _, _ in freq_analysis]
        english_letters_sorted = sorted(self.ENGLISH_FREQ.keys(), 
                                       key=lambda x: self.ENGLISH_FREQ[x], 
                                       reverse=True)
        
        suggested = {}
        for i, cipher_letter in enumerate(cipher_letters_sorted):
            if i < len(english_letters_sorted):
                suggested[cipher_letter] = english_letters_sorted[i]
        
        return suggested
    
    def apply_mapping(self, mapping: Dict[str, str]) -> str:
        """Apply a given mapping to decode ciphertext."""
        result = []
        for char in self.ciphertext:
            if char.isalpha():
                result.append(mapping.get(char, '_'))
            else:
                result.append(char)
        return ''.join(result)
    
    def set_mapping(self, cipher_char: str, plain_char: str):
        """Manually set a character mapping."""
        cipher_char = cipher_char.upper()
        plain_char = plain_char.upper()
        
        # Remove old mappings if they exist
        if cipher_char in self.mapping:
            old_plain = self.mapping[cipher_char]
            del self.reverse_mapping[old_plain]
        if plain_char in self.reverse_mapping:
            old_cipher = self.reverse_mapping[plain_char]
            del self.mapping[old_cipher]
        
        # Set new mapping
        self.mapping[cipher_char] = plain_char
        self.reverse_mapping[plain_char] = cipher_char
    
    def get_current_decryption(self) -> str:
        """Get current decryption with current mapping."""
        return self.apply_mapping(self.mapping)
    
    def find_pattern_matches(self, english_dict: Set[str] = None) -> Dict[str, List[str]]:
        """Find potential word matches based on patterns."""
        if english_dict is None:
            # Use common words if no dictionary provided
            english_dict = self.COMMON_WORDS
        
        cipher_patterns = self.get_word_patterns()
        matches = {}
        
        for pattern, cipher_words in cipher_patterns.items():
            potential_matches = []
            for english_word in english_dict:
                if self._get_pattern(english_word) == pattern:
                    potential_matches.append(english_word)
            
            if potential_matches:
                matches[cipher_words[0]] = potential_matches
        
        return matches
    
    def score_decryption(self, text: str, common_words: Set[str] = None) -> float:
        """Score a decryption attempt based on English word frequency."""
        if common_words is None:
            common_words = self.COMMON_WORDS
        
        words = re.findall(r'[A-Z]+', text.upper())
        if not words:
            return 0.0
        
        matches = sum(1 for word in words if word in common_words)
        return matches / len(words)
    
    def auto_crack_basic(self) -> Tuple[str, Dict[str, str]]:
        """Attempt automatic cracking using frequency analysis."""
        suggested = self.suggest_mapping_by_frequency()
        decrypted = self.apply_mapping(suggested)
        return decrypted, suggested
    
    def print_analysis(self):
        """Print comprehensive analysis of the ciphertext."""
        print("=" * 60)
        print("CIPHERTEXT ANALYSIS")
        print("=" * 60)
        print(f"\nCiphertext:\n{self.ciphertext}\n")
        
        print("\nFREQUENCY ANALYSIS:")
        print(f"{'Letter':<10} {'Count':<10} {'Percentage':<10}")
        print("-" * 30)
        for letter, count, pct in self.analyze_frequency():
            print(f"{letter:<10} {count:<10} {pct:>6.2f}%")
        
        print("\n\nWORD PATTERNS:")
        patterns = self.get_word_patterns()
        for pattern, words in list(patterns.items())[:10]:  # Show first 10
            print(f"Pattern {pattern}: {', '.join(set(words))}")
        
        print("\n\nSUGGESTED FREQUENCY-BASED MAPPING:")
        suggested = self.suggest_mapping_by_frequency()
        for cipher, plain in list(suggested.items())[:10]:
            print(f"{cipher} -> {plain}")
        
        print("\n" + "=" * 60)


def interactive_crack():
    """Interactive cipher cracking session."""
    print("ARISTOCRAT CIPHER CRACKER")
    print("=" * 60)
    
    # Sample ciphertext (you can replace this)
    sample = """
    FZQ YQOFQUF OQEKQF UE YUVKVY UYFQBBUVQYFBI HUFZ EUCIBUAUFB.
    FZQ FWEQ HZE YQFTQY FZQGBQBTQB HUFZ FZUB UYFQBBUVQYTQ
    ZWTTQ YTWQB HZWF FZQ FWEQ HZE YQTQWBQB.
    """
    
    print("\nUsing sample ciphertext:")
    print(sample)
    print("\n(You can modify the code to use your own ciphertext)")
    print("=" * 60)
    
    cracker = AristocratCracker(sample)
    cracker.print_analysis()
    
    print("\n\nATTEMPTING AUTOMATIC CRACK:")
    decrypted, mapping = cracker.auto_crack_basic()
    print(f"\nDecrypted text:\n{decrypted}")
    
    print("\n\nMANUAL REFINEMENT MODE:")
    print("Commands:")
    print("  set <cipher_char> <plain_char> - Set a character mapping")
    print("  show - Show current decryption")
    print("  matches - Show pattern matches")
    print("  quit - Exit")
    
    while True:
        cmd = input("\n> ").strip().lower()
        
        if cmd == 'quit':
            break
        elif cmd == 'show':
            print(f"\n{cracker.get_current_decryption()}")
        elif cmd == 'matches':
            matches = cracker.find_pattern_matches()
            for cipher_word, english_words in list(matches.items())[:5]:
                print(f"{cipher_word}: {', '.join(english_words)}")
        elif cmd.startswith('set '):
            parts = cmd.split()
            if len(parts) == 3:
                cracker.set_mapping(parts[1], parts[2])
                print(f"Set {parts[1]} -> {parts[2]}")
                print(f"\n{cracker.get_current_decryption()}")
            else:
                print("Usage: set <cipher_char> <plain_char>")


if __name__ == "__main__":
    # Run interactive mode
    interactive_crack()
    
    # Or use programmatically:
    # cracker = AristocratCracker("YOUR CIPHERTEXT HERE")
    # cracker.print_analysis()
    # decrypted, mapping = cracker.auto_crack_basic()
    # print(decrypted)