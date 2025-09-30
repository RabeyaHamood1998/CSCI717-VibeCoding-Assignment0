"""
Aristocrat Cipher Cracker - Enhanced Version
A comprehensive tool for breaking monoalphabetic substitution ciphers
using multiple strategies: frequency analysis, pattern matching, hill climbing, and dictionary attacks.
"""

import re
from collections import Counter, defaultdict
from typing import Dict, List, Tuple, Set, Optional
import string
import random

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
    
    # Common English words for validation
    COMMON_WORDS = {
        'THE', 'AND', 'FOR', 'ARE', 'BUT', 'NOT', 'YOU', 'ALL', 'CAN', 'HER', 
        'WAS', 'ONE', 'OUR', 'OUT', 'DAY', 'HAD', 'HAS', 'HIS', 'HOW', 'MAN',
        'NEW', 'NOW', 'OLD', 'SEE', 'TIME', 'VERY', 'WHEN', 'WHO', 'WILL', 'WITH',
        'HAVE', 'THIS', 'THAT', 'FROM', 'THEY', 'BEEN', 'HAVE', 'WERE', 'SAID',
        'EACH', 'WHICH', 'THEIR', 'WOULD', 'THERE', 'COULD', 'OTHER', 'THAN',
        'THEN', 'THESE', 'SOME', 'INTO', 'ONLY', 'OVER', 'SUCH', 'KNOW', 'THAN'
    }
    
    # Common bigrams and trigrams
    COMMON_BIGRAMS = ['TH', 'HE', 'IN', 'ER', 'AN', 'RE', 'ON', 'AT', 'EN', 'ND', 
                      'TI', 'ES', 'OR', 'TE', 'OF', 'ED', 'IS', 'IT', 'AL', 'AR']
    COMMON_TRIGRAMS = ['THE', 'AND', 'ING', 'HER', 'HAT', 'HIS', 'THA', 'ERE', 
                       'FOR', 'ENT', 'ION', 'TER', 'WAS', 'YOU', 'ITH', 'VER']
    
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
    
    def score_decryption(self, text: str) -> float:
        """
        Score a decryption using multiple factors:
        - Common word matches
        - Bigram frequencies
        - Trigram frequencies
        """
        words = re.findall(r'[A-Z]+', text.upper())
        if not words:
            return 0.0
        
        # Score based on common words
        word_score = sum(1 for word in words if word in self.COMMON_WORDS)
        word_score = word_score / len(words) if words else 0
        
        # Score based on bigrams
        bigrams = [text[i:i+2] for i in range(len(text)-1) if text[i:i+2].isalpha()]
        bigram_score = sum(1 for bg in bigrams if bg in self.COMMON_BIGRAMS)
        bigram_score = bigram_score / len(bigrams) if bigrams else 0
        
        # Score based on trigrams
        trigrams = [text[i:i+3] for i in range(len(text)-2) if text[i:i+3].isalpha()]
        trigram_score = sum(1 for tg in trigrams if tg in self.COMMON_TRIGRAMS)
        trigram_score = trigram_score / len(trigrams) if trigrams else 0
        
        # Weighted combination
        return 0.5 * word_score + 0.3 * bigram_score + 0.2 * trigram_score
    
    def hill_climb_crack(self, iterations: int = 10000, temp_start: float = 10.0) -> Tuple[str, Dict[str, str], float]:
        """
        Use hill climbing algorithm to find best mapping.
        Starts with frequency-based guess and iteratively improves.
        """
        # Get unique cipher letters
        cipher_letters = list(set(self.cipher_letters))
        plain_letters = list(string.ascii_uppercase[:len(cipher_letters)])
        
        # Start with frequency-based mapping
        current_mapping = self.suggest_mapping_by_frequency()
        
        # Ensure we have all letters
        for letter in cipher_letters:
            if letter not in current_mapping:
                available = [l for l in plain_letters if l not in current_mapping.values()]
                if available:
                    current_mapping[letter] = available[0]
        
        current_text = self.apply_mapping(current_mapping)
        current_score = self.score_decryption(current_text)
        best_mapping = current_mapping.copy()
        best_score = current_score
        
        print(f"Starting hill climb with initial score: {current_score:.4f}")
        
        for i in range(iterations):
            # Try swapping two random letters
            new_mapping = current_mapping.copy()
            letter1, letter2 = random.sample(list(new_mapping.keys()), 2)
            new_mapping[letter1], new_mapping[letter2] = new_mapping[letter2], new_mapping[letter1]
            
            new_text = self.apply_mapping(new_mapping)
            new_score = self.score_decryption(new_text)
            
            # Accept if better
            if new_score > current_score:
                current_mapping = new_mapping
                current_score = new_score
                
                if new_score > best_score:
                    best_score = new_score
                    best_mapping = new_mapping.copy()
                    print(f"Iteration {i}: New best score: {best_score:.4f}")
            
            # Occasional random restart to escape local maxima
            if i % 1000 == 0 and i > 0:
                if random.random() < 0.1:
                    current_mapping = self.suggest_mapping_by_frequency()
                    current_score = self.score_decryption(self.apply_mapping(current_mapping))
        
        best_text = self.apply_mapping(best_mapping)
        print(f"\nFinal best score: {best_score:.4f}")
        return best_text, best_mapping, best_score
    
    def simulated_annealing_crack(self, iterations: int = 20000, temp_start: float = 20.0, cooling_rate: float = 0.9995) -> Tuple[str, Dict[str, str], float]:
        """
        Use simulated annealing to find best mapping.
        Accepts worse solutions with decreasing probability to escape local maxima.
        """
        import math
        
        # Get unique cipher letters
        cipher_letters = list(set(self.cipher_letters))
        plain_letters = list(string.ascii_uppercase[:len(cipher_letters)])
        
        # Start with frequency-based mapping
        current_mapping = self.suggest_mapping_by_frequency()
        
        # Ensure we have all letters
        for letter in cipher_letters:
            if letter not in current_mapping:
                available = [l for l in plain_letters if l not in current_mapping.values()]
                if available:
                    current_mapping[letter] = available[0]
        
        current_text = self.apply_mapping(current_mapping)
        current_score = self.score_decryption(current_text)
        best_mapping = current_mapping.copy()
        best_score = current_score
        temperature = temp_start
        
        print(f"Starting simulated annealing with initial score: {current_score:.4f}")
        
        for i in range(iterations):
            # Try swapping two random letters
            new_mapping = current_mapping.copy()
            letter1, letter2 = random.sample(list(new_mapping.keys()), 2)
            new_mapping[letter1], new_mapping[letter2] = new_mapping[letter2], new_mapping[letter1]
            
            new_text = self.apply_mapping(new_mapping)
            new_score = self.score_decryption(new_text)
            
            # Calculate acceptance probability
            if new_score > current_score:
                # Always accept better solutions
                current_mapping = new_mapping
                current_score = new_score
                
                if new_score > best_score:
                    best_score = new_score
                    best_mapping = new_mapping.copy()
                    print(f"Iteration {i}: New best score: {best_score:.4f}, temp: {temperature:.4f}")
            else:
                # Accept worse solutions with probability based on temperature
                delta = new_score - current_score
                acceptance_prob = math.exp(delta / temperature)
                
                if random.random() < acceptance_prob:
                    current_mapping = new_mapping
                    current_score = new_score
            
            # Cool down temperature
            temperature *= cooling_rate
            
            # Display progress
            if i % 2000 == 0 and i > 0:
                print(f"Iteration {i}: Current score: {current_score:.4f}, Best: {best_score:.4f}, Temp: {temperature:.4f}")
        
        best_text = self.apply_mapping(best_mapping)
        print(f"\nFinal best score: {best_score:.4f}")
        return best_text, best_mapping, best_score
    
    def genetic_algorithm_crack(self, population_size: int = 100, generations: int = 500) -> Tuple[str, Dict[str, str], float]:
        """
        Use genetic algorithm to evolve population of mappings.
        """
        cipher_letters = list(set(self.cipher_letters))
        plain_letters = list(string.ascii_uppercase[:len(cipher_letters)])
        
        # Initialize population with random mappings
        population = []
        for _ in range(population_size):
            shuffled = plain_letters.copy()
            random.shuffle(shuffled)
            mapping = dict(zip(cipher_letters, shuffled))
            population.append(mapping)
        
        # Add frequency-based mapping to population
        population[0] = self.suggest_mapping_by_frequency()
        
        print(f"Starting genetic algorithm with population size: {population_size}")
        
        best_mapping = None
        best_score = 0
        
        for gen in range(generations):
            # Evaluate fitness
            fitness_scores = []
            for mapping in population:
                text = self.apply_mapping(mapping)
                score = self.score_decryption(text)
                fitness_scores.append((mapping, score))
            
            # Sort by fitness
            fitness_scores.sort(key=lambda x: x[1], reverse=True)
            
            # Track best
            if fitness_scores[0][1] > best_score:
                best_score = fitness_scores[0][1]
                best_mapping = fitness_scores[0][0].copy()
                print(f"Generation {gen}: New best score: {best_score:.4f}")
            
            # Selection: Keep top 20%
            elite_count = population_size // 5
            new_population = [mapping for mapping, score in fitness_scores[:elite_count]]
            
            # Crossover and mutation
            while len(new_population) < population_size:
                # Select two parents from elite
                parent1 = random.choice(fitness_scores[:elite_count])[0]
                parent2 = random.choice(fitness_scores[:elite_count])[0]
                
                # Crossover: take some mappings from each parent
                child = {}
                used_plains = set()
                
                for cipher_letter in cipher_letters:
                    if random.random() < 0.5:
                        plain = parent1.get(cipher_letter, plain_letters[0])
                    else:
                        plain = parent2.get(cipher_letter, plain_letters[0])
                    
                    # Ensure no duplicates
                    while plain in used_plains:
                        plain = random.choice(plain_letters)
                    
                    child[cipher_letter] = plain
                    used_plains.add(plain)
                
                # Mutation: swap two random letters with small probability
                if random.random() < 0.1:
                    l1, l2 = random.sample(list(child.keys()), 2)
                    child[l1], child[l2] = child[l2], child[l1]
                
                new_population.append(child)
            
            population = new_population
            
            if gen % 50 == 0 and gen > 0:
                print(f"Generation {gen}: Best score so far: {best_score:.4f}")
        
        best_text = self.apply_mapping(best_mapping)
        print(f"\nFinal best score: {best_score:.4f}")
        return best_text, best_mapping, best_score
    
    def smart_pattern_crack(self) -> Tuple[str, Dict[str, str]]:
        """
        Use pattern matching with common words to build mapping.
        Start with short, common words like THE, AND, etc.
        """
        cipher_words = re.findall(r'[A-Z]+', self.ciphertext)
        mapping = {}
        
        # Try to match 3-letter words first (THE, AND, FOR, etc.)
        three_letter_cipher = [w for w in cipher_words if len(w) == 3]
        
        # Look for THE pattern (most common 3-letter word with all different letters)
        for word in three_letter_cipher:
            if len(set(word)) == 3:  # All different letters
                # Try mapping to "THE"
                test_mapping = {word[0]: 'T', word[1]: 'H', word[2]: 'E'}
                if self._is_mapping_consistent(test_mapping):
                    mapping.update(test_mapping)
                    print(f"Found potential 'THE': {word}")
                    break
        
        # Try to extend mapping using pattern matching
        pattern_matches = self.find_pattern_matches()
        for cipher_word, english_matches in pattern_matches.items():
            if len(english_matches) == 1:  # Unique match
                word_mapping = {}
                for i, char in enumerate(cipher_word):
                    word_mapping[char] = english_matches[0][i]
                
                if self._is_mapping_consistent({**mapping, **word_mapping}):
                    mapping.update(word_mapping)
                    print(f"Mapped {cipher_word} -> {english_matches[0]}")
        
        return self.apply_mapping(mapping), mapping
    
    def _is_mapping_consistent(self, mapping: Dict[str, str]) -> bool:
        """Check if mapping doesn't have conflicts."""
        # Check no duplicate mappings
        if len(mapping.values()) != len(set(mapping.values())):
            return False
        return True
    
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
        for pattern, words in list(patterns.items())[:10]:
            print(f"Pattern {pattern}: {', '.join(set(words))}")
        
        print("\n\nPATTERN MATCHES WITH COMMON WORDS:")
        matches = self.find_pattern_matches()
        for cipher_word, english_words in list(matches.items())[:10]:
            print(f"{cipher_word}: {', '.join(english_words[:5])}")
        
        print("\n" + "=" * 60)


def interactive_crack():
    """Interactive cipher cracking session with multiple methods."""
    print("ARISTOCRAT CIPHER CRACKER - ENHANCED")
    print("=" * 60)
    
    # Sample ciphertext with known solution for testing
    sample = """
    znoy oy g ygsvrk gxoyzuixgz iovnkx zkdz jkyomtkj zu hk ghuaz zcu natjxkj ingxgiz kxy rutm yu zngz yzajktzy igt vxgizoik lxkwaktie gtgreyoy gtj vgzzkxt yurbotm cozn znk norr iroshotm yurbkx ck haorz jkz oy znoy gxoyzuixgz xkgzotm zu ykrrut znoy zgxxk
    """
    
    print("\nUsing sample ciphertext:")
    print(sample)
    print("\n" + "=" * 60)
    
    cracker = AristocratCracker(sample)
    cracker.print_analysis()
    
    print("\n\nCRACKING METHODS:")
    print("1. Frequency Analysis (basic)")
    print("2. Hill Climbing (advanced)")
    print("3. Pattern Matching (smart)")
    print("4. Manual Refinement")
    
    choice = input("\nChoose method (1-4): ").strip()
    
    if choice == '1':
        print("\n--- FREQUENCY ANALYSIS ---")
        decrypted, mapping = cracker.auto_crack_basic()
        print(f"\nDecrypted:\n{decrypted}")
        print(f"\nScore: {cracker.score_decryption(decrypted):.4f}")
        
    elif choice == '2':
        print("\n--- HILL CLIMBING ---")
        print("This may take 30-60 seconds...")
        decrypted, mapping, score = cracker.hill_climb_crack(iterations=10000)
        print(f"\nBest Decrypted:\n{decrypted}")
        
    elif choice == '3':
        print("\n--- PATTERN MATCHING ---")
        decrypted, mapping = cracker.smart_pattern_crack()
        print(f"\nDecrypted:\n{decrypted}")
        print(f"\nScore: {cracker.score_decryption(decrypted):.4f}")
        
    elif choice == '4':
        print("\n--- MANUAL REFINEMENT ---")
        print("Commands:")
        print("  set <cipher_char> <plain_char> - Set a character mapping")
        print("  show - Show current decryption")
        print("  score - Show current score")
        print("  matches - Show pattern matches")
        print("  hint - Try frequency-based guess")
        print("  quit - Exit")
        
        while True:
            cmd = input("\n> ").strip().lower()
            
            if cmd == 'quit':
                break
            elif cmd == 'show':
                print(f"\n{cracker.get_current_decryption()}")
            elif cmd == 'score':
                text = cracker.get_current_decryption()
                print(f"Score: {cracker.score_decryption(text):.4f}")
            elif cmd == 'hint':
                suggested = cracker.suggest_mapping_by_frequency()
                print("\nFrequency-based suggestions:")
                for k, v in list(suggested.items())[:5]:
                    print(f"{k} -> {v}")
            elif cmd == 'matches':
                matches = cracker.find_pattern_matches()
                for cipher_word, english_words in list(matches.items())[:5]:
                    print(f"{cipher_word}: {', '.join(english_words[:3])}")
            elif cmd.startswith('set '):
                parts = cmd.split()
                if len(parts) == 3:
                    cracker.set_mapping(parts[1], parts[2])
                    print(f"Set {parts[1]} -> {parts[2]}")
                    print(f"\n{cracker.get_current_decryption()}")
                else:
                    print("Usage: set <cipher_char> <plain_char>")
    
    print("\n\nFinal Mapping:")
    if hasattr(cracker, 'mapping') and cracker.mapping:
        for k, v in sorted(cracker.mapping.items()):
            print(f"{k} -> {v}")


def auto_crack_basic(self) -> Tuple[str, Dict[str, str]]:
    """Attempt automatic cracking using frequency analysis."""
    suggested = self.suggest_mapping_by_frequency()
    decrypted = self.apply_mapping(suggested)
    return decrypted, suggested

# Add method to class
AristocratCracker.auto_crack_basic = auto_crack_basic


if __name__ == "__main__":
    interactive_crack()