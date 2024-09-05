"""
Author Tim Johns (last modified July 17th, 2024)
Program that mangles passwords listed in the rows in the first column of a 
.csv file. The mangled passwords are returned in a .txt file called mang_out.txt.
"""

import sys
import random
import string

def generate_year_patterns():
    # Generate years from 1940 to 2024 inclusive
    return [str(year) for year in range(1940, 2025)]

def generate_case_variations(word):
    results = set()

    # Capitalize first letter of each word and/or last letter
    if word:
        # Capitalize first letter of the entire word
        results.add(word.capitalize())
        
        # Capitalize last letter
        results.add(word[:-1] + word[-1].upper())
        
        # Capitalize first and last letter
        if len(word) > 1:
            results.add(word[0].upper() + word[1:-1] + word[-1].upper())
        
        # Original word in lowercase
        results.add(word.lower())
    
    return results

def mangling_variations(word):
    variations = set()

    # Define character substitutions and replacements
    substitutions = {
        'a': ['@', '4'], 'e': ['3'], 'i': ['1', '!'], 'o': ['0'], 's': ['$', '5'],
        't': ['+', '7'], 'l': ['|', '1'], 'b': ['8'], 'g': ['9']
    }

    # Add original word
    variations.add(word)
    
    # Apply substitutions probabilistically
    for char, reps in substitutions.items():
        if char in word:
            for rep in reps:
                if random.random() < 0.5:  # 50% chance to substitute
                    variations.add(word.replace(char, rep))
                
    # Apply multiple substitutions probabilistically
    for char1, reps1 in substitutions.items():
        for char2, reps2 in substitutions.items():
            if char1 != char2:
                for rep1 in reps1:
                    for rep2 in reps2:
                        if random.random() < 0.5:  # 50% chance to substitute both
                            new_word = word.replace(char1, rep1).replace(char2, rep2)
                            variations.add(new_word)
    
    # Case variations with targeted capitalization
    variations.update(generate_case_variations(word))
    
    return list(variations)

def append_and_prepend_years_probabilistically(variants):
    year_patterns = generate_year_patterns()
    final_variations = set()

    for var in variants:
        # 50% chance to prepend a year
        if random.random() < 0.5:
            year = random.choice(year_patterns)
            final_variations.add(year + var)
        
        # 50% chance to append a year
        if random.random() < 0.5:
            year = random.choice(year_patterns)
            final_variations.add(var + year)
    
    return list(final_variations)[:5]

def process_file(file_path):
    with open(file_path, 'r') as file:
        words = file.read().strip().split('\n')
    
    # Open 'mang_out.txt' for writing
    with open('mang_out.txt', 'w') as out_file:
        for word in words:
            base_variations = mangling_variations(word)
            final_variations = append_and_prepend_years_probabilistically(base_variations)
            # Write each variant to the output file, each on a new line
            for variant in final_variations:
                out_file.write(f"{variant}\n")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python mangler.py <file_path>")
        sys.exit(1)
    
    file_path = sys.argv[1]
    process_file(file_path)
