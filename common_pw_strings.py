"""
Author: Tim Johns; last modified 7/30/24
Program that prints the top 50 most frequently occuring substring-words and full passwords
from a .CSV file of passwords (one per row, column 1 only).
Syntax: 
    python3 common_pw_strings.py <name or path to .csv password file>
    Example: python3 common_pw_strings.py ./crackable_pwds.csv
Output:
    frequent_passwords.txt -> .txt file containing the frequently occurring passwords disovered (one per line)
    frequent_words.txt -> .txt file containing the frequntly occurring words discovered (one per line)
    results.txt -> file if you pipe output to a .txt file. (Optional)
"""
import argparse
import csv
import nltk
import spacy
from nltk.corpus import words
from tabulate import tabulate
from tqdm import tqdm

# Download the words corpus if not already downloaded
nltk.download('words')

# Load the words corpus
word_list = set(words.words())

# Load SpaCy model
nlp = spacy.load('en_core_web_sm')

# Specific names and words to allow
specific_terms = {
    'thomas', 'jefferson', 'philadelphia', 'philly',
    'health', 'hospital', 'hospitals', 'healthcare', 'medic', 'medicine', 'phillies', 'eagles', 'flyers', 'union', '76ers', 'seventysixers', 'baseball', 'football', 'banana', 'Philly', 'Banana'
}

# Words to exclude
exclusions = {
    'the', 'is', 'and', 'ing', 'ers', 'alt', 'son', 'all', 'ist', 'of',
    'in', 'at', 'a', 'for', 'to', 'that', 'an', 'ower', 'ember', 'utum', 'wint', 'inter', 'gree', 'reen', 'rist', 'ring', 'tobe', 'yell', 'rang', 'harl', 'shin', 'bing', 'lower', 'ring', 'elle', 'char'
}

def extract_words(s, min_length=4):
    """Extract valid words from the given string."""
    found_words = set()
    
    # Add specific terms directly
    for term in specific_terms:
        if term in s.lower():
            found_words.add(term)
    
    # Extract substrings of length >= min_length
    s_lower = s.lower()
    for length in range(min_length, len(s_lower) + 1):
        for start in range(len(s_lower) - length + 1):
            substring = s_lower[start:start + length]
            if substring in word_list and substring not in exclusions and substring not in specific_terms:
                found_words.add(substring)
                
    return found_words

def extract_named_entities(s):
    """Extract named entities from the string using SpaCy."""
    doc = nlp(s)
    named_entities = set(ent.text.lower() for ent in doc.ents if ent.label_ in {'PERSON', 'ORG', 'GPE', 'LOC'})
    return named_entities

def process_csv(file_path):
    """Processes a CSV file and extracts valid words and full strings from every row."""
    substring_counts = {}
    full_string_counts = {}
    
    try:
        with open(file_path, 'r', newline='', encoding='utf-8', errors='ignore') as csvfile:
            reader = csv.reader(csvfile)
            total_rows = sum(1 for _ in csvfile)  # Count rows for progress bar
            
            with open(file_path, 'r', newline='', encoding='utf-8', errors='ignore') as csvfile:
                reader = csv.reader(csvfile)
                for row in tqdm(reader, desc="Processing", total=total_rows, unit="row"):
                    if row:
                        cell_value = row[0]
                        valid_words = extract_words(cell_value)
                        named_entities = extract_named_entities(cell_value)
                        valid_words.update(named_entities)
                        
                        # Count substrings
                        for word in valid_words:
                            if word in substring_counts:
                                substring_counts[word] += 1
                            else:
                                substring_counts[word] = 1
                        
                        # Count full strings
                        full_string_lower = cell_value.lower()
                        if full_string_lower in full_string_counts:
                            full_string_counts[full_string_lower] += 1
                        else:
                            full_string_counts[full_string_lower] = 1

    except FileNotFoundError:
        print(f"Error: The file {file_path} does not exist.")
        return
    except PermissionError:
        print(f"Error: Permission denied for the file {file_path}.")
        return
    except csv.Error as e:
        print(f"Error: CSV file reading error: {e}")
        return
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        return
    
    # Filter and sort substrings that appear more than 10 times
    filtered_substrings = {word: count for word, count in substring_counts.items() if count > 10}
    
    # Sort by frequency in descending order and get the top 50
    top_50_substrings = sorted(filtered_substrings.items(), key=lambda item: item[1], reverse=True)[:50]
    
    # Sort full strings by frequency in descending order and get the top 50
    top_50_full_strings = sorted(full_string_counts.items(), key=lambda item: item[1], reverse=True)[:50]
    
    # Write the top 50 substrings to a file
    with open('frequent_words.txt', 'w', encoding='utf-8') as file:
        file.writelines(f"{word}\n" for word, _ in top_50_substrings)
    
    # Write the top 50 full strings to a file
    with open('frequent_passwords.txt', 'w', encoding='utf-8') as file:
        file.writelines(f"{string}\n" for string, _ in top_50_full_strings)
    
    return top_50_substrings, top_50_full_strings, total_rows

def main():
    print("\n=== Common String Search ===\n")
    
    parser = argparse.ArgumentParser(description='Extract valid words and full strings from a CSV file.')
    parser.add_argument('csv_file', type=str, help='Path to the CSV file to process')
    args = parser.parse_args()

    top_substrings, top_full_strings, line_count = process_csv(args.csv_file)
    
    if top_substrings:
        print("Top 50 Detected Substrings:")
        headers_substrings = ["String", "Occurrences"]
        table_substrings = [(word, count) for word, count in top_substrings]
        print(tabulate(table_substrings, headers=headers_substrings, tablefmt="grid"))
    
    if top_full_strings:
        print("\nTop 50 Most Common Full Strings:")
        headers_full_strings = ["Full String", "Occurrences"]
        table_full_strings = [(string, count) for string, count in top_full_strings]
        print(tabulate(table_full_strings, headers=headers_full_strings, tablefmt="grid"))
    
    print(f"\n{line_count:,} lines processed.")

if __name__ == "__main__":
    main()
