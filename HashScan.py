"""
Author: Tim Johns
Last modified: (6/28/24)
This program pulls hashes from a given .csv file and prints the virustotal scan results.
Requirements: The sys, csv and requests modules.
Input: A .csv file that stores hashes in each descending rows in the first column.
Output: The results of the scan for each hash.
Example Usage (in terminal):
---
$python3 HashScan.py <path to csv file>
---
"""
import sys
import requests
import csv

#Replace with personal VirusTotal API key:
API_KEY = 'c111f6516b6d00c1c7994ee04870e7e3996182f9954ea9477a24fa984e7e5c84'

#Universal variables used for final tally
Malware = 0
MalwareList = []
Likely_Malware = 0
LikelyMalwareList = []
Likely_Clean = 0
Likely_CleanList = []


#Gets the file report for a given hash via the virustotal api:
#Returns the json response to be analyzed.
def get_file_report(file_hash):
    url = f'https://www.virustotal.com/vtapi/v2/file/report'
    params = {'apikey': API_KEY, 'resource': file_hash}
    response = requests.get(url, params=params)
    #If no response was found, return 0: 
    if len(response.text) < 100:
        return 0
    return response.json()


#Pulls all the hashes from the .csv file and puts them in a list.
def read_csv_first_column(csv_file):
    items = []
    with open(csv_file, 'r', newline='') as file:
        reader = csv.reader(file)
        for row in reader:
            if row:  # Check if the row is not empty
                items.append(row[0])  # Add the first column item to the list
    return items

#Prints the results from the hash results:
def print_Verdict(report, hash, results):
    global Likely_Malware, Malware, Likely_Clean
    # Print the results
    print("\n------------------------------------------\n")
    print("Hash: " + hash)

    if report['response_code'] == 1:
        print(f"Scan date: {report['scan_date']}")
        print("Positives / Total: {}/{}".format(report['positives'], report['total']))
        
        #Conditional statements used to make verdict about the file.
        if (report['positives'] / report['total'] >= 0.5):
            Malware += 1
            MalwareList.append(hash)
            print("Verdict: MALWARE")
        elif (report['positives'] / report['total'] == 0):
            Likely_Clean += 1
            Likely_CleanList.append(hash)
            print("Verdict: LIKELY CLEAN")
        else:
            print("Verdict: LIKELY MALWARE")
            Likely_Malware += 1
            LikelyMalwareList.append(hash)

        #Prints the full results, if the user wants to see them.
        if results == True: 
            print("\nFull Scan results:\n")
            for antivirus, result in report['scans'].items():
                print(f"{antivirus}: {result['result']}")

    else:
        print("File not found in VirusTotal database.")

def main():

    #Prints Opening Banner:
    print("\n\n" + (42*"*") + "\n\n")
    print("Welcome to VirusTotal .csv Scanner!")

    #Checks to ensure that the user included the .csv filepath as an argument. If they did not, it prompts the user.
    if len(sys.argv) != 2:
        csv_file = input("\n\nPlease enter the full filepath for the .csv file you wish to scan: ")
        
    else:
        #Pulls the csv_file from the command-line argument.
        csv_file = sys.argv[1]
    

    #Places all the hashes from the csv_file into a list called items.
    items = read_csv_first_column(csv_file)


    #Prompt the user to see whether they would like to see the full report:
    seeReport = False
    preference = input("\n\n\nWould you like to see the full report for each hash?\nEnter Y/N: ")
    if preference.upper() == "Y":
        seeReport = True

    print(f"\n\nScanning {len(items)} hashes from {csv_file}...\n")

    #Iterates through every hash in the items list.
    for hash in items:
        #Gets the report from VirusTotal for the current hash, and feeds it into the print function.
        print_Verdict(get_file_report(hash), hash, seeReport)
    print("\n------------------------------------------\n")

    #Once the scan is complete, print a final report utilizing the combined totals in each category:
    print("*"*42)
    print("\nFinal Report:\n")
    print(f"Total Scans: {len(items)}")
    print(f"\nHashes Found: {Malware + Likely_Malware + Likely_Clean}")
    print(f"Hashes not in database: {len(items) - (Malware + Likely_Malware + Likely_Clean)}")
    print(f"\nMalware files detected: {Malware}")
    if len(MalwareList) > 0:
        for current in MalwareList:
            print(current)
    print(f"\nLikely malware files detected: {Likely_Malware}")
    if len(LikelyMalwareList) > 0:
        for current in LikelyMalwareList:
            print(current)
    print(f"\nLikely clean files detected: {Likely_Clean}")
    if len(Likely_CleanList) > 0:
        for current in Likely_CleanList:
            print(current)
    print("\n"+"*"*42)


if __name__ == "__main__":
    main()
