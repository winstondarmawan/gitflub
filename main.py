# GitFlub

# A scanner that checks for vulnerabilities in GitHub respositories.
# Author: Winston Darmawan (z5205439)
# Course: COMP6841

import sys
import os
from os import path
from git import Repo
from glob import glob
# from high_entropy_string import PythonStringData

# Function to append information to the report.
def append(file, text):
    with open(file, "a+") as file_object:
        file_object.seek(0)
        data = file_object.read(100)
        if len(data) > 0:
            file_object.write("\n")
        file_object.write(text)

if __name__ == "__main__":
    # Clone the target repo into a new local directory for static scanning.
    # arg1: repo link, Arg2: name of dir
    print("Cloning repository...")
    Repo.clone_from(sys.argv[1], sys.argv[2])
    print("Cloning complete!")

    # ANALYSIS

    # Collect list of all files.
    print("Collecting files...")
    result = [y for x in os.walk(sys.argv[2]) for y in glob(os.path.join(x[0], '*'))]
    # print(result)
    print("Files collected!")

    # Check requirements.txt for any potentially deprecated/vulnerable packages.
    append("reports/{}-report.txt".format(sys.argv[2]), "Project Requirements Check\nCheck requirements.txt for any potentially deprecated/vulnerable packages.\n")
    print("Starting project requirements analysis...")
    rqs = False
    for file in result:
        if 'requirements.txt' in file:
            rqs = True
            os.system("safety check -r {} >> reports/{}-report.txt".format(file, sys.argv[2]))
    if rqs is False:
        append("reports/{}-report.txt".format(sys.argv[2]), "requirements.txt not found.")
    print("Project requirements analysis complete!")
    
    # Check static files for key-terms.
    append("reports/{}-report.txt".format(sys.argv[2]), "Grepping Key-Terms Check\nCheck files for any potentially revealing key-terms and their lines.")
    print("Starting static code analysis...")
    terms = ["authentication", "key", "secret", "username", "password", "vulnerable", "http://", "https://", "hash", "md5", "sha-1", "sha-2", "hmac"]
    for file in result:
        if path.isfile(file) and 'yarn.lock' not in file and 'package-lock.json' not in file:
            read_file = open(file, 'rb')
            lines = read_file.readlines()
            line_count = 1
            for line in lines:
                line_count += 1
                for term in terms:
                    if term in str(line).lower():
                        append("reports/{}-report.txt".format(sys.argv[2]), "From {}, line {}".format(file, line_count))
                        append("reports/{}-report.txt".format(sys.argv[2]), "{}".format(str(line)))
                        

    print("Static code analysis complete!")

    print("Report complete! Viewable at: reports/{}-report.txt".format(sys.argv[2]))









