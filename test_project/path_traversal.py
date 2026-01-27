def read_file(filename):
    path = "/var/www/data/" + filename
    with open(path, "r") as f:
        return f.read()

read_file("../../etc/passwd")
