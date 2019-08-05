class UserData:

    def __init__(self, filename):
        self.filename = filename
        self.userData = {}
        self.readfile()

    def readfile(self):
        f = open(self.filename, 'r')
        # read a line and remove the "\n" at the end
        line = f.readline()[:-1]
        while line:
            user = line.split(',')
            if len(user) == 2:
                self.userData[user[0]] = user[1]
                line = f.readline()[:-1]
            else:
                print("Invalid line in " + file + ": " + line + "\n")
                return False
        f.close()
        return self.userData

    # append an entry to the file if the email address is not already in and add the user to the dict
    def appendfile(self, email, pswd):
        res = {}
        if email in self.userData:
            print("email already registered")
            res["success"] = False
            res["reason"] = "email " + email + " already registered"
        else:
            self.userData[email] = pswd
            line_to_write = email + "," + pswd + "\n"
            with open(self.filename, "a") as myfile:
                myfile.write(line_to_write)
            res["success"] = True
            res["reason"] = ""
        return res

    def addentry(self, email, pswd):
        res = {}
        if email in self.userData:
            print("email already registered")
            res["success"] = False
            res["reason"] = "email " + email + " already registered"
        else:
            self.userData[email] = pswd
            res["success"] = True
            res["reason"] = ""
        return res

    def writeTofile(self):
        # TODO ovewrite file with all the entries in the dict
        pass

    def authorize(self, username, password):
        if username in self.userData:
            return self.userData[username] == password
        else:
            return False


# ud = UserData("user_data.csv")
# ud.readfile()
# print(ud.userData)
# ud.appendfile("salut","bonjour")
# ud.readfile()
# print(ud.userData)