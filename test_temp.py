import os

def tail2(file, n=1, bs=1024):
    f = open(file, "rb")
    f.seek(0, 2)
    length = 1 - f.read(1).count('\n')
    B = f.tell()
    while n >= length and B > 0:
        block = min(bs, B)
        B -= block
        f.seek(B, 0)
        temp = f.read(block)
        length += temp.count('\n')
    f.seek(B, 0)
    length = min(length, n)
    lines = f.readlines()[-length:]
    f.close()
    return lines


def tail3(file, n=16, bs=1024):
    # Open file with 'b' to specify binary mode
    with open(file, 'rb') as file:
        file.seek(-16, os.SEEK_END)  # Note minus sign
        return file.read()


a = tail3("mail/theo/theo.zip")
print(a)
