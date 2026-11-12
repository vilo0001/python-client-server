import string

alphabet = list(string.ascii_uppercase)
cipher_text = "eoqcqiwlkbnshkdcuciftsdokbjxjsymisqitsfmrvhv?"
keyword = "code"

keyword_numbers = []
for c in keyword:
    keyword_numbers.append(alphabet.index(c.upper()))

for i,c in enumerate(cipher_text):
    if(c.upper() in alphabet):
        print(alphabet[(alphabet.index(c.upper())-keyword_numbers[i%4])%26], end="")
    else:
        print(c, end="")