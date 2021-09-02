import base64
import sys

def challenge1():
    '''convert a hex string to base 64'''
    solution = hex_to_b64('49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d')
    print('challenge1: ' + solution)

def challenge2():
    '''take two equal length buffers and produce their XOR combination'''
    bytes1 = bytearray.fromhex('1c0111001f010100061a024b53535009181c')
    bytes2 = bytearray.fromhex('686974207468652062756c6c277320657965')
    xorstring = bytes(a ^ b for (a, b) in zip(bytes1, bytes2))
    result = base64.b16encode(xorstring)
    print('challenge2: ' + result.decode())

def challenge3():
    '''single byte XOR cipher'''
    hex_string='1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736'
    results = single_char_xor_decode(bytearray.fromhex(hex_string))
    print(results[0])

def challenge4():
    '''detect single character xor'''
    file = open('set1chal4.txt', 'r')
    input = file.readlines()
    results = detect_single_char_xor(input)
    print(results[0])

def challenge5():
    '''implement repeating-key XOR'''
    plaintext = 'Burning \'em, if you ain\'t quick and nimble\nI go crazy when I hear a cymbal'
    print(plaintext)
    key = 'ICE'
    result =  repeating_xor_encrypt(plaintext, key)
    print(result.hex())


def repeating_xor_encrypt(plaintext, key):
    plaintext_bytes = plaintext.encode('ascii')
    key_length = len(key)
    key_bytes = key.encode('ascii')

    counter = 0
    output = b''
    for byte in plaintext_bytes:
        xor = (byte ^ key_bytes[counter % key_length])
        output += xor.to_bytes(1, 'big')
        counter += 1
    return output

def detect_single_char_xor(input):

    results = []

    for hex_string in input:
        result = single_char_xor_decode(bytearray.fromhex(hex_string))
        results.append(result[0])

    sortedresults = sorted(results, key=lambda k: k['score'], reverse=True)

    return sortedresults



def single_char_xor(bytes, key):
    output = b''

    for byte in bytes:
        xor = (byte ^ key)
        output += xor.to_bytes(1, 'big')
    return output

def bitwise_xor_bytes(a, b):
    result_int = int.from_bytes(a, byteorder='big') ^ int.from_bytes(b, byteorder='big')
    return result_int.to_bytes(max(len(a), len(b)), byteorder='big')

def single_char_xor_decode(bytes):

    results = []

    for key in range(255):
        result = single_char_xor(bytes, key)
        result_score = english_scoring(result)

        results.append({'result': result, 'key': key, 'score': result_score})

        sortedresults = sorted(results, key=lambda k: k['score'], reverse=True)

    return sortedresults




def english_scoring(bytes):
    ENG_CHAR_FREQ = {
        'a': 0.08167, 'b': 0.01492, 'c': 0.02782, 'd': 0.04253, 'e': 0.12702, 'f': 0.02228,
        'g': 0.02015, 'h': 0.06094, 'i': 0.06966, 'j': 0.00153, 'k': 0.00772, 'l': 0.04025,
        'm': 0.02406, 'n': 0.06749, 'o': 0.07507, 'p': 0.01929, 'q': 0.00095, 'r': 0.05987,
        's': 0.06327, 't': 0.09056, 'u': 0.02758, 'v': 0.00978, 'w': 0.02360, 'x': 0.00150,
        'y': 0.01974, 'z': 0.00074, ' ': 0.00000}



    score = 0
    count = 0
    for byte in bytes:
        if chr(byte) in ENG_CHAR_FREQ:
            count += 1
            score += (ENG_CHAR_FREQ.get(chr(byte)))
    score = score * count/len(bytes)
    return score



def hex_to_b64(hexstring):
    bytes = bytearray.fromhex(hexstring)
    b64string = base64.b64encode(bytes)
    return b64string.decode()



if __name__ == "__main__":
    challenge1()
    challenge2()
    challenge3()
    challenge4()
    challenge5()
