# ECC
p = 67
a = 2
b = 3

# starting point on the curve
G = (3,6)

# Need to multiply k by a number to get to 1
def modularInverse(k, p):
    for i in range(p):
        mod = (k * i) % p
        if mod == 1:
            return i
# end modularInverse 

# Need to take two points to return the next point
def pointAddition(P, Q):
    if P is None:
        return Q
    if Q is None:
        return P

    x1, y1 = P
    x2, y2 = Q

    if x1 == x2 and (y1 + y2) % p == 0:
        return None
    
    if P == Q:
        m = (((3 * pow(x1, 2)) + a) * modularInverse(2 * y1, p)) % p
    else: 
        m = ((y2 - y1) * modularInverse(x2 - x1, p)) % p

    x3 = (pow(m, 2) - x1 - x2) % p
    y3 = ((m * (x1 - x3)) - y1) % p

    return (x3, y3)
# end of pointAddition

# loop point addition into result using P, k times
def scalarMultiply(k, P):
    if k == 0:
        return None
    if P == None: 
        return None
    if k == 1: 
        return P

    result = None

    for _ in range(k):
        result = pointAddition(result, P)
    
    return result
# end of scalarMultiply

# ECC key to AES key
def generatePublicKey(privateKey):
    return scalarMultiply(privateKey, G)

def generateSharedKey(privateKey, otherKey):
    return scalarMultiply(privateKey, otherKey)

# derive key using x coordinate
def deriveAESKey(sharedKey):
    x, _ = sharedKey
    bytes = str(x).encode()
    
    while len(bytes) < 16:
        bytes += bytes

    return bytes[:16]
# end of deriveAESKey

# AES
# text to ascii to ascii matrix
def matrix_generator(text):
    values = []
    for char in text:
        values.append(ord(char))

    matrix = []
    for i in range(4):
        row = [values[i], values[i+4], values[i+8], values[i+12]]
        matrix.append(row)
    
    return matrix
#End of matrix generator

# Take text and key matrices and XOR matching index
def AddRoundKey(matrix1, matrix2):
    XOR_matrix = []

    for row in range(4):
        xor1 = matrix1[row][0] ^ matrix2[row][0]
        xor2 = matrix1[row][1] ^ matrix2[row][1]
        xor3 = matrix1[row][2] ^ matrix2[row][2]
        xor4 = matrix1[row][3] ^ matrix2[row][3]

        row = [xor1,xor2,xor3,xor4]
        XOR_matrix.append(row)
    
    return XOR_matrix
# end of AddRoundKey

# replace each byte using sbox
def SubBytes(matrix):
    sbox = [
        0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
        0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
        0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
        0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
        0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
        0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
        0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
        0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
        0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
        0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
        0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
        0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
        0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
        0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
        0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
        0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
        ]
    
    subbytes_values = []
    for row in range(4):
        sub1 = sbox[matrix[row][0]]
        sub2 = sbox[matrix[row][1]]
        sub3 = sbox[matrix[row][2]]
        sub4 = sbox[matrix[row][3]]

        row = [sub1,sub2,sub3,sub4]
        subbytes_values.append(row)
    
    return subbytes_values
# end of SubBytes

# first row is not shifted, shift second row once, shift third row twice, shift fourth row three times
def ShiftRows(matrix):
    shiftrows_matrix = []
    row1 = [matrix[0][0], matrix[0][1], matrix[0][2], matrix[0][3]]
    row2 = [matrix[1][1], matrix[1][2], matrix[1][3], matrix[1][0]]
    row3 = [matrix[2][2], matrix[2][3], matrix[2][0], matrix[2][1]]
    row4 = [matrix[3][3], matrix[3][0], matrix[3][1], matrix[3][2]]

    shiftrows_matrix.append(row1)
    shiftrows_matrix.append(row2)
    shiftrows_matrix.append(row3)
    shiftrows_matrix.append(row4)

    return shiftrows_matrix
# end of ShiftRows

# just so MixColumns is more readable
def MixColumns_Helper(a, num):
    if a >= 128:
        num = num ^ 27
    if num >= 256:
        num = num - 256

    return num
#end of MixColumns_Helper

def MixColumns(matrix):
    mix_columns = [
        [0,0,0,0],
        [0,0,0,0],
        [0,0,0,0],
        [0,0,0,0]
    ]

    column1 = [matrix[0][0], matrix[1][0], matrix[2][0], matrix[3][0]]
    column2 = [matrix[0][1], matrix[1][1], matrix[2][1], matrix[3][1]]
    column3 = [matrix[0][2], matrix[1][2], matrix[2][2], matrix[3][2]]
    column4 = [matrix[0][3], matrix[1][3], matrix[2][3], matrix[3][3]]

    columns = [column1, column2, column3, column4]

    for i in range(4):
        column = columns[i]

        mult2_a0 = 2 * column[0]
        mult2_a0 = MixColumns_Helper(column[0], mult2_a0)
        mult3_a0 = 2 * column[0]
        mult3_a0 = MixColumns_Helper(column[0], mult3_a0)
        mult3_a0 = mult3_a0 ^ column[0]

        mult2_a1 = 2 * column[1]
        mult2_a1 = MixColumns_Helper(column[1], mult2_a1)
        mult3_a1 = 2 * column[1]
        mult3_a1 = MixColumns_Helper(column[1], mult3_a1)
        mult3_a1 = mult3_a1 ^ column[1]
            
        mult2_a2 = 2 * column[2]
        mult2_a2 = MixColumns_Helper(column[2], mult2_a2)
        mult3_a2 = 2 * column[2]
        mult3_a2 = MixColumns_Helper(column[2], mult3_a2)
        mult3_a2 = mult3_a2 ^ column[2]
            
        mult2_a3 = 2 * column[3]
        mult2_a3 = MixColumns_Helper(column[3], mult2_a3)
        mult3_a3 = 2 * column[3]
        mult3_a3 = MixColumns_Helper(column[3], mult3_a3)
        mult3_a3 = mult3_a3 ^ column[3]

        b0 = mult2_a0 ^ mult3_a1 ^ column[2] ^ column[3]
        b1 = column[0] ^ mult2_a1 ^ mult3_a2 ^ column[3]
        b2 = column[0] ^ column[1] ^ mult2_a2 ^ mult3_a3
        b3 = mult3_a0 ^ column[1] ^ column[2] ^ mult2_a3

        mix_columns[0][i] = b0
        mix_columns[1][i] = b1
        mix_columns[2][i] = b2
        mix_columns[3][i] = b3

    return mix_columns
# end of MixColumns

# replace each byte using inverse sbox table
def inverseSubBytes(matrix):
    inverse_sbox = [
        0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
        0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
        0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
        0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
        0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
        0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
        0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
        0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
        0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
        0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
        0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
        0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
        0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
        0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
        0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
        0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
        ]
    inverse_subbytes_values = []
    for row in range(4):
        sub1 = inverse_sbox[matrix[row][0]]
        sub2 = inverse_sbox[matrix[row][1]]
        sub3 = inverse_sbox[matrix[row][2]]
        sub4 = inverse_sbox[matrix[row][3]]

        row = [sub1,sub2,sub3,sub4]
        inverse_subbytes_values.append(row)
    
    return inverse_subbytes_values
# end of inverseSubBytes

# reverses shift rows shifts
def inverseShiftRows(matrix):
    shiftrows_matrix = []
    row1 = [matrix[0][0], matrix[0][1], matrix[0][2], matrix[0][3]]
    row2 = [matrix[1][3], matrix[1][0], matrix[1][1], matrix[1][2]]
    row3 = [matrix[2][2], matrix[2][3], matrix[2][0], matrix[2][1]]
    row4 = [matrix[3][1], matrix[3][2], matrix[3][3], matrix[3][0]]

    shiftrows_matrix.append(row1)
    shiftrows_matrix.append(row2)
    shiftrows_matrix.append(row3)
    shiftrows_matrix.append(row4)
    
    return shiftrows_matrix
# end of inverseShiftRows

# reverses mix columns shifts
def inverseMixColumns(matrix):
    inverse_mix_columns = [
        [0,0,0,0],
        [0,0,0,0],
        [0,0,0,0],
        [0,0,0,0]
    ]

    column1 = [matrix[0][0], matrix[1][0], matrix[2][0], matrix[3][0]]
    column2 = [matrix[0][1], matrix[1][1], matrix[2][1], matrix[3][1]]
    column3 = [matrix[0][2], matrix[1][2], matrix[2][2], matrix[3][2]]
    column4 = [matrix[0][3], matrix[1][3], matrix[2][3], matrix[3][3]]

    columns = [column1, column2, column3, column4]

    for i in range(4):
        column = columns[i]

        mult2_a0 = 2 * column[0]
        mult2_a0 = MixColumns_Helper(column[0], mult2_a0)
        mult4_a0 = 2 * mult2_a0
        mult4_a0 = MixColumns_Helper(mult2_a0, mult4_a0)
        mult8_a0 = 2 * mult4_a0
        mult8_a0 = MixColumns_Helper(mult4_a0, mult8_a0)

        mult2_a1 = 2 * column[1]
        mult2_a1 = MixColumns_Helper(column[1], mult2_a1)
        mult4_a1 = 2 * mult2_a1
        mult4_a1 = MixColumns_Helper(mult2_a1, mult4_a1)
        mult8_a1 = 2 * mult4_a1
        mult8_a1 = MixColumns_Helper(mult4_a1, mult8_a1)

        mult2_a2 = 2 * column[2]
        mult2_a2 = MixColumns_Helper(column[2], mult2_a2)
        mult4_a2 = 2 * mult2_a2
        mult4_a2 = MixColumns_Helper(mult2_a2, mult4_a2)
        mult8_a2 = 2 * mult4_a2
        mult8_a2 = MixColumns_Helper(mult4_a2, mult8_a2)

        mult2_a3 = 2 * column[3]
        mult2_a3 = MixColumns_Helper(column[3], mult2_a3)
        mult4_a3 = 2 * mult2_a3
        mult4_a3 = MixColumns_Helper(mult2_a3, mult4_a3)
        mult8_a3 = 2 * mult4_a3
        mult8_a3 = MixColumns_Helper(mult4_a3, mult8_a3)

        mult9_a0 = mult8_a0 ^ column[0]
        mult11_a0 = mult8_a0 ^ mult2_a0 ^ column[0]
        mult13_a0 = mult8_a0 ^ mult4_a0 ^ column[0]
        mult14_a0 = mult8_a0 ^ mult4_a0 ^ mult2_a0

        mult9_a1 = mult8_a1 ^ column[1]
        mult11_a1 = mult8_a1 ^ mult2_a1 ^ column[1]
        mult13_a1 = mult8_a1 ^ mult4_a1 ^ column[1]
        mult14_a1 = mult8_a1 ^ mult4_a1 ^ mult2_a1

        mult9_a2 = mult8_a2 ^ column[2]
        mult11_a2 = mult8_a2 ^ mult2_a2 ^ column[2]
        mult13_a2 = mult8_a2 ^ mult4_a2 ^ column[2]
        mult14_a2 = mult8_a2 ^ mult4_a2 ^ mult2_a2

        mult9_a3 = mult8_a3 ^ column[3]
        mult11_a3 = mult8_a3 ^ mult2_a3 ^ column[3]
        mult13_a3 = mult8_a3 ^ mult4_a3 ^ column[3]
        mult14_a3 = mult8_a3 ^ mult4_a3 ^ mult2_a3
        

        b0 = mult14_a0 ^ mult11_a1 ^ mult13_a2 ^ mult9_a3
        b1 = mult9_a0 ^ mult14_a1 ^ mult11_a2 ^ mult13_a3
        b2 = mult13_a0 ^ mult9_a1 ^ mult14_a2 ^ mult11_a3
        b3 = mult11_a0 ^ mult13_a1 ^ mult9_a2 ^ mult14_a3

        inverse_mix_columns[0][i] = b0
        inverse_mix_columns[1][i] = b1
        inverse_mix_columns[2][i] = b2
        inverse_mix_columns[3][i] = b3

    return inverse_mix_columns
# end of inverseMixColumns

# helper for main to print matrices
def print_Helper(matrix):
    for row in matrix:
        print(row)

if __name__ == "__main__":
    alicePrivate = 5
    bobPrivate = 9

    alicePublic = generatePublicKey(alicePrivate)
    print(f"Alice Public Key: {alicePublic}")
    bobPublic = generatePublicKey(bobPrivate)
    print(f"Bob Public Key: {bobPublic}\n")

    aliceShared = generateSharedKey(alicePrivate, bobPublic)
    print(f"Alice Shared Key: {aliceShared}")
    bobShared = generateSharedKey(bobPrivate, alicePublic)
    print(f"Bob Shared Key: {bobShared}\n")

    aesKey = deriveAESKey(aliceShared)
    print(f"AES Key: {aesKey}\n")

    key_matrix = matrix_generator(aesKey.decode())
    print(f"Key Matrix: ")
    print_Helper(key_matrix)
    print("")

    text = "HELLO CSUN WORLD"
    print(f"Text: {text}\n")
    text_matrix = matrix_generator(text)
    print(f"Text Matrix:")
    print_Helper(text_matrix)
    print("")

    encrypt = AddRoundKey(text_matrix, key_matrix)
    print("Initial Round Key: ")
    print_Helper(encrypt)
    print("")

    for i in range(9):
        encrypt = SubBytes(encrypt)
        encrypt = ShiftRows(encrypt)
        encrypt = MixColumns(encrypt)
        encrypt = AddRoundKey(encrypt, key_matrix)

    print("After 9 rounds")
    print_Helper(encrypt)
    print("")

    encrypt = SubBytes(encrypt)
    encrypt = ShiftRows(encrypt)
    encrypt = AddRoundKey(encrypt, key_matrix)

    print("After Final round: ")
    print("Encrypted matrix:")
    print_Helper(encrypt)
    print("")
    
    decrypt = AddRoundKey(encrypt, key_matrix)
    decrypt = inverseShiftRows(decrypt)
    decrypt = inverseSubBytes(decrypt)
    print("After first round of decrypting: ")
    print_Helper(decrypt)
    print("")

    for i in range(9):
        decrypt = AddRoundKey(decrypt, key_matrix)
        decrypt = inverseMixColumns(decrypt)
        decrypt = inverseShiftRows(decrypt)
        decrypt = inverseSubBytes(decrypt)
    
    print("After 10 rounds of decrypting: ")
    print_Helper(decrypt)
    print("")

    decrypt = AddRoundKey(decrypt, key_matrix)
    print("Decrypted matrix:")
    print_Helper(decrypt)
    print("")

    decrypted_text = ""
    for col in range(4):
        for row in range(4):
            decrypted_text += chr(decrypt[row][col])

    print(f"Decrypted text: {decrypted_text}")