import pickle

### Constants and Utility Functions
#Jonah Mihir

h_hex = ['0x6a09e667', '0xbb67ae85', '0x3c6ef372', '0xa54ff53a', '0x510e527f', '0x9b05688c', '0x1f83d9ab', '0x5be0cd19']

K = ['0x428a2f98', '0x71374491', '0xb5c0fbcf', '0xe9b5dba5', '0x3956c25b', '0x59f111f1', '0x923f82a4',
 '0xab1c5ed5', '0xd807aa98', '0x12835b01', '0x243185be', '0x550c7dc3', '0x72be5d74', '0x80deb1fe', 
 '0x9bdc06a7', '0xc19bf174', '0xe49b69c1', '0xefbe4786', '0x0fc19dc6', '0x240ca1cc', '0x2de92c6f', 
 '0x4a7484aa', '0x5cb0a9dc', '0x76f988da', '0x983e5152', '0xa831c66d', '0xb00327c8', '0xbf597fc7', 
 '0xc6e00bf3', '0xd5a79147', '0x06ca6351', '0x14292967', '0x27b70a85', '0x2e1b2138', '0x4d2c6dfc', 
 '0x53380d13', '0x650a7354', '0x766a0abb', '0x81c2c92e', '0x92722c85', '0xa2bfe8a1', '0xa81a664b', 
 '0xc24b8b70', '0xc76c51a3', '0xd192e819', '0xd6990624', '0xf40e3585', '0x106aa070', '0x19a4c116', 
 '0x1e376c08', '0x2748774c', '0x34b0bcb5', '0x391c0cb3', '0x4ed8aa4a', '0x5b9cca4f', '0x682e6ff3', 
 '0x748f82ee', '0x78a5636f', '0x84c87814', '0x8cc70208', '0x90befffa', '0xa4506ceb', '0xbef9a3f7', 
 '0xc67178f2']

def isTrue(x): return x == 1

def if_(i, y, z): return y if isTrue(i) else z

def and_(i, j): return if_(i, j, 0)
def AND(i, j): return [and_(ia, ja) for ia, ja in zip(i,j)] 

def not_(i): return if_(i, 0, 1)
def NOT(i): return [not_(x) for x in i]

def xor(i, j): return if_(i, not_(j), j)
def XOR(i, j): return [xor(ia, ja) for ia, ja in zip(i, j)]

def xorxor(i, j, l): return xor(i, xor(j, l))
def XORXOR(i, j, l): return [xorxor(ia, ja, la) for ia, ja, la, in zip(i, j, l)]

def maj(i,j,k): return max([i,j,], key=[i,j,k].count)

def rotr(x, n): return x[-n:] + x[:-n]

def shr(x, n): return n * [0] + x[:-n]

def add(i, j):
  length = len(i)
  sums = list(range(length))
  c = 0
  for x in range(length-1,-1,-1):
    sums[x] = xorxor(i[x], j[x], c)
    c = maj(i[x], j[x], c)
  return sums

### Message Preprocessing (you'll probably want to look at this!)

def chunker(bits, chunk_length=8):
    chunked = []
    for b in range(0, len(bits), chunk_length):
        chunked.append(bits[b:b+chunk_length])
    return chunked

def fillZeros(bits, length=8, endian='LE'):
    l = len(bits)
    if endian == 'LE':
        for i in range(l, length):
            bits.append(0)
    else: 
        while l < length:
            bits.insert(0, 0)
            l = len(bits)
    return bits

def bitPreprocessMessage(bitinput):
    bits = bitinput.copy()
    length = len(bits)
    message_len = [int(b) for b in bin(length)[2:].zfill(64)]
    if length < 448:
        bits.append(1)
        bits = fillZeros(bits, 448, 'LE')
        bits = bits + message_len
        return [bits]
    elif 448 <= length <= 512:
        bits.append(1)
        bits = fillZeros(bits, 1024, 'LE')
        bits[-64:] = message_len
        return chunker(bits, 512)
    else:
        bits.append(1)
        while (len(bits)+64) % 512 != 0:
            bits.append(0)
        bits = bits + message_len
        return chunker(bits, 512)

def initializer(values):
    binaries = [bin(int(v, 16))[2:] for v in values]
    words = []
    for binary in binaries:
        word = []
        for b in binary:
            word.append(int(b))
        words.append(fillZeros(word, 32, 'BE'))
    return words

def b2Tob16(value):
  value = ''.join([str(x) for x in value])
  binaries = []
  for d in range(0, len(value), 4):
    binaries.append('0b' + value[d:d+4])
  hexes = ''
  for b in binaries:
    hexes += hex(int(b ,2))[2:]
  return hexes

### Main SHA-256 Method (you'll want to look at this as well!)

def sha256(bits): 
    k = initializer(K)
    h0, h1, h2, h3, h4, h5, h6, h7 = initializer(h_hex)
    chunks = bitPreprocessMessage(bits)
    for chunk in chunks:
        w = chunker(chunk, 32)
        for _ in range(48):
            w.append(32 * [0])
        for i in range(16, 64):
            s0 = XORXOR(rotr(w[i-15], 7), rotr(w[i-15], 18), shr(w[i-15], 3) ) 
            s1 = XORXOR(rotr(w[i-2], 17), rotr(w[i-2], 19), shr(w[i-2], 10))
            w[i] = add(add(add(w[i-16], s0), w[i-7]), s1)
        a = h0
        b = h1
        c = h2
        d = h3
        e = h4
        f = h5
        g = h6
        h = h7
        for j in range(64):
            S1 = XORXOR(rotr(e, 6), rotr(e, 11), rotr(e, 25) )
            ch = XOR(AND(e, f), AND(NOT(e), g))
            temp1 = add(add(add(add(h, S1), ch), k[j]), w[j])
            S0 = XORXOR(rotr(a, 2), rotr(a, 13), rotr(a, 22))
            m = XORXOR(AND(a, b), AND(a, c), AND(b, c))
            temp2 = add(S0, m)
            h = g
            g = f
            f = e
            e = add(d, temp1)
            d = c
            c = b
            b = a
            a = add(temp1, temp2)
        h0 = add(h0, a)
        h1 = add(h1, b)
        h2 = add(h2, c)
        h3 = add(h3, d)
        h4 = add(h4, e)
        h5 = add(h5, f)
        h6 = add(h6, g)
        h7 = add(h7, h)
    digest = ''
    for val in [h0, h1, h2, h3, h4, h5, h6, h7]:
        digest += b2Tob16(val)
    return digest

# This is the value of sha256(KEY + X). We know that KEY is an array of bits of length 256, but don't know what it is.
HASH = "61fa41e8b85249da206e4101d5d52f2257aef2ad7139a096e1cb7f00a8734b43"

#This is the value of X
X = [1,0,0,1,0,1,0,1]

### YOUR CODE HERE

# Your goal is to find a Y and NEW_HASH such that sha256(KEY + X + Y) == NEW_HASH

def hex_to_bitarray(hexstr):
    result = []
    for char in hexstr:
        val = int(char, 16)
        bits = [int(b) for b in bin(val)[2:].zfill(4)]
        result.extend(bits)
    return result

def length_extension(og_hash, extension, length):
    h_states = []

    for byte in range(0, 64, 8):
        h_states.append(hex_to_bitarray(og_hash[byte:byte+8]))
    
    h0, h1, h2, h3, h4, h5, h6, h7 = h_states

    padding = [1]

    while (length + len(padding)) % 512 != 448:
        padding.append(0)

    padding.extend([int(b) for b in bin(length)[2:].zfill(64)])

    block = extension.copy()
    block.append(1)

    while (len(block) + 64) % 512 != 0:
        block.append(0)

    total_len = length + len(padding) + len(extension)
    block.extend([int(b) for b in bin(total_len)[2:].zfill(64)])

    w = chunker(block, 32)
    w.extend([32 * [0]] * 48)
    
    for i in range(16, 64):
        s0 = XORXOR(rotr(w[i-15], 7), rotr(w[i-15], 18), shr(w[i-15], 3))
        s1 = XORXOR(rotr(w[i-2], 17), rotr(w[i-2], 19), shr(w[i-2], 10))
        w[i] = add(add(add(w[i-16], s0), w[i-7]), s1)
    
    a, b, c, d, e, f, g, h = h0, h1, h2, h3, h4, h5, h6, h7
    k = initializer(K)

    for j in range(64):
        S1 = XORXOR(rotr(e, 6), rotr(e, 11), rotr(e, 25))
        ch = XOR(AND(e, f), AND(NOT(e), g))
        temp1 = add(add(add(add(h, S1), ch), k[j]), w[j])
        S0 = XORXOR(rotr(a, 2), rotr(a, 13), rotr(a, 22))
        maj = XORXOR(AND(a, b), AND(a, c), AND(b, c))
        temp2 = add(S0, maj)

        h = g
        g = f 
        f = e
        e = add(d, temp1)
        d = c
        c = b
        b = a
        a = add(temp1, temp2)

    h_new = [add(h0, a), add(h1, b), add(h2, c), add(h3, d), add(h4, e), add(h5, f), add(h6, g), add(h7, h)]

    forged = ''.join(b2Tob16(h) for h in h_new)
    
    return forged, padding

# All testing functionality in one function - DELETE THIS BEFORE SUBMITTING
def run_tests():
    print("========== TESTING FUNCTIONALITY - DELETE BEFORE SUBMISSION ==========")
    
    # Test method using the successful approach
    def test_successful_approach():
        # Create a fake key
        fake_key = [0] * 256
        original_message = fake_key + X
        original_hash = sha256(original_message)
        
        # Create test extension
        test_extension = [1, 1, 0, 0, 1, 1, 0, 0]
        
        # Perform the length extension attack
        forged, padding = length_extension(original_hash, test_extension, len(original_message))
        
        # Calculate the actual hash for comparison
        message_with_glue = original_message + padding + test_extension
        actual_hash = sha256(message_with_glue)
        
        print(f"Original hash: {original_hash}")
        print(f"Forged hash:   {forged}")
        print(f"Actual hash:   {actual_hash}")
        print(f"Match:         {forged == actual_hash}")
        
        return forged == actual_hash
    
    # Run the test
    print("Testing successful approach...")
    if test_successful_approach():
        print("Test successful! Using this method for the final solution.")
    else:
        print("Test failed! Something is still wrong with our implementation.")
    
    print("\nTesting with different Y values:")
    # Test with different Y values
    fake_key = [0] * 256
    test_y_values = [
        [1, 0, 1, 0],
        [1, 1, 1, 1, 0, 0, 0, 0],
        [0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1],
    ]
    
    for i, test_y in enumerate(test_y_values):
        original_message = fake_key + X
        original_hash = sha256(original_message)
        forged, padding = length_extension(original_hash, test_y, len(original_message))
        message_with_glue = original_message + padding + test_y
        actual_hash = sha256(message_with_glue)
        
        print(f"\nTest {i+1} with Y = {test_y}")
        print(f"Forged hash: {forged}")
        print(f"Actual hash: {actual_hash}")
        print(f"Match:       {forged == actual_hash}")
    
    print("=================================================================")

# Run tests (COMMENT OUT OR DELETE THIS LINE BEFORE SUBMITTING)
run_tests()

# Y ("JonahMihir" in binary)
Y = [0,1,0,0,1,0,1,0, 0,1,1,0,1,1,1,1, 0,1,1,0,1,1,1,0, 0,1,1,0,0,0,0,1, 0,1,1,0,1,0,0,0, 0,1,0,0,1,1,0,1, 0,1,1,0,1,0,0,1, 0,1,1,0,1,0,0,0, 0,1,1,0,1,0,0,1, 0,1,1,1,0,0,1,0]

NEW_HASH, padding = length_extension(HASH, Y, 256 + 8)

print("\n---- Original Information ----")
print(f"Original HASH: {HASH}")
print(f"X: {X}")
print(f"Y: {Y}")
print(f"NEW_HASH: {NEW_HASH}")

# Submit this file to GradeScope
with open('COMS_4995_hw5' , 'wb') as f:
    pickle.dump((Y, NEW_HASH), f)
    f.close()