def aes_encrypt(plaintext, key):
    expanded_key = key_expansion(key)
    state = add_round_key(plaintext,expanded_key[0])
    rounds = number_of_rounds(key)
    for round in range(1,rounds-1):
        state = sub_bytes(state)
        state = shift_rows(state)
        state = mix_columns(state)
        state = add_round_key(state,expanded_key[round])
    state = sub_bytes(state)
    state = shift_rows(state)
    state = add_round_key(state,expanded_key[rounds])

    return state


def aes_decrypt(ciphertext,key):
    expanded_key = key_expansion(key)
    state = add_round_key(ciphertext,expanded_key[0])
    rounds = number_of_rounds(key)
    for round in range(rounds-1,1,-1):
        state = inv_shift_rows(state)
        state = inv_sub_bytes(state)
        state = add_round_key(state,expanded_key[round])
    state = inv_shift_rows(state)
    state = inv_sub_bytes(state)
    state = add_round_key(state,expanded_key[0])

    return state

def key_expansion(key):
    expanded_key = []
    expanded_key = key_schedule(key)
    return expanded_key

def add_round_key(state,round_key):
    for i in range(15):
        state[i] = state[i]^round_key[i]
    return state

def sub_bytes(state):
    for i in range(15):
        state[i] = s_box[state[i]]
    return state

def inv_sub_bytes(state):
    for i in range(15):
        state[i] = inv_s_box[state[i]]
    return state

def shift_rows(state):
    state = [
        state[0], state[5], state[10], state[15],
        state[4], state[9], state[14], state[3],
        state[8], state[13], state[2], state[7],
        state[12], state[1], state[6], state[11]
        ]
    return state

def inv_shift_rows(state):
    state = [
        state[0], state[13], state[10], state[7],
        state[4], state[1], state[14], state[11],
        state[8], state[5], state[2], state[15],
        state[12], state[9], state[6], state[3]
        ]
    return state

def mix_columns(state):
    for i in range(3):
        column = state[i*4:i*4+4]
        state[i*4:i*4+4] = mix_single_column(column)
    return state

def inv_mix_columns(state):
    for i in range(3):
        column = state[i*4:i*4+4]
        state[i*4:i*4+4] = inv_mix_single_column(column)
    return state

def mix_single_column(column):
    return [
        multiply(0x02,column[0]) ^ multiply(0x03,column[1]) ^ column[2] ^ column[3],
        column[0] ^ multiply(0x02,column[1]) ^ multiply(0x03,column[2]) ^ column[3],
        column[0] ^ column[1] ^ multiply(0x02,column[2]) ^ multiply(0x03,column[3]),
        multiply(0x03,column[0]) ^ column[1] ^ column[2] ^ multiply(0x02,column[3])
    ]

def inv_mix_single_column(column):
    return [
        multiply(0x0e,column[0]) ^ multiply(0x0b,column[1]) ^ multiply(0x0d,column[2]) ^ multiply(0x09,column[3]),
        multiply(0x09,column[0]) ^ multiply(0x0e,column[1]) ^ multiply(0x0b,column[2]) ^ multiply(0x0d,column[3]),
        multiply(0x0d,column[0]) ^ multiply(0x09,column[1]) ^ multiply(0x0e,column[2]) ^ multiply(0x0b,column[3]),
        multiply(0x0b,column[0]) ^ multiply(0x0d,column[1]) ^ multiply(0x09,column[2]) ^ multiply(0x0e,column[3]),
    ]

def multiply(a,b):
    result = 0
    while b:
        if b & 1:
            result^=a
        a<<=1
        if a & 0x100:
            a ^= 0x11b
        b>>=1
    return result

def number_of_rounds(key):
    key_size = len(key)
    if key_size == 16: #128-bit
        return 10
    elif key_size == 24: #192-bit
        return 12
    elif key_size == 32: #256-bit
        return 14
    else:
        raise ValueError("Invalid Key Size")

def key_schedule(key):
    expanded_key = []
    return expanded_key