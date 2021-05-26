'''
Written by: Balazs Valer Fekete fbv81bp@outlook.hu fbv81bp@gmail.com
Last updated: 29.01.2021
'''

import random 

# CONFIGURATION
# -------------

# number of choosen plain texts based side channel attack measurements
run_length = 2 # 30..50 already bring fairly stable results without noise

# MODELLING
# ---------

# Modelling non-linearity of the Chi function to check its leakage: if this component can be made leakage free,
# the entire design will be so, because linear functions don't leak
def chi_leakage(state_in):
    array = [0 for i in range(5)]
    # convert integer to array
    for i in range(5):
        if state_in % 2 == 1:
            array[4-i] = 1
        state_in //= 2
    # calculate 1 Chi on 5 bits: Chi's are calculated independently on 5-5 bits, if that's done parallely, it
    # just adds algorithmic noise, but the correlation still works
    for x in range(5):
        array[x] = array[x] ^ ((not array[(x + 1) % 5]) and array[(x + 2) % 5])
    # convert array to integer
    state_out = 0
    for i in range(5):
        state_out *= 2
        if array[i] == 1:
            state_out += 1
    return state_out

# Hamming weight of x
def count1s(x):
    y = 0
    while(x>0):
        if x%2==1:
            y+=1
        x=x//2
    return y

# PREPARATION
# -----------

# hypothesises of hamming weights for keys

hypothesises = [[] for i in range(32)] #1st index: key; 2nd index: plain texts
for key_state in range(32):
    for data_state in range(32):
        hypothesises[key_state].append(count1s(chi_leakage(key_state ^ data_state))) 
        # this XOR is way more complex in the real SHA3 and includes permutations too,
        # yet ultimately it just comes down to XOR-ing the dedicated bits and performing
        # the non-linear function on them

# SIMULATE MEASUREMENTS
# ---------------------

# pick any random number between 0 and 31
key_bits = random.randint(0,31)

# pick some random numbers you like to run hacking with
choosen_plain_texts = [random.randint(0,31) for i in range(run_length)]

# simulate leakage: no algorithmic or other noise is being simulated, making the
# entire hacking process more effective, yet it is impossible to hack the key_state
# of just 2 measurements enabled by its value being applied only twice maximum
leakages = [count1s(chi_leakage(key_bits ^ plain)) for plain in choosen_plain_texts]

# HACK IT
# -------

#calculating correlations with diverse hypothesises on assumed key values
most_likely_key = 0
highest_correlation = 0
for assumed_key in range(32):
    correlation = 0
    for i in range(len(leakages)):
        correlation += hypothesises[assumed_key][choosen_plain_texts[i]] * leakages[i]
    if correlation > highest_correlation:
        highest_correlation = correlation
        most_likely_key = assumed_key

print('real key:', key_bits)
print('most likely key:', most_likely_key)
