'''
Written by: Balazs Valer Fekete fbv81bp@outlook.hu fbv81bp@gmail.com
Last updated: 29.01.2021
'''

# the concept is to generate a side channel resistant initialisation of the hashing function based on
# one secret key and several openly known initialisation vectors (IV) in a manner that the same input
# is not hashed too more than two times, which is hopefully not sufficient for side channel
# measurements based computations: the number of consecutive measurements for a successful attack on
# the CHI function in a practically noiseless computer simulation (see "chi_cpa.py") takes around a
# 100 measurements

# this concept is achieved by taking a counter of a certain bitlength, and twice as many IVs as bits in
# the counter: "IV0s" and "IV1s" and compute a series of hashes starting with the secret key then with a
# correspong IV of the sets 0 and 1 based on whether the counter's corresponding bit - starting at MSB -
# is 0 or 1; this way every hash output is exactly used 2 times if the intermediate values are STORTED
# and the entire series of initial hashes are NOT fully recomputed only such whose corresponding
# counter bits has changed and all the next levels too down to the LSB of the counter

# the working solution is going to based on the algorithms presented here, although
# in this file the algorithm here does the full padding so the results won't equal to
# a scheme where the rate is fully filled with IVs and the data comes only afterwards...
    
import hashlib

# KEY DATA STRUCTURES' INTERPRETATION
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

IV0s = [658678, 6785697, 254376, 67856, 1432543, 786, 124345, 5443654]
IV1s = [2565, 256658, 985, 218996, 255, 685652, 28552, 3256565]
# LSB ... MSB

hash_copies = [None for i in range(len(IV0s))]
# LSB ... MSB

# counter
# MSB ... LSB

# COMPUTING HASHES FOR EVERY COUNTER VALUE INDIVIDUALLY
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

for counter in range(11):
    hash = hashlib.sha3_512()
    # looping from MSB to LSB in counter too
    for i in range(len(IV0s)-1, -1, -1):
        if (counter>>i) & 1 == 1:
            IV = bytes(IV1s[i])
        else:
            IV = bytes(IV0s[i])
        hash.update(IV)
    print(hash.hexdigest())

print()

# COMPUTING HASHES BASED ON THE NATURE OF BINARY INCREMENTATION:
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
# only fewer values need to be recomputed, those whose corresponding
# bits have changed, down until LSB

# initialize
hash = hashlib.sha3_512()
# looping from MSB to LSB
for i in range(len(IV0s)-1, -1, -1):
    # addressing "MSB" of IVs at first, "LSB" at last!
    IV = bytes(IV0s[i])
    hash.update(IV)
    # index 0 of hash_copies changes the most frequently ie. according to counter's LSB
    hash_copies[i] = hash.copy()

# compute
last_counter = 0
for counter in range(11):
    IV_mask = last_counter ^ counter
    last_counter = counter
    # determine the highest non-zero bit of IV_mask, LSB is 1, 0 means there was no change
    nz = 0
    while IV_mask > 0:
        IV_mask >>= 1
        nz += 1
    # initialize hash to the last value whose corresponding counter bit didn't switch
    # have to copy object otherwise the originally pointed version gets updated!
    hash = hash_copies[nz].copy() # LSB is index 0
    # compute only the remaining hashes
    while nz != 0: # nz=0 is the initial condition, nothing needs to be done
        nz -= 1
        if (counter>>nz) & 1 == 1:
            IV = bytes(IV1s[nz])
        else:
            IV = bytes(IV0s[nz])
        hash.update(IV)
        # needs to be copied again because of object orientation
        hash_copies[nz] = hash.copy()
    
    # showing the hash copies' entire table after each computation
    #for hashes in hash_copies:
    #    print(hashes.hexdigest())
        
    print(hash_copies[0].hexdigest())
