import os
import cProfile
import sys

import ed25519

help_desc = """
profile.py [case] [loops]

Run profiling of ed25519 functions

case - must be one of:
       pub -- generating a public key
       sig -- generating a signature
       val -- validating a signature

loop - how many times to repeat test
"""

seed = os.urandom(32)
data = b"The quick brown fox jumps over the lazy dog"
private_key = seed
public_key = ed25519.publickey(seed)
signature = ed25519.signature(data, private_key, public_key)

gen_public_key = 'ed25519.publickey(seed)'
gen_signature = 'ed25519.signature(data, private_key, public_key)'
do_validation = 'ed25519.checkvalid(signature, data, public_key)'

case = {
    'pub': gen_public_key,
    'sig': gen_signature,
    'val': do_validation,
}

length = 300
choice = ''

if len(sys.argv) >= 2:
    if sys.argv[1] == '-h' or sys.argv[1] == '--help':
        print(help_desc)
        exit()
    choice = sys.argv[1]
if len(sys.argv) >= 3:
    length = int(sys.argv[2])

method = case.get(choice, 'val')

loop = '[%s for _ in range(%d)]'

print('Running %s, %d times\n' % (case[method], length))

cProfile.run(loop % (case[method], length))
