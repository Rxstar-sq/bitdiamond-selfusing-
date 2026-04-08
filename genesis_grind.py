import hashlib, struct, time

def dsha(b):
    return hashlib.sha256(hashlib.sha256(b).digest()).digest()

def compact_to_target(bits):
    exp = (bits >> 24) & 0xff
    mant = bits & 0x007fffff
    if exp <= 3:
        return mant >> (8 * (3-exp))
    return mant << (8 * (exp-3))

def varint(n):
    if n < 0xfd: return bytes([n])
    if n <= 0xffff: return b'\xfd' + struct.pack('<H', n)
    if n <= 0xffffffff: return b'\xfe' + struct.pack('<I', n)
    return b'\xff' + struct.pack('<Q', n)

ts = b"My name is 77 - My Own Bitdiamond 2026-04-07"
script_sig = b'\x04' + bytes.fromhex('ffff001d') + b'\x01\x04' + bytes([len(ts)]) + ts
script_pubkey = bytes.fromhex('4104678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5fac')

tx = struct.pack('<i', 1)
tx += varint(1)
tx += b'\x00'*32 + struct.pack('<I', 0xffffffff)
tx += varint(len(script_sig)) + script_sig
tx += struct.pack('<I', 0xffffffff)
tx += varint(1)
tx += struct.pack('<q', 30000000*100000000)
tx += varint(len(script_pubkey)) + script_pubkey
tx += struct.pack('<I', 0)

merkle = dsha(tx)
merkle_hex = merkle[::-1].hex()

nVersion = 1
nBits = 0x207fffff  # RegTest difficulty (very low, instant)
nTime = 1231006505
nonce = 0

target = compact_to_target(nBits)
print('target=', hex(target))
print('merkle=', merkle_hex)

start = time.time()
checked = 0
while True:
    hdr = struct.pack('<I', nVersion) + b'\x00'*32 + merkle + struct.pack('<I', nTime) + struct.pack('<I', nBits) + struct.pack('<I', nonce)
    h = dsha(hdr)
    h_int = int.from_bytes(h[::-1], 'big')
    if h_int <= target:
        print('FOUND')
        print('nTime=', nTime)
        print('nNonce=', nonce)
        print('hash=', h[::-1].hex())
        print('merkle=', merkle_hex)
        break
    nonce = (nonce + 1) & 0xffffffff
    checked += 1
    if nonce == 0:
        nTime += 1
    if checked % 2000000 == 0:
        elapsed = time.time() - start
        rate = checked / elapsed if elapsed else 0
        print(f'checked={checked} rate={rate:.0f}/s nTime={nTime} nonce={nonce}')
