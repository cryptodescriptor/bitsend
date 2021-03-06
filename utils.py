from base58 import b58decode
import bech32, struct

class UnsupportedFormat(Exception):
  """unsupported address format"""

DUP = b"\x76"
PUSH_20 = b"\x14"
HASH160 = b"\xA9"
EQUAL = b"\x87"
EQUALVERIFY = b"\x88"
CHECKSIG = b"\xAC"

def b58_check(addr):
  return b58decode(addr)[1:-4]

def get_witness_prog(addr, testnet=False):
  hrp = "tb" if testnet else "bc"
  ret = bech32.decode(hrp, addr)
  witness_prog = str(bytearray(ret[1]))

  if len(witness_prog) == 32:
    raise UnsupportedFormat("Error: We dont support P2SH segwit addresses. (" + addr + ")")
  
  ver = struct.pack("<B", ret[0])

  return witness_prog, ver

def p2wpkh(addr, testnet=False):
  witness_prog, ver = get_witness_prog(addr, testnet)
  return ver + PUSH_20 + witness_prog
    
def p2sh_p2wpkh(addr):
  script = b58_check(addr)
  if len(script) != 20:
    raise UnsupportedFormat(
      "Error: We only support hashed redeemscript p2sh addresses. (" + addr + ")"
    )
  return HASH160 + PUSH_20 + script + EQUAL

def p2pkh(addr):
  hash = b58_check(addr)
  return DUP + HASH160 + PUSH_20 + hash + EQUALVERIFY + CHECKSIG