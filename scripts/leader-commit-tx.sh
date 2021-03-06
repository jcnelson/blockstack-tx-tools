#!/bin/sh

BLOCK_HASH="$1"
VRF_SEED="$2"
PARENT_BLOCK_PTR="$3"
PARENT_BLOCK_VTXINDEX="$4"
KEY_BLOCK_PTR="$5"
KEY_BLOCK_VTXINDEX="$6"
MEMO="$7"

KEY="$8"

if [ -z "$KEY" ]; then 
   echo "Usage: $0 block_hash vrf_seed parent_block_ptr parent_block_vtxindex key_block_ptr key_block_vtxindex memo key"
   exit 1
fi

SCRIPT_PUBKEY_HEX="$(ecdsa_addr -h "$KEY")"
SCRIPT_PUBKEY="76a914${SCRIPT_PUBKEY_HEX}88ac"

TXTOOL="../target/debug/blockstack-tx-tools"

PAYLOAD="69645b${BLOCK_HASH}${VRF_SEED}${PARENT_BLOCK_PTR}${PARENT_BLOCK_VTXINDEX}${KEY_BLOCK_PTR}${KEY_BLOCK_VTXINDEX}${MEMO}"
LENGTH="$(echo -n "$PAYLOAD" | wc -c | xargs printf "%d/2\n" | bc)"
LENGTH_HEX=

if [[ $LENGTH -lt 76 ]]; then 
    LENGTH_HEX="$(echo "$LENGTH" | xargs printf "%02x")"
else
    LENGTH_HEX="4c$(echo "$LENGTH" | xargs printf "%02x")"
fi

RAW_TXDATA="$($TXTOOL make-tx inputs "1111111111111111111111111111111111111111111111111111111111111111" 0 "" 0 outputs 0 "6a${LENGTH_HEX}${PAYLOAD} 12345 "76a914000000000000000000000000000000000000000088ac" 23456 "$SCRIPT_PUBKEY")"
TXDATA="$($TXTOOL sign-tx "$RAW_TXDATA" "$SCRIPT_PUBKEY" "$KEY" 0)"

echo "$TXDATA"
