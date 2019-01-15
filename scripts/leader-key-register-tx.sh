#!/bin/sh

CONSENSUS_HASH="$1"
PROVING_PUBLIC_KEY="$2"
MEMO="$3"

KEY="$4"

if [ -z "$KEY" ]; then
   echo "Usage: $0 consensus_hash vrf_key memo key" 
   exit 1
fi

SCRIPT_PUBKEY_HEX="$(ecdsa_addr -h "$KEY")"
SCRIPT_PUBKEY="76a914${SCRIPT_PUBKEY_HEX}88ac"

TXTOOL="../target/debug/blockstack-tx-tools"
PAYLOAD="69645e${CONSENSUS_HASH}${PROVING_PUBLIC_KEY}${MEMO}"
LENGTH="$(echo -n "$PAYLOAD" | wc -c | xargs printf "%d/2\n" | bc)"
LENGTH_HEX=

if [[ $LENGTH -lt 76 ]]; then 
    LENGTH_HEX="$(echo "$LENGTH" | xargs printf "%02x")"
else
    LENGTH_HEX="4c$(echo "$LENGTH" | xargs printf "%02x")"
fi

RAW_TXDATA="$($TXTOOL make-tx inputs "1111111111111111111111111111111111111111111111111111111111111111" 0 "" 0 outputs 0 "6a${LENGTH_HEX}${PAYLOAD}" 12345 "$SCRIPT_PUBKEY")"
TXDATA="$($TXTOOL sign-tx "$RAW_TXDATA" "$SCRIPT_PUBKEY" "$KEY" 0)"

echo "$TXDATA"
