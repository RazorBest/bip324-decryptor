# anon_pcap

A python script that pseudoanonymizes pcap files.


## Usage

```bash
# Basic usage: anonymize IPs with table mapping (payload remains untouched)
python anon_pcap.py \
    --input capture.pcap \
    --output anonymized.pcap \
    --save-mapping mapping.json

# Advanced usage: anonymize MACs, normalize time, and save mapping table
python anon_pcap.py \
    --input capture1.pcap \
    --output anonymized.pcap \
    --ip-mode table \
    --ip-subnet 10.0.0.0/8 \
    --anonymize-mac \
    --relative-time \
    --strip-ip-options \
    --save-mapping mapping.json

# Do it for multiple files, inplace
python anon_pcap.py \
    --input *.pcap \
    --inplace
    --ip-mode table \
    --ip-subnet 10.0.0.0/8 \
    --anonymize-mac \
    --relative-time \
    --strip-ip-options \
    --save-mapping mapping.json

# De-anonymize / revert a PCAP using an existing mapping file
python anon_pcap.py \
    --input anonymized.pcap \
    --output restored.pcap \
    --load-mapping mapping.json \
    --reverse
```

### CLI Options Summary

```
usage: anon_pcap.py [-h] -i [INPUT ...] [-o [OUTPUT ...]] [--inplace] [--ip-mode {table,cryptopan,feistel}] [--ip-subnet IP_SUBNET] [--key KEY]
                    [--save-mapping SAVE_MAPPING] [--load-mapping LOAD_MAPPING] [--reverse] [--anonymize-mac] [--relative-time] [--anonymize-ephemeral-ports]
                    [--mask-isn] [--strip-ip-options]

Anonymize PCAP captures with bijective IP mapping and protocol integrity.

options:
  -h, --help            show this help message and exit
  -i, --input [INPUT ...]
                        Input PCAP or PCAPNG file path(s)
  -o, --output [OUTPUT ...]
                        Output anonymized PCAP file path(s)
  --inplace             If set, edit the input files inplace
  --ip-mode {table,cryptopan,feistel}
                        Bijective IP anonymization algorithm (default: table)
  --ip-subnet IP_SUBNET
                        Target IPv4 private subnet for 'table' mode (default: 10.0.0.0/8)
  --key KEY             Secret key/passphrase for 'cryptopan' or 'feistel' modes (auto-generated if omitted)
  --save-mapping SAVE_MAPPING
                        Path to save bijective mapping table (JSON) for de-anonymization
  --load-mapping LOAD_MAPPING
                        Path to load existing bijective mapping table (JSON)
  --reverse             Reverse anonymization (de-anonymize) using loaded mapping table or key
  --anonymize-mac       Bijectively anonymize Ethernet MAC addresses (OUI masked to 02:xx:xx:...)
  --relative-time       Shift timestamps so first packet is at t0 = 0.0s (preserves delta-t)
  --anonymize-ephemeral-ports
                        Bijectively remap ephemeral TCP ports (preserves well-known service ports)
  --mask-isn            Apply consistent random offset to TCP Initial Sequence Numbers per flow
  --strip-ip-options    Strip IP header options (e.g. Record Route, Timestamp)
```
