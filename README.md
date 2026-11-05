# bip324-decryptor

## Install

```
cargo install --git https://github.com/RazorBest/bip324-decryptor
```

## Getting started

The decryptor uses NFQUEUE and needs some iptables rules. You can use the `--iptables-by-uname` option, or set the rules manually by referring to [Iptables examples](#iptables-examples)

First, stop `bitcoind` from the user that runs bitcoin-core:
```
bitcoin_user:~ bitcoin-cli stop
```

Then, run the binary with root privileges:
```
BIP324_DECRYPTOR_PATH=$(which bip324-decryptor); sudo --preserve-env=BIP324_DECRYPTOR_PATH $BIP324_DECRYPTOR_PATH --node-name my_node --log-template logs/decryptor --log debug --iptables-by-uname btc_username
```

And finally, you can start bitcoind:
```
bitcoin_user:~ bitcoind -daemon
```

The program will create the following files:
- `capture_<node_name>_<date>.pcap` - the packets that were forwarded by the interceptor
- `capture_<node_name>_decrypted_<date>.pcap` - the same packets as in `capture_<node_name>_<date>.pcap`, but with decrypted contents
- `capture_<node_name>_unprocessed_<date>.pcap` - all packets received by the interceptor, even if the dropped ones
- `capture_<node_name>_suspicious_<date>.pcap` - packets that were not expected, but still forwarded and bypassed by the MitM layer
- `./logs/decryptor.<day_date>` - log files

### Not running with sudo

Alternatively, f you configure `iptables` manually, you can set the `CAP_NET_ADMIN` capability for the binary:
```
sudo setcap cap_net_admin+ep $(which bip324-decryptor)
```
However, keep in mind that this is persistent (`setcap` only needs to be called once).

Now, you can run:
```
# iptables was configured manually, so the program doesn't need access to iptables
bip324-decryptor --node-name my_node --log-template logs/decryptor --log debug
```

To remove the `CAP_NET_ADMIN` capability:
```
sudo setcap -r cap_net_admin $(which bip324-decryptor)
```

## Iptables examples

### User based selection
`bip324-decryptor` can manage these rules automatically when run as `bip324-decryptor --iptables-by-uname <user_running_bitcoind>`. When it exits, the rules will be deleted.

You can feed these rules to `iptables-restore --noflush`. `--noflush` is needed to preserve existing rules in the table.

Replace `<user_running_bitcoind>` with the user under which `bitcoind` runs. It is strongly recommended that this user not be root or your daily driver user. The rules have some safety mechanisms, such as ignoring port 0-1023 connections (so you don't lose access to SSH, DNS, etc.).

Of these rules, this one is a little unexpected:
```
-A BIP324_DECR_QUEUE_IN -p tcp -m tcp --dport 8333 -j NFQUEUE --queue-num 0 --queue-bypass
```
This rule is needed because Linux doesn't attribute a packet to a process (and therefore a user) before the packet passes through netfilter. This is only needed for the first incoming SYN packet. Subsequent packets can also be matched by CONNMARK.

Feel free to change `--dport 8333`, the id of `queue-num`, or the `--queue-bypass` flag.

```
*mangle
:BIP324_DECR_QUEUE_IN - [0:0]
:BIP324_DECR_QUEUE_OUT - [0:0]

-A INPUT -j BIP324_DECR_QUEUE_IN
-A OUTPUT -j BIP324_DECR_QUEUE_OUT

# Skip system ports for safety
-A BIP324_DECR_QUEUE_IN -p tcp -m multiport --dports 0:1023 -j RETURN
-A BIP324_DECR_QUEUE_IN -p tcp -m multiport --sports 0:1023 -j RETURN
-A BIP324_DECR_QUEUE_IN -p udp -m multiport --dports 0:1023 -j RETURN
-A BIP324_DECR_QUEUE_IN -p udp -m multiport --sports 0:1023 -j RETURN

-A BIP324_DECR_QUEUE_IN -m connmark --mark 0x1 -j NFQUEUE --queue-num 0 --queue-bypass
# Generic way of ensuring that a packet matched by any of the NFQEUEUE rules is connmarked
-A BIP324_DECR_QUEUE_IN -j CONNMARK --set-xmark 0x1/0x1
-A BIP324_DECR_QUEUE_IN -p tcp -m tcp --dport 8333 -j NFQUEUE --queue-num 0 --queue-bypass
-A BIP324_DECR_QUEUE_IN -j CONNMARK --set-xmark 0x0/0x1

# Skip system ports for safety
-A BIP324_DECR_QUEUE_OUT -p tcp -m multiport --dports 0:1023 -j RETURN
-A BIP324_DECR_QUEUE_OUT -p tcp -m multiport --sports 0:1023 -j RETURN
-A BIP324_DECR_QUEUE_OUT -p udp -m multiport --dports 0:1023 -j RETURN
-A BIP324_DECR_QUEUE_OUT -p udp -m multiport --sports 0:1023 -j RETURN

# Skip bitcoin mainnet rpc
-A BIP324_DECR_QUEUE_OUT -p tcp -m tcp --dport 8332 -m owner --uid-owner <user_running_bitcoind> -j RETURN
-A BIP324_DECR_QUEUE_OUT -p tcp -m tcp --sport 8332 -m owner --uid-owner <user_running_bitcoind> -j RETURN

-A BIP324_DECR_QUEUE_OUT -m connmark --mark 0x1 -j NFQUEUE --queue-num 0 --queue-bypass
# Generic way of ensuring that a packet matched by any of the NFQEUEUE rules is connmarked
-A BIP324_DECR_QUEUE_OUT -j CONNMARK --set-xmark 0x1/0x1
-A BIP324_DECR_QUEUE_OUT -m owner --uid-owner <user_running_bitcoind> -j NFQUEUE --queue-num 0 --queue-bypass
-A BIP324_DECR_QUEUE_OUT -j CONNMARK --set-xmark 0x0/0x1

COMMIT
```

### Catch-all rules (not recommended)

This minimal set of rules sends all TCP packets to NFQUEUE (except for bitcoin-rpc packets). Packets that belong to local connections will enter twice the queue because they will hit both the INPUT and OUTPUT chain.

You can feed these rules to `iptables-restore --noflush`. `--noflush` is needed to preserve existing rules in the table.

Feel free to change the id of `queue-num`, or the `--queue-bypass` flag.

```
*mangle

-A INPUT -p tcp -m tcp --dport 8332 -j ACCEPT
-A INPUT -p tcp -m tcp --sport 8332 -j ACCEPT
-A INPUT -p tcp -m tcp -j NFQUEUE --queue-num 0 --queue-bypass

# Skip bitcoin mainnet rpc
-A OUTPUT -p tcp -m tcp --dport 8332 -j ACCEPT
-A OUTPUT -p tcp -m tcp --sport 8332 -j ACCEPT
-A OUTPUT -j NFQUEUE --queue-num 0 --queue-bypass

COMMIT
```
