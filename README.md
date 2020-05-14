# Wireguard DOS attack via KCI

Allows you to deny user from connecting for the next minute, if you have the
server private key and user public key.

## Building

Put all files in the original directory tree positions. Then clone the
submodule:
```
mkdir lib && git clone https://github.com/centromere/cacophony/ lib/cacophony
```
Apply the patch to the submodule:
```
cd lib/cacophony/ && git apply ../../attack.patch
```
Then build using [stack](https://docs.haskellstack.org/en/stable/README/) (this
might take a while to download all deps):
```
stack build
```
Verify that everything works:
```
stack run -- default
```

## Attacking

Edit the main file with your target creds: open `src/Main.hs`, navigate to line
54, and edit the server credentials for your user. Then on line 61 edit the
credentials for the same server, but now you put the public key for user and
private for server.

After that, rebuild and verify that connection can be established:
```
stack run -- mine
```
(ICMP might not work on misconfigured virtual machine, but look for it at least
connecting).

Then you can perform the attack, and verify that the connection cannot be established:
```
stack run -- kci && stack run -- mine
```

You can also monitor the succesful connection attempts on the server via
wireguard logs.
