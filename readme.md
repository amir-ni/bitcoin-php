# Simple Bitcoin message transmitter

I just needed to create something to communicate with Bitcoin nodes with some specific features, so I made this(specific features are not included inn this repository).

The code is not complete yet!

To write this script, I used the details presented in [Bitcoin Developer Reference](https://bitcoin.org/en/developer-reference), [Bitcoin Protocol documentation](https://en.bitcoin.it/wiki/Protocol_documentation) and [learn me a Bitcoin](https://learnmeabitcoin.com/).

This is simple presentation of basic messages transmitted between nodes in the Bitcoin network.
![P2P Protocol Data Request And Reply Messages](https://github.com/amir-ni/bitcoin-php/raw/master/p2p-data-messages.svg)

## How to Use
Change config in `utils.php`, then just run 
```bash
php node.php
```

In case of `Call to undefined function error`, You'll need to install (or enable) the [Sockets PHP extension](https://www.php.net/manual/en/sockets.installation.php).