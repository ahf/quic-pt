# Quic Pluggable Transport

This is an experimental Pluggable Transport (PT)  to experiment with the
Quic protocol and Tor.

## Building `quic-client`

To build the `quic-client`:

    $ git clone https://github.com/ahf/quic-pt.git
    $ cd quic-pt/src/quic-client
    $ go get
    $ go build

You can now copy the `src/quic-client/quic-client` binary to a location
of your choice.

### Client Configuration

To configure a `tor` client to use the Quic Pluggable Transport you
should set the following options in your `torrc`:

    UseBridges 1
    Bridge quic <Server IP>:<Server Port>

    ClientTransportPlugin quic exec path/to/quic-client path/to/quic-client.log -certificate-pin <certificate fingerprint> -public-key-pin <public key fingerprint>

See below on how to find the public key and certificate fingerprint
values. These values should be published by the server operator.

## Building `quic-server`

To build the `quic-server`:

    $ git clone https://github.com/ahf/quic-pt.git
    $ cd quic-pt/src/quic-server
    $ go get
    $ go build

You can now copy the `src/quic-server/quic-server` binary to a location
of your choice.

### Server Configuration

To configure a `tor` bridge to support the Quic Pluggable Transport you
should set the following options in your `torrc`:

    BridgeRelay 1
    ORPort 9001
    ExtORPort 9002

    ServerTransportPlugin quic exec path/to/quic-server -log-file path/to/quic-server.log -certificate cert.pem -key key.pem
    ServerTransportListenAddr quic <IP>:<Port>

It is important that you publish the SHA2-256 public key and certificate
fingerprints for clients to pin in their `torrc`. A client cannot
connect to your bridge unless at least one of the two values are passed
to their `quic-client` program as a command line argument.

To find the public key fingerprint use:

    $ openssl x509 -in key.pem -fingerprint -sha256 -noout | tr A-Z a-z | tr -d :
    sha256 fingerprint=b111f42b37ada7627f610c63ac329118da2963cdc528e712e87da29a35988bb6

To find the certificate fingerprint use:

    $ openssl x509 -in cert.pem -pubkey -noout | openssl pkey -pubin -outform der | openssl dgst -sha256 -c | tr A-Z a-z | tr -d :
    (stdin)= ca72f32243c65f1b39b3986d9a1a1efb27245dc11b27355e3c371743a5335ec3

## Authors

- Alexander Færøy (<ahf@torproject.org>)
