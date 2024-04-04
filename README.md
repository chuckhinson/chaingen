Generates a self-signed certificate chain for a wildcard domain.

chaingen generates a server certificate along with a ca chain containing a root and an intermediate CA.

This project serves as my way to start learning go.

The idea for this project came from a work project where we had a need to generate a self-signed certificate chain - root, intermediate and server cert.  One concern with setting up a CA is the need to safeguard the private keys used to sign the ca certificates.  If you've added your self-signed CA to your browser's trusted CA certs and someone manages to get the private keys for the CA certificates, they can mint new server certs and use them along with DNS spoofing to redirect you to fake versions of websites you trust.  To address this risk, rather than setting up a CA that we can use to generate server certificates, we just generate the entire chain and then discard the private keys for the ca certificates.  This mitigates some of the risk of trusting a self-signed certificate because it's not possible to use the CA certificates to generate new server certificates.

