The program accepts a filename, and a private signing key (n, d) as input and returns an RSA signature of the file using PKCS
1.5 padding, SHA-256 hashing and ASN.1 encoding.A public verification exponent e is provided to allow you to check the correctness of the 
program.
