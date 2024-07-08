## Secure SMS Exchange Protocol

### Protocol Overview
- **Key Exchange**: Using DH for generating private keys and RSA for blind digital signatures.
- **Encryption**: Messages are encrypted using RC6, with RSA used for digital signature.
- **Message Handling**: Blinded RSA signatures ensure sender identity authentication and message integrity.

### Detailed Steps
1. **DH Key Exchange**
   - Alice and Bob generate private DH exponents and RSA key pairs.
   - They sign their DH public keys using their RSA private keys.
   - Exchange signed public keys and verify signatures.

2. **Message Sending (Sender = Alice)**
   - Alice generates a random blinding factor.
   - Blinds the message with server's public key using RSA.
   - Encrypts the blinded message using RC6 and sends it to the server.

3. **Message Storage and Delivery (Server)**
   - Receives and stores the encrypted and blinded message securely.
   - Generates a signature on the message using its private key.

4. **Message Retrieval (Recipient = Bob)**
   - Bob retrieves the encrypted message and server's signature.
   - Decrypts the message using RC6 and verifies the signature using server's public key.

5. **Message Verification and Unblinding**
   - Bob verifies the message integrity and authenticity.
   - Uses a secure channel via the server to communicate with Alice if needed.

### Implementation Details
- **RC6 Algorithm**: Implemented with a 128-bit key size.
- **RSA Blind Signature**: Ensures message authenticity without revealing message content.
- **Code Implementation**: Separate scripts for RC6 encryption with DH key exchange and blind RSA signature implementation.

### Future Work
- Integrate blind signature functionality directly into the DH and RC6 algorithm.
- Implement a server-side component for full protocol functionality.
