# KeyStoreEncryptionExample

This project shows an example of generating an encryption key for a realm database.
For API23 we have implemented Symmetric Key encryption.
For API21 we use asymmetric key encryption as symmetric key generation is not supported on 21.
The encrypted db-key is stored in shared preference. The key to decrypt the db-key is stored in Keystore.
