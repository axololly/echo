Can decrypt Megolm messages multiple times because the session key has no backward secrecy (the HKDF it uses to advance group state goes forward, so a current key can decrypt all current and future messages)

Megolm has forward secrecy (the HKDF doesn't go back) but being able to decrypt past messages would involve preserving the keys, which creates partial forward secrecy

Clearly, using Megolm for storage works against the protocol, so it should be used for transport only

## Storage Layer

Start with the naive approach of each person stores an encrypted whole version of each message

Then, when getting to implementing group chats, realise that this becomes impractical for the intended goal of 100 users, so make each Megolm message send a decryption key to the central message object instead of a copy of the message object instead

Message decryption keys will be stored in a group-specific table (`group_message_decryption_keys` for example)

Realise again that to allow for forwarding messages, messages in DMs should use the same system that messages in a group do, so then you have to reform the DM messaging too

Then you can generalise the table for message decryption keys to work across groups and DMs
