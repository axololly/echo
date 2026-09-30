Cannot decrypt Olm messages multiple times due to forward and backward secrecy, which means Olm messages are for transport exclusively and NOT storage

Therefore, a new storage layer has to be invented:

## Storage Layer

Start with the naive approach of each person stores an encrypted whole version of each message

Then, when getting to implementing group chats, realise that this becomes impractical for the intended goal of 100 users, so make each Megolm message send a decryption key to the central message object instead of a copy of the message object instead

Message decryption keys will be stored in a group-specific table (`group_message_decryption_keys` for example)

Realise again that to allow for forwarding messages, messages in DMs should use the same system that messages in a group do, so then you have to reform the DM messaging too

Then you can generalise the table for message decryption keys to work across groups and DMs
