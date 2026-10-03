As already established, you cannot decrypt the same `OlmMessage` more than once, and you cannot decrypt your own `OlmMessage` either, because Olm and Megolm messages are used for transporting data, not for storing it.

You can try to store it naively by encrypting the sender's copy of the message with a separate key and then sending the other person the message through Olm, but then they need a place to keep the message contents once opened, since you cannot reopen an `OlmMessage` due to Olm's forward and backward secrecy.

Another method would be to re-encrypt a message's contents for each user so that everyone maintains a copy of the message that only they can read. The storage footprint would be abysmal though, being 2x for DMs and Nx for group chats with N members in. Supporting 100-member group chats would be completely unfeasible with this schema.

Instead, a user can encrypt a message and share the decryption key with the other users through Olm. Then, users can keep a vault of message decryption keys that only they can read. A message decryption key is only a few bytes, so duplicating and distributing these is almost negligible when considering both storage and bandwidth.
