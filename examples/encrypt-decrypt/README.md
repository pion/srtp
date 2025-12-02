# encrypt-decrypt
encrypt-decrypt shows how on Encrypt+Decrypt packets using pion/srtp

## Instructions
```
go run .
```

This results in output
```
encrypted RTP seq=1 ts=123616 payload=0101010101
decrypted RTP seq=1 ts=123616 payload=0101010101

encrypted RTP seq=2 ts=123776 payload=0202020202
decrypted RTP seq=2 ts=123776 payload=0202020202

encrypted RTP seq=3 ts=123936 payload=0303030303
decrypted RTP seq=3 ts=123936 payload=0303030303

```

This example demonstrates how to use pion/srtp, but
in a production application you would have a few differences.

* Use a different Key/Salt for each side
* Payload would be real media data

You may also want to use more realtime media helpers like those
found in https://github.com/pion/interceptor for error correction
and bandwidth estimation.
