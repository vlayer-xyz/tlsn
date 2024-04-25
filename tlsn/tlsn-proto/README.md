# tlsn-proto

TLSNotary protobufs

## Generate

Install `quick-protobuf`

```bash
cargo install pb-rs
```

Generate the rust models:

```bash
cd src/generated
pb-rs attestation.proto connection.proto crypto.proto -D
```