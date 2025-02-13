# avalanche_dump_blocks
Receive new blocks from Avalanche node via HTTP API endpoint and store them into the PostgreSQL database.

## Settings from environment variables
- `DUMPBLOCKS_DRY_RUN` - `1` to enable dry run; `0` to disable dry run. Dry run means that no data will be written to the database.
- `DUMPBLOCKS_LOG` - `1` to write blocks data to the terminal; `0` otherwise.
- `DUMPBLOCKS_PERIOD` - Update period in milliseconds, e.g. `200`.
- `DUMPBLOCKS_NODE_ENDPOINT` - Avalanche node endpoint, e.g. `"https://avalanche-p-chain-rpc.publicnode.com/ext/bc/P"`
- `DUMPBLOCKS_DB_ACCESS` - PostgreSQL database access string, e.g. `"host=127.0.0.1 port=12345 user=postgres password=postgres dbname=blocks sslmode=disable"`
- `DUMPBLOCKS_DB_REQUEST` - PostgreSQL request string, e.g. `"INSERT INTO blocks (height, hex) VALUES (%d, '%s') ON CONFLICT DO NOTHING"`
- `DUMPBLOCKS_TLS_SKIP_VERIFY` - `1` to skip verification for TLS; `0` otherwise.

### Optional client TLS certificate
- `DUMPBLOCKS_CA_CERT_FILE` - CA cert file path, e.g. `"/usr/ca-cert.pem"`
- `DUMPBLOCKS_CERT_FILE` - Client cert file, e.g. `"/usr/client-cert.pem"`
- `DUMPBLOCKS_KEY_FILE` - Client key file, e.g. `"/usr/client-key.pem"`
