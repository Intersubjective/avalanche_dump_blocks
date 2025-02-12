FROM golang:alpine AS compile

WORKDIR /usr/project
COPY . .

RUN go build

FROM scratch

ENV DUMPBLOCKS_DRY_RUN=0
ENV DUMPBLOCKS_LOG=0
ENV DUMPBLOCKS_PERIOD=200
ENV DUMPBLOCKS_NODE_ENDPOINT="https://avalanche-p-chain-rpc.publicnode.com/ext/bc/P"
ENV DUMPBLOCKS_DB_ACCESS="host=127.0.0.1 port=12345 user=postgres password=postgres dbname=blocks sslmode=disable"
ENV DUMPBLOCKS_DB_REQUEST="INSERT INTO blocks (height, hex) VALUES (%d, '%s') ON CONFLICT DO NOTHING"

# ENV DUMPBLOCKS_CA_CERT_FILE="/usr/ca-cert.pem"
# ENV DUMPBLOCKS_CERT_FILE="/usr/client-cert.pem"
# ENV DUMPBLOCKS_KEY_FILE="/usr/client-key.pem"

WORKDIR /usr
ENTRYPOINT [ "/usr/avalanche_dump_blocks" ]
COPY --from=compile /usr/project/avalanche_dump_blocks avalanche_dump_blocks
