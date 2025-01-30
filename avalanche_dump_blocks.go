package main

import (
  "bytes"
  "crypto"
  "crypto/ecdsa"
  "crypto/elliptic"
  "crypto/rand"
  "crypto/tls"
  "crypto/x509"
  "crypto/sha256"
  "encoding/hex"
  "encoding/pem"
  "encoding/binary"
  "fmt"
  "math/big"
  "net"
  "net/netip"
  "time"
  "io"
  blst "github.com/supranational/blst/bindings/go"
)

func concat(x []byte, y []byte) []byte {
  z := make([]byte, len(x) + len(y))
  for i := 0; i < len(x); i++ {
    z[i] = x[i]
  }
  for i := 0; i < len(y); i++ {
    z[len(x)+i] = y[i]
  }
  return z
}

func pbuf_varint_encode(x uint64) []byte {
  bytes := make([]byte, 0)
  for x != 0 {
    bytes = append(bytes, (byte)(x&0x7f))
    x   >>= 7
  }
  if len(bytes) == 0 {
    bytes = append(bytes, 0)
  }
  for i := 0; i+1 < len(bytes); i++ {
    bytes[i] |= 0x80
  }
  return bytes
}

func pbuf_varint_decode(bytes []byte) uint64 {
  x := (uint64)(0)
  n := 0
  for n < len(bytes) {
    n++
    if (bytes[n-1] & 0x80) != 0x80 {
      break
    }
  }
  for i := n; i > 0; i-- {
    x <<= 7
    x  |= (uint64)(bytes[i-1] & 0x7f)
  }
  return x
}

func pbuf_u64(bytes *[]byte, tag uint64, value uint64) {
  *bytes = concat(*bytes, pbuf_varint_encode((tag << 3) | 0))
  *bytes = concat(*bytes, pbuf_varint_encode(value));
}

func pbuf_i64(bytes *[]byte, tag uint64, value int64) {
  pbuf_u64(bytes, tag, (uint64)(value))
}

func pbuf_int(bytes *[]byte, tag uint64, value int) {
  pbuf_u64(bytes, tag, (uint64)(value))
}

func pbuf_bytes(bytes *[]byte, tag uint64, value []byte) {
  *bytes = concat(*bytes, pbuf_varint_encode((tag << 3) | 2))
  *bytes = concat(*bytes, pbuf_varint_encode((uint64)(len(value))))
  *bytes = concat(*bytes, value)
}

func pbuf_str(bytes *[]byte, tag uint64, value string) {
  pbuf_bytes(bytes, tag, ([]byte)(value))
}

func new_tls_cert() (*tls.Certificate, error) {
  key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
  if err != nil {
    return nil, fmt.Errorf("couldn't generate ecdsa key: %w", err)
  }

  cert_template := &x509.Certificate{
    SerialNumber          : big.NewInt(0),
    NotBefore             : time.Date(2000, time.January, 0, 0, 0, 0, 0, time.UTC),
    NotAfter              : time.Now().AddDate(100, 0, 0),
    KeyUsage              : x509.KeyUsageDigitalSignature,
    BasicConstraintsValid : true,
  }
  cert_bytes, err := x509.CreateCertificate(rand.Reader, cert_template, cert_template, key.Public(), key)
  if err != nil {
    return nil, fmt.Errorf("couldn't create certificate: %w", err)
  }
  var cert_buf bytes.Buffer
  if err := pem.Encode(&cert_buf, &pem.Block{Type: "CERTIFICATE", Bytes: cert_bytes}); err != nil {
    return nil, fmt.Errorf("couldn't write cert file: %w", err)
  }

  priv_bytes, err := x509.MarshalPKCS8PrivateKey(key)
  if err != nil {
    return nil, fmt.Errorf("couldn't marshal private key: %w", err)
  }

  var key_buf bytes.Buffer
  if err := pem.Encode(&key_buf, &pem.Block{Type: "PRIVATE KEY", Bytes: priv_bytes}); err != nil {
    return nil, fmt.Errorf("couldn't write private key: %w", err)
  }

  cert, err := tls.X509KeyPair(cert_buf.Bytes(), key_buf.Bytes())
  if err != nil {
    return nil, err
  }
  cert.Leaf, err = x509.ParseCertificate(cert.Certificate[0])
  return &cert, err
}

func outbound_ip() string {
  conn, err := net.Dial("udp", "8.8.8.8:80")
  if err != nil {
    return "127.0.0.1"
  }

  local_addr := conn.LocalAddr().(*net.UDPAddr)
  conn.Close()

  return local_addr.IP.String()
}

func send(conn *net.Conn, message []byte) error {
  len_bytes := make([]byte, 4)
  binary.BigEndian.PutUint32(len_bytes, (uint32)(len(message)))
  send_bytes := concat(len_bytes, message)
  fmt.Printf("SEND %d bytes\n%s\n", len(send_bytes), hex.EncodeToString(send_bytes))
  _, err := (*conn).Write(send_bytes)
  return err
}

func recv(conn *net.Conn) ([]byte, error) {
  buf := make([]byte, 4)
  _, err := (*conn).Read(buf[0:4])
  if err != nil {
    return nil, err
  }
  total_len := (int)(binary.BigEndian.Uint32(buf))
  len       := 0
  buf = make([]byte, total_len)
  for len < total_len {
    n, err := (*conn).Read(buf[len:])
    len    += n
    if err != nil {
      return nil, err
    }
  }
  response := make([]byte, len)
  copy(response, buf[:len])
  fmt.Printf("RECV %d bytes\n%s\n\"\"\"\n%s\n\"\"\"\n", len, hex.EncodeToString(response), string(response))
  return response, nil
}

func main() {
  //  ------------------------------------------------------------------
  //
  //  Options
  //
  //  ------------------------------------------------------------------

  bootstrappers := [...]string{
    // "127.0.0.1:9650",
    "54.232.137.108:9651",
    "13.124.187.98:9651",
    "54.232.142.167:9651",
    "3.39.67.183:9651",
    "13.245.185.253:9651",
    "13.246.169.11:9651",
    "13.251.82.39:9651",
    "34.250.50.224:9651",
    "18.142.247.237:9651",
    "34.252.106.116:9651",
    "43.205.156.229:9651",
    "13.233.176.118:9651",
    "35.164.160.193:9651",
    "54.185.77.104:9651",
    "3.74.3.14:9651",
    "3.135.107.20:9651",
    "3.77.28.168:9651",
    "18.216.88.69:9651",
    "3.24.26.175:9651",
    "52.64.55.185:9651",
    "16.162.27.145:9651",
    "18.163.169.191:9651",
    "13.39.184.151:9651",
    "13.36.28.133:9651",
  }

  NAME  := "avalanchego"
  MAJOR := 1
  MINOR := 12
  BABY  := 2

  enable_tls := true
  // enable_tls := false
  ip_addr    := outbound_ip()
  ip_port    := 9651
  network_id := 1 // Mainnet
  my_time    := time.Now().Unix()

  addr, err := netip.ParseAddr(ip_addr)
  if err != nil {
    fmt.Printf("ParseAddr failed: %s\n", err);
    return
  }
  addr_bytes := addr.As16()

  ip_bytes := make([]byte, 0); {
    n := len(addr_bytes)
    ip_bytes = concat(ip_bytes, addr_bytes[:])
    ip_bytes = concat(ip_bytes, make([]byte, 6))
    binary.LittleEndian.PutUint16(ip_bytes[n:],   (uint16)(ip_port))
    binary.LittleEndian.PutUint32(ip_bytes[n+2:], (uint32)(my_time))
  }

  //  ------------------------------------------------------------------
  //
  //  1. Certificates
  //
  //  ------------------------------------------------------------------

  cer, err := new_tls_cert()
  if err != nil {
    fmt.Printf("TLS cert failed: %s\n", err)
    return
  }

  ip_signing_time := my_time
  var ip_node_id_sig []byte
  var ip_bls_sig     []byte
  {
    var ikm [32]byte
    _, err = rand.Read(ikm[:])
    if err != nil {
      fmt.Printf("Read failed: %s\n", err)
      return
    }

    ip_hash  := sha256.Sum256(ip_bytes[:])
    tls_sig  := cer.PrivateKey.(crypto.Signer)
    bls_key  := blst.KeyGen(ikm[:])
    bls_sig  := new(blst.P2Affine)

    ip_node_id_sig, err = tls_sig.Sign(rand.Reader, ip_hash[:], crypto.SHA256)
    if err != nil {
      fmt.Printf("Sign failed: %s\n", err);
      return
    }

    ip_bls_sig = bls_sig.Sign(bls_key, ip_bytes[:], []byte("BLS_POP_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_")).Compress()
  }

  //  ------------------------------------------------------------------
  //
  //  2. TLS connection
  //
  //  ------------------------------------------------------------------

  peer_address := bootstrappers[0]
  var peer_conn net.Conn
  if enable_tls {
    peer_conn, err = tls.Dial("tcp", peer_address, &tls.Config {
      InsecureSkipVerify : true,
      Certificates       : []tls.Certificate{*cer},
    })
  } else {
    peer_conn, err = net.Dial("tcp", peer_address)
  }
  if err != nil {
    fmt.Printf("Dial failed: %s\n", err)
    return
  }

  //  ------------------------------------------------------------------
  //
  //  3. Handshake
  //
  //  ------------------------------------------------------------------

  ok := true
  msg_handshake := make([]byte, 0); {
    data := make([]byte, 0); {
      client := make([]byte, 0); {
        pbuf_str(&client, 1, NAME)
        pbuf_int(&client, 2, MAJOR)
        pbuf_int(&client, 3, MINOR)
        pbuf_int(&client, 4, BABY)
      }

      known_peers := make([]byte, 0); {
        num_hashes  := 10
        num_entries := 230
        hash_size   := 8
        filter_size := 1 + num_hashes * hash_size + num_entries
        salt_size   := 32

        filter   := make([]byte, filter_size)
        filter[0] = (byte)(num_hashes)
        _, err    = rand.Reader.Read(filter[1:1+num_hashes*hash_size])
        if err != nil {
          fmt.Printf("Read failed: %s\n", err)
          ok = false
        }

        salt  := make([]byte, salt_size)
        _, err = rand.Reader.Read(salt)
        if err != nil {
          fmt.Printf("Read failed: %s\n", err)
          ok = false
        }

        pbuf_bytes(&known_peers, 1, filter)
        pbuf_bytes(&known_peers, 2, salt)
      }

      pbuf_int  (&data, 1, network_id)
      pbuf_i64  (&data, 2, my_time)
      pbuf_bytes(&data, 3, addr_bytes[:])
      pbuf_int  (&data, 4, ip_port)
      pbuf_i64  (&data, 6, ip_signing_time)
      pbuf_bytes(&data, 7, ip_node_id_sig)
      pbuf_bytes(&data, 9, client)
      pbuf_bytes(&data, 12, known_peers)
      pbuf_bytes(&data, 13, ip_bls_sig)
    }
    pbuf_bytes(&msg_handshake, 13, data)
  }
  if ok {
    err = send(&peer_conn, msg_handshake)
    if err != nil {
      fmt.Printf("Send failed: %s\n", err)
      ok = false
    }
  }
  for ok {
    _, err := recv(&peer_conn)
    if err == io.EOF {
      break
    }
    if err != nil {
      fmt.Printf("Recv failed: %s\n", err)
      ok = false
    }
  }

  //  ------------------------------------------------------------------
  //
  //  4. Peers
  //
  //  ------------------------------------------------------------------

  //  ------------------------------------------------------------------
  //
  //  5. Accepted frontier
  //
  //  ------------------------------------------------------------------

  //  ------------------------------------------------------------------
  //
  //  6. Blocks
  //
  //  ------------------------------------------------------------------

  //  ------------------------------------------------------------------
  //
  //  Cleanup
  //
  //  ------------------------------------------------------------------

  peer_conn.Close()
}
