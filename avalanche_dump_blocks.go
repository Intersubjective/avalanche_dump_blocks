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
  "errors"
  "os"
  "os/signal"
  "syscall"
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

func pbuf_u32(bytes *[]byte, tag uint64, value uint32) {
  pbuf_u64(bytes, tag, (uint64)(value))
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

func make_handshake(network_id int, addr_bytes []byte, ip_port int, ip_signing_time int64, ip_node_id_sig []byte, ip_bls_sig []byte) ([]byte, error) {
  NAME  := "avalanchego"
  MAJOR := 1
  MINOR := 12
  BABY  := 2

  my_time := time.Now().Unix()

  msg := make([]byte, 0); {
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
        _, err   := rand.Reader.Read(filter[1:1+num_hashes*hash_size])
        if err != nil {
          return nil, err
        }

        salt  := make([]byte, salt_size)
        _, err = rand.Reader.Read(salt)
        if err != nil {
          return nil, err
        }

        pbuf_bytes(&known_peers, 1, filter)
        pbuf_bytes(&known_peers, 2, salt)
      }

      pbuf_int  (&data, 1, network_id)
      pbuf_i64  (&data, 2, my_time)
      pbuf_bytes(&data, 3, addr_bytes)
      pbuf_int  (&data, 4, ip_port)
      pbuf_i64  (&data, 6, ip_signing_time)
      pbuf_bytes(&data, 7, ip_node_id_sig)
      pbuf_bytes(&data, 9, client)
      pbuf_bytes(&data, 12, known_peers)
      pbuf_bytes(&data, 13, ip_bls_sig)
    }
    pbuf_bytes(&msg, 13, data)
  }

  return msg, nil
}

func make_peer_list() []byte {
  msg := make([]byte, 0); {
    data := make([]byte, 0); {
      //  FIXME

      claimed_ip_port := make([]byte, 0); {
        x509_certificate := make([]byte, 0)
        ip_addr          := make([]byte, 0)
        signature        := make([]byte, 0)
        tx_id            := make([]byte, 0)

        pbuf_bytes(&claimed_ip_port, 1, x509_certificate)
        pbuf_bytes(&claimed_ip_port, 2, ip_addr)
        pbuf_u32  (&claimed_ip_port, 3, 9651)
        pbuf_i64  (&claimed_ip_port, 4, time.Now().Unix())
        pbuf_bytes(&claimed_ip_port, 5, signature)
        pbuf_bytes(&claimed_ip_port, 6, tx_id)
      }
      pbuf_bytes(&data, 1, claimed_ip_port)
    }
    pbuf_bytes(&msg, 14, data)
  }

  return msg
}

func make_get_accepted_frontier(request_id uint32, chain_id []byte) []byte {
  msg := make([]byte, 0); {
    data := make([]byte, 0); {
      // FIXME: Make sure this is correct.
      deadline := time.Now().Unix() + 30

      pbuf_bytes(&data, 1, chain_id)
      pbuf_u32  (&data, 2, request_id)
      pbuf_i64  (&data, 3, deadline)
    }
    pbuf_bytes(&msg, 19, data)
  }

  return msg
}

func make_get(request_id uint32, chain_id []byte, container_id []byte) []byte {
  //  TODO
  return nil
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

func init_cert(addr_bytes []byte, ip_port int) (int64, *tls.Certificate, []byte, []byte, error) {
  cer, err := new_tls_cert()
  if err != nil {
    return 0, nil, nil, nil, err
  }

  ip_signing_time := time.Now().Unix()

  ip_bytes := make([]byte, 0); {
    n := len(addr_bytes)
    ip_bytes = concat(ip_bytes, addr_bytes[:])
    ip_bytes = concat(ip_bytes, make([]byte, 6))
    binary.LittleEndian.PutUint16(ip_bytes[n:],   (uint16)(ip_port))
    binary.LittleEndian.PutUint32(ip_bytes[n+2:], (uint32)(ip_signing_time))
  }

  var ikm [32]byte
  _, err = rand.Read(ikm[:])
  if err != nil {
    return 0, nil, nil, nil, err
  }

  ip_hash  := sha256.Sum256(ip_bytes[:])
  tls_sig  := cer.PrivateKey.(crypto.Signer)
  bls_key  := blst.KeyGen(ikm[:])
  bls_sig  := new(blst.P2Affine)

  ip_node_id_sig, err := tls_sig.Sign(rand.Reader, ip_hash[:], crypto.SHA256)
  if err != nil {
    return 0, nil, nil, nil, err
  }

  ip_bls_sig := bls_sig.Sign(bls_key, ip_bytes[:], []byte("BLS_POP_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_")).Compress()

  return ip_signing_time, cer, ip_node_id_sig, ip_bls_sig, nil
}

func msg_tag(msg []byte) int {
  return (int)(pbuf_varint_decode(msg) >> 3)
}

func msg_name(tag int) string {
  switch tag {
    case 2:  return "Compressed ZSTD"
    case 11: return "Ping"
    case 13: return "Handshake"
    case 14: return "Peer list"
    case 19: return "Get accepted frontier"
    case 20: return "Accepted frontier"
    case 26: return "Put"
    case 35: return "Get peer list"
  }

  return fmt.Sprintf("<%d>", tag)
}

func send(index int, conn *net.Conn, message []byte) error {
  if conn == nil {
    return errors.New("Invalid argument")
  }
  if len(message) == 0 {
    return nil
  }

  len_bytes := make([]byte, 4)
  binary.BigEndian.PutUint32(len_bytes, (uint32)(len(message)))
  send_bytes := concat(len_bytes, message)
  _, err := (*conn).Write(send_bytes)
  fmt.Printf("[%2d] SEND %s\n", index, msg_name(msg_tag(message)))
  // fmt.Printf("     %s\n", hex.EncodeToString(send_bytes))
  return err
}

func recv(conn *net.Conn) ([]byte, error) {
  if conn == nil {
    return nil, errors.New("Invalid argument")
  }

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
  return response, nil
}

type Session struct {
  conn              net.Conn
  accepted_frontier []byte
  queue             [][]byte
}

type State struct {
  network_id      int
  ip_addr         string
  ip_port         int
  addr_bytes      []byte
  cer             *tls.Certificate
  ip_signing_time int64
  ip_node_id_sig  []byte
  ip_bls_sig      []byte
  sessions        []Session
  peers           []string
  request_id      uint32
  clock           int64
}

func send_all(state *State) int {
  if state == nil {
    fmt.Printf("Error: Invalid argument\n")
    return 0
  }

  num_requests := 0

  for i := 0; i < len(state.sessions); {
    ok := true
    for k := 0; k < len(state.sessions[i].queue); k++ {
      num_requests++
      err := send(i, &state.sessions[i].conn, state.sessions[i].queue[k])
      if err != nil {
        fmt.Printf("Send failed: %s\n", err)
        ok = false
        break
      }
    }

    state.sessions[i].queue = make([][]byte, 0)

    if ok {
      i++
    } else {
      state.sessions[i].conn.Close()
      n  := len(state.sessions) - 1
      ss := make([]Session, n)
      copy(ss[0:i], state.sessions[  0:i  ])
      copy(ss[i:n], state.sessions[i+1:n+1])
      state.sessions = ss
    }
  }

  return num_requests
}

func queue_one(state *State, index int, request []byte) {
  if state == nil {
    fmt.Printf("Error: Invalid argument\n")
    return
  }

  n     := len(state.sessions[index].queue)
  queue := make([][]byte, n + 1)
  copy(queue[0:n], state.sessions[index].queue)
  queue[n] = request
  state.sessions[index].queue = queue
}

func queue_to_all(state *State, request []byte) {
  if state == nil {
    fmt.Printf("Error: Invalid argument\n")
    return
  }

  for i := 0; i < len(state.sessions); i++ {
    queue_one(state, i, request)
  }
}

func handle_response(state *State, index int, response []byte) {
  if state == nil {
    fmt.Printf("Error: No state\n")
    return
  }

  tag := msg_tag(response)

  fmt.Printf("[%2d] RECV %s\n", index, msg_name(tag))
  switch tag {
    case 13:
      // msg := []byte { 0x12, 0x0b, 0x28, 0xb5, 0x2f, 0xfd, 0x20, 0x02, 0x11, 0x00, 0x00, 0x72, 0x00 }
      msg := make_peer_list()
      queue_one(state, index, msg)
    default:
      fmt.Printf("     %s\n", hex.EncodeToString(response))
  }
}

func handle_sessions(state *State) {
  if state == nil {
    fmt.Printf("Error: No state\n")
    return
  }

  PLATFORM_CHAIN_ID := [32]byte {0}

  t := time.Now().Unix()

  if t >= state.clock {
    msg := make_get_accepted_frontier(state.request_id, PLATFORM_CHAIN_ID[:])
    queue_to_all(state, msg)
    state.clock       = t + 1
    state.request_id += 1
  }

  if send_all(state) == 0 {
    time.Sleep(time.Millisecond * 10)
  }

  for i := 0; i < len(state.sessions); i++ {
    response, err := recv(&state.sessions[i].conn)
    if err == io.EOF {
      break
    }
    if err != nil {
      fmt.Printf("Recv failed: %s\n", err)
      break
    }
    handle_response(state, i, response)
  }
}

func close_all(state *State) {
  if state == nil {
    fmt.Printf("Error: No state\n")
    return
  }

  for i := 0; i < len(state.sessions); i++ {
    state.sessions[i].conn.Close()
  }
  state.sessions = make([]Session, 0)
}

func main() {
  on_sig := make(chan bool,      1)
  sigs   := make(chan os.Signal, 1)

  signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)

  go func() {
           <- sigs
    on_sig <- true
  }()

  bootstrappers := []string {
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

  MAINNET_NETWORK_ID := 1

  state := State {
    network_id : MAINNET_NETWORK_ID,
    ip_addr    : outbound_ip(),
    ip_port    : 9651,
  }

  addr, err := netip.ParseAddr(state.ip_addr)
  if err != nil {
    fmt.Printf("ParseAddr failed: %s\n", err);
    return
  }
  addr_bytes := addr.As16()
  state.addr_bytes = make([]byte, len(addr_bytes))
  copy(state.addr_bytes, addr_bytes[:])

  state.ip_signing_time, state.cer, state.ip_node_id_sig, state.ip_bls_sig, err = init_cert(addr_bytes[:], state.ip_port)
  if err != nil {
    fmt.Printf("Init cert failed: %s\n", err)
    return
  }

  state.sessions = make([]Session, 1)
  state.peers    = make([]string,  1)

  state.clock = time.Now().Unix() + 2

  index, err := rand.Int(rand.Reader, new(big.Int).SetUint64((uint64)(len(bootstrappers))))
  if err != nil {
    fmt.Printf("Rand failed: %s\n", err)
    state.peers[0] = bootstrappers[0]
  } else {
    state.peers[0] = bootstrappers[index.Uint64()]
  }

  state.sessions[0].conn, err = tls.Dial("tcp", state.peers[0], &tls.Config {
    InsecureSkipVerify : true,
    Certificates       : []tls.Certificate{*state.cer},
  })
  if err != nil {
    fmt.Printf("Dial failed: %s\n", err)
    return
  }

  fmt.Printf("Connect %s\n", state.peers[0])

  msg, err := make_handshake(state.network_id, state.addr_bytes, state.ip_port, state.ip_signing_time, state.ip_node_id_sig, state.ip_bls_sig)
  if err != nil {
    fmt.Printf("Make handshake failed: %s\n", err)
    close_all(&state)
  }

  queue_to_all(&state, msg)

  for done := false; !done; {
    if len(state.sessions) == 0 {
      fmt.Printf("No sessions.\n")
      break
    }

    handle_sessions(&state)

    select {
      case <-on_sig:
        fmt.Printf("\n");
        done = true
      default:
    }
  }

  close_all(&state)
}
