package main

import (
  "fmt"
  "os"
  "os/signal"
  "syscall"
  "net/http"
  "strings"
  "time"
  "io"
  "crypto/tls"
  "crypto/x509"
  "encoding/json"
  "strconv"
  "database/sql"
  _ "github.com/lib/pq"
)

func store_block(access string, req string, height int, block_hex string) error {
  db, err := sql.Open("postgres", access)
  if err != nil {
    return err
  }

  sql := fmt.Sprintf(req, height, block_hex)

  _, err = db.Exec(sql)
  db.Close()
  return err
}

type Response_Height struct {
  Result struct {
    Height string `json:"height"`
  } `json:"result"`
}

type Response_Block struct {
  Result struct {
    Block string `json:"block"`
  } `json:"result"`
}

func get_height(client *http.Client, endpoint string) (int, error) {
  req      := "{ \"jsonrpc\": \"2.0\", \"method\": \"platform.getHeight\", \"params\": {}, \"id\": 1 }"
  res, err := client.Post(endpoint, "application/json", strings.NewReader(req))

  if err != nil {
    fmt.Printf("Failed to send request\n")
    return 0, err
  }

  body, err := io.ReadAll(res.Body)
  res.Body.Close()

  if err != nil {
    fmt.Printf("Failed to read response\n")
    return 0, err
  }

  var json_height Response_Height

  err = json.Unmarshal(body, &json_height)
  if err != nil {
    fmt.Printf("Failed to unmarshal JSON:\n%s\n", body)
    return 0, err
  }

  height, err := strconv.Atoi(json_height.Result.Height)
  if err != nil {
    return 0, err
  }

  return height, nil
}

func get_block(client *http.Client, endpoint string, height int) (string, error) {
  req := fmt.Sprintf("{ \"jsonrpc\": \"2.0\", \"method\": \"platform.getBlockByHeight\", \"params\": { \"height\": %d, \"encoding\": \"hex\" }, \"id\": 1 }", height)
  res, err := client.Post(endpoint, "application/json", strings.NewReader(req))

  if err != nil {
    fmt.Printf("Failed to send request\n")
    return "", err
  }

  body, err := io.ReadAll(res.Body)
  res.Body.Close()

  if err != nil {
    fmt.Printf("Failed to read response\n")
    return "", err
  }

  var json_block Response_Block

  err = json.Unmarshal(body, &json_block)
  if err != nil {
    fmt.Printf("Failed to unmarshal JSON:\n%s\n", body)
    return "", err
  }

  return json_block.Result.Block, nil
}

func init_http(cert_file_path string, key_file_path string, ca_cert_file_path string, skip_verify bool) (*http.Client, error) {
  if cert_file_path == "" && key_file_path == "" && ca_cert_file_path == "" {
    tr := &http.Transport {
      TLSClientConfig : &tls.Config { InsecureSkipVerify: skip_verify, },
    }

    return &http.Client { Transport : tr, }, nil
  }

  client_tls_cert, err := tls.LoadX509KeyPair(cert_file_path, key_file_path)
  if err != nil {
    return nil, err
  }

  cert_pool, err := x509.SystemCertPool()
  if err != nil {
    return nil, err
  }

  ca_cert_pem, err := os.ReadFile(ca_cert_file_path)
  if err != nil {
    return nil, err
  }

  if ok := cert_pool.AppendCertsFromPEM(ca_cert_pem); !ok {
    return nil, err
  }

  tls_config := &tls.Config{
    RootCAs      : cert_pool,
    Certificates : []tls.Certificate { client_tls_cert },
  }

  tr := &http.Transport{
    TLSClientConfig : tls_config,
  }

  return &http.Client { Transport : tr, }, nil
}

func main() {
  //  ----------------------------------------------------------------
  //
  //    Cancel signal
  //
  //  ----------------------------------------------------------------

  on_sig := make(chan bool,      1)
  sigs   := make(chan os.Signal, 1)

  signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)

  go func() {
           <- sigs
    on_sig <- true
  }()

  //  ----------------------------------------------------------------
  //
  //    Settings
  //
  //  ----------------------------------------------------------------

  dry_run, err := strconv.Atoi(os.Getenv("DUMPBLOCKS_DRY_RUN"))
  if err != nil {
    fmt.Printf("Invalid DUMPBLOCKS_DRY_RUN value: %s\n", err)
    return
  }

  log_blocks, err := strconv.Atoi(os.Getenv("DUMPBLOCKS_LOG"))
  if err != nil {
    fmt.Printf("Invalid DUMPBLOCKS_LOG value: %s\n", err)
    return
  }

  skip_verify, err := strconv.Atoi(os.Getenv("DUMPBLOCKS_TLS_SKIP_VERIFY"))
  if err != nil {
    fmt.Printf("Invalid DUMPBLOCKS_TLS_SKIP_VERIFY value: %s\n", err);
    return
  }

  update_period := 200

  update_period_str := os.Getenv("DUMPBLOCKS_PERIOD")
  if update_period_str != "" {
    update_period, err = strconv.Atoi(update_period_str)
    if err != nil {
      fmt.Printf("Invalid DUMPBLOCKS_PERIOD value: %s\n", err)
      return;
    }
  }

  endpoint := os.Getenv("DUMPBLOCKS_NODE_ENDPOINT")
  access   := os.Getenv("DUMPBLOCKS_DB_ACCESS")
  req      := os.Getenv("DUMPBLOCKS_DB_REQUEST")

  cert_file_path    := os.Getenv("DUMPBLOCKS_CERT_FILE")
  key_file_path     := os.Getenv("DUMPBLOCKS_KEY_FILE");
  ca_cert_file_path := os.Getenv("DUMPBLOCKS_CA_CERT_FILE");

  if endpoint == "" {
    fmt.Printf("Error: No DUMPBLOCKS_NODE_ENDPOINT\n")
    return
  }

  if access == "" {
    fmt.Printf("Error: No DUMPBLOCKS_DB_ACCESS\n")
    return
  }

  if req == "" {
    fmt.Printf("Error: No DUMPBLOCKS_DB_REQUEST\n")
    return
  }

  //  Check DUMPBLOCKS_DB_REQUEST syntax
  {
    s := fmt.Sprintf(req, 0, "00000000")
    if strings.Contains(s, "%!") {
      fmt.Printf("Error: Invalid DUMPBLOCKS_DB_REQUEST value\n")
      return
    }
  }

  //  ----------------------------------------------------------------
  //
  //    Receive and store blocks
  //
  //  ----------------------------------------------------------------

  client, err := init_http(cert_file_path, key_file_path, ca_cert_file_path, skip_verify != 0)
  if err != nil {
    fmt.Printf("%s\n", err)
    return
  }

  max_height := 0

  for {
    done := false

    select {
      case <-on_sig:
        fmt.Printf("\n");
        done = true
      default:
        time.Sleep(time.Millisecond * time.Duration(update_period))
    }

    if done {
      break
    }

    height, err := get_height(client, endpoint)
    if err != nil {
      fmt.Printf("get_height failed\n");
      fmt.Printf("%s\n", err);
      continue;
    }

    if height <= max_height {
      continue;
    }

    if max_height == 0 {
      max_height = height - 1
    }

    for max_height < height {
      max_height++

      block, err := get_block(client, endpoint, max_height)
      if err != nil {
        fmt.Printf("get_block failed");
        fmt.Printf("%s\n", err);
        continue;
      }

      if block[:2] != "0x" {
        fmt.Printf("Invalid hex string: %s\n", block);
        continue;
      }

      block_hex := block[2:]

      if dry_run == 0 {
        err = store_block(access, req, max_height, block_hex)
        if err != nil {
          fmt.Printf("%s\n", err)
        }
      }

      if log_blocks != 0 {
        fmt.Printf("[%08d] %s\n", max_height, block_hex)
      }
    }
  }
}
