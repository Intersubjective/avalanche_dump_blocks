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
  "encoding/json"
  "strconv"
  "database/sql"
  _ "github.com/lib/pq"
)

func store_block(height int, block string) error {
  access := "host=127.0.0.1 port=12345 user=postgres password=postgres dbname=zombie sslmode=disable"
  req    := "INSERT INTO blocks (height, hex) VALUES (%d, '%s') ON CONFLICT DO NOTHING"

  db, err := sql.Open("postgres", access)
  if err != nil {
    return err
  }

  sql := fmt.Sprintf(req, height, block)

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
  res, err := client.Post(fmt.Sprintf("%s/ext/bc/P", endpoint), "application/json", strings.NewReader(req))

  if err != nil {
    return 0, err
  }

  body, err := io.ReadAll(res.Body)
  res.Body.Close()

  if err != nil {
    fmt.Printf("%s\n", err)
  }

  var json_height Response_Height

  err = json.Unmarshal(body, &json_height)
  if err != nil {
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
  res, err := client.Post(fmt.Sprintf("%s/ext/bc/P", endpoint), "application/json", strings.NewReader(req))

  if err != nil {
    return "", err
  }

  body, err := io.ReadAll(res.Body)
  res.Body.Close()

  if err != nil {
    fmt.Printf("%s\n", err)
  }

  var json_block Response_Block

  err = json.Unmarshal(body, &json_block)
  if err != nil {
    return "", err
  }

  return json_block.Result.Block, nil
}

func main() {
  on_sig := make(chan bool,      1)
  sigs   := make(chan os.Signal, 1)

  signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)

  go func() {
           <- sigs
    on_sig <- true
  }()

  endpoints := []string {
    "https://avalanche-p-chain-rpc.publicnode.com",
  }

  index := 0

  tr := &http.Transport{
    TLSClientConfig : &tls.Config{ InsecureSkipVerify: true, },
  }
  client := &http.Client { Transport: tr, }

  max_height := 0

  for {
    done := false

    select {
      case <-on_sig:
        fmt.Printf("\n");
        done = true
      default:
        time.Sleep(time.Millisecond * 200);
    }

    if done {
      break
    }

    height, err := get_height(client, endpoints[index])
    if err != nil {
      fmt.Printf("%s\n", err);
      index = (index + 1) % len(endpoints)
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

      block, err := get_block(client, endpoints[index], max_height)
      if err != nil {
        fmt.Printf("%s\n", err);
        index = (index + 1) % len(endpoints)
        continue;
      }

      fmt.Printf("[%08d] %s\n", max_height, block)

      err = store_block(max_height, block)
      if err != nil {
        fmt.Printf("%s\n", err)
      }
    }
  }
}
