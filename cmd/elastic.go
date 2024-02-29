package main

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/elastic/go-elasticsearch/v7"
	"github.com/elastic/go-elasticsearch/v7/esapi"
)

// https://pkg.go.dev/github.com/elastic/go-elasticsearch/v7

type Elasticsearch struct {
	Index     string   `json:"index,omitempty"`
	Addresses []string `json:"addresses,omitempty"`
	Username  string   `json:"username,omitempty"`
	Password  string   `json:"password,omitempty"`

	c chan string
	m sync.Mutex
}

func (e *Elasticsearch) log(l string, hostname string) bool {

	if e.Index == "" {
		return true
	}

	e.m.Lock()
	defer e.m.Unlock()

	if e.c == nil {
		config := elasticsearch.Config{
			Addresses: e.Addresses,
			Username:  e.Username,
			Password:  e.Password,
		}

		e.c = elastic(config, e.Index, hostname)
	}

	select {
	case e.c <- l:
	default:
		close(e.c)
		e.c = nil
		return false
	}

	return true
}

func elastic(config elasticsearch.Config, index, hostname string) chan string {

	id := uint64(time.Now().UnixNano())

	client, err := elasticsearch.NewClient(config)

	if err != nil {
		return nil
	}

	in := make(chan string, 10000)

	go func() {
		for m := range in {
			id++
			indexRequest(client, index, hostname, fmt.Sprintf("%d", id), m)
		}
	}()

	return in
}

func indexRequest(client *elasticsearch.Client, index, host, id, message string) {

	for {
		ctx := context.Background()
		req := esapi.IndexRequest{
			Index:      index,
			DocumentID: host + "-" + id,
			Body:       strings.NewReader(message),
			Refresh:    "true",
		}

		res, err := req.Do(ctx, client)

		if err == nil {
			res.Body.Close()
			return
		}

		time.Sleep(time.Second)
	}
}
