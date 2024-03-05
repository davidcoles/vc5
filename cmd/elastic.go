package main

import (
	"context"
	"errors"
	"fmt"
	//"log"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/elastic/go-elasticsearch/v7"
	"github.com/elastic/go-elasticsearch/v7/esapi"
)

// https://pkg.go.dev/github.com/elastic/go-elasticsearch/v7
// https://www.elastic.co/guide/en/elasticsearch/reference/7.17/security-minimal-setup.html

type Elasticsearch struct {
	Index     string   `json:"index,omitempty"`
	Addresses []string `json:"addresses,omitempty"`
	Username  secret   `json:"username,omitempty"`
	Password  secret   `json:"password,omitempty"`

	c       chan string
	mutex   sync.Mutex
	started bool
	client  *elasticsearch.Client
	fail    atomic.Uint64
}

func (e *Elasticsearch) Fail() uint64 {
	return e.fail.Load()
}

func (e *Elasticsearch) log(l string, hostname string) (err error) {

	e.mutex.Lock()
	defer e.mutex.Unlock()

	if e.Index == "" {
		return nil
	}

	if !e.started {
		e.started = true
		e.client, err = elasticsearch.NewClient(elasticsearch.Config{
			Addresses: e.Addresses,
			Username:  string(e.Username),
			Password:  string(e.Password),
		})

		if err != nil {
			return
		}
	}

	if e.client == nil {
		return nil
	}

	if e.c == nil {
		e.c = elastic(e.client, e.Index, hostname, &(e.fail))
	}

	if e.c == nil {
		return nil
	}

	select {
	case e.c <- l:
	default:
		close(e.c)
		e.c = nil
		e.fail.Add(1)
		return errors.New("Elasticsearch channel blocked")
	}

	return nil
}

func elastic(client *elasticsearch.Client, index, hostname string, fail *atomic.Uint64) chan string {

	id := uint64(time.Now().UnixNano())
	in := make(chan string, 1000)

	//ctx, _ := context.WithCancel(context.Background())
	ctx := context.Background()

	go func() {
		for m := range in {
			if !indexRequest(ctx, client, id, index, hostname, m) {
				fail.Add(1)
			}

			id++
		}
	}()

	return in
}

func indexRequest(ctx context.Context, client *elasticsearch.Client, id uint64, index, host, message string) bool {

	//ctx := context.Background()
	req := esapi.IndexRequest{
		Index:      index,
		DocumentID: fmt.Sprintf("%s-%d", host, id),
		Body:       strings.NewReader(message),
		Refresh:    "true",
	}

	res, err := req.Do(ctx, client)

	if err == nil {
		res.Body.Close()

		if res.StatusCode == 201 {
			return true
		}
	}

	return false
}
