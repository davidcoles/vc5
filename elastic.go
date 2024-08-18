package vc5

import (
	"bytes"
	"context"
	"fmt"
	"sync"
	"sync/atomic"

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

func (e *Elasticsearch) start() (err error) {

	e.client, err = elasticsearch.NewClient(elasticsearch.Config{
		Addresses: e.Addresses,
		Username:  string(e.Username),
		Password:  string(e.Password),
	})

	if err != nil {
		return err
	}

	return nil
}

func (e *Elasticsearch) log(host string, id uint64, body []byte) bool {
	if e.client == nil {
		return false
	}

	ctx := context.Background()
	req := esapi.IndexRequest{
		Index:      e.Index,
		DocumentID: fmt.Sprintf("%s-%d", host, id),
		Body:       bytes.NewReader(body),
		Refresh:    "true",
	}

	res, err := req.Do(ctx, e.client)

	if err != nil {
		return false
	}

	defer res.Body.Close()

	return res.StatusCode == 201
}
