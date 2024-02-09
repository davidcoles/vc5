package main

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/elastic/go-elasticsearch/v7"
	"github.com/elastic/go-elasticsearch/v7/esapi"
)

// https://pkg.go.dev/github.com/elastic/go-elasticsearch/v7

func elastic(index, hostname string) chan string {

	id := uint64(time.Now().UnixNano())

	client, err := elasticsearch.NewDefaultClient()

	if err != nil {
		return nil
	}

	c := make(chan string, 10000)

	go func() {
		for m := range c {

			id++

			indexRequest(client, index, hostname, fmt.Sprintf("%d", id), m)
		}
	}()

	return c
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
