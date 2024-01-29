package main

import (
	"context"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/elastic/go-elasticsearch/v7"
	"github.com/elastic/go-elasticsearch/v7/esapi"
)

func elastic(hostname string) chan string {

	id := uint64(time.Now().UnixNano())

	client, err := elasticsearch.NewDefaultClient()

	if err != nil {
		return nil
	}

	c := make(chan string, 10000)

	go func() {
		for m := range c {

			id++

			logit(client, hostname, fmt.Sprintf("%d", id), m)
		}
	}()

	return c
}

func logit(client *elasticsearch.Client, host, id, message string) error {

again:
	ctx := context.Background()
	req := esapi.IndexRequest{
		Index:      "vc5",
		DocumentID: host + "-" + id,
		Body:       strings.NewReader(message),
		Refresh:    "true",
	}

	res, err := req.Do(ctx, client)

	if err != nil {
		log.Println("Coulnd't log message", id)
		//return err
		time.Sleep(time.Second)
		goto again
	}

	defer res.Body.Close()

	return nil
}
