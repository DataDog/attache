package main

import (
	"context"
	"fmt"
	"io"
	"os"

	"cloud.google.com/go/storage"
)

func main() {
	ctx := context.Background()
	client, err := storage.NewClient(ctx)
	if err != nil {
		fmt.Printf("new client: %v", err)
		os.Exit(1)
	}

	// Read the object1 from bucket.
	rc, err := client.Bucket("emissary").Object("sherman.txt").NewReader(ctx)
	if err != nil {
		fmt.Printf("get object: %v\n", err)
		os.Exit(1)
	}
	defer rc.Close()
	body, err := io.ReadAll(rc)
	if err != nil {
		fmt.Printf("read object: %v\n", err)
		os.Exit(1)
	}

	fmt.Println(string(body))
}
