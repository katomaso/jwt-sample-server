package main

import (
	"fmt"
	"testing"
)

func TestServer(t *testing.T) {
	fmt.Printf("{typ: \"JWT\", alg: \"HS265\"}", enJSON(Header{"JWT", "HS256"}))
}
