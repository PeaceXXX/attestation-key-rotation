BIN := keyrot

.PHONY: build test vet fmt run clean

build:
	go build -o $(BIN) ./cmd/keyrot

test:
	go test ./...

vet:
	go vet ./...

fmt:
	gofmt -l .

run: build
	./$(BIN) serve --addr :8080

clean:
	rm -f $(BIN)
