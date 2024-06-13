GOFILES:=$(shell find . -type f -iname '*.go')

attache: $(GOFILES)
	go build -o attache ./cmd/attache/main.go

demo-runner: $(GOFILES)
	go build -o demo-runner ./cmd/demo-runner/main.go

thirdparty-licenses:
	@echo "Retrieving third-party licenses..."
	go get github.com/google/go-licenses
	go install github.com/google/go-licenses
	$(GOPATH)/bin/go-licenses csv github.com/DataDog/attache/cmd | sort > LICENSE-3rdparty.csv
	@echo "Third-party licenses retrieved and saved to $(ROOT_DIR)/LICENSE-3rdparty.csv"
