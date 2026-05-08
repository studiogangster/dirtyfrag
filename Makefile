APP=checker
PKG=./cmd/checker
DIST=dist

.PHONY: build clean build-all build-probe-scripts

build:
	@mkdir -p $(DIST)
	CGO_ENABLED=0 go build -o $(DIST)/$(APP)-$$(go env GOOS)-$$(go env GOARCH) $(PKG)

build-all:
	@mkdir -p $(DIST)
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o $(DIST)/$(APP)-linux-amd64 $(PKG)
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -o $(DIST)/$(APP)-linux-arm64 $(PKG)
	CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -o $(DIST)/$(APP)-windows-amd64.exe $(PKG)
	CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 go build -o $(DIST)/$(APP)-darwin-amd64 $(PKG)
	CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go build -o $(DIST)/$(APP)-darwin-arm64 $(PKG)

clean:
	rm -rf $(DIST)

build-probe-scripts:
	./scripts/build-single-file-probes.sh ./release
