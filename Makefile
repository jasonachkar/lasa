SHELL := /bin/sh
GO ?= go
GO_VERSION := 1.27.3
VERSION ?= 0.1.0-dev
VULN_DB ?=
BIN := bin/lasa
LDFLAGS := -s -w -buildid= -X github.com/jasonachkar/lasa/internal/domain.Version=$(VERSION)
export GOTOOLCHAIN := local

.PHONY: all build test vet fmt lint vuln deps race check release-binaries reproducible tools bpf fuzz notices sbom packages print-version clean
all: build
build:
	@mkdir -p bin
	CGO_ENABLED=0 $(GO) build -trimpath -buildvcs=false -ldflags='$(LDFLAGS)' -o $(BIN) ./cmd/lasa
test:
	$(GO) test ./...
race:
	CGO_ENABLED=1 $(GO) test -race ./...
vet:
	$(GO) vet ./...
fmt:
	@test -z "$$(gofmt -l $$(find cmd internal rules test -name '*.go'))" || { gofmt -l $$(find cmd internal rules test -name '*.go'); exit 1; }
lint:
	staticcheck ./...
vuln:
	govulncheck $(if $(VULN_DB),-db $(VULN_DB),) ./...
deps:
	sh scripts/check-dependencies.sh
check: build fmt vet test race lint deps vuln
reproducible:
	VERSION=$(VERSION) sh scripts/reproducible-build.sh
release-binaries:
	@mkdir -p dist
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 $(GO) build -trimpath -buildvcs=false -ldflags='$(LDFLAGS)' -o dist/lasa-$(VERSION)-linux-amd64 ./cmd/lasa
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 $(GO) build -trimpath -buildvcs=false -ldflags='$(LDFLAGS)' -o dist/lasa-$(VERSION)-linux-arm64 ./cmd/lasa
	cd dist && sha256sum lasa-$(VERSION)-linux-amd64 lasa-$(VERSION)-linux-arm64 > SHA256SUMS
tools:
	$(GO) install honnef.co/go/tools/cmd/staticcheck@v0.8.2
	$(GO) install golang.org/x/vuln/cmd/govulncheck@v1.9.0
	$(GO) install golang.org/x/tools/cmd/goimports@v0.52.0
	$(GO) install github.com/CycloneDX/cyclonedx-gomod/cmd/cyclonedx-gomod@v1.9.0
bpf:
	$(GO) generate ./internal/collector/ebpf
fuzz:
	$(GO) test ./internal/collector/process -run '^$$' -fuzz '^FuzzStat$$' -fuzztime=3s -parallel=2
	$(GO) test ./internal/collector/process -run '^$$' -fuzz '^FuzzStatus$$' -fuzztime=3s -parallel=2
	$(GO) test ./internal/collector/network -run '^$$' -fuzz '^FuzzSocket$$' -fuzztime=3s -parallel=2
	$(GO) test ./internal/collector/network -run '^$$' -fuzz '^FuzzSocketTable$$' -fuzztime=3s -parallel=2
	$(GO) test ./internal/collector/identity -run '^$$' -fuzz '^FuzzMountInfo$$' -fuzztime=3s -parallel=2
	$(GO) test ./internal/rules -run '^$$' -fuzz '^FuzzLoad$$' -fuzztime=3s -parallel=2
	$(GO) test ./internal/report -run '^$$' -fuzz '^FuzzDecode$$' -fuzztime=3s -parallel=2
	$(GO) test ./internal/access -run '^$$' -fuzz '^FuzzACL$$' -fuzztime=3s -parallel=2
	$(GO) test ./internal/advisory -run '^$$' -fuzz '^FuzzVersionComparators$$' -fuzztime=3s -parallel=2
	$(GO) test ./internal/inspection -run '^$$' -fuzz '^FuzzConfigurationParsers$$' -fuzztime=3s -parallel=2
	$(GO) test ./internal/inspection -run '^$$' -fuzz '^FuzzFirewall$$' -fuzztime=3s -parallel=2
notices:
	sh scripts/package-notices.sh
sbom: release-binaries notices
	cyclonedx-gomod bin -json -std -version v$(VERSION) -output dist/lasa-amd64.cdx.json dist/lasa-$(VERSION)-linux-amd64
	cyclonedx-gomod bin -json -std -version v$(VERSION) -output dist/lasa-arm64.cdx.json dist/lasa-$(VERSION)-linux-arm64
packages: sbom
	bash scripts/package-release.sh $(VERSION)
	bash scripts/write-release-manifest.sh $(VERSION)
print-version:
	@printf '%s\n' '$(VERSION)'
clean:
	rm -rf bin dist
