.PHONY: install_protoc_deps proto-lint proto

install-protoc-deps:	## Installs all protobuf dependencies
	@go install github.com/ckaznocha/protoc-gen-lint@0.2.4
	@go install google.golang.org/protobuf/cmd/protoc-gen-go@v1.28.0

proto-lint:  ## Lint protos
	@protoc --lint_out=. proofs/proto/*.proto

proto:	## Compile protos
	@protoc -Iproofs/proto \
		--go_out=paths=source_relative:proofs/proto \
		--lint_out=. \
		proofs/proto/*.proto