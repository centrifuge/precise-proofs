.PHONY: help install_protoc_deps proto-lint proto

help: ## Show this help message.
	@echo 'usage: make [target] ...'
	@echo
	@echo 'targets:'
	@egrep '^(.+)\:\ ##\ (.+)' ${MAKEFILE_LIST} | column -t -c 2 -s ':#'

install-protoc-deps: ## Installs all protobuf dependencies
	@go install github.com/ckaznocha/protoc-gen-lint@0.2.4
	@go install google.golang.org/protobuf/cmd/protoc-gen-go@v1.28.0

proto-lint: ## Lint protos
	@protoc --lint_out=. proofs/proto/*.proto

proto: ## Compile protos
	@protoc -Iproofs/proto \
		--go_out=paths=source_relative:proofs/proto \
		proofs/proto/*.proto