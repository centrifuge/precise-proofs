lint-check: ## runs linters on go code
		@gometalinter --disable-all --enable=golint --enable=goimports --enable=vet --enable=nakedret \
				--enable=staticcheck --vendor --skip=resources --skip=testingutils --skip=protobufs  --deadline=1m ./...;

install_protoc_deps:	## Installs all protobuf dependencies
	go install google.golang.org/protobuf/cmd/protoc-gen-go@v1.28.0

proto:	## Compile protos
	protoc -Iproofs/proto \
		--go_out=paths=source_relative:proofs/proto \
		proofs/proto/*.proto