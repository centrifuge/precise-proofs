lint-check: ## runs linters on go code
		@gometalinter --disable-all --enable=golint --enable=goimports --enable=vet --enable=nakedret \
				--enable=staticcheck --vendor --skip=resources --skip=testingutils --skip=protobufs  --deadline=1m ./...;
