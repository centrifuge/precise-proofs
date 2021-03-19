module github.com/centrifuge/precise-proofs

go 1.15

require (
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/golang/protobuf v1.3.1
	github.com/pkg/errors v0.8.0
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/stretchr/testify v1.2.2
	github.com/xsleonard/go-merkle v1.1.0
	golang.org/x/crypto v0.0.0-20190530122614-20be4c3c3ed5
	golang.org/x/sys v0.0.0-20190531073156-46560c3f3c0a // indirect
)

replace github.com/xsleonard/go-merkle v1.1.0 => github.com/centrifuge/go-merkle v0.0.0-20190727075423-0ac78bbbc01b
