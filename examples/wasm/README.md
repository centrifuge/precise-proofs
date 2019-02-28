Using precise-proofs tree generation with WebAssembly
=====================================================

This page assumes a functional Go 1.11 or newer installation. For
troubleshooting, see the https://github.com/golang/go/wiki/InstallTroubleshooting[Install Troubleshooting]
page.

The package `examples/wasm` is a simple demo that can be compiled for use in a web browser. It will generate a tree from some JSON input, calculate the roothash and validate a proof.

## Compilation

Set `GOOS=js` and `GOARCH=wasm` environment variables to compile
for WebAssembly:

```sh
$ cd examples/wasm
$ GOOS=js GOARCH=wasm go build -o main.wasm
```

That will build the package and produce an executable WebAssembly
module file named main.wasm. The .wasm file extension will make it
easier to serve it over HTTP with the correct Content-Type header
later on.

To execute `main.wasm` in a browser, we'll also need a JavaScript
support file, and a HTML page to connect everything together.

Copy the JavaScript support file:

```sh
$ cp "$(go env GOROOT)/misc/wasm/wasm_exec.js" ./
```

If your browser doesn't yet support `WebAssembly.instantiateStreaming`,
you can use a [polyfill](https://github.com/golang/go/blob/b2fcfc1a50fbd46556f7075f7f1fbf600b5c9e5d/misc/wasm/wasm_exec.html#L17-L220).

Then serve the three files (`index.html`, `wasm_exec.js`, and
`main.wasm`) from a web server. For example, with
[`goexec`](https://github.com/shurcooL/goexec#goexec):

```sh
$ goexec 'http.ListenAndServe(":8080", http.FileServer(http.Dir(".")))'
```

Finally, navigate to http://localhost:8080/index.html, open the
JavaScript debug console, and you should see the output. You can
modify the program, rebuild `main.wasm`, and refresh to see new
output.
