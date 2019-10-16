# firefox-adddon-sign

## Installation

```
go get github.com/taisa831/firefox-addon-sign
```

## QuickStart

```go
package main

import (
        "github.com/taisa831/firefox-addon-sign/sign"
)

func main() {
        err := run()
	if err != nil {
		panic(err.Error())
	}
}

func run() error {
        s := sign.NewSign(
                "{path/to/xpi-file.xpi}", // extension path
                "{xpi-file.xpi}", // extension file name
                "{gecko-id}", // gecko id
                "{version}", // version
                "{jwt-token}", // jwt token
                "{jwt-secret}", // jwt secret
                "{download-path}", // download path
        )
        err := s.Register()
        if err != nil {
                panic(err)
        }
        return nil
}
```

## License

MIT
