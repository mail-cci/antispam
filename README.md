# AntiSpam

This project implements a simple milter and HTTP API written in Go. The
application reads its configuration from `cmd/antispam/config.yaml` and
can also be influenced by environment variables via [Viper](https://github.com/spf13/viper).

## Building

Make sure you have Go installed (version 1.22 or higher). To build the
binary run:

```bash
go build -o antispam ./cmd/antispam
```

This will produce an executable named `antispam` in the project root.

## Running

Copy or edit `cmd/antispam/config.yaml` to match your environment and then
start the application:

```bash
./antispam
```

The program will start the milter and HTTP servers using the ports defined
in the configuration file.

## Testing

Unit tests can be executed with:

```bash
go test ./...
```


### Testing the milter

Use the helper script to compile the project, start the server and send the sample emails with [swaks](https://www.jetmore.org/john/code/swaks/). A local SMTP service listening on port 25 is required.

```bash
scripts/test_milter.sh
```
