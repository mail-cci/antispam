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

## Database

The application uses MySQL to persist processed emails. Connection settings are
configured in `cmd/antispam/config.yaml` under the `database` section. A helper
initialization in the code will automatically create the required tables:

- `emails` – main metadata
- `email_headers` – individual header fields
- `email_attachments` – attachment contents
- `spam_scores` – analysis results
- `quarantine` – quarantined emails

Ensure a MySQL instance is available and the configured user has privileges to
create tables.

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
