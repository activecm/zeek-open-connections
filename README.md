# zeek-open-connections

By default, Zeek only logs connection information after a connection is closed or Zeek is stopped. Long-running connections can go hours, days, or weeks before they show up in logs.

This plugin periodically logs open connection info to `open_conn.log`, `open_ssl.log`, and `open_http.log`. The output is identical to `conn.log`, `ssl.log`, and `http.log`. Each entry contains the total duration and bytes for the connection.

The default interval is 1 hour. An open connection gets logged after 1 hour, then every hour after that until it closes.

Based on [zeek-long-connections](https://github.com/corelight/zeek-long-connections) by Corelight.

## Installation

```bash
zkg install zeek-open-connections
zeekctl deploy
```

## Development

Releases are created automatically when a version tag is pushed. CI tests against Zeek 6.2.1, 7.2.2, and 8.1.1.
