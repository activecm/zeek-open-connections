# zeek-open-connections

By default, Zeek will only log connection information after the connection as been closed or Zeek has been stopped. This means that long running connections could run for hours, days, or even weeks before they are noticed. For threat hunters, this behavior is highly undesirable.

This Zeek plugin will cause Zeek to periodically write out connection information for open connections. The information is written out to three files named "open_conn.log", "open_ssl.log" and "open_http.log". The information written to these log files is identical to what is written to conn.log, ssl.log, and http.log. Each entry contains the TOTAL duration and bytes transferred by the open connection.

The entries are written out at an interval that is specified by the user. The default interval is to write out an entry after the connection has been open for 1 hour and then every hour after that first hour.

This project is based on the excellent work by Corelight and retains the copyright information within the main script: https://github.com/corelight/zeek-long-connections
