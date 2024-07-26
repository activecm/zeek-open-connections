# zeek-open-connections

By default, Zeek will only log connection information after the connection as been closed or Zeek has been stopped. This means that long running connections could run for hours, days, or even weeks before they are noticed. For threat hunters, this behavior is highly undesirable.

This Zeek plugin will cause Zeek to periodically write out connection information for open connections. The information is written out to three files named "open_conn.log", "open_ssl.log" and "open_http.log". The information written to these log files is identical to what is written to conn.log, ssl.log, and http.log. Each entry contains the TOTAL duration and bytes transferred by the open connection.

The entries are written out at an interval that is specified by the user. The default interval is to write out an entry after the connection has been open for 1 hour and then every hour after that first hour.

This project is based on the excellent work by Corelight and retains the copyright information within the main script: https://github.com/corelight/zeek-long-connections


### Locally testing changes
Update the script for the plugin located at `/usr/local/zeek/share/zeek/site/zeek-open-connections/zeek-open-connections.zeek`
Run `zeekctl deploy` after making changes.

### Updating the Package
In order for the Zeek package manager to update the commit that it uses for the plugin, make sure that the commit is tagged. It is unclear if a new tag needs to be created or if the commit just needs to be tagged in general. The package can be viewed [here](https://packages.zeek.org/packages/view/d9a14d6e-ca6a-11eb-81e7-0a598146b5c6). This site does not update immediately.

In order to immediately pull down the new version to test that it is working, run the following:

If using `docker-zeek`, enter a bash terminal inside the Zeek container:
`docker exec -it zeek /bin/sh`

Update the Zeek package registry to fetch the new version:
`zkg refresh`

This should display every package that is outdated. The `activecm/zeek-open-connections` plugin should appear here.

Update the package:
`zkg update` (to update all packages) or `zkg upgrade zeek-open-connections` to update just this package

Make Zeek use the updated packages:
`zeekctl deploy`
