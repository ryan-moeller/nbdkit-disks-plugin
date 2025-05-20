## FreeBSD disk devices configurable plugin for nbdkit NBD server

[nbdkit](https://gitlab.com/nbdkit/nbdkit) does not support serving FreeBSD disk
devices such as ATA disks, SCSI disks, or ZFS volumes.  This plugin implements
the basic necessities for serving the devices.  The server configuration is read
using [libucl](https://github.com/vstakhov/libucl), enabling the use of any file
format it supports, such as UCL, JSON, or YAML.  Hooks are provided allowing the
config file to run custom commands with a configurable environment on list,
open, and close actions.  The configuration can be reloaded at runtime, avoiding
server downtime.

For a simpler FreeBSD disk device plugin with no configuration file, see
[nbdkit-disk-plugin](https://github.com/ryan-moeller/nbdkit-disk-plugin).

## Prerequisites

The dependencies are nbdkit and libucl, which can be installed by `pkg` or from
ports.

The nbdkit port/package is quite outdated, and more functionality can be enabled
by building and installing nbdkit from source before building the plugin.  The
version in ports does not support reporting block size properties of the device.

While libucl is part of the base system, it is a private library not to be used
by third party software, hence needing to install it separately as well.

The example below uses git to clone the sources from GitHub, but one could
simply download the sources as a ZIP from GitHub using fetch.

## Building

Clone, build, and install the plugin:

```
$ git clone https://github.com/ryan-moeller/nbdkit-disks-plugin.git
$ cd nbdkit-disks-plugin
$ make
# make install # (optional) avoid needing to specify full path to shared library
```

## Usage

Serve a 40GB ZFS volume named `storage/nbdvol` as an export named `nbdvol`
without running `make install`:

```
# zfs create -V 40G storage/nbdvol
# echo nbdvol /dev/zvol/storage/nbdvol >nbdkit.conf
# nbdkit ./nbdkit-disks-plugin.so nbdkit.conf
```

Dynamically create and partition a swap-backed memory disk for every connection
to the export named "md" after running `make install`:

```
# cat >nbdkit.conf <<EOF
md {
    # Environment variables provided to the hooks
    env { SIZE 128m }
    # Command to run before opening the export.  The export name is written to
    # the first line on stdin, and the path to open is read from the first line
    # on stdout.
    open <<EOD
set -e
read NAME
PROV=$(mdconfig -a -t swap -s $SIZE -L $NAME)
{
    gpart create -s gpt $PROV
    gpart add -t freebsd-ufs $PROV
} >/dev/null
echo /dev/${PROV}
EOD
    # Command to run after closing the export.  The export name is written to
    # the first line and the path to the device is written to the second line on
    # stdin.
    close <<EOD
set -e
read NAME
read DEV
PROV=$(geom -p ${DEV#/dev/} | awk -F ': ' '$1 == "Geom name" { print $2 }')
gpart destroy -F $PROV
mdconfig -du $PROV
EOD
}
EOF
# nbdkit disks nbdkit.conf
```

Reload the configuration file after making changes:

```
# pkill -USR1 nbdkit
```

NOTE: Existing connections use the config state they were connected with.  The
new configuration only applies to new connections.

## Configuration

The basic format of the configuration file is `<export> = <properties>`.  As a
convenience, the form `<export> = <path>` is equivalent to
`<export> = { path = <path> }`.  The default export is "" in the NBD protocol,
but must be named "default" in the config file.

The full set of recognized properties are:

```
# Export name is a string, "default" meaning the default "" export.
<name> = {
    # Optional environment variables to set for hook commands.
    env = {
        # Variable values are forced to JSON if not a string.
        <name> = <value>,
        [...]
    }

    # Optional hook invoked when a client requests a list of exports.
    # <name> is written to first line of stdin.
    # <name>[\t<description>] is read from each line of stdout.
    # max 4096 chars per string (limited by nbdkit).
    list = <command>

    # Optional hook invoked when a client connects to an export, before the
    # device is opened by the plugin.
    # <name> is written to first line of stdin.
    # <path> is read from first line of stdout.
    open = <command>

    # Optional hook invoked when a client disconnects from an export, after the
    # device is closed by the plugin.
    # <name> is written to first line of stdin.
    # <path> is written to second line of stdin.
    close = <command>

    # Path to the device, required if no open hook is provided.
    path = <path>

    # Optional string description of the export.
    description = <desc>
}
```

Hook commands are passed directly to `popen(3)`, so are evaluated by /bin/sh.
Use with care.

Only disk-like devices on FreeBSD are currently supported by this plugin.  For
regualar files or for block devices on Linux, use `nbdkit-file-plugin(1)`.
