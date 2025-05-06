## FreeBSD disk device plugin for nbdkit NBD server

[nbdkit](https://gitlab.com/nbdkit/nbdkit) does not support serving FreeBSD disk
devices such as ATA disks, SCSI disks, or ZFS volumes.  This plugin implements
the basic necessities for serving the devices.

## Prerequisites

The only dependency is nbdkit, which can be installed by `pkg` or from ports.

The port/package is quite outdated, and more functionality can be enabled by
building and installing nbdkit from source before building the plugin.  The
version in ports does not support reporting block size properties of the device.

## Usage

Serve a 40GB ZFS volume named `storage/nbdvol`:

```
# make
# zfs create -V 40G storage/nbdvol
# nbdkit ./nbdkit-disk-plugin.so /dev/zvol/storage/nbdvol
```
