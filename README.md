Fixes mdssvc regex on TrueNAS Core

Add `export LD_PRELOAD="/path/to/libsscanfpatch.so"` to `/etc/local/rc.d/smbd`  
Must be reapplied every update

Example patch:

```diff
# ./smbd.patch

--- smbd	2022-10-07 12:07:26.000000000 +0200
+++ smbd_patch	2022-10-07 12:08:04.000000000 +0200
@@ -11,6 +11,8 @@
 rcvar=smbd_enable
 smbd_group=""
 
+export LD_PRELOAD="/mnt/Apps/libsscanfpatch.so"
+
 smbd_pidfile="/var/run/samba4/smbd.pid"
 smbcontrol="/usr/local/bin/smbcontrol"
 jq="/usr/local/bin/jq"
```

```bash
patch -fsu --fuzz 0 --reject-file '-' /etc/local/rc.d/smbd < ./smbd.patch
```
