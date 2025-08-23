combiner.c is used to combine both parts of the master key together. This key would be then passed to cryptsetup to decrypt disks on chosen encrypted LUKS partitions. 

The decrypt script is simply to check the functionality of the entire system, i.e. getting both parts of the master key and combining them together.
The usbmount script uses this master key to decrypt data on a USB drive, which is subsequently mounted. The USB drive was LUKS encrypted.

STILL NEEDS FIXING, STUCK ON SERIAL PORTS NOT AVAILABLE DURING INITRAMFS:
Included here are also a script cryptsetup can use as a keyscript (for automatic decryption) during the initramfs stage of booting, as well as a initramfs hook which provides all needed files to the initramfs. This means that this entire system can run as the device is being loaded from initramfs.
