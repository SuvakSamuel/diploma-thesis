combiner.c is used to combine both parts of the master key together. This key would be then passed to cryptsetup to decrypt disks on chosen encrypted LUKS partitions. 

The passmaker script is simply to check the functionality of the entire system, i.e. getting both parts of the master key and combining them together.

Included here are also a script cryptsetup can use as a keyscript (for automatic decryption) during the initramfs stage of booting, as well as a initramfs hook which provides all needed files to the initramfs. This means that this entire system can run as the device is being loaded from initramfs.
