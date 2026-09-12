# RED Hydrogen One kernel source

This vendor tree is paired with the source-built RED Hydrogen One MSM8998
kernel:

| Field | Value |
|---|---|
| Workspace path | `kernel/red/msm8998` |
| Repository | `https://github.com/derveror/android_kernel_red_msm8998` |
| Branch | `lineage-22.2` |
| Verified commit | `440e8eb4eea36404d340a2a4ad001cf013304447` |
| Kernel version | Linux `4.4.302+` |
| Defconfig | `lineageos_hydrogenone_defconfig` |
| Image target | `Image.gz-dtb` |

The verified kernel contains the four RED production/PVT DTBs in TM, TM CSP,
SIM and JDI order and source-built FPC1020, LM36923H, TFA9894 and JDI CYTTSP5
support. The proprietary rear SmartPort is intentionally excluded; ordinary
USB-C, charging, Bluetooth and UFS remain in scope.

The TFA driver requests `tfa98xx.cnt` and `tfa98xx_a3d.cnt`. Those containers
are not currently selected by this vendor tree, so speaker runtime remains
unverified until the stock-authoritative files are recovered, packaged and
tested on the device.

Kernel compilation and static artifact validation pass at the commit above.
Physical boot and hardware runtime validation are separate required gates.
