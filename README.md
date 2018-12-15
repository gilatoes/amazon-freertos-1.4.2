## Introduction

This Github repository works on ESP32 with FreeRTOS 1.4.2. The application is Infineon Trust X device which performs One-way Authentication. The X.509 root CA certificate will first verify the Trust X end device certificate and it will generate a random number for ECDSA signing. The One-way Authentication will be completed by ECDSA verification of the signature using the Trust X public key. This project does not requires Wifi connectivity.

## Getting Started with Amazon FreeRTOS with ESP32 and OPTIGA Trust X

Install the ESP32 development platform.
Follow the ESP documentation for the Windows based toolchain setup.
https://docs.espressif.com/projects/esp-idf/en/latest/get-started/windows-setup.html

This Github repository can be copied into the MingW32 "home"\esp folder.

## Hardware

ESP32 devkitc is used to work with FreeRTOS. Trust X is connected to the I2C interface and the JTAG with FTDI cable can be used to debug the project.
Refer to Amazon documentation:
https://docs.aws.amazon.com/freertos/latest/userguide/getting_started_espressif.html

## Hardware connectivity
Trust X is connected via standard I2C and 1 GPIO is used for the reset pin.

## Configuring the FreeRTOS environment
Configure the serial terminal in the "home"\esp\amazon=freertos-1.4.2\demo\espressif\esp32_devkitc_esp_wrover_kit_trustx\make\sdkconfig

The default COM setting is 11. Please change it to the value according to your enumerated serial port.

```serial configuration
#
# Serial flasher config
#
CONFIG_ESPTOOLPY_PORT="COM11"
```

## Compiling the project

Start the MingW32 environment and navigate to "home"\esp\amaozon=freertos-1.4.2\demo\espressif\esp32_devkitc_esp_wrover_kit_trustx\make\ directory.
Execute the following command to compile, flash the image and start the serial monitor.

```
make flash monitor
```

## Compilation, flash and monitor output

Expects a long message output on the terminal when the software is compilation.

Here is the tail message of the compilation process.

```
CC build/xtensa-debug-module/trax.o
AR build/xtensa-debug-module/libxtensa-debug-module.a
LD build/aws_trustx_demo.elf
esptool.py v2.2.1
Flashing binaries to serial port COM11 (app at offset 0x20000)...
esptool.py v2.2.1
Connecting....
Chip is ESP32D0WDQ5 (revision 0)
Uploading stub...
Running stub...
Stub running...
Configuring flash size...
Auto-detected Flash size: 4MB
Flash params set to 0x0220
Compressed 21952 bytes to 13042...
Wrote 21952 bytes (13042 compressed) at 0x00001000 in 1.1 seconds (effective 152.7 kbit/s)...
Hash of data verified.
Compressed 448736 bytes to 275011...
Wrote 448736 bytes (275011 compressed) at 0x00020000 in 24.2 seconds (effective 148.1 kbit/s)...
Hash of data verified.
Compressed 3072 bytes to 119...
Wrote 3072 bytes (119 compressed) at 0x00008000 in 0.0 seconds (effective 1365.9 kbit/s)...
Hash of data verified.

Leaving...
Hard resetting...
MONITOR
--- idf_monitor on COM11 115200 ---
--- Quit: Ctrl+] | Menu: Ctrl+T | Help: Ctrl+T followed by Ctrl+H ---
ets Jun  8 2016 00:22:57

rst:0x1 (POWERON_RESET),boot:0x13 (SPI_FAST_FLASH_BOOT)
ets Jun  8 2016 00:22:57

rst:0x10 (RTCWDT_RTC_RESET),boot:0x13 (SPI_FAST_FLASH_BOOT)
configsip: 0, SPIWP:0xee
clk_drv:0x00,q_drv:0x00,d_drv:0x00,cs0_drv:0x00,hd_drv:0x00,wp_drv:0x00
mode:DIO, clock div:2
load:0x3fff0018,len:4
load:0x3fff001c,len:6060
load:0x40078000,len:0
load:0x40078000,len:15784
entry 0x400792e8
I (29) boot: ESP-IDF v3.1-dev-322-gf307f41-dirty 2nd stage bootloader
I (29) boot: compile time 23:35:42
I (30) boot: Enabling RNG early entropy source...
I (35) boot: SPI Speed      : 40MHz
I (39) boot: SPI Mode       : DIO
I (43) boot: SPI Flash Size : 4MB
I (47) boot: Partition Table:
I (51) boot: ## Label            Usage          Type ST Offset   Length
I (58) boot:  0 nvs              WiFi data        01 02 00010000 00006000
I (66) boot:  1 otadata          OTA data         01 00 00016000 00002000
I (73) boot:  2 phy_init         RF data          01 01 00018000 00001000
I (80) boot:  3 ota_0            OTA app          00 10 00020000 00100000
I (88) boot:  4 ota_1            OTA app          00 11 00120000 00100000
I (95) boot:  5 storage          Unknown data     01 82 00220000 00010000
I (103) boot: End of partition table
E (107) boot: ota data partition invalid and no factory, will try all partitions
I (115) esp_image: segment 0: paddr=0x00020020 vaddr=0x3f400020 size=0x0fda0 ( 64928) map
I (147) esp_image: segment 1: paddr=0x0002fdc8 vaddr=0x3ffb0000 size=0x00248 (   584) load
I (147) esp_image: segment 2: paddr=0x00030018 vaddr=0x400d0018 size=0x4db8c (318348) map
0x400d0018: _stext at ??:?

I (264) esp_image: segment 3: paddr=0x0007dbac vaddr=0x3ffb0248 size=0x021e8 (  8680) load
I (268) esp_image: segment 4: paddr=0x0007fd9c vaddr=0x40080000 size=0x00400 (  1024) load
0x40080000: _iram_start at C:/msys32/home/Gary/esp/amazon-freertos-1.4.2/lib/FreeRTOS/portable/ThirdParty/GCC/Xtensa_ESP32/xtensa_vectors.S:1685

I (271) esp_image: segment 5: paddr=0x000801a4 vaddr=0x40080400 size=0x0d708 ( 55048) load
I (302) esp_image: segment 6: paddr=0x0008d8b4 vaddr=0x400c0000 size=0x00000 (     0) load
I (311) boot: Loaded app from partition at offset 0x20000
I (311) boot: Disabling RNG early entropy source...
I (312) cpu_start: Pro cpu up.
I (315) cpu_start: Single core mode
I (320) heap_init: Initializing. RAM available for dynamic allocation:
I (327) heap_init: At 3FFAE6E0 len 00001920 (6 KiB): DRAM
I (333) heap_init: At 3FFBEEE8 len 00021118 (132 KiB): DRAM
I (339) heap_init: At 3FFE0440 len 00003BC0 (14 KiB): D/IRAM
I (345) heap_init: At 3FFE4350 len 0001BCB0 (111 KiB): D/IRAM
I (352) heap_init: At 4008DB08 len 000124F8 (73 KiB): IRAM
I (358) cpu_start: Pro cpu start user code
I (40) cpu_start: Starting scheduler on PRO CPU.
```

## Expected output

```
I (40) cpu_start: Starting scheduler on PRO CPU.
>app_main()
>prvMiscInitialization()
>trustx_reset_gpio_init()
<trustx_reset_gpio_init()
<prvMiscInitialization()
>optiga_init()
>pal_i2c_init()
<pal_i2c_init()
>pal_i2c_init()
E (721) i2c: i2c driver install error
<pal_i2c_init()
<optiga_init()
Boosting the OPTIGA Trust X performance..
Trust X UID:
cd 16 33 56
01 00 1c 00
05 00 00 0a
07 84 d7 00
05 00 90 00
94 80 10 10
70 10 48
OPTIGA Trust X generated DRNG random number:
46 33 5e 84
1f ed ed 53
17 70 f0 4e
79 49 1d 65
Data Digest:
5e 86 75 8c
85 f6 61 9f
ef 1b b1 a2
c1 24 f0 05
05 97 9e 60
5e 3a 42 3a
32 ee 59 97
0d 28 63 95
Trust X signature:
Signature length = 69.
02 20 73 f6
4f 33 ba 2b
c1 07 56 42
de ac 92 c4
dd 33 01 7c
d8 f2 1d ff
b4 c3 39 75
39 da 52 63
1c 9f 02 21
00 e6 1d 46
6f 41 7a f4
9d 75 10 63
ac 0e f5 7b
fb ae f4 79
ee 58 32 a9
ac 77 e4 69
e2 5f fd 3d
36 a5 45 00
Verify end device certificate against Root CA...
Parsing IFX CA certificate... ok
Parsing device certificate... ok
Verifying certificate chain... ok
Verified End device certificate against the Root CA.
Extract Public key from the certificate...
Public Key Size:65
Trust X Public Key:
04 fd ea 49
64 ef 03 b9
bd ef 00 e8
61 4f 9d db
cc 85 f5 6f
ad 69 80 32
d2 38 27 0c
60 6e 64 df
33 74 94 f5
26 5c 8a fd
76 56 65 fc
e9 18 40 4d
64 de d2 f9
43 11 6e 2c
49 99 ce 93
01 1e fc 80
ad 00 41 00

Signature is Ok.
<app_main()
```
