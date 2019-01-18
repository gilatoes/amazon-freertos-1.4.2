/*
 * Amazon FreeRTOS V1.4.2
 * Copyright (C) 2018 Amazon.com, Inc. or its affiliates.  All Rights Reserved.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy of
 * this software and associated documentation files (the "Software"), to deal in
 * the Software without restriction, including without limitation the rights to
 * use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
 * the Software, and to permit persons to whom the Software is furnished to do so,
 * subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
 * FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
 * COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
 * IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 *
 * http://aws.amazon.com/freertos
 * http://www.FreeRTOS.org
 */

/* FreeRTOS includes. */
#include "FreeRTOS.h"
#include "task.h"
#include "timers.h"

/* Demo includes */
#include "aws_demo_runner.h"

/* AWS System includes. */
#include "aws_system_init.h"
#include "aws_logging_task.h"
#include "aws_wifi.h"
#include "aws_clientcredential.h"
#include "nvs_flash.h"
#include "FreeRTOS_IP.h"
#include "FreeRTOS_Sockets.h"

#include "driver/gpio.h"
#include "esp_vfs.h"
#include "esp_vfs_fat.h"

#include "esp_system.h"
#include "esp_wifi.h"
#include "esp_interface.h"

/* Application version info. */
#include "aws_application_version.h"
#include "esp_log.h"

#include "optiga/pal/pal.h"
#include "optiga/comms/optiga_comms.h"
#include "optiga/optiga_util.h"
#include "optiga/optiga_crypt.h"
#include "optiga/pal/pal_os_timer.h"
#include "optiga/pal/pal_os_event.h"
#include "optiga/ifx_i2c/ifx_i2c.h"

#include "mbedtls/base64.h"
#include "mbedtls/ssl.h"
#include "mbedtls/sha256.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/ecdsa.h"
#include "mbedtls/x509.h"
#include "mbedtls/x509_crt.h"

#include "aws_demo_config.h"
//#include "aws_mqtt_agent.h"

/* Logging Task Defines. */
#define mainLOGGING_MESSAGE_QUEUE_LENGTH    ( 32 )
#define mainLOGGING_TASK_STACK_SIZE         ( configMINIMAL_STACK_SIZE * 6 )
#define mainDEVICE_NICK_NAME                "Espressif_Demo"

/* Declare the firmware version structure for all to see. */
const AppVersion32_t xAppFirmwareVersion = {
   .u.x.ucMajor = APP_VERSION_MAJOR,
   .u.x.ucMinor = APP_VERSION_MINOR,
   .u.x.usBuild = APP_VERSION_BUILD,
};

///Requested operation completed without any error
#define CRYPTO_LIB_OK                               0

///Null parameter(s)
#define CRYPTO_LIB_NULL_PARAM                       0x80003001

///Certificate parse failure
#define CRYPTO_LIB_CERT_PARSE_FAIL                  (CRYPTO_LIB_NULL_PARAM + 1)

///Signature Verification failure
#define CRYPTO_LIB_VERIFY_SIGN_FAIL                 (CRYPTO_LIB_NULL_PARAM + 2)

///SHA256 generation failure
#define CRYPTO_LIB_SHA256_FAIL                      (CRYPTO_LIB_NULL_PARAM + 3)

///Length of input is zero
#define CRYPTO_LIB_LENZERO_ERROR                    (CRYPTO_LIB_NULL_PARAM + 4)

///Length of Parameters are zero
#define CRYPTO_LIB_LENMISMATCH_ERROR                (CRYPTO_LIB_NULL_PARAM + 5)

///Memory allocation failure
#define CRYPTO_LIB_MEMORY_FAIL                      (CRYPTO_LIB_NULL_PARAM + 6)

///Insufficient memory
#define CRYPTO_LIB_INSUFFICIENT_MEMORY              (CRYPTO_LIB_NULL_PARAM + 7)

///Generic error condition
#define CRYPTO_LIB_ERROR                            0xF1743903

/* Static arrays for FreeRTOS+TCP stack initialization for Ethernet network connections
 * are use are below. If you are using an Ethernet connection on your MCU device it is 
 * recommended to use the FreeRTOS+TCP stack. The default values are defined in 
 * FreeRTOSConfig.h. */

/* Default MAC address configuration.  The demo creates a virtual network
 * connection that uses this MAC address by accessing the raw Ethernet data
 * to and from a real network connection on the host PC.  See the
 * configNETWORK_INTERFACE_TO_USE definition for information on how to configure
 * the real network connection to use. */
uint8_t ucMACAddress[ 6 ] =
{
    configMAC_ADDR0,
    configMAC_ADDR1,
    configMAC_ADDR2,
    configMAC_ADDR3,
    configMAC_ADDR4,
    configMAC_ADDR5
};

/* The default IP and MAC address used by the demo.  The address configuration
 * defined here will be used if ipconfigUSE_DHCP is 0, or if ipconfigUSE_DHCP is
 * 1 but a DHCP server could not be contacted.  See the online documentation for
 * more information.  In both cases the node can be discovered using
 * "ping RTOSDemo". */
static const uint8_t ucIPAddress[ 4 ] =
{
    configIP_ADDR0,
    configIP_ADDR1,
    configIP_ADDR2,
    configIP_ADDR3
};
static const uint8_t ucNetMask[ 4 ] =
{
    configNET_MASK0,
    configNET_MASK1,
    configNET_MASK2,
    configNET_MASK3
};
static const uint8_t ucGatewayAddress[ 4 ] =
{
    configGATEWAY_ADDR0,
    configGATEWAY_ADDR1,
    configGATEWAY_ADDR2,
    configGATEWAY_ADDR3
};
static const uint8_t ucDNSServerAddress[ 4 ] =
{
    configDNS_SERVER_ADDR0,
    configDNS_SERVER_ADDR1,
    configDNS_SERVER_ADDR2,
    configDNS_SERVER_ADDR3
};

/**
 * @brief Application task startup hook.
 * Application task startup hook for applications using Wi-Fi.
 */
void vApplicationDaemonTaskStartupHook( void );

/**
 * @brief Connects to WiFi.
 */
static void prvWifiConnect( void );

/**
 * @brief Initializes the board.
 */
static void prvMiscInitialization( void );

static int32_t optiga_init(void);

//Infineon OPTIGA(TM) Trust X CA 101 certificate
//Certificate:
//    Data:
//        Version: 3 (0x2)
//        Serial Number: 1792794070 (0x6adbddd6)
//    Signature Algorithm: ecdsa-with-SHA384
//        Issuer: C=DE, O=Infineon Technologies AG, OU=OPTIGA(TM) Devices, CN=Infineon OPTIGA(TM) ECC Root CA
//        Validity
//            Not Before: Aug 29 16:27:08 2017 GMT
//            Not After : Aug 29 16:27:08 2042 GMT
//        Subject: C=DE, O=Infineon Technologies AG, OU=OPTIGA(TM), CN=Infineon OPTIGA(TM) Trust X CA 101
//        Subject Public Key Info:
//            Public Key Algorithm: id-ecPublicKey
//                Public-Key: (256 bit)
//                pub:
//                    04:60:d7:9d:39:60:fb:10:d4:28:89:09:56:4f:fd:
//                    a8:47:e2:22:fd:8d:3a:24:07:7b:38:0d:c3:70:4e:
//                    37:42:08:1b:33:c6:ec:47:d0:a8:fb:cf:ad:3f:dc:
//                    7c:6e:cd:94:7a:4c:1e:90:63:d0:7f:e4:20:a7:ab:
//                    14:d5:92:b6:c0
//                ASN1 OID: prime256v1
//                NIST CURVE: P-256
//        X509v3 extensions:
//            X509v3 Subject Key Identifier:
//                CA:05:33:D7:4F:C4:7F:09:49:FB:DB:12:25:DF:D7:97:9D:41:1E:15
//            X509v3 Key Usage: critical
//                Certificate Sign
//            X509v3 Basic Constraints: critical
//                CA:TRUE, pathlen:0
//            X509v3 Certificate Policies:
//                Policy: 1.2.276.0.68.1.20.1
//
//            X509v3 Authority Key Identifier:
//                keyid:B4:18:85:C8:4A:4A:C5:12:7A:F2:40:39:DE:C4:F5:8B:1E:7E:4A:D1
//
//    Signature Algorithm: ecdsa-with-SHA384
//         30:65:02:31:00:d2:21:49:c3:46:70:4b:16:85:9e:f2:92:6d:
//         0c:d2:b8:74:4f:dd:12:61:78:45:9b:54:31:d2:9d:50:4a:dd:
//         5c:fe:f7:54:12:b8:03:c2:11:21:95:53:fc:30:39:00:d6:02:
//         30:13:62:98:1f:e7:64:4c:89:ef:f0:e7:83:eb:71:5c:a1:ae:
//         47:f7:e7:fb:7e:70:a8:df:28:04:14:42:47:66:70:62:22:1d:
//         bf:f3:e6:b3:5e:23:cb:29:32:de:ea:b5:8e

//Infineon OPTIGA(TM) Trust X CA 101 certificate in HEX Format
uint8_t IFX_TRUSTX_CA101_Certificate_HEX[] = {
		0x30, 0x82, 0x02, 0x78, 0x30, 0x82, 0x01, 0xfe, 0xa0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x04, 0x6a,
		0xdb, 0xdd, 0xd6, 0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x03, 0x30,
		0x77, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x44, 0x45, 0x31, 0x21,
		0x30, 0x1f, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x0c, 0x18, 0x49, 0x6e, 0x66, 0x69, 0x6e, 0x65, 0x6f,
		0x6e, 0x20, 0x54, 0x65, 0x63, 0x68, 0x6e, 0x6f, 0x6c, 0x6f, 0x67, 0x69, 0x65, 0x73, 0x20, 0x41,
		0x47, 0x31, 0x1b, 0x30, 0x19, 0x06, 0x03, 0x55, 0x04, 0x0b, 0x0c, 0x12, 0x4f, 0x50, 0x54, 0x49,
		0x47, 0x41, 0x28, 0x54, 0x4d, 0x29, 0x20, 0x44, 0x65, 0x76, 0x69, 0x63, 0x65, 0x73, 0x31, 0x28,
		0x30, 0x26, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x1f, 0x49, 0x6e, 0x66, 0x69, 0x6e, 0x65, 0x6f,
		0x6e, 0x20, 0x4f, 0x50, 0x54, 0x49, 0x47, 0x41, 0x28, 0x54, 0x4d, 0x29, 0x20, 0x45, 0x43, 0x43,
		0x20, 0x52, 0x6f, 0x6f, 0x74, 0x20, 0x43, 0x41, 0x30, 0x1e, 0x17, 0x0d, 0x31, 0x37, 0x30, 0x38,
		0x32, 0x39, 0x31, 0x36, 0x32, 0x37, 0x30, 0x38, 0x5a, 0x17, 0x0d, 0x34, 0x32, 0x30, 0x38, 0x32,
		0x39, 0x31, 0x36, 0x32, 0x37, 0x30, 0x38, 0x5a, 0x30, 0x72, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03,
		0x55, 0x04, 0x06, 0x13, 0x02, 0x44, 0x45, 0x31, 0x21, 0x30, 0x1f, 0x06, 0x03, 0x55, 0x04, 0x0a,
		0x0c, 0x18, 0x49, 0x6e, 0x66, 0x69, 0x6e, 0x65, 0x6f, 0x6e, 0x20, 0x54, 0x65, 0x63, 0x68, 0x6e,
		0x6f, 0x6c, 0x6f, 0x67, 0x69, 0x65, 0x73, 0x20, 0x41, 0x47, 0x31, 0x13, 0x30, 0x11, 0x06, 0x03,
		0x55, 0x04, 0x0b, 0x0c, 0x0a, 0x4f, 0x50, 0x54, 0x49, 0x47, 0x41, 0x28, 0x54, 0x4d, 0x29, 0x31,
		0x2b, 0x30, 0x29, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x22, 0x49, 0x6e, 0x66, 0x69, 0x6e, 0x65,
		0x6f, 0x6e, 0x20, 0x4f, 0x50, 0x54, 0x49, 0x47, 0x41, 0x28, 0x54, 0x4d, 0x29, 0x20, 0x54, 0x72,
		0x75, 0x73, 0x74, 0x20, 0x58, 0x20, 0x43, 0x41, 0x20, 0x31, 0x30, 0x31, 0x30, 0x59, 0x30, 0x13,
		0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d,
		0x03, 0x01, 0x07, 0x03, 0x42, 0x00, 0x04, 0x60, 0xd7, 0x9d, 0x39, 0x60, 0xfb, 0x10, 0xd4, 0x28,
		0x89, 0x09, 0x56, 0x4f, 0xfd, 0xa8, 0x47, 0xe2, 0x22, 0xfd, 0x8d, 0x3a, 0x24, 0x07, 0x7b, 0x38,
		0x0d, 0xc3, 0x70, 0x4e, 0x37, 0x42, 0x08, 0x1b, 0x33, 0xc6, 0xec, 0x47, 0xd0, 0xa8, 0xfb, 0xcf,
		0xad, 0x3f, 0xdc, 0x7c, 0x6e, 0xcd, 0x94, 0x7a, 0x4c, 0x1e, 0x90, 0x63, 0xd0, 0x7f, 0xe4, 0x20,
		0xa7, 0xab, 0x14, 0xd5, 0x92, 0xb6, 0xc0, 0xa3, 0x7d, 0x30, 0x7b, 0x30, 0x1d, 0x06, 0x03, 0x55,
		0x1d, 0x0e, 0x04, 0x16, 0x04, 0x14, 0xca, 0x05, 0x33, 0xd7, 0x4f, 0xc4, 0x7f, 0x09, 0x49, 0xfb,
		0xdb, 0x12, 0x25, 0xdf, 0xd7, 0x97, 0x9d, 0x41, 0x1e, 0x15, 0x30, 0x0e, 0x06, 0x03, 0x55, 0x1d,
		0x0f, 0x01, 0x01, 0xff, 0x04, 0x04, 0x03, 0x02, 0x00, 0x04, 0x30, 0x12, 0x06, 0x03, 0x55, 0x1d,
		0x13, 0x01, 0x01, 0xff, 0x04, 0x08, 0x30, 0x06, 0x01, 0x01, 0xff, 0x02, 0x01, 0x00, 0x30, 0x15,
		0x06, 0x03, 0x55, 0x1d, 0x20, 0x04, 0x0e, 0x30, 0x0c, 0x30, 0x0a, 0x06, 0x08, 0x2a, 0x82, 0x14,
		0x00, 0x44, 0x01, 0x14, 0x01, 0x30, 0x1f, 0x06, 0x03, 0x55, 0x1d, 0x23, 0x04, 0x18, 0x30, 0x16,
		0x80, 0x14, 0xb4, 0x18, 0x85, 0xc8, 0x4a, 0x4a, 0xc5, 0x12, 0x7a, 0xf2, 0x40, 0x39, 0xde, 0xc4,
		0xf5, 0x8b, 0x1e, 0x7e, 0x4a, 0xd1, 0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04,
		0x03, 0x03, 0x03, 0x68, 0x00, 0x30, 0x65, 0x02, 0x31, 0x00, 0xd2, 0x21, 0x49, 0xc3, 0x46, 0x70,
		0x4b, 0x16, 0x85, 0x9e, 0xf2, 0x92, 0x6d, 0x0c, 0xd2, 0xb8, 0x74, 0x4f, 0xdd, 0x12, 0x61, 0x78,
		0x45, 0x9b, 0x54, 0x31, 0xd2, 0x9d, 0x50, 0x4a, 0xdd, 0x5c, 0xfe, 0xf7, 0x54, 0x12, 0xb8, 0x03,
		0xc2, 0x11, 0x21, 0x95, 0x53, 0xfc, 0x30, 0x39, 0x00, 0xd6, 0x02, 0x30, 0x13, 0x62, 0x98, 0x1f,
		0xe7, 0x64, 0x4c, 0x89, 0xef, 0xf0, 0xe7, 0x83, 0xeb, 0x71, 0x5c, 0xa1, 0xae, 0x47, 0xf7, 0xe7,
		0xfb, 0x7e, 0x70, 0xa8, 0xdf, 0x28, 0x04, 0x14, 0x42, 0x47, 0x66, 0x70, 0x62, 0x22, 0x1d, 0xbf,
		0xf3, 0xe6, 0xb3, 0x5e, 0x23, 0xcb, 0x29, 0x32, 0xde, 0xea, 0xb5, 0x8e
};

//Infineon OPTIGA(TM) Trust X CA 101 certificate in PEM format
char IFX_TRUSTX_CA101_Certificate_PEM[] =
"-----BEGIN CERTIFICATE-----\n"
"MIICeDCCAf6gAwIBAgIEatvd1jAKBggqhkjOPQQDAzB3MQswCQYDVQQGEwJERTEh\n"
"MB8GA1UECgwYSW5maW5lb24gVGVjaG5vbG9naWVzIEFHMRswGQYDVQQLDBJPUFRJ\n"
"R0EoVE0pIERldmljZXMxKDAmBgNVBAMMH0luZmluZW9uIE9QVElHQShUTSkgRUND\n"
"IFJvb3QgQ0EwHhcNMTcwODI5MTYyNzA4WhcNNDIwODI5MTYyNzA4WjByMQswCQYD\n"
"VQQGEwJERTEhMB8GA1UECgwYSW5maW5lb24gVGVjaG5vbG9naWVzIEFHMRMwEQYD\n"
"VQQLDApPUFRJR0EoVE0pMSswKQYDVQQDDCJJbmZpbmVvbiBPUFRJR0EoVE0pIFRy\n"
"dXN0IFggQ0EgMTAxMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEYNedOWD7ENQo\n"
"iQlWT/2oR+Ii/Y06JAd7OA3DcE43QggbM8bsR9Co+8+tP9x8bs2UekwekGPQf+Qg\n"
"p6sU1ZK2wKN9MHswHQYDVR0OBBYEFMoFM9dPxH8JSfvbEiXf15edQR4VMA4GA1Ud\n"
"DwEB/wQEAwIABDASBgNVHRMBAf8ECDAGAQH/AgEAMBUGA1UdIAQOMAwwCgYIKoIU\n"
"AEQBFAEwHwYDVR0jBBgwFoAUtBiFyEpKxRJ68kA53sT1ix5+StEwCgYIKoZIzj0E\n"
"AwMDaAAwZQIxANIhScNGcEsWhZ7ykm0M0rh0T90SYXhFm1Qx0p1QSt1c/vdUErgD\n"
"whEhlVP8MDkA1gIwE2KYH+dkTInv8OeD63Fcoa5H9+f7fnCo3ygEFEJHZnBiIh2/\n"
"8+azXiPLKTLe6rWO\n"
"-----END CERTIFICATE-----\n";

optiga_comms_t optiga_comms = {(void*)&ifx_i2c_context_0, NULL, NULL, 0};
static host_lib_status_t optiga_comms_status;

//GPIO 18 is used to control Trust X reset pin
#define GPIO_OUTPUT_IO_OTX_RST    18
#define GPIO_OUTPUT_PIN_SEL       (1ULL<<GPIO_OUTPUT_IO_OTX_RST)

/**
 * Initialization GPIO Reset pin for OPTIGA™ Trust X
 */
static void trustx_reset_gpio_init()
{
	//printf(">trustx_reset_gpio_init()\r\n");
	gpio_pad_select_gpio(GPIO_OUTPUT_IO_OTX_RST);
	/* Set the GPIO as a push/pull output */
	gpio_set_direction(GPIO_OUTPUT_IO_OTX_RST, GPIO_MODE_OUTPUT);
	//printf("<trustx_reset_gpio_init()\r\n");
}

/**
 * OPTIGA™ Trust X comms handler
 */
static void optiga_comms_event_handler(void* upper_layer_ctx, host_lib_status_t event)
{
    optiga_comms_status = event;
}

/**
 * OPTIGA™ Trust X initialization
 */
static int32_t optiga_init(void)
{
	int32_t status = (int32_t) OPTIGA_LIB_ERROR;

	printf(">optiga_init()\r\n");

	do
	{
		if (pal_os_event_init() == PAL_STATUS_FAILURE)
		{
			return OPTIGA_COMMS_BUSY;
		}

		//Invoke optiga_comms_open to initialize the IFX I2C Protocol and security chip
		optiga_comms_status = OPTIGA_COMMS_BUSY;
		optiga_comms.upper_layer_handler = optiga_comms_event_handler;
		status = optiga_comms_open(&optiga_comms);
		if(E_COMMS_SUCCESS != status)
		{
			configPRINTF( ("Failure: optiga_comms_open(): 0x%04X\n\r", status) );
			break;
		}

		printf("optiga_init() wait for IFX initialization to complete\r\n");

		//Wait until IFX I2C initialization is complete
		while(optiga_comms_status == OPTIGA_COMMS_BUSY)
		{
			pal_os_timer_delay_in_milliseconds(5);
		}

		printf("optiga_init() wait for IFX initialization to completed\r\n");

		if((OPTIGA_COMMS_SUCCESS != status) || (optiga_comms_status == OPTIGA_COMMS_ERROR))
		{
			configPRINTF( ("Failure: optiga_comms_status(): 0x%04X\n\r", status) );
			break;
		}

		printf("optiga_init() open application.w\r\n");

		status = optiga_util_open_application(&optiga_comms);
		if(OPTIGA_LIB_SUCCESS != status)
		{
			configPRINTF( ("Failure: CmdLib_OpenApplication(): 0x%04X\n\r", status) );
			break;
		}

		status = OPTIGA_LIB_SUCCESS;
	} while(0);

	printf("<optiga_init()\r\n\n");

	//Stop
	configPRINTF( ("Halt after Open Application()\n\r") );
	while(1);

	return status;
}

/**
 * Helper routine to convert signature format
*/
optiga_lib_status_t asn1_to_ecdsa_rs(const uint8_t * asn1, size_t asn1_len,
									 uint8_t * rs, size_t * rs_len)
{
	optiga_lib_status_t return_status = OPTIGA_LIB_ERROR;
	const uint8_t * cur = asn1;
	// points to first invalid mem-location
	const uint8_t * end = asn1 + asn1_len;

	do {
		if(asn1 == NULL || rs == NULL || rs_len == NULL) {
			break;
		}

		if(asn1_len == 0 || *rs_len == 0) {
			break;
		}

		if(*cur != 0x02) {
			// wrong tag type
			break;
		}

		if((cur + 2) >= end) {
			// prevented out-of-bounds read
			break;
		}

		// move to length value
		cur++;
		uint8_t r_len = *cur;

		// move to first data value
		cur++;

		// check for stuffing bits
		if(*cur == 0x00) {
			cur++;
			r_len--;
		}

		// check for out-of-bounds read
		if((cur + r_len) >= end) {
			// prevented out-of-bounds read
			break;
		}
		// check for out-of-bounds write
		if((rs + r_len) > (rs + *rs_len)) {
			// prevented out-of-bounds write
			break;
		}

		// copy R component to output
		memcpy(rs, cur, r_len);

		// move to next tag
		cur += r_len;

		if(*cur != 0x02) {
			// wrong tag type
			break;
		}

		if((cur + 2) >= end) {
			// prevented out-of-bounds read
			break;
		}
		cur++;
		uint8_t s_len = *cur;
		cur++;

		if(*cur == 0x00) {
			cur++;
			s_len--;
		}

		// check for out-of-bounds read
		if((cur + s_len) > end) {
			// prevented out-of-bounds read
			break;
		}
		// check for out-of-bounds write
		if((rs + r_len + s_len) > (rs + *rs_len)) {
			// prevented out-of-bounds write
			break;
		}

		memcpy(rs + r_len, cur, s_len);

		return_status = OPTIGA_LIB_SUCCESS;

	}while(FALSE);


    return return_status;
}

// Maximum size of the signature (for P256 0x40)
#define LENGTH_MAX_SIGNATURE				0x40

mbedtls_entropy_context 					entropy;
mbedtls_ctr_drbg_context 					ctr_drbg;

/**
 * Verifies the ECC signature using the given public key.
 */
static int32_t crypt_verify_ecc_signature(const uint8_t* p_pubkey, uint16_t pubkey_size,
                                      const uint8_t* p_signature, uint16_t signature_size,
                                      uint8_t* p_digest, uint16_t digest_size)
{
    int32_t  status = CRYPTO_LIB_VERIFY_SIGN_FAIL;
    uint8_t   signature_rs[LENGTH_MAX_SIGNATURE];
    size_t    signature_rs_size = LENGTH_MAX_SIGNATURE;
    const uint8_t* p_pk = p_pubkey;

    mbedtls_ecp_group grp;
    // Public Key
    mbedtls_ecp_point Q;
    mbedtls_mpi r;
    mbedtls_mpi s;

    mbedtls_ecp_point_init( &Q );
    mbedtls_mpi_init( &r );
    mbedtls_mpi_init( &s );
    mbedtls_ecp_group_init( &grp );

    mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_SECP256R1);

    //printf(">crypt_verify_ecc_signature()\r\n");

    do
    {
        if((NULL == p_pubkey)||(NULL == p_digest)||(NULL == p_signature))
        {
            status = CRYPTO_LIB_NULL_PARAM;
            break;
        }

        //Import the public key
        mbedtls_ecp_point_read_binary(&grp, &Q, p_pk, pubkey_size);

        //Import the signature
        asn1_to_ecdsa_rs(p_signature, signature_size, signature_rs, &signature_rs_size);
        mbedtls_mpi_read_binary(&r, signature_rs, LENGTH_MAX_SIGNATURE/2);
        mbedtls_mpi_read_binary(&s, signature_rs + LENGTH_MAX_SIGNATURE/2, LENGTH_MAX_SIGNATURE/2);

        //Verify generated hash with given public key
        status = mbedtls_ecdsa_verify(&grp, p_digest, digest_size, &Q, &r, &s);

        //printf("mbedtls_ecdsa_verify status: 0x%x\r\n",status);

        if ( 0 != status)
        {
            status = CRYPTO_LIB_VERIFY_SIGN_FAIL;
            printf("crypt_verify_ecc_signature(): failed verification\r\n");
            break;
        }else{
        status = CRYPTO_LIB_OK;
        }

    }while(FALSE);

    //printf("<crypt_verify_ecc_signature()\r\n");

    return status;
}

/**
* Retrieves an Trust X public key from the End Device Certificate
*
*/
optiga_lib_status_t crypt_get_public_key(const uint8_t* p_cert, uint16_t cert_size,
		                                 uint8_t* p_pubkey, uint16_t* p_pubkey_size)
{
    int32_t status  = (int32_t)CRYPTO_LIB_ERROR;
    int32_t ret;
    mbedtls_x509_crt mbedtls_cert;
    size_t pubkey_size = 0;
    // We know, that we will work with ECC
    mbedtls_ecp_keypair * mbedtls_keypair = NULL;

    do
    {
        if((NULL == p_cert) || (NULL == p_pubkey) || (NULL == p_pubkey_size))
        {
        	status = (int32_t)CRYPTO_LIB_NULL_PARAM;
            break;
        }

        //Check for length equal to zero
        if( (0 == cert_size) || (0 == *p_pubkey_size))
        {
        	status = (int32_t)CRYPTO_LIB_LENZERO_ERROR;
            break;
        }

        //Initialise certificates
        mbedtls_x509_crt_init(&mbedtls_cert);


        if ( (ret = mbedtls_x509_crt_parse_der(&mbedtls_cert, p_cert, cert_size)) != 0 )
		{
			status = (int32_t)CRYPTO_LIB_CERT_PARSE_FAIL;
			break;
		}

        mbedtls_keypair = (mbedtls_ecp_keypair* )mbedtls_cert.pk.pk_ctx;
        if ( (ret = mbedtls_ecp_point_write_binary(&mbedtls_keypair->grp, &mbedtls_keypair->Q,
        		                                   MBEDTLS_ECP_PF_UNCOMPRESSED, &pubkey_size,
												   p_pubkey, *p_pubkey_size)) != 0 )
        {
			status = (int32_t)CRYPTO_LIB_CERT_PARSE_FAIL;
			break;
        }
        *p_pubkey_size = pubkey_size;

        status =   CRYPTO_LIB_OK;
    }while(FALSE);

    return status;
}

/**
* Retrieves an End Device Certificate stored in OPTIGA™ Trust X
*
*/
///size of end entity certificate of OPTIGA™ Trust X
#define LENGTH_OPTIGA_CERT          512

static optiga_lib_status_t read_end_device_cert(uint16_t cert_oid,
		                                        uint8_t* p_cert, uint16_t* p_cert_size)
{
	int32_t status  = (int32_t)OPTIGA_LIB_ERROR;
	// We might need to modify a certificate buffer pointer
	uint8_t tmp_cert[LENGTH_OPTIGA_CERT];
	uint8_t* p_tmp_cert_pointer = tmp_cert;

	do
	{
		// Sanity check
		if ((NULL == p_cert) || (NULL == p_cert_size) ||
			(0 == cert_oid) || (0 == *p_cert_size))
		{
			break;
		}

		//Get end entity device certificate
		status = optiga_util_read_data(cert_oid, 0, p_tmp_cert_pointer, p_cert_size);
		if(OPTIGA_LIB_SUCCESS != status)
		{
			break;
		}

		// Refer to the Solution Reference Manual (SRM) v1.35 Table 30. Certificate Types
		switch (p_tmp_cert_pointer[0])
		{
		/* One-Way Authentication Identity. Certificate DER coded The first byte
		*  of the DER encoded certificate is 0x30 and is used as Tag to differentiate
		*  from other Public Key Certificate formats defined below.
		*/
		case 0x30:
			/* The certificate can be directly used */
			status = OPTIGA_LIB_SUCCESS;
			break;
		/* TLS Identity. Tag = 0xC0; Length = Value length (2 Bytes); Value = Certificate Chain
		 * Format of a "Certificate Structure Message" used in TLS Handshake
		 */
		case 0xC0:
			/* There might be a certificate chain encoded.
			 * For this example we will consider only one certificate in the chain
			 */
			p_tmp_cert_pointer = p_tmp_cert_pointer + 9;
			*p_cert_size = *p_cert_size - 9;
			memcpy(p_cert, p_tmp_cert_pointer, *p_cert_size);
			status = OPTIGA_LIB_SUCCESS;
			break;
		/* USB Type-C identity
		 * Tag = 0xC2; Length = Value length (2 Bytes); Value = USB Type-C Certificate Chain [USB Auth].
		 * Format as defined in Section 3.2 of the USB Type-C Authentication Specification (SRM)
		 */
		case 0xC2:
		// Not supported for this example
		// Certificate type isn't supported or a wrong tag
		default:
			break;
		}

	}while(FALSE);

	return status;
}

/**
* Verifies the end device certificate using RootCA certificate
*
*/
optiga_lib_status_t  crypt_verify_certificate(const uint8_t* p_cacert,
		                                      uint16_t cacert_size,
		                                      const uint8_t* p_cert,
											  uint16_t cert_size)
{
    int32_t status  = (int32_t)CRYPTO_LIB_ERROR;
    int32_t ret;
    mbedtls_x509_crt mbedtls_cert;
    mbedtls_x509_crt mbedtls_cacert;
    uint32_t mbedtls_flags;

    do
    {
        if((NULL == p_cacert) || (NULL == p_cert) )
        {
        	status = (int32_t)CRYPTO_LIB_NULL_PARAM;
            break;
        }

        //Check for length equal to zero
        if( (0 == cacert_size) || (0 == cert_size) )
        {
        	status = (int32_t)CRYPTO_LIB_LENZERO_ERROR;
            break;
        }

        //Initialise certificates
        mbedtls_x509_crt_init(&mbedtls_cacert);
        mbedtls_x509_crt_init(&mbedtls_cert);

        printf("Parsing IFX CA certificate... ");
#if 0
        //Decode the CA DER format
        if ( (ret = mbedtls_x509_crt_parse_der(&mbedtls_cacert, p_cacert, cacert_size)) != 0 )
		{
        	printf("Unable to to parse the CA DER certificate \r\n");
        	printf("size=%d \r\n",cacert_size);
        	printf("ret = 0x%x \r\n",ret);
			status = (int32_t)CRYPTO_LIB_CERT_PARSE_FAIL;
			break;
		}
#else
        //Decode the CA PEM format
        if ( (ret = mbedtls_x509_crt_parse(&mbedtls_cacert, (const uint8_t*)IFX_TRUSTX_CA101_Certificate_PEM, sizeof(IFX_TRUSTX_CA101_Certificate_PEM))) != 0 )
		{
        	printf("Unable to to parse the CA PEM certificate \r\n");
        	printf("size=%d \r\n",cacert_size);
        	printf("ret = 0x%x \r\n\n",ret);
			status = (int32_t)CRYPTO_LIB_CERT_PARSE_FAIL;
			break;
		}else{
			printf("ok\r\n");
		}
#endif
        printf("Parsing device certificate... ");
        if ( (ret = mbedtls_x509_crt_parse_der(&mbedtls_cert, p_cert, cert_size)) != 0 )
		{
        	printf("Unable to to parse the device certificate \r\n");
			status = (int32_t)CRYPTO_LIB_CERT_PARSE_FAIL;
			break;
		}else{
			printf("ok\r\n");
		}

        printf("Verifying certificate chain... ");
        if( ( ret = mbedtls_x509_crt_verify( &mbedtls_cert, &mbedtls_cacert,
        		                             NULL, NULL, &mbedtls_flags,
                                             NULL, NULL ) ) != 0 )
		{
        	printf("fail to mbedtls_x509_crt_verify \r\n");
        	status = (int32_t)CRYPTO_LIB_VERIFY_SIGN_FAIL;
			break;
		}else{
			printf("ok\r\n");
		}

        status =   CRYPTO_LIB_OK;
    }while(FALSE);

    return status;
}

///Length of R and S vector
#define LENGTH_RS_VECTOR            0x40

///Length of maximum additional bytes to encode sign in DER
#define MAXLENGTH_SIGN_ENCODE       0x06
///Length of Signature
#define LENGTH_SIGNATURE            (LENGTH_RS_VECTOR + MAXLENGTH_SIGN_ENCODE)

/**
 * Application runtime entry point.
 */
int app_main( void )
{
	//mbedtls_x509_crt x509_certificate;
	//mbedtls_ecdsa_context   ecdsa_context;
	//mbedtls_ecp_keypair    *ecp_keypair;
	int result;
	
	printf(">app_main()\r\n");
	
    /* Perform any hardware initialization that does not require the RTOS to be
     * running.  */
    prvMiscInitialization();
    
	/* Create tasks that are not dependent on the WiFi being initialized. */
    xLoggingTaskInitialize( mainLOGGING_TASK_STACK_SIZE,
							tskIDLE_PRIORITY + 5,
							mainLOGGING_MESSAGE_QUEUE_LENGTH );
    FreeRTOS_IPInit( ucIPAddress,
            ucNetMask,
            ucGatewayAddress,
            ucDNSServerAddress,
            ucMACAddress );

    /* Start the scheduler.  Initialization that requires the OS to be running,
     * including the WiFi initialization, is performed in the RTOS daemon task
     * startup hook. */
    // Following is taken care by initialization code in ESP IDF
    // vTaskStartScheduler();

    if( SYSTEM_Init() == pdPASS )
	{

    	/* Connect to the wifi before running the demos */
        //prvWifiConnect();
        /* Run all demos. */
        //DEMO_RUNNER_RunDemos();
    }
	ESP_ERROR_CHECK( optiga_init() );


	printf( "Boosting the OPTIGA Trust X performance..\r\n");
	// 15mA is the maximum, 6 is the minimum
	uint8_t current_value = 15;
	ESP_ERROR_CHECK( optiga_util_write_data(eCURRENT_LIMITATION, OPTIGA_UTIL_ERASE_AND_WRITE, 0, &current_value, 1) );

	uint8_t UID[27];
	uint16_t  UID_length = 27;
	printf("Trust X UID:\r\n");
	ESP_ERROR_CHECK( optiga_util_read_data(eCOPROCESSOR_UID, 0, UID, &UID_length));
	for(int x=0; x<27;)
	{
		if(x!=24){
			printf("%.2x %.2x %.2x %.2x\n", UID[x], UID[x+1], UID[x+2], UID[x+3]);
		}
		else{
			printf("%.2x %.2x %.2x\n", UID[x], UID[x+1], UID[x+2]);

		}
		x+=4;
	}

	uint16_t  random_data_length = 16;
	uint8_t random_data[random_data_length];

	ESP_ERROR_CHECK( optiga_crypt_random( OPTIGA_RNG_TYPE_TRNG,
	                                      random_data,
	                                      random_data_length));

	printf("OPTIGA Trust X generated DRNG random number: \r\n");
	for(int i=0; i<random_data_length-1;)
	{
		printf("%.2x %.2x %.2x %.2x\n", random_data[i], random_data[i+1], random_data[i+2], random_data[i+3]);
		i+=4;
	}

	uint8_t sign_digest[32]; // Stores a SHA-256 hash digest of 256 bits = 32 Byte
    // Calculate the SHA-256 hash digest from the to-be-signed data
    mbedtls_sha256(random_data, sizeof(random_data), sign_digest, 0);

	printf("Data Digest:\r\n");
	for(int i=0; i<32;)
	{
		printf("%.2x %.2x %.2x %.2x\n", sign_digest[i], sign_digest[i+1], sign_digest[i+2], sign_digest[i+3]);
		i+=4;
	}

	uint8_t     signature[LENGTH_SIGNATURE];
	uint16_t     signature_len=LENGTH_SIGNATURE;

	result = optiga_crypt_ecdsa_sign(sign_digest, sizeof(sign_digest), eFIRST_DEVICE_PRIKEY_1, signature, &signature_len);
	if(result==OPTIGA_LIB_ERROR){
		printf("Unable to sign data using Trust X.\r\n");
	}
	printf("Trust X signature:\r\n");
	printf("Signature length = %d.\r\n", signature_len);
	for(int i=0; i<signature_len;)
	{
		printf("%.2x %.2x %.2x %.2x\n", signature[i], signature[i+1], signature[i+2], signature[i+3]);
		i+=4;
	}

	uint32_t status=0;

	///size of end entity certificate of OPTIGA™ Trust X
	#define LENGTH_OPTIGA_CERT          512
	///size of public key for NIST-P256
	#define LENGTH_PUB_KEY_NISTP256     0x41

	uint8_t chip_cert[LENGTH_OPTIGA_CERT];
	uint16_t chip_cert_size = LENGTH_OPTIGA_CERT;
	uint8_t chip_pubkey[LENGTH_PUB_KEY_NISTP256];
	uint16_t chip_pubkey_size = LENGTH_PUB_KEY_NISTP256;
	uint16_t chip_cert_oid = eDEVICE_PUBKEY_CERT_IFX;
	//uint16_t chip_privkey_oid = eFIRST_DEVICE_PRIKEY_1;

	// Retrieve a Certificate of the security chip
	status = read_end_device_cert(chip_cert_oid, chip_cert, &chip_cert_size);
	if (status !=0)
	{
		printf("Error getting certificate\r\n");
	}

	// Verify End device certificate against the Root CA
	printf("Verify end device certificate against Root CA...\r\n");
	status = crypt_verify_certificate(IFX_TRUSTX_CA101_Certificate_HEX, sizeof(IFX_TRUSTX_CA101_Certificate_HEX), chip_cert, chip_cert_size);
	if(CRYPTO_LIB_OK != status){
		printf("Error unable to verify end device certificate status=0x%x\r\n", status);
	}else{
		printf("Verified End device certificate against the Root CA.\r\n");
	}


	printf("Extract Public key from the certificate...\r\n");
	// Extract Public Key from the certificate
    status = crypt_get_public_key(chip_cert, chip_cert_size, chip_pubkey, &chip_pubkey_size);

	printf("Public Key Size:%d\r\n", chip_pubkey_size);
	printf("Trust X Public Key:\r\n");
	for(int i=0; i<chip_pubkey_size;)
	{
		printf("%.2x %.2x %.2x %.2x\n", chip_pubkey[i], chip_pubkey[i+1], chip_pubkey[i+2], chip_pubkey[i+3]);
		i+=4;
	}

	status = crypt_verify_ecc_signature(chip_pubkey,
			                        chip_pubkey_size,
									signature,
									signature_len,
									sign_digest,
									sizeof(sign_digest));

	if(status!=0){
		printf("Failed to verify signature \r\n");
	}else{
		printf("\r\nSignature is Ok.\r\n");
	}


	printf("<app_main()\r\n");
    return 0;
}

/*-----------------------------------------------------------*/

static void prvMiscInitialization( void )
{
	//printf(">prvMiscInitialization()\r\n");

	// Initialize NVS
	esp_err_t ret = nvs_flash_init();
	if (ret == ESP_ERR_NVS_NO_FREE_PAGES) {
		ESP_ERROR_CHECK(nvs_flash_erase());
		ret = nvs_flash_init();
	}
	
	trustx_reset_gpio_init();
	
	//printf("<prvMiscInitialization()\r\n");

	ESP_ERROR_CHECK( ret );
}
/*-----------------------------------------------------------*/

void vApplicationDaemonTaskStartupHook( void )
{}
/*-----------------------------------------------------------*/

void prvWifiConnect( void )
{
	printf(">prvWifiConnect()\r\n");

    WIFINetworkParams_t xNetworkParams;
    WIFIReturnCode_t xWifiStatus;

    xWifiStatus = WIFI_On();

    if( xWifiStatus == eWiFiSuccess )
    {
        configPRINTF( ( "WiFi module initialized. Connecting to AP %s...\r\n", clientcredentialWIFI_SSID ) );
    }
    else
    {
        configPRINTF( ( "WiFi module failed to initialize.\r\n" ) );

        while( 1 )
        {
        }
    }

    /* Setup parameters. */
    xNetworkParams.pcSSID = clientcredentialWIFI_SSID;
    xNetworkParams.ucSSIDLength = sizeof( clientcredentialWIFI_SSID );
    xNetworkParams.pcPassword = clientcredentialWIFI_PASSWORD;
    xNetworkParams.ucPasswordLength = sizeof( clientcredentialWIFI_PASSWORD );
    xNetworkParams.xSecurity = clientcredentialWIFI_SECURITY;

    xWifiStatus = WIFI_ConnectAP( &( xNetworkParams ) );

    if( xWifiStatus == eWiFiSuccess )
    {
        configPRINTF( ( "WiFi Connected to AP. Creating tasks which use network...\r\n" ) );

    }
    else
    {
        configPRINTF( ( "WiFi failed to connect to AP.\r\n" ) );
configPRINTF( ( "\r\nSYSTEM HALT !!!!!!!!!!!\r\n" ) );

        portDISABLE_INTERRUPTS();
        while( 1 )
        {
        }
    }
    printf("<prvWifiConnect()\r\n");
}
/*-----------------------------------------------------------*/
/* configUSE_STATIC_ALLOCATION is set to 1, so the application must provide an
 * implementation of vApplicationGetIdleTaskMemory() to provide the memory that is
 * used by the Idle task. */
void vApplicationGetIdleTaskMemory( StaticTask_t ** ppxIdleTaskTCBBuffer,
                                    StackType_t ** ppxIdleTaskStackBuffer,
                                    uint32_t * pulIdleTaskStackSize )
{
/* If the buffers to be provided to the Idle task are declared inside this
 * function then they must be declared static - otherwise they will be allocated on
 * the stack and so not exists after this function exits. */
    static StaticTask_t xIdleTaskTCB;
    static StackType_t uxIdleTaskStack[ configIDLE_TASK_STACK_SIZE ];

    /* Pass out a pointer to the StaticTask_t structure in which the Idle
     * task's state will be stored. */
    *ppxIdleTaskTCBBuffer = &xIdleTaskTCB;

    /* Pass out the array that will be used as the Idle task's stack. */
    *ppxIdleTaskStackBuffer = uxIdleTaskStack;

    /* Pass out the size of the array pointed to by *ppxIdleTaskStackBuffer.
     * Note that, as the array is necessarily of type StackType_t,
     * configMINIMAL_STACK_SIZE is specified in words, not bytes. */
    *pulIdleTaskStackSize = configIDLE_TASK_STACK_SIZE;
}
/*-----------------------------------------------------------*/

/* configUSE_STATIC_ALLOCATION is set to 1, so the application must provide an
 * implementation of vApplicationGetTimerTaskMemory() to provide the memory that is
 * used by the RTOS daemon/time task. */
void vApplicationGetTimerTaskMemory( StaticTask_t ** ppxTimerTaskTCBBuffer,
                                     StackType_t ** ppxTimerTaskStackBuffer,
                                     uint32_t * pulTimerTaskStackSize )
{
/* If the buffers to be provided to the Timer task are declared inside this
 * function then they must be declared static - otherwise they will be allocated on
 * the stack and so not exists after this function exits. */
    static StaticTask_t xTimerTaskTCB;
    static StackType_t uxTimerTaskStack[ configTIMER_TASK_STACK_DEPTH ];

    /* Pass out a pointer to the StaticTask_t structure in which the Idle
     * task's state will be stored. */
    *ppxTimerTaskTCBBuffer = &xTimerTaskTCB;

    /* Pass out the array that will be used as the Timer task's stack. */
    *ppxTimerTaskStackBuffer = uxTimerTaskStack;

    /* Pass out the size of the array pointed to by *ppxTimerTaskStackBuffer.
     * Note that, as the array is necessarily of type StackType_t,
     * configMINIMAL_STACK_SIZE is specified in words, not bytes. */
    *pulTimerTaskStackSize = configTIMER_TASK_STACK_DEPTH;
}
/*-----------------------------------------------------------*/

#if ( ipconfigUSE_LLMNR != 0 ) || ( ipconfigUSE_NBNS != 0 ) || ( ipconfigDHCP_REGISTER_HOSTNAME == 1 )

const char * pcApplicationHostnameHook( void )
{
    /* This function will be called during the DHCP: the machine will be registered 
     * with an IP address plus this name. */
    return clientcredentialIOT_THING_NAME;
}

#endif
/*-----------------------------------------------------------*/

#if ( ipconfigUSE_LLMNR != 0 ) || ( ipconfigUSE_NBNS != 0 )

BaseType_t xApplicationDNSQueryHook( const char * pcName )
{
    BaseType_t xReturn;

    /* Determine if a name lookup is for this node.  Two names are given
     * to this node: that returned by pcApplicationHostnameHook() and that set
     * by mainDEVICE_NICK_NAME. */
    if( strcmp( pcName, pcApplicationHostnameHook() ) == 0 )
    {
        xReturn = pdPASS;
    }
    else if( strcmp( pcName, mainDEVICE_NICK_NAME ) == 0 )
    {
        xReturn = pdPASS;
    }
    else
    {
        xReturn = pdFAIL;
    }

    return xReturn;
}

#endif /* if ( ipconfigUSE_LLMNR != 0 ) || ( ipconfigUSE_NBNS != 0 ) */
/*-----------------------------------------------------------*/

/**
 * @brief Warn user if pvPortMalloc fails.
 *
 * Called if a call to pvPortMalloc() fails because there is insufficient
 * free memory available in the FreeRTOS heap.  pvPortMalloc() is called
 * internally by FreeRTOS API functions that create tasks, queues, software
 * timers, and semaphores.  The size of the FreeRTOS heap is set by the
 * configTOTAL_HEAP_SIZE configuration constant in FreeRTOSConfig.h.
 *
 */
void vApplicationMallocFailedHook()
{
    configPRINTF( ( "ERROR: Malloc failed to allocate memory\r\n" ) );
}
/*-----------------------------------------------------------*/

/**
 * @brief Loop forever if stack overflow is detected.
 *
 * If configCHECK_FOR_STACK_OVERFLOW is set to 1,
 * this hook provides a location for applications to
 * define a response to a stack overflow.
 *
 * Use this hook to help identify that a stack overflow
 * has occurred.
 *
 */
void vApplicationStackOverflowHook( TaskHandle_t xTask,
                                    char * pcTaskName )
{
    configPRINTF( ( "ERROR: stack overflow with task %s\r\n", pcTaskName ) );
    portDISABLE_INTERRUPTS();

    /* Loop forever */
    for( ; ; )
    {
    }
}
/*-----------------------------------------------------------*/
extern void esp_vApplicationTickHook();
void IRAM_ATTR vApplicationTickHook()
{
    esp_vApplicationTickHook();
}

/*-----------------------------------------------------------*/
extern void esp_vApplicationIdleHook();
void vApplicationIdleHook()
{
    esp_vApplicationIdleHook();
}

/*-----------------------------------------------------------*/
void vApplicationIPNetworkEventHook( eIPCallbackEvent_t eNetworkEvent )
{
    uint32_t ulIPAddress, ulNetMask, ulGatewayAddress, ulDNSServerAddress;
    system_event_t evt;

    if (eNetworkEvent == eNetworkUp) {
        /* Print out the network configuration, which may have come from a DHCP
         * server. */
        FreeRTOS_GetAddressConfiguration(
                &ulIPAddress,
                &ulNetMask,
                &ulGatewayAddress,
                &ulDNSServerAddress );

        evt.event_id = SYSTEM_EVENT_STA_GOT_IP;
        evt.event_info.got_ip.ip_changed = true;
        evt.event_info.got_ip.ip_info.ip.addr = ulIPAddress;
        evt.event_info.got_ip.ip_info.netmask.addr = ulNetMask;
        evt.event_info.got_ip.ip_info.gw.addr = ulGatewayAddress;
        esp_event_send(&evt);
    }
}
