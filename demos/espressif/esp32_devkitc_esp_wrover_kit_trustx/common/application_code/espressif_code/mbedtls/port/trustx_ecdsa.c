#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/esp_config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#if defined(MBEDTLS_ECDSA_C)

#include "mbedtls/ecdsa.h"
#include "mbedtls/asn1write.h"
#include "mbedtls/pk.h"

#include <string.h>


#include "optiga/optiga_crypt.h"
#include "optiga/optiga_util.h"

#define LOG_LOCAL_LEVEL ESP_LOG_VERBOSE
#include "esp_log.h"

static const char* TAG = "ECDSA_TRUSTX";

#if defined(MBEDTLS_ECDSA_SIGN_ALT)


int mbedtls_ecdsa_sign( mbedtls_ecp_group *grp, mbedtls_mpi *r, mbedtls_mpi *s,
                const mbedtls_mpi *d, const unsigned char *buf, size_t blen,
                int (*f_rng)(void *, unsigned char *, size_t), void *p_rng )
{
	int ret;
	uint8_t der_signature[110];
	uint16_t dslen = sizeof(der_signature);
	uint8_t rlen = 0;
	uint8_t slen = 0;
	uint8_t rslen = 32;
    unsigned char *p = der_signature;
    const unsigned char *end = der_signature + dslen;

	ESP_LOGI(TAG, "+++++++++++++entering mbedtls_ecdsa_sign++++++++++++++++");

	ESP_LOGI(TAG, "To be signed");
	esp_log_buffer_hex("trustx_ecdsa", buf, blen);

    if(optiga_crypt_ecdsa_sign((unsigned char *)buf, blen, OPTIGA_KEY_STORE_ID_E0F0, der_signature, &dslen) != OPTIGA_LIB_SUCCESS)
    {
        ESP_LOGE(TAG, "Failed to get the signature from optiga_calc_sign" );
    	ret = MBEDTLS_ERR_PK_BAD_INPUT_DATA;
		goto cleanup;
    }

	ESP_LOGI(TAG, "DER encoded signature");
	esp_log_buffer_hex("trustx_ecdsa", der_signature, dslen);
	
	MBEDTLS_MPI_CHK( mbedtls_asn1_get_mpi( &p, end, r ) );
	MBEDTLS_MPI_CHK( mbedtls_asn1_get_mpi( &p, end, s ) );

	ESP_LOGI(TAG, "+++++++++++++leaving mbedtls_ecdsa_sign++++++++++++++++");
	
cleanup:
    return ret;
}
#endif


#if defined(MBEDTLS_ECDSA_VERIFY_ALT)
#include "optiga/pal/pal.h"
#include "optiga/pal/pal_os_timer.h"
int mbedtls_ecdsa_verify( mbedtls_ecp_group *grp,
                  const unsigned char *buf, size_t blen,
                  const mbedtls_ecp_point *Q, const mbedtls_mpi *r, const mbedtls_mpi *s)
{
	int ret;
	optiga_lib_status_t status = OPTIGA_LIB_ERROR;
    public_key_from_host_t public_key;
    uint8_t public_key_out [100];
	uint8_t signature [110];
    uint8_t *p = signature + sizeof(signature);
	size_t  signature_len = 0;
	size_t public_key_len = 0;
	uint8_t truncated_hash_length;
	
	ESP_LOGI(TAG, "+++++++++++++entering mbedtls_ecdsa_verify++++++++++++++++");

	signature_len = mbedtls_asn1_write_mpi( &p, signature, s );
    signature_len+= mbedtls_asn1_write_mpi( &p, signature, r );
	
    public_key.public_key = public_key_out;
	public_key.length     = sizeof( public_key_out );

	if (mbedtls_ecp_point_write_binary( grp, Q,
                                        MBEDTLS_ECP_PF_UNCOMPRESSED, &public_key_len,
                                        &public_key_out[3], sizeof( public_key_out ) ) != 0 )
    {
        return 1;
    }

    if ( ( grp->id !=  MBEDTLS_ECP_DP_SECP256R1 ) && 
         ( grp->id  != MBEDTLS_ECP_DP_SECP384R1 ) )
    {
        return 1;
    }

    grp->id == MBEDTLS_ECP_DP_SECP256R1 ? ( public_key.curve = OPTIGA_ECC_NIST_P_256 )
                                            : ( public_key.curve = OPTIGA_ECC_NIST_P_384 );

    public_key_out [0] = 0x03;
    public_key_out [1] = public_key_len + 1;
    public_key_out [2] = 0x00;
    public_key.length = public_key_len + 3;//including 3 bytes overhead

    if ( public_key.curve == OPTIGA_ECC_NIST_P_256 )
    {
        truncated_hash_length = 32; //maximum bytes of hash length for the curve
    }
    else
    {
        truncated_hash_length = 48; //maximum bytes of hash length for the curve
    }

    // If the length of the digest is larger than 
    // key length of the group order, then truncate the digest to key length.
    if ( blen > truncated_hash_length )
    {
        blen = truncated_hash_length;
    }

	ESP_LOGI(TAG, "+++++++++++++signature++++++++++++++++");
	esp_log_buffer_hex(TAG, p, signature_len);
	
	ESP_LOGI(TAG, "+++++++++++++digest++++++++++++++++");
	esp_log_buffer_hex(TAG, buf, blen);
	
	ESP_LOGI(TAG, "+++++++++++++public key++++++++++++++++");
	esp_log_buffer_hex(TAG, public_key.public_key, public_key.length);
	
    status = optiga_crypt_ecdsa_verify ( (uint8_t *) buf, blen,
                                         (uint8_t *) p, signature_len,
                                        0, (void *)&public_key );

    ESP_LOGI(TAG, "+++++++++++++leaving mbedtls_ecdsa_verify++++++++++++++++");

    if ( status != OPTIGA_LIB_SUCCESS )
    {
    	ESP_LOGI(TAG, "MBEDTLS Bad Data input");
       return ( MBEDTLS_ERR_PK_BAD_INPUT_DATA );
    }

    return status;
}
#endif

#if defined(MBEDTLS_ECDSA_GENKEY_ALT)
int mbedtls_ecdsa_genkey( mbedtls_ecdsa_context *ctx, mbedtls_ecp_group_id gid,
                  int (*f_rng)(void *, unsigned char *, size_t), void *p_rng )
{
	optiga_lib_status_t status;
    uint8_t public_key [100];
    size_t public_key_len = sizeof( public_key );
    optiga_ecc_curve_t curve_id;
	mbedtls_ecp_group *grp = &ctx->grp;
 
	ESP_LOGI(TAG, "+++++++++++++entering mbedtls_ecdsa_genkey++++++++++++++++");
 
	mbedtls_ecp_group_load( &ctx->grp, gid );
 
    //checking group against the supported curves of Optiga Trust X
    if ( ( grp->id != MBEDTLS_ECP_DP_SECP256R1 ) &&
		 ( grp->id != MBEDTLS_ECP_DP_SECP384R1 ) )
	{
		return 1;
	}
	grp->id == MBEDTLS_ECP_DP_SECP256R1 ? ( curve_id = OPTIGA_ECC_NIST_P_256 )
                                                : ( curve_id = OPTIGA_ECC_NIST_P_384 ); 
    //invoke optiga command to generate a key pair.
	status = optiga_crypt_ecc_generate_keypair( curve_id,
                                                (optiga_key_usage_t)( OPTIGA_KEY_USAGE_KEY_AGREEMENT | OPTIGA_KEY_USAGE_AUTHENTICATION ),
												OPTIGA_KEY_STORE_ID_E0F0,
												public_key,
												(uint16_t *)&public_key_len ) ;
	if ( status != OPTIGA_LIB_SUCCESS )
    {
		status = MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
    }

    //store public key generated from optiga into mbedtls structure .
	if ( mbedtls_ecp_point_read_binary( grp, &ctx->Q,(unsigned char *)&public_key[3],(size_t )public_key_len-3 ) != 0 )
	{
		return 1;
	}
	
	ESP_LOGI( TAG, "+++++++++++++leaving mbedtls_ecdsa_genkey++++++++++++++++" );

    return status;
}					  
#endif

#endif
