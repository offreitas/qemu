#include <stdlib.h>
#include <stdio.h>
#include "spdm/core.h"

void libspdm_dump_hex_str(const uint8_t *buffer, size_t buffer_size)
{
    size_t index;

    for (index = 0; index < buffer_size; index++) {
        printf("%02x", buffer[index]);
    }
}

bool libspdm_read_input_file(const char *file_name, void **file_data,
                             size_t *file_size)
{
    FILE *fp_in;
    size_t temp_result;

    if ((fp_in = fopen(file_name, "rb")) == NULL) {
        printf("Unable to open file %s\n", file_name);
        *file_data = NULL;
        return false;
    }

    fseek(fp_in, 0, SEEK_END);
    *file_size = ftell(fp_in);
    if (*file_size == -1) {
        printf("Unable to get the file size %s\n", file_name);
        *file_data = NULL;
        fclose(fp_in);
        return false;
    }

    *file_data = (void *)malloc(*file_size);
    if (NULL == *file_data) {
        printf("No sufficient memory to allocate %s\n", file_name);
        fclose(fp_in);
        return false;
    }

    fseek(fp_in, 0, SEEK_SET);
    temp_result = fread(*file_data, 1, *file_size, fp_in);
    if (temp_result != *file_size) {
        printf("Read input file error %s", file_name);
        free((void *)*file_data);
        fclose(fp_in);
        return false;
    }

    fclose(fp_in);

    return true;
}

bool libspdm_write_output_file(const char *file_name, const void *file_data,
                               size_t file_size)
{
    FILE *fp_out;

    if ((fp_out = fopen(file_name, "w+b")) == NULL) {
        printf("Unable to open file %s\n", file_name);
        return false;
    }

    if (file_size != 0) {
        if ((fwrite(file_data, 1, file_size, fp_out)) != file_size) {
            printf("Write output file error %s\n", file_name);
            fclose(fp_out);
            return false;
        }
    }

    fclose(fp_out);

    return true;
}

/*
 * Initialize SPDM context 
 *
 * @param   spdm_state      A pointer to the SPDM state struct 
 * */
void spdm_setup_cap(struct spdm_state *spdm_state)
{
    void *requester_cert_chain_buffer;
    uint8_t data8;
    uint16_t data16;
    uint32_t data32;
    size_t scratch_buffer_size;
    spdm_version_number_t spdm_version;
    libspdm_data_parameter_t parameter;

    /*
    * Initializing SPDM context
    * */
    spdm_state->spdm_context = (void *)malloc(libspdm_get_context_size());
    if (spdm_state->spdm_context == NULL) {
        printf("[SPDM] Failed tring to allocate SPDM context\n");
        return;
    }

    libspdm_init_context(spdm_state->spdm_context);

    /*
    * Register SPDM send and receive message functions
    * */
    libspdm_register_device_io_func(spdm_state->spdm_context,
                                    spdm_state->spdm_state_ops->send_message,
                                    spdm_state->spdm_state_ops->receive_message);

    /*
    * TODO: add support beyond MCTP
    * */
    if (spdm_state->use_transport_layer == SOCKET_TRANSPORT_TYPE_MCTP) {
        libspdm_register_transport_layer_func(
            spdm_state->spdm_context,
            LIBSPDM_MAX_MSG_SIZE,
            LIBSPDM_TRANSPORT_HEADER_SIZE,
            LIBSPDM_TRANSPORT_TAIL_SIZE,
            libspdm_transport_mctp_encode_message,
            libspdm_transport_mctp_decode_message
        );
    } else {
        printf("[SPDM] No SPDM transport layer configured\n");
        free(spdm_state->spdm_context);
        spdm_state->spdm_context = NULL;
        return;
    }

    /*
    * Register device buffers
    * */
    libspdm_register_device_buffer_func(
        spdm_state->spdm_context,
        LIBSPDM_SENDER_BUFFER_SIZE,
        LIBSPDM_RECEIVER_BUFFER_SIZE,
        spdm_state->spdm_state_ops->acquire_sender_buffer,
        spdm_state->spdm_state_ops->release_sender_buffer,
        spdm_state->spdm_state_ops->acquire_receiver_buffer,
        spdm_state->spdm_state_ops->release_receiver_buffer
    );

    scratch_buffer_size = libspdm_get_sizeof_required_scratch_buffer(spdm_state->spdm_context);
    spdm_state->scratch_buffer = (void *)malloc(scratch_buffer_size);
    if (spdm_state->scratch_buffer == NULL) {
        printf("[SPDM] Failed trying to allocate scratch buffer\n");
        free(spdm_state->spdm_context);
        spdm_state->spdm_context = NULL;
        return;
    }

    libspdm_set_scratch_buffer(spdm_state->spdm_context,
                               spdm_state->scratch_buffer,
                               scratch_buffer_size);

    /*
     * Requester certificate chain buffer 
     * */ 
    requester_cert_chain_buffer = (void *)malloc(SPDM_MAX_CERTIFICATE_CHAIN_SIZE);
    if (requester_cert_chain_buffer == NULL) {
        printf("[SPDM] Failed trying to allocate requester certificate chain buffer\n");
        return;
    }

    libspdm_register_cert_chain_buffer(spdm_state->spdm_context,
                                       requester_cert_chain_buffer,
                                       SPDM_MAX_CERTIFICATE_CHAIN_SIZE);

    /*
     * Check SPDM context before continuing
     * */
    if (!libspdm_check_context(spdm_state->spdm_context)) {
        printf("[SPDM] Failed checking SPDM context\n");
        return;
    }

    /*
    * Set connection parameters
    * */
    if (spdm_state->use_version != 0) {
        libspdm_zero_mem(&parameter, sizeof(parameter));
        parameter.location = LIBSPDM_DATA_LOCATION_LOCAL;
        spdm_version = spdm_state->use_version << SPDM_VERSION_NUMBER_SHIFT_BIT;
        libspdm_set_data(spdm_state->spdm_context,
                         LIBSPDM_DATA_SPDM_VERSION,
                         &parameter,
                         &spdm_version,
                         sizeof(spdm_version));
    }

    if (spdm_state->use_secured_message_version != 0) {
        libspdm_zero_mem(&parameter, sizeof(parameter));
        parameter.location = LIBSPDM_DATA_LOCATION_LOCAL;
        spdm_version = spdm_state->use_secured_message_version << SPDM_VERSION_NUMBER_SHIFT_BIT;
        libspdm_set_data(spdm_state->spdm_context,
                         LIBSPDM_DATA_SECURED_MESSAGE_VERSION,
                         &parameter,
                         &spdm_version,
                         sizeof(spdm_version));
    }

    libspdm_zero_mem(&parameter, sizeof(parameter));
    parameter.location = LIBSPDM_DATA_LOCATION_LOCAL;

    data8 = 0;
    libspdm_set_data(spdm_state->spdm_context,
                     LIBSPDM_DATA_CAPABILITY_CT_EXPONENT,
                     &parameter,
                     &data8,
                     sizeof(data8));

    data32 = spdm_state->use_responder_capability_flags;
    if (spdm_state->use_slot_id == 0xFF) {
        data32 |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PUB_KEY_ID_CAP;
        data32 &= ~SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP;
        data32 &= ~SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ALIAS_CERT_CAP;
        data32 &= ~SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_SET_CERT_CAP;
        data32 &= ~SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CSR_CAP;
        data32 &= ~SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_INSTALL_RESET_CAP;
        data32 &= ~SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MULTI_KEY_CAP;
        data32 &= ~SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_GET_KEY_PAIR_INFO_CAP;
        data32 &= ~SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_SET_KEY_PAIR_INFO_CAP;
    }
    if (spdm_state->use_capability_flags != 0) {
        data32 = spdm_state->use_capability_flags;
        spdm_state->use_responder_capability_flags = spdm_state->use_capability_flags;
    }
    libspdm_set_data(spdm_state->spdm_context,
                     LIBSPDM_DATA_CAPABILITY_FLAGS,
                     &parameter,
                     &data32,
                     sizeof(data32));

    data8 = spdm_state->support_measurement_spec;
    libspdm_set_data(spdm_state->spdm_context,
                     LIBSPDM_DATA_MEASUREMENT_SPEC,
                     &parameter,
                     &data8,
                     sizeof(data8));

    data32 = spdm_state->support_asym_algo;
    libspdm_set_data(spdm_state->spdm_context,
                     LIBSPDM_DATA_BASE_ASYM_ALGO,
                     &parameter,
                     &data32,
                     sizeof(data32));

    data32 = spdm_state->support_hash_algo;
    libspdm_set_data(spdm_state->spdm_context,
                    LIBSPDM_DATA_BASE_HASH_ALGO,
                    &parameter,
                    &data32,
                    sizeof(data32));

    data16 = spdm_state->support_dhe_algo;
    libspdm_set_data(spdm_state->spdm_context,
                    LIBSPDM_DATA_DHE_NAME_GROUP,
                    &parameter,
                    &data16,
                    sizeof(data16));

    data16 = spdm_state->support_aead_algo;
    libspdm_set_data(spdm_state->spdm_context,
                    LIBSPDM_DATA_AEAD_CIPHER_SUITE,
                    &parameter,
                    &data16,
                    sizeof(data16));

    data16 = spdm_state->support_req_asym_algo;
    libspdm_set_data(spdm_state->spdm_context,
                    LIBSPDM_DATA_REQ_BASE_ASYM_ALG,
                    &parameter,
                    &data16,
                    sizeof(data16));

    data16 = spdm_state->support_key_schedule_algo;
    libspdm_set_data(spdm_state->spdm_context,
                    LIBSPDM_DATA_KEY_SCHEDULE,
                    &parameter,
                    &data16,
                    sizeof(data16));

    data8 = spdm_state->support_other_params_support;
    libspdm_set_data(spdm_state->spdm_context,
                    LIBSPDM_DATA_OTHER_PARAMS_SUPPORT,
                    &parameter,
                    &data8,
                    sizeof(data8));

    data8 = spdm_state->support_mel_spec;
    libspdm_set_data(spdm_state->spdm_context,
                    LIBSPDM_DATA_MEL_SPEC,
                    &parameter,
                    &data8,
                    sizeof(data8));
    
    if (!spdm_state->is_requester) {
        data8 = spdm_state->use_heartbeat_period;
        libspdm_set_data(spdm_state->spdm_context,
                         LIBSPDM_DATA_HEARTBEAT_PERIOD,
                         &parameter,
                         &data8,
                         sizeof(data8));
    }

    return;
}

/*
 * Notify the connection state to an SPDM context register 
 * 
 * @param spdm_context          A pointer to the SPDM context
 * @param connection_state      Indicate the SPDM connection state 
 * */
void spdm_server_connection_state_callback(
    void *spdm_context, libspdm_connection_state_t connection_state)
{
    struct spdm_state *spdm_state = spdm_context;
    bool res;
    void *data;
    void *data1;
    void *hash;
    size_t data_size;
    size_t data1_size;
    size_t hash_size;
    size_t root_cert_size;
    const uint8_t *root_cert;
    uint8_t index;
    uint8_t data8;
    uint16_t data16;
    uint32_t data32;
    libspdm_data_parameter_t parameter;
    spdm_version_number_t spdm_version;

    /*
     * TODO: Implement PSK case 
     * */
    switch (connection_state) {
    case LIBSPDM_CONNECTION_STATE_NEGOTIATED:
        if (spdm_context == 0) {
            libspdm_zero_mem(&parameter, sizeof(parameter));
            parameter.location = LIBSPDM_DATA_LOCATION_CONNECTION;
            data_size = sizeof(spdm_version);
            libspdm_get_data(spdm_context, LIBSPDM_DATA_SPDM_VERSION,
                            &parameter, &spdm_version, &data_size);
            spdm_state->use_version = spdm_version >> SPDM_VERSION_NUMBER_SHIFT_BIT;
        }

        libspdm_zero_mem(&parameter, sizeof(parameter));
        parameter.location = LIBSPDM_DATA_LOCATION_CONNECTION;

        data_size = sizeof(data32);
        libspdm_get_data(spdm_context, LIBSPDM_DATA_MEASUREMENT_HASH_ALGO,
                         &parameter, &data32, &data_size);
        spdm_state->use_measurement_hash_algo = data32;
        data_size = sizeof(data32);
        libspdm_get_data(spdm_context, LIBSPDM_DATA_BASE_ASYM_ALGO,
                         &parameter, &data32, &data_size);
        spdm_state->use_asym_algo = data32;
        data_size = sizeof(data32);
        libspdm_get_data(spdm_context, LIBSPDM_DATA_BASE_HASH_ALGO,
                         &parameter, &data32, &data_size);
        spdm_state->use_hash_algo = data32;
        data_size = sizeof(data16);
        libspdm_get_data(spdm_context, LIBSPDM_DATA_REQ_BASE_ASYM_ALG,
                         &parameter, &data16, &data_size);
        spdm_state->use_req_asym_algo = data16;

        libspdm_zero_mem(&parameter, sizeof(parameter));
        parameter.location = LIBSPDM_DATA_LOCATION_LOCAL;
        data_size = sizeof(data32);
        libspdm_get_data(spdm_context, LIBSPDM_DATA_CAPABILITY_FLAGS,
                         &parameter, &data32, &data_size);
        
        if ((data32 & SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ALIAS_CERT_CAP) == 0) {
            res = libspdm_read_responder_public_certificate_chain(
                spdm_state->use_hash_algo,
                spdm_state->use_asym_algo,
                &data, &data_size,
                NULL, NULL);
        } else {
            res = libspdm_read_responder_public_certificate_chain_alias_cert(
                spdm_state->use_hash_algo,
                spdm_state->use_asym_algo,
                &data, &data_size,
                NULL, NULL);
        }

        res = libspdm_read_responder_public_certificate_chain_per_slot(
            1, spdm_state->use_hash_algo,
            spdm_state->use_asym_algo,
            &data1, &data1_size,
            NULL, NULL);

        if (res) {
            libspdm_zero_mem(&parameter, sizeof(parameter));
            parameter.location = LIBSPDM_DATA_LOCATION_LOCAL;

            for (index = 0; index < spdm_state->use_slot_count; index++) {
                parameter.additional_data[0] = index;
                if (index == 1) {
                    libspdm_set_data(spdm_context,
                                     LIBSPDM_DATA_LOCAL_PUBLIC_CERT_CHAIN,
                                     &parameter, data1, data1_size);
                } else {
                    libspdm_set_data(spdm_context,
                                     LIBSPDM_DATA_LOCAL_PUBLIC_CERT_CHAIN,
                                     &parameter, data, data_size);
                }
                data8 = (uint8_t)(0xA0 + index);
                libspdm_set_data(spdm_context,
                                 LIBSPDM_DATA_LOCAL_KEY_PAIR_ID,
                                 &parameter, &data8, sizeof(data8));
                data8 = SPDM_CERTIFICATE_INFO_CERT_MODEL_DEVICE_CERT;
                libspdm_set_data(spdm_context,
                                 LIBSPDM_DATA_LOCAL_CERT_INFO,
                                 &parameter, &data8, sizeof(data8));
                data16 = SPDM_KEY_USAGE_BIT_MASK_KEY_EX_USE | 
                         SPDM_KEY_USAGE_BIT_MASK_CHALLENGE_USE |
                         SPDM_KEY_USAGE_BIT_MASK_MEASUREMENT_USE |
                         SPDM_KEY_USAGE_BIT_MASK_ENDPOINT_INFO_USE;
                libspdm_set_data(spdm_context,
                                 LIBSPDM_DATA_LOCAL_KEY_USAGE_BIT_MASK,
                                 &parameter, &data16, sizeof(data16));
            }
            /* Do not free it*/
        }

        if (spdm_state->use_req_asym_algo != 0) {
            if ((spdm_state->use_responder_capability_flags &
                 SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PUB_KEY_ID_CAP) != 0) {
                 spdm_state->use_slot_id = 0xFF;
            }
            if (spdm_state->use_slot_id == 0xFF) {
                res = libspdm_read_responder_public_key(spdm_state->use_asym_algo, &data, &data_size);
                if (res) {
                    libspdm_zero_mem(&parameter, sizeof(parameter));
                    parameter.location = LIBSPDM_DATA_LOCATION_LOCAL;
                    libspdm_set_data(spdm_context,
                                     LIBSPDM_DATA_LOCAL_PUBLIC_KEY,
                                     &parameter, data, data_size);
                    /* Do not free it.*/
                }
                res = libspdm_read_requester_public_key(spdm_state->use_req_asym_algo, &data, &data_size);
                if (res) {
                    libspdm_zero_mem(&parameter, sizeof(parameter));
                    parameter.location = LIBSPDM_DATA_LOCATION_LOCAL;
                    libspdm_set_data(spdm_context,
                                     LIBSPDM_DATA_PEER_PUBLIC_KEY,
                                     &parameter, data, data_size);
                    /* Do not free it.*/
                }
            } else {
                res = libspdm_read_requester_root_public_certificate(
                    spdm_state->use_hash_algo, spdm_state->use_req_asym_algo, &data,
                    &data_size, &hash, &hash_size);
                libspdm_x509_get_cert_from_cert_chain(
                    (uint8_t *)data + sizeof(spdm_cert_chain_t) + hash_size,
                    data_size - sizeof(spdm_cert_chain_t) - hash_size, 0,
                    &root_cert, &root_cert_size);
                if (res) {
                    libspdm_zero_mem(&parameter, sizeof(parameter));
                    parameter.location = LIBSPDM_DATA_LOCATION_LOCAL;
                    libspdm_set_data(
                        spdm_context,
                        LIBSPDM_DATA_PEER_PUBLIC_ROOT_CERT,
                        &parameter, (void *)root_cert, root_cert_size);
                    /* Do not free it.*/
                }
            }

            if (res) {
                if (spdm_state->use_slot_id == 0xFF) {
                    /* 0xFF slot is only allowed in */
                    spdm_state->use_mut_auth = SPDM_KEY_EXCHANGE_RESPONSE_MUT_AUTH_REQUESTED;
                }
                data8 = spdm_state->use_mut_auth;
                parameter.additional_data[0] =
                    spdm_state->use_slot_id; /* req_slot_id;*/
                libspdm_set_data(spdm_context,
                                 LIBSPDM_DATA_MUT_AUTH_REQUESTED, &parameter,
                                 &data8, sizeof(data8));

                data8 = spdm_state->use_basic_mut_auth;
                parameter.additional_data[0] =
                    spdm_state->use_slot_id; /* req_slot_id;*/
                libspdm_set_data(spdm_context,
                                 LIBSPDM_DATA_BASIC_MUT_AUTH_REQUESTED,
                                 &parameter, &data8, sizeof(data8));
            }
        }

        libspdm_zero_mem(&parameter, sizeof(parameter));
        parameter.location = LIBSPDM_DATA_LOCATION_LOCAL;
        data8 = 0;
        for (index = 0; index < spdm_state->use_slot_count; index++) {
            data8 |= (1 << index);
        }
        libspdm_set_data(spdm_context, LIBSPDM_DATA_LOCAL_SUPPORTED_SLOT_MASK, &parameter,
                         &data8, sizeof(data8));

        break;

    default:
        break;
    }

    return;
}

/**
 * Notify the session state to a session APP.
 *
 * @param  spdm_context                  A pointer to the SPDM context.
 * @param  session_id                    The session_id of a session.
 * @param  session_state                 The state of a session.
 **/
void spdm_server_session_state_callback(void *spdm_context,
                                        uint32_t session_id,
                                        libspdm_session_state_t session_state)
{
    struct spdm_state *spdm_state = spdm_context;
    size_t data_size;
    libspdm_data_parameter_t parameter;
    uint8_t data8;

    switch (session_state) {
    case LIBSPDM_SESSION_STATE_HANDSHAKING:
        /* collect session policy*/
        if (spdm_state->use_version >= SPDM_MESSAGE_VERSION_12) {
            libspdm_zero_mem(&parameter, sizeof(parameter));
            parameter.location = LIBSPDM_DATA_LOCATION_SESSION;
            *(uint32_t *)parameter.additional_data = session_id;

            data8 = 0;
            data_size = sizeof(data8);
            libspdm_get_data(spdm_context,
                             LIBSPDM_DATA_SESSION_POLICY,
                             &parameter, &data8, &data_size);
            printf("session policy - %x\n", data8);
        }
        break;

    case LIBSPDM_SESSION_STATE_ESTABLISHED:
        /* no action*/
        break;

    default:
        LIBSPDM_ASSERT(false);
        break;
    }

    return;
}

/*
 * Initialize SPDM responder 
 *
 * @param   spdm_state      A pointer to the SPDM state struct 
 * */
void spdm_responder_init(struct spdm_state *spdm_state)
{
    spdm_state->is_requester = false;

    spdm_setup_cap(spdm_state);
    libspdm_register_get_response_func(
        spdm_state->spdm_context,
        spdm_state->spdm_state_ops->spdm_get_response_vendor_defined_request);
    libspdm_register_session_state_callback_func(
        spdm_state->spdm_context,
        spdm_server_session_state_callback);
    libspdm_register_connection_state_callback_func(
        spdm_state->spdm_context,
        spdm_server_connection_state_callback);

    return;
}
