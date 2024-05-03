#ifndef __SPDM_CORE_H__
#define __SPDM_CORE_H__

#include "hal/base.h"
#include "hal/library/memlib.h"
#include "industry_standard/spdm.h"
#include "library/spdm_common_lib.h"
#include "library/spdm_responder_lib.h"
#include "library/spdm_transport_mctp_lib.h"
#include "spdm_device_secret_lib_sample/spdm_device_secret_lib_internal.h"

#define LIBSPDM_MAX_MSG_SIZE 0x1200
#define LIBSPDM_TRANSPORT_HEADER_SIZE 64 
#define LIBSPDM_TRANSPORT_TAIL_SIZE 64
#define LIBSPDM_TRANSPORT_ADDITIONAL_SIZE \
  (LIBSPDM_TRANSPORT_HEADER_SIZE + LIBSPDM_TRANSPORT_TAIL_SIZE)

#define LIBSPDM_SENDER_BUFFER_SIZE (0x1000 + \
                                    LIBSPDM_TRANSPORT_ADDITIONAL_SIZE)
#define LIBSPDM_RECEIVER_BUFFER_SIZE (0x1000 + \
                                      LIBSPDM_TRANSPORT_ADDITIONAL_SIZE)

#define SOCKET_TRANSPORT_TYPE_NONE 0x00
#define SOCKET_TRANSPORT_TYPE_MCTP 0x01
#define SOCKET_TRANSPORT_TYPE_PCI_DOE 0x02
#define SOCKET_TRANSPORT_TYPE_TCP 0x03

#define EXE_CONNECTION_VERSION_ONLY 0x1 
#define EXE_CONNECTION_DIGEST 0x2 
#define EXE_CONNECTION_CERT 0x4 
#define EXE_CONNECTION_CHAL 0x8 
#define EXE_CONNECTION_MEAS 0x10 
#define EXE_CONNECTION_SET_CERT 0x20 
#define EXE_CONNECTION_GET_CSR 0x40

#define EXE_SESSION_KEY_EX 0x1
#define EXE_SESSION_PSK 0x2
#define EXE_SESSION_NO_END 0x4
#define EXE_SESSION_KEY_UPDATE 0x8
#define EXE_SESSION_HEARTBEAT 0x10
#define EXE_SESSION_MEAS 0x20
#define EXE_SESSION_SET_CERT 0x40
#define EXE_SESSION_GET_CSR 0x80
#define EXE_SESSION_DIGEST 0x100
#define EXE_SESSION_CERT 0x200
#define EXE_SESSION_APP 0x400

struct spdm_ops {
  // Message exchange functions
  libspdm_return_t (*send_message) (void *spdm_context,
                                    size_t request_size,
                                    const void *request,
                                    uint64_t timeout);
  libspdm_return_t (*receive_message) (void *spdm_context,
                                       size_t *response_size,
                                       void **response,
                                       uint64_t timeout);

  // Buffers' functions
  libspdm_return_t (*acquire_sender_buffer) (void *context,
                                             void **msg_but_ptr);
  void (*release_sender_buffer) (void *context, const void *msg_buf_ptr);
  libspdm_return_t (*acquire_receiver_buffer) (void *context,
                                               void **msg_but_ptr);
  void (*release_receiver_buffer) (void *context, const void *msg_buf_ptr);

  // Vendor defined request
  libspdm_return_t (*spdm_get_response_vendor_defined_request) (
        void *spdm_context,
        const uint32_t *session_id,
        bool is_app_message,
        size_t request_size,
        const void *request,
        size_t *response_size,
        void *response);
};

struct spdm_state {
  void *spdm_context;
  
  void *scratch_buffer;

  bool is_requester;

  uint8_t use_basic_mut_auth;
  uint8_t use_heartbeat_period;
  uint8_t use_mut_auth;
  uint8_t use_version;
  uint8_t use_secured_message_version;
  uint8_t use_slot_count;
  uint8_t use_slot_id;
  uint16_t use_req_asym_algo;
  uint32_t use_asym_algo;
  uint32_t use_capability_flags;
  uint32_t use_hash_algo;
  uint32_t use_measurement_hash_algo;
  uint32_t use_requester_capability_flags;
  uint32_t use_responder_capability_flags;
  uint32_t use_transport_layer;

  uint8_t support_measurement_spec;
  uint8_t support_other_params_support;
  uint8_t support_mel_spec;
  uint16_t support_dhe_algo;
  uint16_t support_aead_algo;
  uint16_t support_req_asym_algo;
  uint16_t support_key_schedule_algo;
  uint32_t support_asym_algo;
  uint32_t support_hash_algo;

  uint32_t exe_connection;
  uint32_t exe_session;

  struct spdm_ops *spdm_state_ops;
};

// Functions' prototypes
void spdm_responder_init(struct spdm_state *spdm_state);

void spdm_setup_cap(struct spdm_state *spdm_state);

void spdm_server_session_state_callback(
        void *spdm_context,
        uint32_t session_id,
        libspdm_session_state_t session_state);

void spdm_server_connection_state_callback(
        void *spdm_context,
        libspdm_connection_state_t connection_state);

void libspdm_dump_hex_str(const uint8_t *buffer, size_t buffer_size);

bool libspdm_read_input_file(
        const char *file_name,
        void **file_data,
        size_t *file_size);

bool libspdm_write_output_file(
        const char *file_name,
        const void *file_data,
        size_t file_size);
#endif
