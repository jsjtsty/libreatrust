#ifndef LIBREATRUST_H
#define LIBREATRUST_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct atr_client_t atr_client_t;
typedef struct atr_auth_session_t atr_auth_session_t;
typedef struct atr_tcp_tunnel_t atr_tcp_tunnel_t;
typedef struct atr_udp_tunnel_t atr_udp_tunnel_t;
typedef struct atr_l3_tunnel_t atr_l3_tunnel_t;
typedef struct atr_proxy_service_t atr_proxy_service_t;

typedef enum atr_error_code {
    ATR_OK = 0,
    ATR_INVALID_ARGUMENT = 1,
    ATR_PARSE_FAILED = 2,
    ATR_NETWORK_FAILED = 3,
    ATR_UNAUTHORIZED = 4,
    ATR_CHALLENGE_REQUIRED = 5,
    ATR_INVALID_STATE = 6,
    ATR_CRYPTO_FAILED = 7,
    ATR_NOT_FOUND = 8,
    ATR_UNSUPPORTED = 9,
    ATR_INTERNAL = 255
} atr_error_code;

typedef struct atr_blob_t {
    uint8_t *data;
    size_t len;
} atr_blob_t;

typedef struct atr_string_list_t {
    char **items;
    size_t len;
} atr_string_list_t;

typedef struct atr_cookie_input_t {
    const char *host;
    const char *scheme;
    const char *name;
    const char *value;
} atr_cookie_input_t;

typedef struct atr_cookie_list_input_t {
    const atr_cookie_input_t *items;
    size_t len;
} atr_cookie_list_input_t;

typedef struct atr_cookie_record_t {
    char *host;
    char *scheme;
    char *name;
    char *value;
} atr_cookie_record_t;

typedef struct atr_cookie_list_t {
    atr_cookie_record_t *items;
    size_t len;
} atr_cookie_list_t;

typedef struct atr_ip_resource_t {
    char *ip_min;
    char *ip_max;
    uint16_t port_min;
    uint16_t port_max;
    char *protocol;
    char *app_id;
    char *node_group_id;
} atr_ip_resource_t;

typedef struct atr_ip_resource_list_t {
    atr_ip_resource_t *items;
    size_t len;
} atr_ip_resource_list_t;

typedef struct atr_domain_resource_t {
    char *domain;
    uint16_t port_min;
    uint16_t port_max;
    char *protocol;
    char *app_id;
    char *node_group_id;
} atr_domain_resource_t;

typedef struct atr_domain_resource_list_t {
    atr_domain_resource_t *items;
    size_t len;
} atr_domain_resource_list_t;

typedef struct atr_dns_resource_t {
    char *domain;
    char *ip;
} atr_dns_resource_t;

typedef struct atr_dns_resource_list_t {
    atr_dns_resource_t *items;
    size_t len;
} atr_dns_resource_list_t;

typedef struct atr_node_group_t {
    char *group_id;
    atr_string_list_t addresses;
} atr_node_group_t;

typedef struct atr_node_group_list_t {
    atr_node_group_t *items;
    size_t len;
} atr_node_group_list_t;

typedef struct atr_resource_snapshot_t {
    atr_blob_t resource_bytes;
    char *dns_server;
    char *major_node_group;
    atr_ip_resource_list_t ip_resources;
    atr_domain_resource_list_t domain_resources;
    atr_dns_resource_list_t dns_resources;
    atr_node_group_list_t node_groups;
    atr_string_list_t excluded_ips;
} atr_resource_snapshot_t;

typedef struct atr_client_config_t {
    const char *server_host;
    uint16_t server_port;
    const char *user_agent;
    uint64_t connect_timeout_ms;
    uint64_t io_timeout_ms;
    uint64_t node_probe_timeout_ms;
    bool allow_insecure_tls;
    const char *bind_interface;
    bool auto_detect_interface;
} atr_client_config_t;

typedef struct atr_auth_config_t {
    const char *server_host;
    uint16_t server_port;
    const char *user_agent;
    const char *client_type;
    const char *platform;
    const char *login_domain;
    const char *preferred_auth_type;
    uint64_t io_timeout_ms;
    bool allow_insecure_tls;
} atr_auth_config_t;

typedef struct atr_auth_method_info_t {
    char *login_domain;
    char *auth_type;
    char *auth_name;
    char *login_url;
} atr_auth_method_info_t;

typedef struct atr_auth_method_list_t {
    atr_auth_method_info_t *items;
    size_t len;
} atr_auth_method_list_t;

typedef struct atr_password_login_input_t {
    const char *username;
    const char *password;
    const char *login_domain;
} atr_password_login_input_t;

typedef struct atr_sms_login_input_t {
    const char *phone;
    const char *login_domain;
} atr_sms_login_input_t;

typedef struct atr_callback_target_t {
    const char *callback_url;
} atr_callback_target_t;

typedef struct atr_session_material_input_t {
    const char *username;
    const char *sid;
    const char *device_id;
    const char *connection_id;
    const char *sign_key_hex;
    atr_cookie_list_input_t cookies;
} atr_session_material_input_t;

typedef struct atr_session_material_t {
    char *username;
    char *sid;
    char *device_id;
    char *connection_id;
    char *sign_key_hex;
    atr_cookie_list_t cookies;
} atr_session_material_t;

typedef enum atr_auth_challenge_kind_t {
    ATR_AUTH_CHALLENGE_CAPTCHA = 0,
    ATR_AUTH_CHALLENGE_SMS_CODE = 1,
    ATR_AUTH_CHALLENGE_CALLBACK_URL = 2,
    ATR_AUTH_CHALLENGE_DONE = 3
} atr_auth_challenge_kind_t;

typedef enum atr_proxy_service_status_t {
    ATR_PROXY_SERVICE_RUNNING = 0,
    ATR_PROXY_SERVICE_STOPPED = 1
} atr_proxy_service_status_t;

typedef enum atr_proxy_service_event_kind_t {
    ATR_PROXY_SERVICE_EVENT_NONE = 0,
    ATR_PROXY_SERVICE_EVENT_ERROR = 1,
    ATR_PROXY_SERVICE_EVENT_SESSION_INVALIDATED = 2
} atr_proxy_service_event_kind_t;

typedef struct atr_proxy_service_config_t {
    const char *listen_host;
    uint16_t listen_port;
    uint64_t connect_timeout_ms;
    uint64_t idle_timeout_ms;
    bool enable_http;
    bool enable_socks5;
} atr_proxy_service_config_t;

typedef struct atr_proxy_service_endpoint_t {
    char *host;
    uint16_t port;
} atr_proxy_service_endpoint_t;

typedef struct atr_proxy_service_stats_t {
    uint64_t active_connections;
    uint64_t total_connections;
    char *last_error;
    atr_proxy_service_event_kind_t last_event_kind;
    char *last_event_message;
} atr_proxy_service_stats_t;

typedef struct atr_proxy_service_traffic_stats_t {
    uint64_t managed_upload_bytes;
    uint64_t managed_download_bytes;
} atr_proxy_service_traffic_stats_t;

typedef struct atr_auth_challenge_t {
    atr_auth_challenge_kind_t kind;
    atr_blob_t image;
    char *auth_id;
    char *auth_url;
    atr_auth_challenge_kind_t callback_kind;
    atr_session_material_t session;
} atr_auth_challenge_t;

const char *atr_last_error_message(void);

void atr_string_free(char *ptr);
void atr_blob_free(atr_blob_t *blob);
void atr_string_list_free(atr_string_list_t *list);
void atr_auth_method_list_free(atr_auth_method_list_t *list);
void atr_session_material_free(atr_session_material_t *session);
void atr_auth_challenge_free(atr_auth_challenge_t *challenge);
void atr_resource_snapshot_free(atr_resource_snapshot_t *snapshot);

int atr_client_new(const atr_client_config_t *config, atr_client_t **out);
void atr_client_free(atr_client_t *client);
int atr_client_set_session(atr_client_t *client, const atr_session_material_input_t *session);
int atr_client_set_resource(atr_client_t *client, const uint8_t *resource_bytes, size_t resource_len, const char *service_host);
int atr_client_route_tcp(const atr_client_t *client, const char *host, uint16_t port, bool *managed);
int atr_client_route_udp(const atr_client_t *client, const char *host, uint16_t port, bool *managed);
int atr_client_route_icmp(const atr_client_t *client, const char *host, bool *managed);
int atr_client_get_resource_bytes(const atr_client_t *client, atr_blob_t *out);
int atr_client_get_dns_server(const atr_client_t *client, char **out);
int atr_client_get_major_node_group(const atr_client_t *client, char **out);
int atr_client_get_resource_snapshot(const atr_client_t *client, atr_resource_snapshot_t *out);

int atr_client_open_tcp(const atr_client_t *client, const char *host, uint16_t port, atr_tcp_tunnel_t **out);
void atr_tcp_tunnel_free(atr_tcp_tunnel_t *tunnel);
int atr_tcp_tunnel_close(atr_tcp_tunnel_t *tunnel);
int atr_tcp_tunnel_read(const atr_tcp_tunnel_t *tunnel, uint8_t *buf, size_t len, size_t *out_len);
int atr_tcp_tunnel_write(const atr_tcp_tunnel_t *tunnel, const uint8_t *buf, size_t len, size_t *out_len);

int atr_client_open_udp(const atr_client_t *client, const char *host, uint16_t port, atr_udp_tunnel_t **out);
void atr_udp_tunnel_free(atr_udp_tunnel_t *tunnel);
int atr_udp_tunnel_close(atr_udp_tunnel_t *tunnel);
int atr_udp_tunnel_read(const atr_udp_tunnel_t *tunnel, uint8_t *buf, size_t len, size_t *out_len);
int atr_udp_tunnel_write(const atr_udp_tunnel_t *tunnel, const uint8_t *buf, size_t len, size_t *out_len);

int atr_client_open_l3(const atr_client_t *client, atr_l3_tunnel_t **out);
void atr_l3_tunnel_free(atr_l3_tunnel_t *tunnel);
int atr_l3_tunnel_close(const atr_l3_tunnel_t *tunnel);
int atr_l3_tunnel_send_heartbeat(const atr_l3_tunnel_t *tunnel);
int atr_l3_tunnel_read_packet(const atr_l3_tunnel_t *tunnel, uint8_t *buf, size_t len, size_t *out_len);
int atr_l3_tunnel_write_packet(const atr_l3_tunnel_t *tunnel, const uint8_t *buf, size_t len, size_t *out_len);
int atr_l3_tunnel_get_virtual_ips(const atr_l3_tunnel_t *tunnel, atr_string_list_t *out);

int atr_client_start_proxy_service(const atr_client_t *client, const atr_proxy_service_config_t *config, atr_proxy_service_t **out);
int atr_proxy_service_stop(const atr_proxy_service_t *service);
int atr_proxy_service_status(const atr_proxy_service_t *service, atr_proxy_service_status_t *out);
int atr_proxy_service_get_endpoint(const atr_proxy_service_t *service, atr_proxy_service_endpoint_t *out);
int atr_proxy_service_get_stats(const atr_proxy_service_t *service, atr_proxy_service_stats_t *out);
int atr_proxy_service_get_traffic_stats(const atr_proxy_service_t *service, atr_proxy_service_traffic_stats_t *out);
int atr_proxy_service_take_event(const atr_proxy_service_t *service, atr_proxy_service_event_kind_t *out_kind, char **out_message);
void atr_proxy_service_endpoint_free(atr_proxy_service_endpoint_t *endpoint);
void atr_proxy_service_stats_free(atr_proxy_service_stats_t *stats);
void atr_proxy_service_free(atr_proxy_service_t *service);

int atr_auth_session_new(const atr_auth_config_t *config, atr_auth_session_t **out);
void atr_auth_session_free(atr_auth_session_t *session);
int atr_auth_session_available_methods(atr_auth_session_t *session, atr_auth_method_list_t *out);
int atr_auth_session_resolve_login_url(const atr_auth_session_t *session, const char *login_url, char **out);
int atr_auth_session_login_password(atr_auth_session_t *session, const atr_password_login_input_t *input, const char *device_id, atr_auth_challenge_t *out);
int atr_auth_session_login_sms(atr_auth_session_t *session, const atr_sms_login_input_t *input, const char *device_id, atr_auth_challenge_t *out);
int atr_auth_session_submit_captcha(atr_auth_session_t *session, const char *captcha, atr_auth_challenge_t *out);
int atr_auth_session_submit_sms_code(atr_auth_session_t *session, const char *code, atr_auth_challenge_t *out);
int atr_auth_session_complete_callback(atr_auth_session_t *session, const atr_callback_target_t *target, atr_auth_challenge_t *out);
int atr_auth_session_prepare_callback_login(atr_auth_session_t *session, const char *device_id);
int atr_auth_session_complete_callback_with_device(atr_auth_session_t *session, const atr_callback_target_t *target, const char *device_id, atr_auth_challenge_t *out);
int atr_auth_session_fetch_client_resource(atr_auth_session_t *session, atr_blob_t *out);
int atr_auth_session_get_client_resource(atr_auth_session_t *session, atr_blob_t *out);
int atr_auth_session_import_session(atr_auth_session_t *session, const atr_session_material_input_t *session_material);
int atr_auth_session_resume_session(atr_auth_session_t *session, const atr_session_material_input_t *session_material, atr_session_material_t *out);
int atr_auth_session_export_session(const atr_auth_session_t *session, atr_session_material_t *out);

#ifdef __cplusplus
}
#endif

#endif
