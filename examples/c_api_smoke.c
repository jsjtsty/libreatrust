#include "../include/libreatrust.h"
#include <stdio.h>

static void print_error_if_any(void) {
    const char *msg = atr_last_error_message();
    if (msg != NULL) {
        fprintf(stderr, "error: %s\n", msg);
    }
}

int main(void) {
    atr_client_t *client = NULL;
    atr_auth_session_t *auth = NULL;

    atr_client_config_t client_cfg = {
        .server_host = "example.org",
        .server_port = 443,
        .user_agent = "libreatrust-demo",
        .connect_timeout_ms = 20000,
        .io_timeout_ms = 20000,
        .node_probe_timeout_ms = 3000,
        .allow_insecure_tls = true,
    };

    if (atr_client_new(&client_cfg, &client) != ATR_OK) {
        print_error_if_any();
        return 1;
    }

    atr_auth_config_t auth_cfg = {
        .server_host = "example.org",
        .server_port = 443,
        .user_agent = "libreatrust-demo",
        .client_type = "SDPClient",
        .platform = "Linux",
        .login_domain = "example.org",
        .preferred_auth_type = NULL,
        .io_timeout_ms = 20000,
        .allow_insecure_tls = true,
    };

    if (atr_auth_session_new(&auth_cfg, &auth) != ATR_OK) {
        print_error_if_any();
        atr_client_free(client);
        return 1;
    }

    atr_auth_method_list_t methods = {0};
    if (atr_auth_session_available_methods(auth, &methods) == ATR_OK) {
        printf("methods: %zu\n", methods.len);
        atr_auth_method_list_free(&methods);
    } else {
        print_error_if_any();
    }

    atr_auth_session_free(auth);
    atr_client_free(client);
    return 0;
}
