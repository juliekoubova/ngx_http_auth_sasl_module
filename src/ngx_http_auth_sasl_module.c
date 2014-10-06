/**
 * Copyright (C) 2014 Julie Koubova <juliekoubova@icloud.com>
 *
 * Based on 'ngx_http_auth_basic_module.c' by Igor Sysoev and
 * 'ngx_http_auth_pam_module.c' by Sergio Talens-Oliag.
 *
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

/*
 * Our per-location configuration.
 */
typedef struct {
    ngx_str_t realm;
    ngx_str_t service_name;
} ngx_http_auth_sasl_loc_conf_t;

/*
 * The public interface of this module.
 */
ngx_module_t ngx_http_auth_sasl_module;

/* ========================================================================================
 * Access Handler
 * ======================================================================================== */

/*
 * Sends a WWW-Authenticate header with realm name
 * and returns HTTP 401 Authorization Required status.
 */
static ngx_int_t
ngx_http_auth_sasl_unauthorized(ngx_http_request_t *r, const ngx_str_t *realm)
{
    static const char   HEADER_NAME[]   = "WWW-Authenticate";
    static const size_t HEADER_NAME_LEN = sizeof(HEADER_NAME) - 1;

    r->headers_out.www_authenticate = ngx_list_push(&r->headers_out.headers);
    if (r->headers_out.www_authenticate == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    r->headers_out.www_authenticate->hash = 1;
    r->headers_out.www_authenticate->key.len = HEADER_NAME_LEN;
    r->headers_out.www_authenticate->key.data = HEADER_NAME;
    r->headers_out.www_authenticate->value = *realm;

    return NGX_HTTP_UNAUTHORIZED;
}

static ngx_int_t
ngx_http_auth_sasl_handler(ngx_http_request_t *r)
{
    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "SASL HANDLER");

    ngx_http_auth_sasl_loc_conf_t  *lcf;
    ngx_int_t                       rc;

    lcf = ngx_http_get_module_loc_conf(r, ngx_http_auth_sasl_module);

    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
            "SASL HANDLER REALM: %s", lcf->realm.data);

    if (lcf->realm.len == 0) {
        /* SASL authentication is not enabled at this location. */
        return NGX_DECLINED;
    }

    /* Decode http auth user and passwd, leaving values on the request.
     * Implemented in ngx_http_core_module. */
    rc = ngx_http_auth_basic_user(r);

    if (rc == NGX_DECLINED) {
        /* No HTTP authentication header provided by the browser.
         * Set realm and return HTTP Unauthorized. */
        return ngx_http_auth_sasl_unauthorized(r, &lcf->realm);
    }

    return NGX_OK;
}

/* ========================================================================================
 * Configuration
 * ======================================================================================== */

/*
 * Registers our request access phase handler.
 */
static ngx_int_t
ngx_http_auth_sasl_init(ngx_conf_t *cf)
{
    ngx_http_handler_pt        *h;
    ngx_http_core_main_conf_t  *cmcf;

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    h = ngx_array_push(&cmcf->phases[NGX_HTTP_ACCESS_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    *h = ngx_http_auth_sasl_handler;
    return NGX_OK;
}

/*
 * Creates an instance of per-location configuration.
 */
static void *
ngx_http_auth_sasl_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_auth_sasl_loc_conf_t *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_auth_sasl_loc_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    return conf;
}

/*
 * Overrides inherited configuration.
 */
static char *
ngx_http_auth_sasl_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_auth_sasl_loc_conf_t *prev = parent;
    ngx_http_auth_sasl_loc_conf_t *conf = child;

    if (conf->realm.data == NULL) {
        conf->realm = prev->realm;
    }

    return NGX_CONF_OK;
}

/*
 * Wraps the realm name with "Basic realm=\"<data>\"", so the value
 * doesn't need any further processing before sending to the client.
 * If the realm name equals "off", the value is discarded, and
 * SASL authentication is disabled at this location.
 */
static char *
ngx_http_auth_sasl_post_handler(ngx_conf_t *cf, void *post, void *data)
{
    static const char   PREFIX[]   = "Basic realm=\"";
    static const size_t PREFIX_LEN = sizeof(PREFIX) - 1;

    static const char   SUFFIX     = '"';
    static const size_t SUFFIX_LEN = sizeof(SUFFIX);

    ngx_str_t  *realm = data;
    u_char     *processed;
    u_char     *p;
    size_t      len;

    if (ngx_strcmp(realm->data, "off") == 0) {
        realm->len = 0;
        realm->data = (u_char *) "";

        return NGX_CONF_OK;
    }

    len = PREFIX_LEN + realm->len + SUFFIX_LEN;

    processed = ngx_palloc(cf->pool, len);
    if (processed == NULL) {
        return NGX_CONF_ERROR;
    }

    p = ngx_cpymem(processed, PREFIX, PREFIX_LEN);
    p = ngx_cpymem(p, realm->data, realm->len);
    *p = SUFFIX;

    realm->len  = len;
    realm->data = processed;

    return NGX_CONF_OK;
}

static ngx_conf_post_t ngx_http_auth_sasl_post = {
    ngx_http_auth_sasl_post_handler          /* post_handler */
};

static ngx_command_t ngx_http_auth_sasl_commands[] = {

    /* auth_sasl off | <realm name>; */
    {
        ngx_string("auth_sasl"),                        /* name */
        NGX_HTTP_MAIN_CONF |                            /* allow in main config */
        NGX_HTTP_SRV_CONF  |                            /* allow in server block */
        NGX_HTTP_LOC_CONF  |                            /* allow in location block */
        NGX_HTTP_LMT_CONF  |                            /* allow in limit_except block */
        NGX_CONF_TAKE1,                                 /* take one argument */
        ngx_conf_set_str_slot,                          /* set string value */
        NGX_HTTP_LOC_CONF_OFFSET,                       /* configuration to set */
        offsetof(ngx_http_auth_sasl_loc_conf_t, realm), /* field to set */
        &ngx_http_auth_sasl_post                        /* config post processing */
    },

    ngx_null_command
};

/* ========================================================================================
 * Module Interface
 * ======================================================================================== */

static ngx_http_module_t ngx_http_auth_sasl_module_ctx = {
    NULL,                                 /* preconfiguration */
    ngx_http_auth_sasl_init,              /* postconfiguration */

    NULL,                                 /* create main configuration */
    NULL,                                 /* init main configuration */

    NULL,                                 /* create server configuration */
    NULL,                                 /* merge server configuration */

    ngx_http_auth_sasl_create_loc_conf,   /* create location configuration */
    ngx_http_auth_sasl_merge_loc_conf     /* merge location configuration */
};

ngx_module_t ngx_http_auth_sasl_module = {
    NGX_MODULE_V1,
    &ngx_http_auth_sasl_module_ctx,       /* module context */
    ngx_http_auth_sasl_commands,          /* module directives */
    NGX_HTTP_MODULE,                      /* module type */
    NULL,                                 /* init master */
    NULL,                                 /* init module */
    NULL,                                 /* init process */
    NULL,                                 /* init thread */
    NULL,                                 /* exit thread */
    NULL,                                 /* exit process */
    NULL,                                 /* exit master */
    NGX_MODULE_V1_PADDING
};



#if 0
#include <sasl/sasl.h>
#include <stdio.h>
#include <string.h>

int
main(int argc, char* argv[])
{
    int          rc       = 0;
    char         user[]   = "julie";
    char         passwd[] = "1234";
    sasl_conn_t *conn     = NULL;

    rc = sasl_server_init(
            ngx_http_auth_sasl_callbacks,
            "nginx");

    if (rc != SASL_OK) {
        printf("sasl_server_init failed, rc=%d\n", rc);
        return rc;
    }

    rc = sasl_server_new("nginx", /* Registered name of service */
                         NULL,   /* my fully qualified domain name; NULL says use gethostname() */
                         NULL,   /* The user realm used for password lookups; NULL means default to serverFQDN Note: This does not affect Kerberos */
                         NULL,
                         NULL,    /* IP Address information strings */
                         NULL,    /* Callbacks supported only for this connection */
                         0,       /* security flags (security layers are enabled using security properties, separately) */
                         &conn);

    if (rc != SASL_OK) {
        printf("sasl_server_new failed, rc=%d\n", rc);
        return rc;
    }

    rc = sasl_checkpass(conn,
                        user, 0,
                        passwd, 0);

    printf("rc=%d\n", rc);
    return rc;
}

static int
ngx_http_auth_sasl_getopt_cb(
    void        *context,
    const char  *plugin_name,
    const char  *option,
    cons t char **result,
    unsigned    *len)
{
    printf("getopt_cb:\n  plugin_name=%s\n  option=%s\n", plugin_name, option);

    if (plugin_name == NULL) {
        if(strcmp("pwcheck_method", option) == 0) {
            printf("set saslauthd\n");
            *result = "saslauthd";
            if (len) {
                *len = strlen(*result);
            }
            return SASL_OK;
        }
    }

    return SASL_FAIL;
}

/*
 * Define a getopt callback so that SASL asks us for
 * configuration.
 */
static sasl_callback_t ngx_http_auth_sasl_callbacks[] = {
    {
        SASL_CB_GETOPT,                              /* id */
        (int (*)(void))ngx_http_auth_sasl_getopt_cb, /* proc */
        NULL                                         /* context */
    },

    { SASL_CB_LIST_END, NULL, NULL }
};
#endif
