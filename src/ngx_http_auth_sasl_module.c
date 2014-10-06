/*
 * Copyright (C) 2014 Julie Koubova <juliekoubova@icloud.com>
 *
 * Based on ngx_http_auth_basic_module by Igor Sysoev and
 * ngx_http_auth_pam_module by Sergio Talens-Oliag.
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include <sasl/sasl.h>

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
 * SASL Error Codes
 * ======================================================================================== */

static char* ngx_http_auth_sasl_errorcodes[] = {
    "SASL_INTERACT",          /*  2  */
    "SASL_CONTINUE",          /*  1  */
    "SASL_OK",                /*  0  */
    "SASL_FAIL",              /* -1  */
    "SASL_NOMEM",             /* -2  */
    "SASL_BUFOVER",           /* -3  */
    "SASL_NOMECH",            /* -4  */
    "SASL_BADPROT",           /* -5  */
    "SASL_NOTDONE",           /* -6  */
    "SASL_BADPARAM",          /* -7  */
    "SASL_TRYAGAIN",          /* -8  */
    "SASL_BADMAC",            /* -9  */
    "SASL_BADSERV",           /* -10 */
    "SASL_WRONGMECH",         /* -11 */
    "SASL_NOTINIT",           /* -12 */
    "SASL_BADAUTH",           /* -13 */
    "SASL_NOAUTHZ",           /* -14 */
    "SASL_TOOWEAK",           /* -15 */
    "SASL_ENCRYPT",           /* -16 */
    "SASL_TRANS",             /* -17 */
    "SASL_EXPIRED",           /* -18 */
    "SASL_DISABLED",          /* -19 */
    "SASL_NOUSER",            /* -20 */
    "SASL_PWLOCK",            /* -21 */
    "SASL_NOCHANGE",          /* -22 */
    "SASL_BADVERS",           /* -23 */
    "SASL_UNAVAIL",           /* -24 */
    NULL,                     /* -25 */
    "SASL_NOVERIFY",          /* -26 */
    "SASL_WEAKPASS",          /* -27 */
    "SASL_NOUSERPASS",        /* -28 */
    "SASL_NEED_OLD_PASSWD",   /* -29 */
    "SASL_CONSTRAINT_VIOLAT", /* -30 */
    NULL,                     /* -31 */
    "SASL_BADBINDING"         /* -32 */
};

/*
 * Covnerts a SASL return code into its textual form.
 */
static const char*
ngx_http_auth_sasl_errorcode_toa(int saslrc)
{
    if (saslrc < -32 || saslrc > 2) {
        return NULL;
    }

    return ngx_http_auth_sasl_errorcodes[2 - saslrc];
}

/*
 * Logs a successful SASL return codes as a NGX_LOG_DEBUG,
 * errors as NGX_LOG_ERR.
 */
static void
ngx_http_auth_sasl_log_sasl_result(
        ngx_http_request_t *r,
        const char         *message,
        int                 saslrc)
{
    const char *saslrc_str;
    ngx_uint_t  log_level;

    saslrc_str = ngx_http_auth_sasl_errorcode_toa(saslrc);
    log_level  = (saslrc >= 0) ? NGX_LOG_DEBUG : NGX_LOG_ERR;

    if (saslrc_str == NULL) {
        ngx_log_error(log_level, r->connection->log, 0,
                "%s: unknown SASL result %d", message, saslrc);
    } else {
        ngx_log_error(log_level, r->connection->log, 0,
                "%s: %s", message, saslrc_str);
    }
}

/* ========================================================================================
 * SASL Callbacks
 * ======================================================================================== */

static int
ngx_http_auth_sasl_getopt_cb(
    void        *context,
    const char  *plugin_name,
    const char  *option,
    const char **result,
    unsigned    *len)
{
    /* TODO: Make this configurable. */
    static const char     PWCHECK_METHOD[] = "pwcheck_method";
    static const char     SASLAUTHD[]      = "saslauthd";
    static const unsigned SASLAUTHD_LEN    = sizeof(SASLAUTHD) - 1;

    ngx_http_request_t *r        = context;
    unsigned            mylen    = 0;

    if (plugin_name == NULL) {
        plugin_name = "(null)";

        if (ngx_strcmp(PWCHECK_METHOD, option) == 0) {
            *result  = SASLAUTHD;
            mylen    = SASLAUTHD_LEN;
        }
    }

    if (r != NULL) {
        ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0,
                "ngx_http_auth_sasl_getopt_cb plugin_name:%s option:%s result:%s",
                plugin_name, option, (mylen ? *result : ""));
    }

    if (len != NULL) {
        *len = mylen;
    }

    return SASL_OK;
}

static ngx_int_t
ngx_http_auth_sasl_checkpass(
        ngx_http_request_t *r,
        ngx_str_t          *user,
        ngx_str_t          *password)
{

    /* Define a getopt callback so that SASL asks us for configuration.
     * Pass the current request as context. */
    sasl_callback_t ngx_http_auth_sasl_callbacks[] = {
        {
            SASL_CB_GETOPT,                              /* id */
            (int (*)(void))ngx_http_auth_sasl_getopt_cb, /* proc */
            r                                            /* context */
        },

        { SASL_CB_LIST_END, NULL, NULL }
    };

    sasl_conn_t *conn     = NULL;
    ngx_int_t    ngxrc    = NGX_ERROR;
    int          saslrc   = SASL_FAIL;

    /* Initialize the SASL global state.
     * TODO: Don't do this on every request.
     * TODO: Make app name configurable. */

    saslrc = sasl_server_init(
            ngx_http_auth_sasl_callbacks,
            "nginx");

    ngx_http_auth_sasl_log_sasl_result(
            r,
            "sasl_server_init",
            saslrc);

    if (saslrc != SASL_OK) {
        ngxrc = NGX_ERROR;
        goto cleanup;
    }

    /* Initialize the SASL connection state.
     * TODO: Provide SASL with all the client info.
     * TODO: Make service name configurable. */
    saslrc = sasl_server_new("nginx", /* Registered name of service */
                             NULL,    /* my fully qualified domain name; NULL says use gethostname() */
                             NULL,    /* The user realm used for password lookups; NULL means default to serverFQDN Note: This does not affect Kerberos */
                             NULL,    /* local IP address and port */
                             NULL,    /* remote IP address and port */
                             NULL,    /* Callbacks supported only for this connection */
                             0,       /* security flags (security layers are enabled using security properties, separately) */
                             &conn);

    ngx_http_auth_sasl_log_sasl_result(
            r,
            "sasl_server_new",
            saslrc);

    if (saslrc != SASL_OK) {
        ngxrc = NGX_ERROR;
        goto cleanup;
    }

    /* Check the password! */
    saslrc = sasl_checkpass(conn,
                            (char*)user->data,
                            user->len,
                            (char*)password->data,
                            password->len);

    ngx_http_auth_sasl_log_sasl_result(
            r,
            "sasl_server_checkpass",
            saslrc);

    switch (saslrc) {

    case SASL_OK:
        ngxrc = NGX_OK;
        break;

    case SASL_BADAUTH:
        ngxrc = NGX_DECLINED;
        break;

    default:
        ngxrc = NGX_ERROR;
        break;
    }

cleanup:

    if (conn != NULL) {
        sasl_dispose(&conn);
    }

    saslrc = sasl_server_done();
    ngx_http_auth_sasl_log_sasl_result(r, "sasl_server_done", saslrc);

    return ngxrc;
}

/* ========================================================================================
 * NGINX Access Handler
 * ======================================================================================== */

/*
 * Sends a WWW-Authenticate header with realm name
 * and returns HTTP 401 Authorization Required status.
 */
static ngx_int_t
ngx_http_auth_sasl_unauthorized(ngx_http_request_t *r, const ngx_str_t *realm)
{
    static const u_char HEADER_NAME[]   = "WWW-Authenticate";
    static const size_t HEADER_NAME_LEN = sizeof(HEADER_NAME) - 1;

    r->headers_out.www_authenticate = ngx_list_push(&r->headers_out.headers);
    if (r->headers_out.www_authenticate == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    r->headers_out.www_authenticate->hash     = 1;
    r->headers_out.www_authenticate->key.len  = HEADER_NAME_LEN;
    r->headers_out.www_authenticate->key.data = (u_char*)HEADER_NAME;
    r->headers_out.www_authenticate->value    = *realm;

    return NGX_HTTP_UNAUTHORIZED;
}

/*
 * Parses the username:password string provided by ngx_http_auth_basic_user
 * and calls ngx_http_auth_sasl_checkpass to validate the credentials.
 */
static ngx_int_t
ngx_http_auth_sasl_authenticate(
        ngx_http_request_t            *r,
        ngx_http_auth_sasl_loc_conf_t *lcf)
{
    ngx_str_t  user = { 0, NULL };
    ngx_int_t  rc;
    u_char    *p;

    /* The user field contains "username:password"
     * Let's find where the username ends. */
    for (user.len = 0; user.len < r->headers_in.user.len; user.len++) {
        if (r->headers_in.user.data[user.len] == ':') {
            break;
        }
    }

    user.data = ngx_palloc(r->pool, user.len + 1);
    if (user.data == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

     p = ngx_cpymem(user.data, r->headers_in.user.data, user.len);
    *p = '\0';

    rc = ngx_http_auth_sasl_checkpass(r, &user, &r->headers_in.passwd);

    if (rc == NGX_DECLINED) {
        return ngx_http_auth_sasl_unauthorized(r, &lcf->realm);
    }

    return rc;
}

/*
 * The request access phase handler. Uses ngx_http_auth_basic_user to decode the
 * credentials, then calls ngx_http_auth_sasl_authenticate to process them further.
 */
static ngx_int_t
ngx_http_auth_sasl_handler(ngx_http_request_t *r)
{
    ngx_http_auth_sasl_loc_conf_t  *lcf;
    ngx_int_t                       rc;

    lcf = ngx_http_get_module_loc_conf(r, ngx_http_auth_sasl_module);

    ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0,
            "ngx_http_auth_sasl_handler: realm:%s", lcf->realm.data);

    if (lcf->realm.len == 0) {
        /* SASL authentication is not enabled at this location. */
        return NGX_DECLINED;
    }

    /* Decode http auth user and passwd, leaving values on the request.
     * Implemented in ngx_http_core_module. */
    rc = ngx_http_auth_basic_user(r);

    if (rc == NGX_DECLINED) {
        /* No HTTP authentication header provided by the client.
         * Set realm and return HTTP Unauthorized. */
        return ngx_http_auth_sasl_unauthorized(r, &lcf->realm);
    }

    return ngx_http_auth_sasl_authenticate(r, lcf);
}

/* ========================================================================================
 * Configuration
 * ======================================================================================== */

/*
 * Register our request access phase handler.
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
 * doesn't need any further processing before being sent to the client.
 * If the realm name equals "off", the value is discarded, and
 * SASL authentication is disabled at the location.
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
