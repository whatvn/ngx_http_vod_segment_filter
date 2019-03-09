#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <stdlib.h>
#include <math.h>

#define MIN_SIZE 1024

typedef struct {
    ngx_flag_t ts_filter;
    ngx_regex_compile_t *ts_num_regex;
    ngx_regex_compile_t *uri_begin_regex; // will be use for cache key
} ngx_ts_filter_loc_conf_t;


static ngx_str_t SEGMENT_NUM_PATTERN = ngx_string(".*-(\\d+)-v1-a1.ts");
static ngx_str_t URI_BEGIN_PATTERN = ngx_string("(.*-)\\d+-v1-a1.ts");
static ngx_str_t URI_END = ngx_string("-v1-a1.ts");

static void *ngx_ts_create_loc_conf(ngx_conf_t *cf);
static char *ngx_ts_merge_loc_conf(ngx_conf_t *cf,
        void *parent, void *child);
static ngx_int_t ngx_ts_filter_init(ngx_conf_t *cf);


static ngx_command_t ngx_ts_filter_commands[] = {

    { ngx_string("ts_filter"),
        NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
        ngx_conf_set_flag_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_ts_filter_loc_conf_t, ts_filter),
        NULL},
    ngx_null_command
};


static ngx_http_module_t ngx_ts_filter_module_ctx = {
    NULL, /* proconfiguration */
    ngx_ts_filter_init, /* postconfiguration */

    NULL, /* create main configuration */
    NULL, /* init main configuration */

    NULL, /* create server configuration */
    NULL, /* merge server configuration */

    ngx_ts_create_loc_conf, /* create location configuration */
    ngx_ts_merge_loc_conf /* merge location configuration */
};


ngx_module_t ngx_ts_filter_module = {
    NGX_MODULE_V1,
    &ngx_ts_filter_module_ctx, /* module context */
    ngx_ts_filter_commands, /* module directives */
    NGX_HTTP_MODULE, /* module type */
    NULL, /* init master */
    NULL, /* init module */
    NULL, /* init process */
    NULL, /* init thread */
    NULL, /* exit thread */
    NULL, /* exit process */
    NULL, /* exit master */
    NGX_MODULE_V1_PADDING
};

ngx_regex_compile_t *
ngx_ts_init_regex(ngx_conf_t *cf, ngx_str_t pattern) {

    ngx_regex_compile_t *rc;

    u_char errstr[NGX_MAX_CONF_ERRSTR];


    rc = ngx_palloc(cf->pool, sizeof (ngx_regex_compile_t));

    if (rc == NULL) {
        return NULL;
    }

    ngx_memzero(rc, sizeof (ngx_regex_compile_t));

    rc->pattern = pattern;
    rc->pool = cf->pool;
    rc->err.len = NGX_MAX_CONF_ERRSTR;
    rc->err.data = errstr;

    if (ngx_regex_compile(rc) != NGX_OK) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "%V", &rc->err);
        return NULL;
    }
    return rc;
}

static void *
ngx_ts_create_loc_conf(ngx_conf_t *cf) {
    ngx_ts_filter_loc_conf_t *conf;

    conf = ngx_pcalloc(cf->pool,
            sizeof (ngx_ts_filter_loc_conf_t));
    if (conf == NULL) {
        return NGX_CONF_ERROR;
    }
    conf->ts_filter = NGX_CONF_UNSET;
    // conf->shm_zone = NULL;

    return conf;
}

static char *
ngx_ts_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child) {
    ngx_ts_filter_loc_conf_t *prev = parent;
    ngx_ts_filter_loc_conf_t *conf = child;
    ngx_conf_merge_value(conf->ts_filter,
            prev->ts_filter, 0);

    if (conf->ts_filter) {
        conf->ts_num_regex = ngx_ts_init_regex(cf, SEGMENT_NUM_PATTERN);
        if (conf->ts_num_regex == NULL) {
            return NGX_CONF_ERROR;
        }
        conf->uri_begin_regex = ngx_ts_init_regex(cf, URI_BEGIN_PATTERN);
        if (conf->uri_begin_regex == NULL) {
            return NGX_CONF_ERROR;
        }
    }
    return NGX_CONF_OK;
}
static ngx_http_output_header_filter_pt ngx_http_next_header_filter;

static ngx_str_t ngx_ts_filter_parse_uri(ngx_http_request_t *r, ngx_regex_compile_t *regex) {
    ngx_str_t *uri = &r->uri;
    u_char *p;
    size_t size;
    ngx_str_t name = ngx_null_string, value = ngx_null_string;
    int i;

    ngx_ts_filter_loc_conf_t *lcf;

    lcf = ngx_http_get_module_loc_conf(r, ngx_ts_filter_module);

    if (lcf == NULL) {
        return value;
    }
    ngx_regex_compile_t *rc = regex;

    ngx_int_t n;
    int captures[(1 + rc->captures) * 3];

    n = ngx_regex_exec(rc->regex, uri, captures, (1 + rc->captures) * 3);
    if (n >= 0) {
        for (i = 0; i < n * 2; i += 2) {
            value.data = uri->data + captures[i];
            value.len = captures[i + 1] - captures[i];
        }
        size = rc->name_size;
        p = rc->names;

        for (i = 0; i < rc->named_captures; i++, p += size) {
            /* capture name */
            name.data = &p[2];
            name.len = ngx_strlen(name.data);

            n = 2 * ((p[0] << 8) + p[1]);

            /* captured value */
            value.data = &uri->data[captures[n]];
            value.len = captures[n + 1] - captures[n];
        }
    }
    return value;
}

static ngx_int_t ngx_ts_filter_parse_len(ngx_int_t index) {
    return index == 0 ? 1 : (ngx_int_t) (log10(abs(index))) + 1;
}

static ngx_str_t ngx_ts_filter_get_next_url(ngx_http_request_t *r, ngx_str_t *path, ngx_int_t index) {
    ngx_int_t len;
    u_char *buf, *p;
    ngx_str_t url = ngx_null_string;

    ngx_int_t index_len = ngx_ts_filter_parse_len(index);
    len = path->len + index_len + URI_END.len;
    buf = ngx_palloc(r->connection->pool, len);

    if (buf == NULL) {
        return url;
    }
    p = buf;
    p = ngx_snprintf(buf, path->len, "%s", path->data);
    p = ngx_snprintf(p, index_len, "%d", index);
    p = ngx_snprintf(p, URI_END.len, "%s", URI_END.data);
    url.data = buf;
    url.len = len;
    return url;
}

// static ngx_int_t ngx_ts_filter_redirect(ngx_http_request_t *r, ngx_str_t *url) {
//     return ngx_http_internal_redirect(r, url, &r->args);
// }

static ngx_int_t
ngx_ts_header_filter(ngx_http_request_t *r) {

    ngx_ts_filter_loc_conf_t *lcf;
    ngx_str_t result;
    ngx_int_t index;
    ngx_str_t url;
    ngx_str_t *location;

    ngx_log_debug(NGX_LOG_DEBUG, r->connection->log, 0,
            "#######START#######http ts header filter module");

    lcf = ngx_http_get_module_loc_conf(r, ngx_ts_filter_module);

    if (r->header_only
            || (r->method & NGX_HTTP_HEAD)
            //            || r->main->internal
            || r->headers_out.status == NGX_HTTP_NO_CONTENT
            ||  r->headers_out.content_length_n <= 0
            || lcf == NULL
            || !lcf->ts_filter) {
        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "url: %V, internal: %d",
                &r->uri, r->main->internal);
        return ngx_http_next_header_filter(r);
    }

    if (r->headers_out.status == NGX_HTTP_OK && r->headers_out.content_length_n < MIN_SIZE) 
    {
        result = ngx_ts_filter_parse_uri(r, lcf->ts_num_regex);

        if (result.len == 0) {
            /* wont process not ts link */
            return ngx_http_next_header_filter(r);
        }

        
        index = ngx_atoi(result.data, result.len);
        if (index == NGX_ERROR) {
            return ngx_http_next_header_filter(r);
        }

        index += 1;
        result = ngx_ts_filter_parse_uri(r, lcf->uri_begin_regex);
        if (result.len == 0) {
            /* wont process not ts link */
            return ngx_http_next_header_filter(r);
        }
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "####nginx http ts header filter module, content length: %d", r->headers_out.content_length_n);
        url = ngx_ts_filter_get_next_url(r, &result, index);
        if (url.len == 0) {
            return ngx_http_next_header_filter(r);
        }

        location = ngx_palloc(r->pool, sizeof(ngx_str_t));
        location->data = ngx_palloc(r->pool, url.len + r->args.len + 1);
        location->len = url.len + r->args.len + (r->args.len > 0 ? 1 : 0);
        u_char *buf;
        buf = location->data;
        buf = ngx_copy(buf, url.data, url.len);
        if (r->args.len > 0) {
            *buf++ = '?';
            ngx_memcpy(buf, r->args.data, r->args.len);
        }
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "####nginx http ts header filter module, url: %V, content-length: %d, redirect to its next segment, next segment url: %V",
                &r->uri, r->headers_out.content_length_n, &url);
        r->headers_out.location = ngx_list_push(&r->headers_out.headers);
        if (r->headers_out.location == NULL) {
            ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
        }
        r->headers_out.location->hash = 1;
        r->headers_out.location->key.len = sizeof("Location") - 1;
        r->headers_out.location->key.data = (u_char *) "Location";
        r->headers_out.location->value.len = location->len;
        r->headers_out.location->value.data = location->data; 
        return NGX_HTTP_MOVED_TEMPORARILY;         
    }
    ngx_log_debug1(NGX_LOG_DEBUG, r->connection->log, 0, "####nginx http ts header filter module, do not process, return to next filter: %V ", &r->uri);
    return ngx_http_next_header_filter(r);
}


static ngx_int_t
ngx_ts_filter_init(ngx_conf_t *cf) {
    ngx_http_next_header_filter = ngx_http_top_header_filter;
    ngx_http_top_header_filter = ngx_ts_header_filter;

    return NGX_OK;
}
