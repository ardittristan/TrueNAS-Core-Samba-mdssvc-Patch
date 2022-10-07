#pragma clang diagnostic push
#pragma ide diagnostic ignored "bugprone-reserved-identifier"
#pragma ide diagnostic ignored "ConstantFunctionResult"
#include <dlfcn.h>
#include <string.h>
#include "samba.h"

#pragma region [external functions]

static struct tevent_req * (*_tevent_req_create)(TALLOC_CTX *, void *, size_t, const char *, const char *);
static bool (*_tevent_req_nomem)(const void *, struct tevent_req *, const char *);
static struct tevent_req * (*tevent_req_post)(struct tevent_req *, struct tevent_context *);
static void (*tevent_req_set_callback)(struct tevent_req *, tevent_req_fn, void *);
static struct tevent_req * (*tstream_readv_pdu_send)(TALLOC_CTX *, struct tevent_context *, struct tstream_context *, tstream_readv_pdu_next_vector_t, void *);
static int (*tstream_readv_pdu_recv)(struct tevent_req *, int *);
static void * (*_tevent_req_callback_data)(struct tevent_req *);
static bool * (*_tevent_req_nterror)(struct tevent_req *, NTSTATUS, const char *);
static void (*_tevent_req_done)(struct tevent_req *, const char *);
static void * (*_talloc_zero)(const void *, size_t, const char *);
static void * (*_talloc_get_type_abort)(const void *, const char *, const char *);
static void * (*_talloc_array)(const void *, size_t, unsigned, const char *);
static void * (*_talloc_zero_array)(const void *, size_t, unsigned, const char *);
static void * (*_talloc_realloc_array)(const void *, void *, size_t, unsigned, const char *);
static void * (*_talloc_steal_loc)(const void *, const void *, const char *);
static char * (*talloc_strndup)(const void *, const char *, size_t);
static int (*_talloc_free)(void *, const char *);
static int (*http_add_header)(TALLOC_CTX *, struct http_header **, const char *, const char *);
static NTSTATUS (*map_nt_error_from_unix_common)(int);
static const char * (*nt_errstr)(NTSTATUS);

#define tevent_req_create(_mem_ctx, _pstate, _type) \
    _tevent_req_create((_mem_ctx), (_pstate), sizeof(_type), \
        #_type, __location__)

#define talloc_zero(ctx, type) (type *)_talloc_zero(ctx, sizeof(type), #type)

#define talloc_array(ctx, type, count) (type *)_talloc_array(ctx, sizeof(type), count, #type)

#define talloc_zero_array(ctx, type, count) (type *)_talloc_zero_array(ctx, sizeof(type), count, #type)

#define talloc_realloc(ctx, p, type, count) (type *)_talloc_realloc_array(ctx, p, sizeof(type), count, #type)

#define talloc_free(ctx) _talloc_free(ctx, __location__)

#define TALLOC_FREE(ctx) do { if ((ctx) != NULL) { talloc_free(ctx); (ctx)=NULL; } } while(0)

#if (__GNUC__ >= 3)
#define _TALLOC_TYPEOF(ptr) __typeof__(ptr)
#define talloc_steal(ctx, ptr) ({ _TALLOC_TYPEOF(ptr) __talloc_steal_ret = (_TALLOC_TYPEOF(ptr))_talloc_steal_loc((ctx),(ptr), __location__); __talloc_steal_ret; })
#else
#define _TALLOC_TYPEOF(ptr) void *
#define talloc_steal(ctx, ptr) (_TALLOC_TYPEOF(ptr))_talloc_steal_loc((ctx),(ptr), __location__)
#endif

#define tevent_req_nomem(p, req) \
    _tevent_req_nomem(p, req, __location__)

#define talloc_get_type_abort(ptr, type) (type *)_talloc_get_type_abort(ptr, #type, __location__)

#define tevent_req_callback_data(_req, _type) \
    talloc_get_type_abort(_tevent_req_callback_data(_req), _type)

#define tevent_req_nterror(req, status) \
    _tevent_req_nterror(req, status, __location__)

#define tevent_req_done(req) \
    _tevent_req_done(req, __location__)

__attribute__((unused)) void __attribute__((constructor)) patch_main() {
    void *libtevent_handle = dlopen("/usr/local/lib/samba4/private/libtevent.so.0", RTLD_LAZY);
    void *libtalloc_handle = dlopen("/usr/local/lib/samba4/private/libtalloc.so.2", RTLD_LAZY);
    void *libsamba_sockets_samba4_handle = dlopen("/usr/local/lib/samba4/private/libsamba-sockets-samba4.so", RTLD_LAZY);
    void *libhttp_samba4_handle = dlopen("/usr/local/lib/samba4/private/libhttp-samba4.so", RTLD_LAZY);
    void *libsamba_errors_handle = dlopen("/usr/local/lib/samba4/libsamba-errors.so", RTLD_LAZY);
    void *libtevent_util_handle = dlopen("/usr/local/lib/samba4/libtevent-util.so", RTLD_LAZY);

    _tevent_req_create = dlsym(libtevent_handle, "_tevent_req_create");
    _tevent_req_nomem = dlsym(libtevent_handle, "_tevent_req_nomem");
    tevent_req_post = dlsym(libtevent_handle, "tevent_req_post");
    tevent_req_set_callback = dlsym(libtevent_handle, "tevent_req_set_callback");
    _tevent_req_callback_data = dlsym(libtevent_handle, "_tevent_req_callback_data");
    _tevent_req_done = dlsym(libtevent_handle, "_tevent_req_done");
    _tevent_req_nterror = dlsym(libtevent_util_handle, "_tevent_req_nterror");
    _talloc_zero = dlsym(libtalloc_handle, "_talloc_zero");
    _talloc_get_type_abort = dlsym(libtalloc_handle, "_talloc_get_type_abort");
    _talloc_free = dlsym(libtalloc_handle, "_talloc_free");
    _talloc_array = dlsym(libtalloc_handle, "_talloc_array");
    _talloc_zero_array = dlsym(libtalloc_handle, "_talloc_zero_array");
    _talloc_realloc_array = dlsym(libtalloc_handle, "_talloc_realloc_array");
    _talloc_steal_loc = dlsym(libtalloc_handle, "_talloc_steal_loc");
    talloc_strndup = dlsym(libtalloc_handle, "talloc_strndup");
    tstream_readv_pdu_send = dlsym(libsamba_sockets_samba4_handle, "tstream_readv_pdu_send");
    tstream_readv_pdu_recv = dlsym(libsamba_sockets_samba4_handle, "tstream_readv_pdu_recv");
    map_nt_error_from_unix_common = dlsym(libsamba_errors_handle, "map_nt_error_from_unix_common");
    nt_errstr = dlsym(libsamba_errors_handle, "nt_errstr");
    http_add_header = dlsym(libhttp_samba4_handle, "http_add_header");
}

#pragma endregion

static bool http_parse_response_line(struct http_read_response_state *state) {
    bool	status = true;
    char	*protocol = NULL;
    char	*msg = NULL;
    char	major;
    char	minor;
    int	code;
    char	*line = NULL;
    int	n;

    /* Sanity checks */
    if (!state) {
        DEBUG(0, ("%s: Input parameter is NULL\n", __func__));
        return false;
    }

    line = talloc_strndup(state, (char*)state->buffer.data, state->buffer.length);
    if (!line) {
        DEBUG(0, ("%s: Memory error\n", __func__));
        return false;
    }

    int s0, s1, s2, s3; s0 = s1 = s2 = s3 = 0;
    n = sscanf(line, "%n%*[^/]%n/%c.%c %d %n%*[^\r\n]%n\r\n", &s0, &s1, &major, &minor, &code, &s2, &s3);
    if(n == 3) {
        protocol = calloc(sizeof(char), s1-s0+1);
        msg = calloc(sizeof(char), s3-s2+1);

        n = sscanf(line, "%[^/]/%c.%c %d %[^\r\n]\r\n", protocol, &major, &minor, &code, msg);
    }

    if (n != 5) {
        DEBUG(0, ("%s: Error parsing header\n",	__func__));
        status = false;
        goto error;
    }

    DEBUG(11, ("%s: Header parsed(%i): protocol->%s, major->%c, minor->%c, "
               "code->%d, message->%s\n", __func__, n, protocol, major, minor,
            code, msg));

    if (major != '1') {
        DEBUG(0, ("%s: Bad HTTP major number '%c'\n", __func__, major));
        status = false;
        goto error;
    }

    if (code == 0) {
        DEBUG(0, ("%s: Bad response code '%d'", __func__, code));
        status = false;
        goto error;
    }

    if (msg == NULL) {
        DEBUG(0, ("%s: Error parsing HTTP data\n", __func__));
        status = false;
        goto error;
    }

    state->response->major = major;
    state->response->minor = minor;
    state->response->response_code = code;
    state->response->response_code_line = talloc_strndup(state->response,
                                                         msg, strlen(msg));

    error:
    free(protocol);
    free(msg);
    TALLOC_FREE(line);
    return status;
}

static int http_response_needs_body(struct http_request *req) {
    struct http_header *h = NULL;

    if (!req) return -1;

    for (h = req->headers; h != NULL; h = h->next) {
        int cmp;
        int n;
        char c;
        unsigned long long v;

        cmp = strcasecmp(h->key, "Content-Length");
        if (cmp != 0) {
            continue;
        }

        n = sscanf(h->value, "%llu%c", &v, &c);
        if (n != 1) {
            return -1;
        }

        req->remaining_content_length = v;

        if (v != 0) {
            return 1;
        }

        return 0;
    }

    return 0;
}

static enum http_read_status http_parse_firstline(struct http_read_response_state *state) {
    enum http_read_status	status = HTTP_ALL_DATA_READ;
    char			*ptr = NULL;
    char			*line;

    /* Sanity checks */
    if (!state) {
        DEBUG(0, ("%s: Invalid Parameter\n", __func__));
        return HTTP_DATA_CORRUPTED;
    }

    if (state->buffer.length > state->max_headers_size) {
        DEBUG(0, ("%s: Headers too long: %zi, maximum length is %zi\n", __func__,
                state->buffer.length, state->max_headers_size));
        return HTTP_DATA_TOO_LONG;
    }

    line = talloc_strndup(state, (char *)state->buffer.data, state->buffer.length);
    if (!line) {
        DEBUG(0, ("%s: Not enough memory\n", __func__));
        return HTTP_DATA_CORRUPTED;
    }

    ptr = strstr(line, "\r\n");
    if (ptr == NULL) {
        TALLOC_FREE(line);
        return HTTP_MORE_DATA_EXPECTED;
    }

    state->response->headers_size = state->buffer.length;
    if (!http_parse_response_line(state)) {
        status = HTTP_DATA_CORRUPTED;
    }

    /* Next state, read HTTP headers */
    state->parser_state = HTTP_READING_HEADERS;

    TALLOC_FREE(line);
    return status;
}

static enum http_read_status http_parse_headers(struct http_read_response_state *state) {
    enum http_read_status	status = HTTP_ALL_DATA_READ;
    char			*ptr = NULL;
    char			*line = NULL;
    char			*key = NULL;
    char			*value = NULL;
    int			n = 0;
    int			ret;

    /* Sanity checks */
    if (!state || !state->response) {
        DEBUG(0, ("%s: Invalid Parameter\n", __func__));
        return HTTP_DATA_CORRUPTED;
    }

    if (state->buffer.length > state->max_headers_size) {
        DEBUG(0, ("%s: Headers too long: %zi, maximum length is %zi\n", __func__,
                state->buffer.length, state->max_headers_size));
        return HTTP_DATA_TOO_LONG;
    }

    line = talloc_strndup(state, (char *)state->buffer.data, state->buffer.length);
    if (!line) {
        DEBUG(0, ("%s: Memory error\n", __func__));
        return HTTP_DATA_CORRUPTED;
    }

    ptr = strstr(line, "\r\n");
    if (ptr == NULL) {
        TALLOC_FREE(line);
        return HTTP_MORE_DATA_EXPECTED;
    }

    state->response->headers_size += state->buffer.length;

    if (strncmp(line, "\r\n", 2) == 0) {
        DEBUG(11,("%s: All headers read\n", __func__));

        ret = http_response_needs_body(state->response);
        switch (ret) {
            case 1:
                if (state->response->remaining_content_length <= state->max_content_length) {
                    DEBUG(11, ("%s: Start of read body\n", __func__));
                    state->parser_state = HTTP_READING_BODY;
                    break;
                }
                FALL_THROUGH;
            case 0:
                DEBUG(11, ("%s: Skipping body for code %d\n", __func__,
                        state->response->response_code));
                state->parser_state = HTTP_READING_DONE;
                break;
            case -1:
                DEBUG(0, ("%s_: Error in http_response_needs_body\n", __func__));
                TALLOC_FREE(line);
                return HTTP_DATA_CORRUPTED;
                break;
        }

        TALLOC_FREE(line);
        return HTTP_ALL_DATA_READ;
    }

    int s0, s1, s2, s3; s0 = s1 = s2 = s3 = 0;
    n = sscanf(line, "%n%*[^:]%n: %n%*[^\r\n]%n\r\n", &s0, &s1, &s2, &s3);
    if(n >= 0) {
        key = calloc(sizeof(char), s1-s0+1);
        value = calloc(sizeof(char), s3-s2+1);

        n = sscanf(line, "%[^:]: %[^\r\n]\r\n", key, value);
    }
    if (n != 2) {
        DEBUG(0, ("%s: Error parsing header '%s'\n", __func__, line));
        status = HTTP_DATA_CORRUPTED;
        goto error;
    }

    if (http_add_header(state->response, &state->response->headers, key, value) == -1) {
        DEBUG(0, ("%s: Error adding header\n", __func__));
        status = HTTP_DATA_CORRUPTED;
        goto error;
    }

    error:
    free(key);
    free(value);
    TALLOC_FREE(line);
    return status;
}

static enum http_read_status http_read_body(struct http_read_response_state *state) {
    struct http_request *resp = state->response;

    if (state->buffer.length < resp->remaining_content_length) {
        return HTTP_MORE_DATA_EXPECTED;
    }

    resp->body = state->buffer;
    state->buffer = data_blob_null;
    talloc_steal(resp, resp->body.data);
    resp->remaining_content_length = 0;

    state->parser_state = HTTP_READING_DONE;
    return HTTP_ALL_DATA_READ;
}

static enum http_read_status http_read_trailer(struct http_read_response_state *state) {
    enum http_read_status status = HTTP_DATA_CORRUPTED;
    /* TODO */
    return status;
}

static enum http_read_status http_parse_buffer(struct http_read_response_state *state) {
    if (!state) {
        DEBUG(0, ("%s: Invalid parameter\n", __func__));
        return HTTP_DATA_CORRUPTED;
    }

    switch (state->parser_state) {
        case HTTP_READING_FIRSTLINE:
            return http_parse_firstline(state);
        case HTTP_READING_HEADERS:
            return http_parse_headers(state);
        case HTTP_READING_BODY:
            return http_read_body(state);
        case HTTP_READING_TRAILER:
            return http_read_trailer(state);
        case HTTP_READING_DONE:
            /* All read */
            return HTTP_ALL_DATA_READ;
        default:
            DEBUG(0, ("%s: Illegal parser state %d", __func__,
                    state->parser_state));
            break;
    }
    return HTTP_DATA_CORRUPTED;
}

static int http_read_response_next_vector(struct tstream_context *stream, void *private_data, TALLOC_CTX *mem_ctx, struct iovec **_vector, size_t *_count) {
    struct http_read_response_state *state;
    struct iovec *vector;

    /* Sanity checks */
    if (!stream || !private_data || !_vector || !_count) {
        DEBUG(0, ("%s: Invalid Parameter\n", __func__));
        return -1;
    }

    state = talloc_get_type_abort(private_data, struct http_read_response_state);
    vector = talloc_array(mem_ctx, struct iovec, 1);

    if (!vector) {
        DEBUG(0, ("%s: No more memory\n", __func__));
        return -1;
    }

    if (state->buffer.data == NULL) {
        state->buffer.data = talloc_zero_array(state, uint8_t, 1);
        if (!state->buffer.data) {
            DEBUG(0, ("%s: No more memory\n", __func__));
            return -1;
        }
        state->buffer.length = 1;

        /* Return now, nothing to parse yet */
        vector[0].iov_base = (void *)(state->buffer.data);
        vector[0].iov_len = 1;
        *_vector = vector;
        *_count = 1;
        return 0;
    }

    switch(http_parse_buffer(state)) {
        case HTTP_ALL_DATA_READ:
            if (state->parser_state == HTTP_READING_DONE) {
                /* Full request or response parsed */
                *_vector = NULL;
                *_count = 0;
            } else {
                /* Free current buffer and allocate new one */
                TALLOC_FREE(state->buffer.data);
                state->buffer.data = talloc_zero_array(state, uint8_t, 1);
                if (!state->buffer.data) {
                    return -1;
                }
                state->buffer.length = 1;

                vector[0].iov_base = (void *)(state->buffer.data);
                vector[0].iov_len = 1;
                *_vector = vector;
                *_count = 1;
            }
            break;
        case HTTP_MORE_DATA_EXPECTED:
            /* TODO Optimize, allocating byte by byte */
            state->buffer.data = talloc_realloc(state, state->buffer.data,
                                                uint8_t, state->buffer.length + 1);
            if (!state->buffer.data) {
                return -1;
            }
            state->buffer.length++;
            vector[0].iov_base = (void *)(state->buffer.data +
                                          state->buffer.length - 1);
            vector[0].iov_len = 1;
            *_vector = vector;
            *_count = 1;
            break;
        case HTTP_DATA_CORRUPTED:
        case HTTP_REQUEST_CANCELED:
        case HTTP_DATA_TOO_LONG:
            return -1;
        default:
            DEBUG(0, ("%s: Unexpected status\n", __func__));
            break;
    }
    return 0;
}

static void http_read_response_done(struct tevent_req *);
__attribute__((unused)) struct tevent_req *http_read_response_send(TALLOC_CTX *mem_ctx, struct tevent_context *ev, struct http_conn *http_conn, size_t max_content_length) {
    struct tevent_req *req;
    struct tevent_req *subreq;
    struct http_read_response_state *state;

    if (ev == NULL || http_conn == NULL)
        return NULL;

    req = tevent_req_create(mem_ctx, &state, struct http_read_response_state);

    if (req == NULL)
        return NULL;

    state->max_headers_size = HTTP_MAX_HEADER_SIZE;
    state->max_content_length = (uint64_t)max_content_length;
    state->parser_state = HTTP_READING_FIRSTLINE;
    state->response = talloc_zero(state, struct http_request);
    if (tevent_req_nomem(state->response, req))
        return tevent_req_post(req, ev);

    subreq = tstream_readv_pdu_send(state, ev, http_conn->tstreams.active, http_read_response_next_vector, state);
    if (tevent_req_nomem(subreq, req))
        return tevent_req_post(req, ev);

    tevent_req_set_callback(subreq, (tevent_req_fn) http_read_response_done, req);

    return req;
}

static void http_read_response_done(struct tevent_req *subreq){
    NTSTATUS status;
    struct tevent_req *req;
    int ret;
    int sys_errno;

    if (!subreq) {
        DEBUG(0, ("%s: Invalid parameter\n", __func__));
        return;
    }

    req = tevent_req_callback_data(subreq, struct tevent_req);

    ret = tstream_readv_pdu_recv(subreq, &sys_errno);
    DEBUG(11, ("%s: HTTP response read (%d bytes)\n", __func__, ret));
    TALLOC_FREE(subreq);
    if (ret == -1){
        status = map_nt_error_from_unix_common(sys_errno);
        DEBUG(0, ("%s: Failed to read HTTP response: %s\n",
                __func__, nt_errstr(status)));
        tevent_req_nterror(req, status);
        return;
    }

    tevent_req_done(req);
}
#pragma clang diagnostic pop