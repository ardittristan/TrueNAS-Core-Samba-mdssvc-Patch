#ifndef SSCANFPATCH_SAMBA_H
#define SSCANFPATCH_SAMBA_H
#pragma clang diagnostic push
#pragma ide diagnostic ignored "bugprone-reserved-identifier"

#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <sys/uio.h>
#include <inttypes.h>
#include <sys/time.h>
#include "talloc.h"
#include "tevent.h"
#include "tsocket.h"
#include "debug.h"

enum http_parser_state {
    HTTP_READING_FIRSTLINE,
    HTTP_READING_HEADERS,
    HTTP_READING_BODY,
    HTTP_READING_TRAILER,
    HTTP_READING_DONE,
};

enum http_read_status {
    HTTP_ALL_DATA_READ,
    HTTP_MORE_DATA_EXPECTED,
    HTTP_DATA_CORRUPTED,
    HTTP_REQUEST_CANCELED,
    HTTP_DATA_TOO_LONG,
};

typedef struct datablob {
    uint8_t *data;
    size_t length;
} DATA_BLOB;

const DATA_BLOB data_blob_null = { NULL, 0 };

struct http_read_response_state {
    enum http_parser_state	parser_state;
    size_t			max_headers_size;
    uint64_t		max_content_length;
    DATA_BLOB		buffer;
    struct http_request	*response;
};

enum http_cmd_type {
    HTTP_REQ_GET		= 1 << 0,
    HTTP_REQ_POST		= 1 << 1,
    HTTP_REQ_HEAD		= 1 << 2,
    HTTP_REQ_PUT		= 1 << 3,
    HTTP_REQ_DELETE		= 1 << 4,
    HTTP_REQ_OPTIONS	= 1 << 5,
    HTTP_REQ_TRACE		= 1 << 6,
    HTTP_REQ_CONNECT	= 1 << 7,
    HTTP_REQ_PATCH		= 1 << 8,
    HTTP_REQ_RPC_IN_DATA	= 1 << 9,
    HTTP_REQ_RPC_OUT_DATA	= 1 << 10,
};

struct http_header {
    struct http_header	*next, *prev;
    char			*key;
    char			*value;
};

struct http_conn {
    struct tevent_queue *send_queue;
    struct {
        struct tstream_context *raw;
        struct tstream_context *tls;
        struct tstream_context *active;
    } tstreams;
};

struct http_request {
    enum http_cmd_type	type;
    char			major;
    char			minor;
    char			*uri;
    struct http_header	*headers;
    size_t			headers_size;
    unsigned int		response_code;
    char			*response_code_line;
    uint64_t		remaining_content_length;
    DATA_BLOB		body;
};

#ifndef __location__
#define __TALLOC_STRING_LINE1__(s)    #s
#define __TALLOC_STRING_LINE2__(s)   __TALLOC_STRING_LINE1__(s)
#define __TALLOC_STRING_LINE3__  __TALLOC_STRING_LINE2__(__LINE__)
#define __location__ __FILE__ ":" __TALLOC_STRING_LINE3__
#endif

typedef uint32_t NTSTATUS;
#define NT_STATUS(x) (x)
#define NT_STATUS_V(x) (x)

#define HTTP_MAX_HEADER_SIZE	0x1FFFF

#ifndef FALL_THROUGH
#define FALL_THROUGH __attribute__ ((fallthrough))
#endif

#pragma clang diagnostic pop
#endif //SSCANFPATCH_SAMBA_H