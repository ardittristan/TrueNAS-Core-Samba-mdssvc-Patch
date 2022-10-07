/*
   Unix SMB/CIFS implementation.

   generalised event loop handling

   INTERNAL STRUCTS. THERE ARE NO API GUARANTEES.
   External users should only ever have to include this header when
   implementing new tevent backends.

   Copyright (C) Stefan Metzmacher 2005-2009

     ** NOTE! The following LGPL license applies to the tevent
     ** library. This does NOT imply that all of Samba is released
     ** under the LGPL

   This library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 3 of the License, or (at your option) any later version.

   This library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with this library; if not, see <http://www.gnu.org/licenses/>.
*/

enum tevent_req_state {
    TEVENT_REQ_INIT,
    TEVENT_REQ_IN_PROGRESS,
    TEVENT_REQ_DONE,
    TEVENT_REQ_USER_ERROR,
    TEVENT_REQ_TIMED_OUT,
    TEVENT_REQ_NO_MEMORY,
    TEVENT_REQ_RECEIVED
};

enum tevent_event_trace_point {
    TEVENT_EVENT_TRACE_ATTACH,
    TEVENT_EVENT_TRACE_DETACH,
    TEVENT_EVENT_TRACE_BEFORE_HANDLER,
};

enum tevent_trace_point {
    TEVENT_TRACE_BEFORE_WAIT,
    TEVENT_TRACE_AFTER_WAIT,
#define TEVENT_HAS_LOOP_ONCE_TRACE_POINTS 1
    TEVENT_TRACE_BEFORE_LOOP_ONCE,
    TEVENT_TRACE_AFTER_LOOP_ONCE,
};

enum tevent_debug_level {
    TEVENT_DEBUG_FATAL,
    TEVENT_DEBUG_ERROR,
    TEVENT_DEBUG_WARNING,
    TEVENT_DEBUG_TRACE
};

#define PRINTF_ATTRIBUTE(a1, a2) __attribute__ ((format (__printf__, a1, a2)))
typedef void (*tevent_req_fn)(struct tevent_req *subreq);
typedef char *(*tevent_req_print_fn)(struct tevent_req *req, TALLOC_CTX *ctx);
typedef bool (*tevent_req_cancel_fn)(struct tevent_req *req);
typedef void (*tevent_req_cleanup_fn)(struct tevent_req *req, enum tevent_req_state req_state);

struct tevent_req {
    struct {
        tevent_req_fn fn;
        void *private_data;
    } async;
    void *data;
    tevent_req_print_fn private_print;
    tevent_req_cancel_fn private_cancel;
    struct {
        tevent_req_cleanup_fn fn;
        enum tevent_req_state state;
    } private_cleanup;

    struct {
        const char *private_type;
        const char *create_location;
        const char *finish_location;
        const char *cancel_location;
        enum tevent_req_state state;
        uint64_t error;
        struct tevent_immediate *trigger;
        struct tevent_context *defer_callback_ev;
        struct tevent_timer *timer;
        struct tevent_req_profile *profile;
    } internal;
};

typedef void (*tevent_fd_handler_t)(struct tevent_context *ev, struct tevent_fd *fde, uint16_t flags, void *private_data);
typedef void (*tevent_fd_close_fn_t)(struct tevent_context *ev, struct tevent_fd *fde, int fd, void *private_data);

struct tevent_fd {
    struct tevent_fd *prev, *next;
    struct tevent_context *event_ctx;
    struct tevent_wrapper_glue *wrapper;
    bool busy;
    bool destroyed;
    int fd;
    uint16_t flags;
    tevent_fd_handler_t handler;
    tevent_fd_close_fn_t close_fn;
    void *private_data;
    const char *handler_name;
    const char *location;
    uint64_t additional_flags;
    void *additional_data;
    uint64_t tag;
};

typedef void (*tevent_timer_handler_t)(struct tevent_context *ev, struct tevent_timer *te, struct timeval current_time, void *private_data);
typedef void (*tevent_immediate_handler_t)(struct tevent_context *ctx, struct tevent_immediate *im, void *private_data);
typedef void (*tevent_signal_handler_t)(struct tevent_context *ev, struct tevent_signal *se, int signum, int count, void *siginfo, void *private_data);

struct tevent_signal {
    struct tevent_signal *prev, *next;
    struct tevent_context *event_ctx;
    struct tevent_wrapper_glue *wrapper;
    bool busy;
    bool destroyed;
    int signum;
    int sa_flags;
    tevent_signal_handler_t handler;
    void *private_data;
    const char *handler_name;
    const char *location;
    void *additional_data;
    uint64_t tag;
};

typedef int (*tevent_nesting_hook)(struct tevent_context *ev, void *private_data, uint32_t level, bool begin, void *stack_ptr, const char *location);
typedef void (*tevent_trace_callback_t)(enum tevent_trace_point, void *private_data);
typedef void (*tevent_trace_fd_callback_t)(struct tevent_fd *fde, enum tevent_event_trace_point, void *private_data);
typedef void (*tevent_trace_signal_callback_t)(struct tevent_signal *se, enum tevent_event_trace_point, void *private_data);
typedef void (*tevent_trace_timer_callback_t)(struct tevent_timer *te, enum tevent_event_trace_point, void *private_data);
typedef void (*tevent_trace_immediate_callback_t)(struct tevent_immediate *im, enum tevent_event_trace_point, void *private_data);
typedef void (*tevent_queue_trigger_fn_t)(struct tevent_req *req, void *private_data);

struct tevent_queue_entry {
    struct tevent_queue_entry *prev, *next;
    struct tevent_queue *queue;

    bool triggered;

    struct tevent_req *req;
    struct tevent_context *ev;

    tevent_queue_trigger_fn_t trigger;
    void *private_data;
    uint64_t tag;
};

typedef void (*tevent_trace_queue_callback_t)(struct tevent_queue_entry *qe, enum tevent_event_trace_point, void *private_data);


struct tevent_queue {
    const char *name;
    const char *location;

    bool running;
    struct tevent_immediate *immediate;

    size_t length;
    struct tevent_queue_entry *list;
};



struct tevent_req_profile {
    struct tevent_req_profile *prev, *next;
    struct tevent_req_profile *parent;
    const char *req_name;
    pid_t pid;
    const char *start_location;
    struct timeval start_time;
    const char *stop_location;
    struct timeval stop_time;
    enum tevent_req_state state;
    uint64_t user_error;
    struct tevent_req_profile *subprofiles;
};

struct tevent_timer {
    struct tevent_timer *prev, *next;
    struct tevent_context *event_ctx;
    struct tevent_wrapper_glue *wrapper;
    bool busy;
    bool destroyed;
    struct timeval next_event;
    tevent_timer_handler_t handler;
    void *private_data;
    const char *handler_name;
    const char *location;
    void *additional_data;
    uint64_t tag;
};

struct tevent_immediate {
    struct tevent_immediate *prev, *next;
    struct tevent_context *event_ctx;
    struct tevent_wrapper_glue *wrapper;
    bool busy;
    bool destroyed;
    struct tevent_context *detach_ev_ctx;
    tevent_immediate_handler_t handler;
    void *private_data;
    const char *handler_name;
    const char *create_location;
    const char *schedule_location;
    void (*cancel_fn)(struct tevent_immediate *im);
    void *additional_data;
    uint64_t tag;
};

struct tevent_threaded_context {
    struct tevent_threaded_context *next, *prev;
    struct tevent_context *event_ctx;
};

struct tevent_debug_ops {
    void (*debug)(void *context, enum tevent_debug_level level,
                  const char *fmt, va_list ap) PRINTF_ATTRIBUTE(3,0);
    void *context;
};

void tevent_debug(struct tevent_context *ev, enum tevent_debug_level level,
                  const char *fmt, ...) PRINTF_ATTRIBUTE(3,4);

void tevent_abort(struct tevent_context *ev, const char *reason);

void tevent_common_check_double_free(TALLOC_CTX *ptr, const char *reason);

struct tevent_context {
    const struct tevent_ops *ops;
    struct tevent_signal *signal_events;
    struct tevent_threaded_context *threaded_contexts;
    struct tevent_immediate *immediate_events;
    struct tevent_fd *fd_events;
    struct tevent_timer *timer_events;
    pthread_mutex_t scheduled_mutex;
    struct tevent_immediate *scheduled_immediates;
    void *additional_data;
    struct tevent_fd *wakeup_fde;
    int wakeup_fd;
    int wakeup_read_fd;
    struct tevent_debug_ops debug_ops;
    struct {
        bool allowed;
        uint32_t level;
        tevent_nesting_hook hook_fn;
        void *hook_private;
    } nesting;

    struct {
        struct {
            tevent_trace_callback_t callback;
            void *private_data;
        } point;

        struct {
            tevent_trace_fd_callback_t callback;
            void *private_data;
        } fde;

        struct {
            tevent_trace_signal_callback_t callback;
            void *private_data;
        } se;

        struct {
            tevent_trace_timer_callback_t callback;
            void *private_data;
        } te;

        struct {
            tevent_trace_immediate_callback_t callback;
            void *private_data;
        } im;

        struct {
            tevent_trace_queue_callback_t callback;
            void *private_data;
        } qe;
    } tracing;

    struct {
        struct tevent_wrapper_glue *list;
        struct tevent_wrapper_glue *glue;
    } wrapper;

    struct tevent_timer *last_zero_timer;
};

const struct tevent_ops *tevent_find_ops_byname(const char *name);

int tevent_common_context_destructor(struct tevent_context *ev);
int tevent_common_loop_wait(struct tevent_context *ev,
                            const char *location);

int tevent_common_fd_destructor(struct tevent_fd *fde);
struct tevent_fd *tevent_common_add_fd(struct tevent_context *ev,
                                       TALLOC_CTX *mem_ctx,
                                       int fd,
                                       uint16_t flags,
                                       tevent_fd_handler_t handler,
                                       void *private_data,
                                       const char *handler_name,
                                       const char *location);
void tevent_common_fd_set_close_fn(struct tevent_fd *fde,
                                   tevent_fd_close_fn_t close_fn);
uint16_t tevent_common_fd_get_flags(struct tevent_fd *fde);
void tevent_common_fd_set_flags(struct tevent_fd *fde, uint16_t flags);
int tevent_common_invoke_fd_handler(struct tevent_fd *fde, uint16_t flags,
                                    bool *removed);

struct tevent_timer *tevent_common_add_timer(struct tevent_context *ev,
                                             TALLOC_CTX *mem_ctx,
                                             struct timeval next_event,
                                             tevent_timer_handler_t handler,
                                             void *private_data,
                                             const char *handler_name,
                                             const char *location);
struct tevent_timer *tevent_common_add_timer_v2(struct tevent_context *ev,
                                                TALLOC_CTX *mem_ctx,
                                                struct timeval next_event,
                                                tevent_timer_handler_t handler,
                                                void *private_data,
                                                const char *handler_name,
                                                const char *location);
struct timeval tevent_common_loop_timer_delay(struct tevent_context *);
int tevent_common_invoke_timer_handler(struct tevent_timer *te,
                                       struct timeval current_time,
                                       bool *removed);

void tevent_common_schedule_immediate(struct tevent_immediate *im,
                                      struct tevent_context *ev,
                                      tevent_immediate_handler_t handler,
                                      void *private_data,
                                      const char *handler_name,
                                      const char *location);
int tevent_common_invoke_immediate_handler(struct tevent_immediate *im,
                                           bool *removed);
bool tevent_common_loop_immediate(struct tevent_context *ev);
void tevent_common_threaded_activate_immediate(struct tevent_context *ev);

bool tevent_common_have_events(struct tevent_context *ev);
int tevent_common_wakeup_init(struct tevent_context *ev);
int tevent_common_wakeup_fd(int fd);
int tevent_common_wakeup(struct tevent_context *ev);

struct tevent_signal *tevent_common_add_signal(struct tevent_context *ev,
                                               TALLOC_CTX *mem_ctx,
                                               int signum,
                                               int sa_flags,
                                               tevent_signal_handler_t handler,
                                               void *private_data,
                                               const char *handler_name,
                                               const char *location);
int tevent_common_check_signal(struct tevent_context *ev);
void tevent_cleanup_pending_signal_handlers(struct tevent_signal *se);
int tevent_common_invoke_signal_handler(struct tevent_signal *se,
                                        int signum, int count, void *siginfo,
                                        bool *removed);

struct tevent_context *tevent_wrapper_main_ev(struct tevent_context *ev);

struct tevent_wrapper_ops;

struct tevent_wrapper_glue {
    struct tevent_wrapper_glue *prev, *next;
    struct tevent_context *wrap_ev;
    struct tevent_context *main_ev;
    bool busy;
    bool destroyed;
    const struct tevent_wrapper_ops *ops;
    void *private_state;
};

void tevent_wrapper_push_use_internal(struct tevent_context *ev,
                                      struct tevent_wrapper_glue *wrapper);
void tevent_wrapper_pop_use_internal(const struct tevent_context *__ev_ptr,
                                     struct tevent_wrapper_glue *wrapper);

bool tevent_standard_init(void);
bool tevent_poll_init(void);
bool tevent_poll_event_add_fd_internal(struct tevent_context *ev,
                                       struct tevent_fd *fde);
bool tevent_poll_mt_init(void);

void tevent_trace_point_callback(struct tevent_context *ev,
                                 enum tevent_trace_point);

void tevent_trace_fd_callback(struct tevent_context *ev,
                              struct tevent_fd *fde,
                              enum tevent_event_trace_point);

void tevent_trace_signal_callback(struct tevent_context *ev,
                                  struct tevent_signal *se,
                                  enum tevent_event_trace_point);

void tevent_trace_timer_callback(struct tevent_context *ev,
                                 struct tevent_timer *te,
                                 enum tevent_event_trace_point);

void tevent_trace_immediate_callback(struct tevent_context *ev,
                                     struct tevent_immediate *im,
                                     enum tevent_event_trace_point);

void tevent_trace_queue_callback(struct tevent_context *ev,
                                 struct tevent_queue_entry *qe,
                                 enum tevent_event_trace_point);