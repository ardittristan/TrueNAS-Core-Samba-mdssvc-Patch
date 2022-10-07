struct tstream_context {
    const char *location;
    const struct tstream_context_ops *ops;
    void *private_data;

    struct tevent_req *readv_req;
    struct tevent_req *writev_req;
};

struct tstream_context_ops {
    const char *name;

    ssize_t (*pending_bytes)(struct tstream_context *stream);

    struct tevent_req *(*readv_send)(TALLOC_CTX *mem_ctx,
                                     struct tevent_context *ev,
                                     struct tstream_context *stream,
                                     struct iovec *vector,
                                     size_t count);
    int (*readv_recv)(struct tevent_req *req,
                      int *perrno);

    struct tevent_req *(*writev_send)(TALLOC_CTX *mem_ctx,
                                      struct tevent_context *ev,
                                      struct tstream_context *stream,
                                      const struct iovec *vector,
                                      size_t count);
    int (*writev_recv)(struct tevent_req *req,
                       int *perrno);

    struct tevent_req *(*disconnect_send)(TALLOC_CTX *mem_ctx,
                                          struct tevent_context *ev,
                                          struct tstream_context *stream);
    int (*disconnect_recv)(struct tevent_req *req,
                           int *perrno);
};

typedef int (*tstream_readv_pdu_next_vector_t)(struct tstream_context *stream, void *private_data, TALLOC_CTX *mem_ctx, struct iovec **vector, size_t *count);