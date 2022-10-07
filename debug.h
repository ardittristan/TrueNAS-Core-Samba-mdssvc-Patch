bool dbgtext( const char *, ... ) PRINTF_ATTRIBUTE(1,2);
bool dbghdrclass( int level, int cls, const char *location, const char *func);
int debuglevel_get_class(size_t idx);

#if (__GNUC__ >= 3)
/* the strange !! is to ensure that __builtin_expect() takes either 0 or 1
   as its first argument */
#ifndef likely
#define likely(x)   __builtin_expect(!!(x), 1)
#endif
#ifndef unlikely
#define unlikely(x) __builtin_expect(!!(x), 0)
#endif
#else
#ifndef likely
#define likely(x) (x)
#endif
#ifndef unlikely
#define unlikely(x) (x)
#endif
#endif

/* the maximum debug level to compile into the code. This assumes a good
   optimising compiler that can remove unused code
   for embedded or low-memory systems set this to a value like 2 to get
   only important messages. This gives *much* smaller binaries
*/
#ifndef MAX_DEBUG_LEVEL
#define MAX_DEBUG_LEVEL 1000
#endif

/* So you can define DBGC_CLASS before including debug.h */
#ifndef DBGC_CLASS
#define DBGC_CLASS            0     /* override as shown above */
#endif

#define DEBUG( level, body ) \
  (void)( ((level) <= MAX_DEBUG_LEVEL) && \
       unlikely(debuglevel_get_class(DBGC_CLASS) >= (level))             \
       && (dbghdrclass( level, DBGC_CLASS, __location__, __FUNCTION__ )) \
       && (dbgtext body) )
