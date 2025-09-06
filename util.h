double time_seconds(void);
int open_socket_in_udp(int port);
int open_socket_in_tcp(int port);
void set_tcp_options(int fd);
const char *addr_to_str(struct sockaddr_in &addr);
const char *time_string(void);
ssize_t tcp_writable_bytes(int fd);
bool socket_is_dead(int fd);
void set_nonblocking(int fd);

#define ZERO_STRUCT(s) memset((void*)&s, 0, sizeof(s))

#define MAX(a,b) ((a)>(b)?(a):(b))
