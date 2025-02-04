#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <pthread.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>

#include "queue.h"

#define CHUNK_SIZE 1024
#define LISTEN_BACKLOG 10

#ifdef USE_AESD_CHAR_DEVICE
#define AESD_DATA "/dev/aesdchar"
#else
#define AESD_DATA "/var/tmp/aesdsocketdata"
#endif
#define AESD_SOCKET "9000"

#define handle_error_en(en, msg) \
        do { errno = en; perror(msg); exit(EXIT_FAILURE); } while (0)

#define handle_error(msg) \
        do { perror(msg); exit(EXIT_FAILURE); } while (0)


volatile sig_atomic_t shutdown_sig = 0;
pthread_mutex_t write_mutex = PTHREAD_MUTEX_INITIALIZER;


struct connection_info
{
    pthread_t thread_id;
    int recv_fd;
    char* ip_str;
    bool complete;
};

// SLIST
struct entry
{
    struct connection_info* conn_info;
    SLIST_ENTRY(entry) entries;  
};

SLIST_HEAD(slisthead, entry);

void signal_handler(int sig)
{
    if (sig == SIGINT || sig == SIGTERM)
    {
        syslog(LOG_INFO, "Caught signal, exiting");
        shutdown_sig = 1;
    }
}

int send_file(int socket_fd, const char *filename)
{
    FILE *file = fopen(filename, "r");
    
    if (file == NULL)
    {
        handle_error("fopen");
    }
    
    char buffer[CHUNK_SIZE];
    size_t bytesRead;
    
    // Read from the file and send to the socket in chunks
    while ((bytesRead = fread(buffer, sizeof(char), CHUNK_SIZE, file)) > 0)
    {
        if (send(socket_fd, buffer, bytesRead, 0) == -1)
        {
            fclose(file);
            handle_error("send");
        }
    }
    
    if (ferror(file))
    {
        handle_error("fread");
    }
    
    fclose(file);

    return 0;
}

// get sockaddr, IPv4 or IPv6:
void* get_in_addr(struct sockaddr *sa)
{
    if (sa->sa_family == AF_INET) {
        return &(((struct sockaddr_in*)sa)->sin_addr);
    }

    return &(((struct sockaddr_in6*)sa)->sin6_addr);
}

void* handle_connection(void* arg)
{
    struct connection_info* conn_info = (struct connection_info*)arg;

    // Receives data over the connection and appends to /var/tmp/aesdsocketdata
#ifdef USE_AESD_CHAR_DEVICE
    int fd = open(AESD_DATA, O_RDWR);
#else
    int fd = open(AESD_DATA, O_WRONLY | O_CREAT | O_APPEND, 0644);
#endif
    if (fd == -1)
    {
        handle_error("open");
    }


    char buf[2];
    memset(buf, 0, sizeof buf);
    int line_index = 0;

    // Dynamically allocate the line buffer
    int buf_size = CHUNK_SIZE;
    char* line_buf = (char*)calloc(CHUNK_SIZE, sizeof(char));

    while (1)
    {
        ssize_t num_bytes = recv(conn_info->recv_fd, buf, 1, 0);

        if (num_bytes == -1)
        {
            handle_error("recv");
        }
        else if (num_bytes == 0)
        {
            // Client has finished sending data
            break;
        }
        else
        {
            // Returns the full content of /var/tmp/aesdsocketdata to the
            // client once packet has been recieved.

            // Resize the buffer if necessary
            if (line_index >= buf_size)
            {
                buf_size = buf_size + CHUNK_SIZE;
                char* tmp = (char*)realloc(line_buf, buf_size);

                if (tmp)
                {
                    line_buf = tmp;
                }
                else
                {
                    syslog(LOG_ERR, "realloc failed, exiting...");
                    free(line_buf);
                    handle_error("realloc");
                }

                memset(&line_buf[line_index], 0, CHUNK_SIZE);
            }

            line_buf[line_index] = buf[0];
            line_index++;

            if (buf[0] == '\n')
            {
                pthread_mutex_lock(&write_mutex);
                if (write(fd, line_buf, line_index) == -1)
                {
                    printf("write fd: %d", fd);
                    handle_error("write");
                }
                pthread_mutex_unlock(&write_mutex);

                if (send_file(conn_info->recv_fd, AESD_DATA) == -1)
                {
                    syslog(LOG_ERR, "Failed to send file.");
                    handle_error("send_file");
                }

                line_index = 0;
            }
        }
    }

    // Free the line buffer and clean up the sockets
    free(line_buf);
    close(conn_info->recv_fd);
    close(fd);
    syslog(LOG_INFO, "Closed connection from %s", conn_info->ip_str);

    pthread_mutex_lock(&write_mutex);
    conn_info->complete = true;
    pthread_mutex_unlock(&write_mutex);

    pthread_exit(NULL);
}

void write_timestamp(int sig, siginfo_t *si, void *uc)
{
    int fd = open(AESD_DATA, O_WRONLY | O_CREAT | O_APPEND, 0644);
    char time_str[128];
    time_t t;
    struct tm* time_info;

    time(&t);
    time_info = localtime(&t);
    if (time_info == NULL)
    {
        handle_error("localtime");
    }

    size_t num_bytes = strftime(time_str, sizeof(time_str), "timestamp: %a, %d %b %Y %T %z\n", time_info);
    if (num_bytes == 0)
    {
        handle_error("strftime");
    }

    syslog(LOG_INFO, "%s", time_str);
    pthread_mutex_lock(&write_mutex);
    if (write(fd, time_str, num_bytes) == -1)
    {
        handle_error("write");
    }
    pthread_mutex_unlock(&write_mutex);

    close(fd);
}

int handle_packets(int sockfd)
{
    int status = 0;
    struct sockaddr_storage their_addr;

    socklen_t addr_size = sizeof(their_addr);

    // Listen for and accept a connection
    if (listen(sockfd, LISTEN_BACKLOG) == -1)
    {
        handle_error("listen");
    }

    struct entry* conn_p;
    struct entry* conn_p_temp;
    struct slisthead head;
    SLIST_INIT(&head);

    while (!shutdown_sig)
    {
        int new_fd = accept(sockfd, (struct sockaddr *)&their_addr, &addr_size);
        if (new_fd == -1)
        {
            // Print error and break so we can clean up 
            if (shutdown_sig)
            {
                break;
            }
            else if(errno == EINTR)
            {
                continue;
            }
            else
            {
                perror("accept");
            }

        }
        else
        {
            // Get the IP string
            char* ip_str = malloc(INET_ADDRSTRLEN * sizeof(char));
            if (ip_str == NULL)
            {
                handle_error("malloc");
            }

            inet_ntop(their_addr.ss_family,
                    get_in_addr((struct sockaddr *)&their_addr),
                    ip_str,
                    INET_ADDRSTRLEN);

            // Logs message to the syslog: "Accepted connection from xxx"
            syslog(LOG_INFO, "Accepted connection from %s", ip_str);

            // TODO: Create the thread and add it to the singly linked list
            struct entry* conn = (struct entry*)malloc(sizeof(struct entry));
            if (conn == NULL)
            {
                handle_error("malloc");
            }

            conn->conn_info = (struct connection_info*)malloc(sizeof(struct connection_info));
            conn->conn_info->recv_fd = new_fd;
            conn->conn_info->ip_str = ip_str;
            conn->conn_info->complete = false;
            
            SLIST_INSERT_HEAD(&head, conn, entries);

            status = pthread_create(&(conn->conn_info->thread_id), NULL, &handle_connection, conn->conn_info);
            if (status != 0)
            {
                handle_error("pthread_create");
                break;
            }

            // Cleanup any completed threads
            SLIST_FOREACH_SAFE(conn_p, &head, entries, conn_p_temp)
            {
                pthread_mutex_lock(&write_mutex);
                bool complete = conn_p->conn_info->complete;
                pthread_mutex_unlock(&write_mutex);

                if (complete)
                {
                    status = pthread_join(conn_p->conn_info->thread_id, NULL);
                    if (status != 0)
                    {
                        perror("pthread_join");
                        break;
                    }

                    SLIST_REMOVE(&head, conn_p, entry, entries);

                    free(conn_p->conn_info->ip_str);
                    free(conn_p->conn_info);
                    free(conn_p);
                }
            }
        }
    }

    // Gracefully teardown if we capture a SIGTERM or SIGINT
    syslog(LOG_INFO, "Removing list elements");
    while (!SLIST_EMPTY(&head))
    {
        syslog(LOG_INFO, "Removing list element...");
        conn_p = SLIST_FIRST(&head);
        status = pthread_join(conn_p->conn_info->thread_id, NULL);
        if (status != 0)
        {
            handle_error_en(status, "pthread_join");
        }

        SLIST_REMOVE_HEAD(&head, entries);

        free(conn_p->conn_info->ip_str);
        free(conn_p->conn_info);
        free(conn_p);
    }

    return 0;
}

void daemonize(bool create_daemon)
{
    if (create_daemon)
    {
        pid_t pid;

        // Fork off the parent process
        pid = fork();

        // Error check
        if (pid < 0)
            exit(EXIT_FAILURE);
        
        // Let parent terminate on success
        if (pid > 0)
            exit(EXIT_SUCCESS);
        
        // Child process becomes session leader on success
        if (setsid() < 0)
            exit(EXIT_FAILURE);
        
        // Fork off the child
        pid = fork();

        // Error check
        if (pid < 0)
            exit(EXIT_FAILURE);
        
        // Let the child terminate on success
        if (pid > 0)
            exit(EXIT_SUCCESS);
    }
}

int main(int argc, char **argv)
{
    int c;
    bool daemon_mode = false;
    int rc;

    while ((c = getopt (argc, argv, "d")) != -1)
    {
        switch (c)
        {
            case 'd':
                daemon_mode = true;
                break;

            default:
                daemon_mode = false;
        }
    }

    openlog("aesdsocketlog", LOG_PID, LOG_USER);

    // Fork if daemon mode is specified
    daemonize(daemon_mode);

    // Initialize the signal handlers
    struct sigaction sa_int;
    sa_int.sa_handler = signal_handler;
    sa_int.sa_flags = 0;
    sigemptyset(&sa_int.sa_mask);

    if (sigaction(SIGINT, &sa_int, NULL) == -1)
    {
        handle_error("sigaction");
    }

    struct sigaction sa_term;
    sa_term.sa_handler = signal_handler;
    sa_term.sa_flags = 0;
    sigemptyset(&sa_term.sa_mask);

    if (sigaction(SIGTERM, &sa_term, NULL) == -1)
    {
        handle_error("sigaction");
    }

    // Setup signal handler for the timestamp
#ifndef USE_AESD_CHAR_DEVICE
    struct sigaction sa_timer;
    struct sigevent sev_timer;
    struct itimerspec its;
    timer_t timer_id;

    sa_timer.sa_flags = SA_SIGINFO;
    sa_timer.sa_sigaction = write_timestamp;
    sigemptyset(&sa_timer.sa_mask);
    
    if (sigaction(SIGRTMIN, &sa_timer, NULL) == -1)
    {
        handle_error("sigaction");
    }

    // Create the timer
    sev_timer.sigev_notify = SIGEV_SIGNAL;
    sev_timer.sigev_signo = SIGRTMIN;
    sev_timer.sigev_value.sival_ptr = &timer_id;
    if (timer_create(CLOCK_REALTIME, &sev_timer, &timer_id) == -1)
    {
        handle_error("timer_create");
    }

    // Start the timer
    its.it_value.tv_sec = 10;
    its.it_value.tv_nsec = 0;
    its.it_interval.tv_sec = 10;
    its.it_interval.tv_nsec = 0;

    if (timer_settime(timer_id, 0, &its, NULL) == -1)
    {
        handle_error("timer_settime");
    }
#endif

    struct addrinfo hints, *res;

    memset(&hints, 0, sizeof hints);
    hints.ai_family = PF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;

    getaddrinfo(NULL, AESD_SOCKET, &hints, &res);

    // Open stream socket bound to port 9000
    int sockfd = socket(res->ai_family, res->ai_socktype, 0);
    if (sockfd == -1)
    {
        handle_error("socket");
    }

    // Set the SO_REUSEADDR option
    int opt = 1;
    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) == -1)
    {
        close(sockfd);
        handle_error("setsockopt");
    }

    if (bind(sockfd, res->ai_addr, res->ai_addrlen) == -1)
    {
        handle_error("bind");
    }

    freeaddrinfo(res);

    rc = handle_packets(sockfd);

    close(sockfd);

    // Delete the socket data
#ifndef USE_AESD_CHAR_DEVICE
    syslog(LOG_INFO, "Deleting file: %s", AESD_DATA);
    if (remove(AESD_DATA) == -1)
    {
        handle_error("remove");
    }
#endif

    closelog();

    return rc;
}
