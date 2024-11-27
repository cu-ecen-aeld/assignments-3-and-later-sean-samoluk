#include <arpa/inet.h>
#include <fcntl.h>
#include <netdb.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <syslog.h>
#include <unistd.h>

#define CHUNK_SIZE 1024
#define LISTEN_BACKLOG 10
#define AESD_DATA "/var/tmp/aesdsocketdata"
#define AESD_SOCKET "9000"

volatile sig_atomic_t shutdown_sig = 0;


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
        perror("fopen");
        return -1;
    }
    
    char buffer[CHUNK_SIZE];
    size_t bytesRead;
    
    // Read from the file and send to the socket in chunks
    while ((bytesRead = fread(buffer, sizeof(char), CHUNK_SIZE, file)) > 0)
    {
        if (send(socket_fd, buffer, bytesRead, 0) == -1)
        {
            perror("send");
            fclose(file);
            return -1;
        }
    }
    
    if (ferror(file))
    {
        perror("fread");
        return -1;
    }
    
    fclose(file);

    return 0;
}

// get sockaddr, IPv4 or IPv6:
void *get_in_addr(struct sockaddr *sa)
{
    if (sa->sa_family == AF_INET) {
        return &(((struct sockaddr_in*)sa)->sin_addr);
    }

    return &(((struct sockaddr_in6*)sa)->sin6_addr);
}

int handle_packets(int sockfd, struct sockaddr_storage* their_addr)
{
    int rc = 0;
    socklen_t addr_size = sizeof(*their_addr);

    // Listen for and accept a connection
    if (listen(sockfd, LISTEN_BACKLOG) == -1)
    {
        perror("listen");
        return -1;
    }

    while (!shutdown_sig)
    {
        int new_fd = accept(sockfd, (struct sockaddr *)their_addr, &addr_size);
        if (new_fd == -1)
        {
            perror("accept");
            break;
        }

        // Get the IP string
        char ip_str[INET_ADDRSTRLEN];
        inet_ntop(their_addr->ss_family,
                  get_in_addr((struct sockaddr *)their_addr),
                  ip_str,
                  sizeof ip_str);

        // Logs message to the syslog: "Accepted connection from xxx"
        syslog(LOG_INFO, "Accepted connection from %s", ip_str);

        // Receives data over the connection and appends to /var/tmp/aesdsocketdata
        int fd = open(AESD_DATA, O_WRONLY | O_CREAT | O_APPEND, 0644);
        char buf[2];
        memset(buf, 0, sizeof buf);
        int line_index = 0;

        // Dynamically allocate the line buffer
        int buf_size = CHUNK_SIZE;
        char* line_buf = (char*)calloc(CHUNK_SIZE, sizeof(char));

        while (1)
        {
            ssize_t num_bytes = recv(new_fd, buf, 1, 0);

            if (num_bytes == -1)
            {
                perror("recv");
                rc = -1;
                break;
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
                        rc = -1;
                        break;
                    }

                    memset(&line_buf[line_index], 0, CHUNK_SIZE);
                }

                line_buf[line_index] = buf[0];
                line_index++;

                if (buf[0] == '\n')
                {
                    write(fd, line_buf, line_index);

                    if (send_file(new_fd, AESD_DATA) == -1)
                    {
                        syslog(LOG_ERR, "Failed to send file.");
                        rc = -1;
                        break;
                    }

                    line_index = 0;
                }
            }
        }

        // Free the line buffer and clean up the sockets
        free(line_buf);
        close(new_fd);
        close(fd);
        syslog(LOG_INFO, "Closed connection from %s", ip_str);
    }

    // Gracefully teardown if we capture a SIGTERM or SIGINT

    // Delete the socket data
    syslog(LOG_INFO, "Deleting file: %s", AESD_DATA);
    if (remove(AESD_DATA) == -1)
    {
        perror("remove");
    }

    return rc;
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

    // Initialize the signal handlers
    struct sigaction sa_int;
    sa_int.sa_handler = signal_handler;
    sa_int.sa_flags = 0;
    sigemptyset(&sa_int.sa_mask);

    if (sigaction(SIGINT, &sa_int, NULL) == -1)
    {
        perror("sigaction");
        exit(-1);
    }

    struct sigaction sa_term;
    sa_term.sa_handler = signal_handler;
    sa_term.sa_flags = 0;
    sigemptyset(&sa_term.sa_mask);

    if (sigaction(SIGTERM, &sa_term, NULL) == -1)
    {
        perror("sigaction");
        exit(-1);
    }

    struct sockaddr_storage their_addr;
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
        perror("socket");
        return -1;
    }

    // Set the SO_REUSEADDR option
    int opt = 1;
    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) == -1)
    {
        perror("setsockopt");
        close(sockfd);
        return -1;
    }

    if (bind(sockfd, res->ai_addr, res->ai_addrlen) == -1)
    {
        perror("bind");
        return -1;
    }

    freeaddrinfo(res);

    // Fork if daemon mode is specified
    if (daemon_mode)
    {
        pid_t pid = fork();
        
        if (pid == -1)
        {
            perror("fork");
            return -1;
        }
        else if (pid == 0)
        {
            // Child logic
            rc = handle_packets(sockfd, &their_addr);
        }
        else
        {
            // Parent logic
            rc = 0;
        }
    }
    else
    {
        rc = handle_packets(sockfd, &their_addr);
    }

    close(sockfd);
    closelog();

    return rc;
}
