#include "systemcalls.h"

#include <fcntl.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

/**
 * @param cmd the command to execute with system()
 * @return true if the command in @param cmd was executed
 *   successfully using the system() call, false if an error occurred,
 *   either in invocation of the system() call, or if a non-zero return
 *   value was returned by the command issued in @param cmd.
*/
bool do_system(const char *cmd)
{

/*
 * TODO  add your code here
 *  Call the system() function with the command set in the cmd
 *   and return a boolean true if the system() call completed with success
 *   or false() if it returned a failure
*/
    bool status = false;

    int rc = system(cmd);
    if (rc == 0)
    {
        status = true;
    }
    else if (rc == -1)
    {
        perror("Command failed with error");
    }
    else
    {
        printf("Command failed with error code: %d", rc);
    }

    return status;
}

/**
* @param count -The numbers of variables passed to the function. The variables are command to execute.
*   followed by arguments to pass to the command
*   Since exec() does not perform path expansion, the command to execute needs
*   to be an absolute path.
* @param ... - A list of 1 or more arguments after the @param count argument.
*   The first is always the full path to the command to execute with execv()
*   The remaining arguments are a list of arguments to pass to the command in execv()
* @return true if the command @param ... with arguments @param arguments were executed successfully
*   using the execv() call, false if an error occurred, either in invocation of the
*   fork, waitpid, or execv() command, or if a non-zero return value was returned
*   by the command issued in @param arguments with the specified arguments.
*/

bool do_exec(int count, ...)
{
    va_list args;
    va_start(args, count);
    char * command[count+1];
    int i;
    for(i=0; i<count; i++)
    {
        command[i] = va_arg(args, char *);
    }
    command[count] = NULL;
    // this line is to avoid a compile warning before your implementation is complete
    // and may be removed
    //command[count] = command[count];

    va_end(args);

/*
 * TODO:
 *   Execute a system command by calling fork, execv(),
 *   and wait instead of system (see LSP page 161).
 *   Use the command[0] as the full path to the command to execute
 *   (first argument to execv), and use the remaining arguments
 *   as second argument to the execv() command.
 *
*/

    bool status = true;
    pid_t pid = fork();

    if (pid == -1)
    {
        perror("fork");
    }
    else if (pid == 0)
    {
        // Child logic
        if (execv(command[0], command) == -1)
        {
            perror("execv");
            exit(EXIT_FAILURE);
        }
    }
    else
    {
        // Parent logic
        int wstatus;

        if (waitpid(pid, &wstatus, 0) == -1)
        {
            perror("wait");
            status = false;
        }
        else
        {
            if (WIFEXITED(wstatus))
            {
                if (WEXITSTATUS(wstatus) == 1)
                {
                    status = false;
                }
            }
            else
            {
                status = false;
            }
        }
    }

    return status;
}

/**
* @param outputfile - The full path to the file to write with command output.
*   This file will be closed at completion of the function call.
* All other parameters, see do_exec above
*/
bool do_exec_redirect(const char *outputfile, int count, ...)
{
    va_list args;
    va_start(args, count);
    char * command[count+1];
    int i;
    for(i=0; i<count; i++)
    {
        command[i] = va_arg(args, char *);
    }
    command[count] = NULL;
    // this line is to avoid a compile warning before your implementation is complete
    // and may be removed
    //command[count] = command[count];
    va_end(args);

/*
 * TODO
 *   Call execv, but first using https://stackoverflow.com/a/13784315/1446624 as a refernce,
 *   redirect standard out to a file specified by outputfile.
 *   The rest of the behaviour is same as do_exec()
 *
*/
    int pipefd[2];

    if (pipe(pipefd) == -1)
    {
        perror("pipe");
        exit(EXIT_FAILURE);
    }

    int fd = open(outputfile, O_WRONLY|O_TRUNC|O_CREAT, 0644);

    bool status = true;
    pid_t pid = fork();

    if (pid == -1)
    {
        perror("fork");
        exit(EXIT_FAILURE);
    }
    else if (pid == 0)
    {
        // Child logic

        // Close the read pipe
        close(pipefd[0]);

        // Point stdout to write to the pipe
        if (dup2(pipefd[1], STDOUT_FILENO) == -1)
        {
            perror("dup2");
            exit(EXIT_FAILURE);
        }

        // Execute the command
        if (execv(command[0], command) == -1)
        {
            perror("execv");
            exit(EXIT_FAILURE);
        }
    }
    else
    {
        // Parent logic
        int wstatus;
        int BUF_SIZE = 2048;
        char buf[BUF_SIZE];

        // Read from the pipe and write it to the output file
        if (waitpid(pid, &wstatus, 0) == -1)
        {
            perror("wait");
            status = false;
        }
        else
        {
            if (WIFEXITED(wstatus))
            {
                if (WEXITSTATUS(wstatus) == 1)
                {
                    status = false;
                }
                else
                {
                    ssize_t num_read = read(pipefd[0], buf, BUF_SIZE);
                    if (num_read == -1)
                    {
                        perror("read");
                        exit(EXIT_FAILURE);
                    }
                    printf("num_bytes: %ld\n", num_read);

                    ssize_t num_write = write(fd, buf, num_read);
                    if (num_write != num_read)
                    {
                        perror("write");
                        exit(EXIT_FAILURE);
                    }
                }
            }
            else
            {
                status = false;
            }
        }
    }

    return status;
}
