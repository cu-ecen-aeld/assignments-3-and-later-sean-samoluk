#include <stdio.h>
#include <stdlib.h>
#include <syslog.h>


int main(int argc, char **argv)
{
    openlog ("writerlog", LOG_PID, LOG_USER);

    // Parse the inputs
    if (argc != 3)
    {
        syslog (LOG_ERR, "Incorrect number of inputs");
        exit(1);
    }

    char* writefile = argv[1];
    char* writestr = argv[2]; 

    FILE* ptr = fopen(writefile, "w");

    if (ptr == NULL)
    {
        syslog (LOG_ERR, "Failed to open file: %s", writefile);
        exit(1);
    }

    int rc = fputs(writestr, ptr);
    if (rc == EOF)
    {
        syslog (LOG_ERR, "Write failed");
    }
    else
    {
        syslog (LOG_INFO, "Wrote to file: %s", writefile);
    }
    
    fclose(ptr);
    closelog();    

    return 0;
}
