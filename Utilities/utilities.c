#include "utilities.h"
#include <string.h>
#include <stdlib.h>


void log_message_str(FILE** log_file, char *msg)
{
    if(!(*log_file))
        printf("%s\n", msg);
    else
        fprintf(*log_file, "%s\n", msg);
}

void log_message_hex(FILE** log_file, const long int* msg)
{
    if(!(*log_file))
        printf("%lX\n", *msg);
    else
        fprintf(*log_file, "%lX\n", *msg);
}

void concat_ip_payload(char* ip_payload, char* ip_buf, char* payload, int payload_len)
{
    int count = 0;

    char* delim_ptr = strtok(ip_buf, ".");  //Getting IP byte sequence
    while (delim_ptr != NULL)
    {
        ip_payload[count++] = atoi(delim_ptr);
        delim_ptr = strtok(NULL, ".");
    }

    memcpy(ip_payload+count, payload, payload_len); //Concatenate IP and payload
}