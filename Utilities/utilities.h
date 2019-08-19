#ifndef CPRACTICE_UTILITIES_H
#define CPRACTICE_UTILITIES_H
#define SUCCESS "Success"
#define FAILED "Failed"
#define SERVER_PORT 5000
#define MAC_LENGTH 32
#define SERVER_ADDRESS "127.0.0.1"
#define MESSAGE_LENGTH 256

#include <stdio.h>

enum Errors{
    SENDING_ERROR = -18,
    RECEIVING_ERROR,
    FILE_ERROR,
    SOCKET_ERROR,
    LENGTH_ERROR,
    SHARED_KEY_ERROR,
    VERIFICATION_ERROR,
    ARGS_ERROR,
    SODIUM_ERROR,
    BINDING_ERROR,
    ACCEPT_ERROR,
    DECRYPTION_ERROR,
    ENCRYPTION_ERROR,
    RESPONSE_ERROR,
    ADDRESS_ERROR,
    CONNECT_ERROR,
    LISTEN_ERROR,
    IOCTL_ERROR
};


void log_message_str(FILE** log_file, char* msg);
void log_message_hex(FILE** log_file, const long int* msg);
void concat_ip_payload(char* ip_payload, char* ip_buf, char* payload, int payload_len);

#endif //CPRACTICE_UTILITIES_H




