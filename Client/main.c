
#include <sodium.h>
#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <zconf.h>
#include <string.h>
#include <arpa/inet.h>

#define SERVER_PORT 5000
#define SERVER_ADDRESS "127.0.0.1"
#define MAC_LENGTH 32
#define MESSAGE_LENGTH 256
#define TRUE 1
#define FALSE 0

enum Errors{
    SENDING_ERROR = -11,
    RECEIVING_ERROR,
    FILE_ERROR,
    SOCKET_ERROR,
    ADDRESS_ERROR,
    CONNECT_ERROR,
    KEY_LENGTH_ERROR,
    SHARED_KEY_ERROR,
    VERIFICATION_ERROR,
    ARGS_ERROR,
    SODIUM_ERROR
};

void log_message_str(FILE* log_file, char *msg, int bool_error)
{
    if(!log_file)
        printf("%s\n", msg);
    else
        fprintf(log_file, "%s\n", msg);
}

void log_message(FILE* log_file, int* msg, int bool_error)
{
    if(!log_file)
        printf("%X\n", *msg);
    else
        fprintf(log_file, "%X\n", *msg);
}

int initiate(const int* argc, char** argv[], FILE** log_file, FILE** read_fp)
{
    if(sodium_init() < 0)
    {
        perror("No sodium\n");
        return SODIUM_ERROR;
    }

    if( 3 > *argc || 4 < *argc )
    {
        printf("Usage: ./Client <message_file_name> <parameter>\n"
               "-c Console logging\n"
               "-f <log_file_name> File logging\n");
        return ARGS_ERROR;
    }

    if ( (strcmp((*argv)[2], "-f") == 0) && (4 == *argc))
    {
        if ( (*log_file = fopen((*argv)[3], "w")) == NULL)
        {
            perror("Couldn't create file\n");
            return FILE_ERROR;
        }
    }
    else if( (strcmp((*argv)[2], "-c") != 0) || (3 != *argc))
    {
        printf("Wrong parameters. Check usage with ./Client\n");
        return ARGS_ERROR;
    }

    if((*read_fp = fopen((*argv)[1],"r")) == NULL)
    {
        char* error = "Couldn't open file";
        log_message(*log_file, error, TRUE);
        return FILE_ERROR;
    }

    return 0;

}

int server_connect(int* user_fd, FILE** log_file, struct sockaddr_in* serv_addr)
{
    if((*user_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
    {
        char* error = "Error while creating socket";
        log_message_str(*log_file, error, TRUE);
        return SOCKET_ERROR;
    }

    log_message_str(*log_file, "Socket created", FALSE);

    if((inet_pton(AF_INET, SERVER_ADDRESS, &serv_addr->sin_addr)) <= 0)
    {
        char* error = "Server address error";
        log_message_str(*log_file, error, TRUE);
        return ADDRESS_ERROR;
    }
    serv_addr->sin_family = AF_INET;
    serv_addr->sin_port = htons(SERVER_PORT);

    if((connect(*user_fd, (struct sockaddr*)serv_addr, sizeof(*serv_addr))) < 0)
    {
        char* error = "Error while connecting";
        log_message_str(*log_file, error, TRUE);
        return CONNECT_ERROR;
    }

    log_message_str(*log_file, "Connected to server", FALSE);

    return 0;
}

int key_exchange(const int* user_fd, FILE** log_file, unsigned char* shared_sk, int shared_sk_len)
{

    unsigned char      user_pk[crypto_box_PUBLICKEYBYTES];
    unsigned char      user_sk[crypto_box_SECRETKEYBYTES];
    unsigned char      server_pk[crypto_box_PUBLICKEYBYTES];
    int                key_len = 0;

    crypto_box_keypair(user_pk, user_sk); // Forming public/secret key pair

    if((send(*user_fd, user_pk, crypto_box_PUBLICKEYBYTES, 0)) < 0) // Sending user public key
    {
        char* error = "Couldn't send server public key\n";
        log_message_str(*log_file, error, TRUE);
        return SENDING_ERROR;
    }

    log_message_str(*log_file, "Send user public key:", FALSE);
    log_message(*log_file, user_pk, FALSE);
    if( (key_len = recv(*user_fd, server_pk, shared_sk_len, 0)) <= 0) // Receiving server public key
    {
        char* error = "Error receiving public key";
        log_message_str(*log_file, error, TRUE);
        return RECEIVING_ERROR;
    }

    if(key_len != crypto_box_PUBLICKEYBYTES)
    {
        char* error = "Key wrong length";
        log_message_str(*log_file, error, TRUE);
        return KEY_LENGTH_ERROR;
    }

    log_message_str(*log_file, "Received server public key:", FALSE);
    log_message(*log_file, (int*)server_pk, FALSE);

    if(crypto_scalarmult(shared_sk, user_sk, server_pk) != 0) // Making shared secret key
    {
        char* error = "Shared key calculation error";
        log_message(*log_file, error, TRUE);
        return SHARED_KEY_ERROR;
    }

    log_message_str(*log_file, "Calculated shared secret key:", FALSE);
    log_message(*log_file, shared_sk, FALSE);

    return 0;
}

int shared_key_verify(const int* user_fd, FILE** log_file, unsigned char* shared_sk)
{
    struct sockaddr_in user_addr;
    unsigned int       len = sizeof(struct sockaddr);
    unsigned char      ip_buf[16];              //Length is 16 because maximum IP length with dots is 15 + '\0'
    unsigned char      ip_payload[9];           //Length is 9 because 4 digits of IP + 4 digits of payload + '\0'
    unsigned char      MAC_CLIENT[MAC_LENGTH];
    unsigned char      MAC_SERVER[MAC_LENGTH];
    unsigned char      server_payload[4] = {0x00,0x00,0x00,0x01};
    unsigned char      user_payload[4] = {0x00,0x00,0x00,0x02};
    int                count = 0;

    memset(&ip_buf, 0, sizeof(ip_buf));
    memset(&ip_payload, 0, sizeof(ip_payload));
    memset(&MAC_CLIENT, 0, sizeof(MAC_CLIENT));
    memset(&MAC_SERVER, 0, sizeof(MAC_SERVER));

    memcpy(ip_buf, SERVER_ADDRESS, sizeof(SERVER_ADDRESS));

    char* delim_ptr = strtok(ip_buf, ".");  //Getting server IP byte sequence
    while (delim_ptr != NULL)
    {
        *(ip_payload + count++) = atoi(delim_ptr);
        delim_ptr = strtok(NULL, ".");
    }

    memcpy(ip_payload+count, server_payload, sizeof(server_payload)); //Concatenate user ip and server_payload

    crypto_auth_hmacsha256(MAC_CLIENT, ip_payload, sizeof(ip_payload), shared_sk);

    if((send(*user_fd, MAC_CLIENT, sizeof(MAC_CLIENT), 0)) < 0) //Sending MAC_CLIENT
    {
        char* error = "Couldn't send MAC_CLIENT";
        log_message_str(*log_file, error, TRUE);
        return SENDING_ERROR;
    }

    log_message_str(*log_file, "Send MAC_CLIENT:", FALSE);
    log_message(*log_file, MAC_CLIENT, FALSE);

    if((recv(*user_fd, MAC_SERVER, sizeof(MAC_SERVER), 0)) < 0) //Receiving MAC_SERVER
    {
        char* error = "Couldn't receive MAC_SERVER";
        log_message_str(*log_file, error, TRUE);
        return RECEIVING_ERROR;
    }

    log_message_str(*log_file, "Received MAC_SERVER:", FALSE);
    log_message(*log_file, MAC_SERVER, FALSE);

    memset(&ip_buf, 0, sizeof(ip_buf));
    memset(&ip_payload, 0 , sizeof(ip_payload));

    getsockname(*user_fd, (struct sockaddr*)&user_addr, &len); //Get user IP

    inet_ntop(AF_INET, &user_addr.sin_addr, (char*)ip_buf, sizeof(ip_buf)); //Get dotted-decimal format of user IP

    delim_ptr = strtok(ip_buf, ".");  //Getting user IP byte sequence
    count = 0;
    while (delim_ptr != NULL)
    {
        *(ip_payload + count++) = atoi(delim_ptr);
        delim_ptr = strtok(NULL, ".");
    }

    memcpy(ip_payload+count, user_payload, sizeof(user_payload)); //Concatenate user ip and user_payload

    if ((crypto_auth_hmacsha256_verify(MAC_SERVER, ip_payload, sizeof(ip_payload), shared_sk)) < 0)
    {
        char* error = "Verification error";
        log_message_str(*log_file, error, TRUE);
        return VERIFICATION_ERROR;
    }

    log_message_str(*log_file, "Verification successful", FALSE);

    log_message_str(*log_file, "File opened", FALSE);

    return 0;

}

int send_message(const int* user_fd, FILE** log_file, FILE** read_file, unsigned char* shared_sk)
{
    unsigned char      cipher_msg[MESSAGE_LENGTH + crypto_aead_xchacha20poly1305_ietf_ABYTES];
    unsigned char      nonce[crypto_aead_xchacha20poly1305_ietf_NPUBBYTES];
    unsigned long long cipher_len;
    unsigned char      message_buf[MESSAGE_LENGTH];

    memset(&message_buf, 0, sizeof(message_buf));

    int las_pos = 0;

    while(!feof(*read_file))
    {
        if(fgets((char*)message_buf, sizeof(message_buf), *read_file))
        {
            if((recv(*user_fd, nonce, sizeof(nonce), 0)) <= 0)
            {
                return RECEIVING_ERROR;
            }

            crypto_aead_xchacha20poly1305_ietf_encrypt(cipher_msg, &cipher_len, message_buf,
                                                       ftell(*read_file) - las_pos, NULL, 0, NULL,
                                                       nonce, shared_sk);

            if((send(*user_fd, cipher_msg, cipher_len, 0)) < 0)
            {
                char* error = "Couldn't send message";
                log_message_str(*log_file, error, TRUE);
                return SENDING_ERROR;
            }
            las_pos = ftell(*read_file);
        }
    }

    log_message_str(*log_file, "Message send", FALSE);

    return 0;
}

void close_all(const int* user_fd, FILE** log_file, FILE** read_file)
{
    if(*log_file)
        fclose(*log_file);
    if(*read_file)
        fclose(*read_file);
    close(*user_fd);
}

int main(int argc, char* argv[])
{

    struct sockaddr_in serv_addr;
    int                user_fd;
    unsigned char      shared_sk[crypto_box_SECRETKEYBYTES];
    FILE*              log_file = NULL;
    FILE*              read_file = NULL;
    int                error;

    memset(&serv_addr, 0, sizeof(serv_addr));

    if (( error = initiate(&argc, &argv, &log_file, &read_file)) < 0)
    {
        perror("Init error\n");
        close_all(&user_fd, &log_file, &read_file);
        return error;
    }

    if ((error = server_connect(&user_fd, &log_file, &serv_addr)) < 0)
    {
        close_all(&user_fd, &log_file, &read_file);
        return error;
    }

    if( (error = key_exchange(&user_fd, &log_file, shared_sk, sizeof(shared_sk))) < 0)
    {
        close_all(&user_fd, &log_file, &read_file);
        return error;
    }

    if((error = shared_key_verify(&user_fd, &log_file, shared_sk)) < 0)
    {
        close_all(&user_fd, &log_file, &read_file);
        return error;
    }

    if((error = send_message(&user_fd, &log_file, &read_file, shared_sk)) < 0)
    {
        close_all(&user_fd, &log_file, &read_file);
        return error;
    }

    close_all(&user_fd, &log_file, &read_file);

    return 0;
}

