
#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <zconf.h>
#include <string.h>
#include <sodium.h>
#include <arpa/inet.h>

#define PORT 5000
#define MAC_LENGTH 32
#define SERVER_ADDRESS "127.0.0.1"
#define MESSAGE_LENGTH 256
#define TRUE 1
#define FALSE 0

enum Errors{
    SENDING_ERROR = -12,
    RECEIVING_ERROR,
    FILE_ERROR,
    SOCKET_ERROR,
    KEY_LENGTH_ERROR,
    SHARED_KEY_ERROR,
    VERIFICATION_ERROR,
    ARGS_ERROR,
    SODIUM_ERROR,
    BINDING_ERROR,
    ACCEPT_ERROR,
    DECRYPTION_ERROR
};

void log_message_str(FILE *log_file, char *msg, int bool_error)
{
    if(!log_file)
        printf("%s\n", msg);
    else
        fprintf(log_file, "%s\n", msg);
}

void log_message_hex(FILE *log_file, void *msg, int bool_error)
{
    if(!log_file)
        printf("%X\n", *(int*)msg);
    else
        fprintf(log_file, "%X\n", *(int*)msg);
}

int initiate(const int* argc, char** argv[], FILE** log_file)
{
    if(sodium_init() < 0)
    {
        perror("No sodium\n");
        return SODIUM_ERROR;
    }

    if( *argc < 2 || *argc > 3 )
    {
        printf("Usage: ./Server <parameter>\n"
               "-c Console logging\n"
               "-f <log_file_name> File logging\n");
        return ARGS_ERROR;
    }

    if ( (strcmp((*argv)[1], "-f") == 0) && (*argc == 3))
    {
        if ( (*log_file = fopen(*argv[2], "w")) == NULL)
        {
            perror("Couldn't create file\n");
            return FILE_ERROR;
        }
    }
    else if( (strcmp((*argv)[1], "-c") != 0) || (*argc != 2))
    {
        printf("Wrong parameters. Check usage with ./Client\n");
        return ARGS_ERROR;
    }

    return 0;
}

int bind_socket(int* listen_fd, struct sockaddr_in* serv_addr, FILE** log_file)
{

    socklen_t size = sizeof(*serv_addr);
    if((*listen_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
    {
        char* error_msg = "Error while creating socket";
        log_message_hex(*log_file, error_msg, TRUE);
        return SOCKET_ERROR;
    }

    log_message_str(*log_file, "Socket created", FALSE);

    inet_pton(AF_INET, SERVER_ADDRESS, &serv_addr->sin_addr);
    serv_addr->sin_family = AF_INET;
    serv_addr->sin_port = htons(PORT);

    if((bind(*listen_fd, (struct sockaddr*)serv_addr, size) ) < 0)
    {
        char* error_msg = "Binding error";
        log_message_str(*log_file, error_msg, TRUE);
        return BINDING_ERROR;
    }

    return 0;
}

int accept_user(int* conn_fd, const int* listen_fd, struct sockaddr_in* user_addr, FILE** log_file)
{
    socklen_t cli_len = sizeof(struct sockaddr_in);

    if((*conn_fd = accept(*listen_fd, (struct sockaddr*)user_addr, &cli_len) ) < 0)
    {
        char* error_msg = "Error while accepting";
        log_message_hex(*log_file, error_msg, TRUE);
        return ACCEPT_ERROR;
    }

    log_message_str(*log_file, "User connected", FALSE);

    printf("Connected\n");

    return 0;
}

int key_exchange(const int* conn_fd, unsigned char* shared_sk, FILE** log_file)
{
    int                key_len = 0;
    unsigned char      user_pk[crypto_box_PUBLICKEYBYTES];
    unsigned char      server_pk[crypto_box_PUBLICKEYBYTES];
    unsigned char      server_sk[crypto_box_SECRETKEYBYTES];

    if((key_len = recv(*conn_fd, user_pk, sizeof(user_pk), 0)) <= 0) // Receiving user public key
    {
        char* error_msg = "Couldn't receive public key";
        log_message_hex(*log_file, error_msg, TRUE);
        return RECEIVING_ERROR;
    }

    log_message_str(*log_file, "Received user public key:", FALSE);
    log_message_hex(*log_file, user_pk, FALSE);

    if(key_len != crypto_box_PUBLICKEYBYTES)
    {
        char* error_msg = "Key wrong length";
        log_message_str(*log_file, error_msg, TRUE);
        return KEY_LENGTH_ERROR;
    }

    crypto_box_keypair(server_pk, server_sk); // Forming public/secret key pair

    if((send(*conn_fd, server_pk, sizeof(server_pk), 0)) < 0) // Sending server public key
    {
        char* error_msg = "Couldn't send server public key";
        log_message_str(*log_file, error_msg, TRUE);
        return SENDING_ERROR;
    }

    log_message_str(*log_file, "Send server public key:", FALSE);
    log_message_hex(*log_file, server_pk, FALSE);

    if(crypto_scalarmult(shared_sk, server_sk, user_pk) != 0) // Making shared secret key
    {
        char* error_msg = "Shared key error";
        log_message_hex(*log_file, error_msg, TRUE);
        return SHARED_KEY_ERROR;
    }

    log_message_str(*log_file, "Calculated shared secret key:", FALSE);
    log_message_hex(*log_file, shared_sk, FALSE);

    return 0;
}

int shared_key_verify(int* conn_fd, struct sockaddr_in* serv_addr, struct sockaddr_in* user_addr, FILE** log_file, unsigned char* shared_sk)
{

    unsigned char      server_payload[4] = {0x00,0x00,0x00,0x01};
    unsigned char      user_payload[4] = {0x00,0x00,0x00,0x02};
    unsigned char      MAC_CLIENT[MAC_LENGTH];
    unsigned char      MAC_SERVER[MAC_LENGTH];
    unsigned char      ip_buf[16];                      //Length is 16 because maximum IP length with dots is 15 + '\0'
    unsigned char      ip_payload[9];                   //Length is 9 because 4 digits of IP + 4 digits of payload + '\0'
    int                count = 0;


    memset(&ip_buf, 0, sizeof(ip_buf));
    memset(&MAC_CLIENT, 0, sizeof(MAC_CLIENT));
    memset(&MAC_SERVER, 0, sizeof(MAC_SERVER));
    memset(&ip_payload, 0 , sizeof(ip_payload));


    inet_ntop(AF_INET, &serv_addr->sin_addr, (char*)ip_buf, sizeof(ip_buf)); //Get dotted-decimal format of server IP

    if( (recv(*conn_fd, MAC_CLIENT, sizeof(MAC_CLIENT), 0)) < 0) //Receiving MAC_CLIENT
    {
        char* error_msg = "Couldn't receive MAC_CLIENT";
        log_message_str(*log_file, error_msg, TRUE);
        return RECEIVING_ERROR;
    }

    log_message_str(*log_file, "Received MAC_CLIENT:", FALSE);
    log_message_hex(*log_file, MAC_CLIENT, FALSE);

    char* delim_ptr = strtok(ip_buf, ".");  //Getting server IP byte sequence
    while (delim_ptr != NULL)
    {
        *(ip_payload + count++) = atoi(delim_ptr);
        delim_ptr = strtok(NULL, ".");
    }

    memcpy(ip_payload+count, server_payload, sizeof(server_payload)); //Concatenate user ip and server_payload

    if((crypto_auth_hmacsha256_verify(MAC_CLIENT, ip_payload, sizeof(ip_payload), shared_sk)) < 0)
    {
        char* error_msg = "Verification error";
        log_message_hex(*log_file, error_msg, TRUE);
        return VERIFICATION_ERROR;
    }

    memset(&ip_buf, 0, sizeof(ip_buf));
    memset(&ip_payload, 0 , sizeof(ip_payload));

    inet_ntop(AF_INET, &user_addr->sin_addr, (char*)ip_buf, sizeof(ip_buf)); //Get dotted-decimal format of user IP

    delim_ptr = strtok(ip_buf, ".");  //Getting user IP byte sequence
    count = 0;
    while (delim_ptr != NULL)
    {
        *(ip_payload + count++) = atoi(delim_ptr);
        delim_ptr = strtok(NULL, ".");
    }

    memcpy(ip_payload+count, user_payload, sizeof(user_payload)); //Concatenate user ip and user_payload


    crypto_auth_hmacsha256(MAC_SERVER, ip_payload, sizeof(ip_payload), shared_sk);

    if((send(*conn_fd, MAC_SERVER, sizeof(MAC_SERVER), 0) < 0)) // Sending MAC_SERVER
    {
        char* error_msg = "Couldn't send MAC_SERVER";
        log_message_str(*log_file, error_msg, TRUE);
        return SENDING_ERROR;
    }

    log_message_str(*log_file, "Send MAC_SERVER:", FALSE);
    log_message_hex(*log_file, MAC_SERVER, FALSE);

    log_message_str(*log_file, "Verification successful", FALSE);

    return 0;
}

int send_nonce(const int* conn_fd, unsigned char* nonce, int nonce_len)
{
    randombytes_buf(nonce, nonce_len);
    if((send(*conn_fd, nonce, nonce_len, 0)) < 0)
    {
        return SENDING_ERROR;
    }

    return 0;
}

int receive_message(const int* conn_fd, FILE** log_file, unsigned char* shared_sk)
{

    unsigned char      nonce[crypto_aead_xchacha20poly1305_ietf_NPUBBYTES];
    unsigned char      decrypted_msg[MESSAGE_LENGTH];
    unsigned long long decrypted_len;
    unsigned char      cipher_msg[MESSAGE_LENGTH + crypto_aead_xchacha20poly1305_ietf_ABYTES];
    int recv_len = 0, error = 0;

    if((error = send_nonce(conn_fd, nonce, sizeof(nonce))) < 0)
    {
        return error;
    }

    while((recv_len = recv(*conn_fd, cipher_msg, sizeof(cipher_msg), 0)) > 0) //Receive encrypted message, decrypt and print it
    {

        if ((crypto_aead_xchacha20poly1305_ietf_decrypt(decrypted_msg, &decrypted_len, NULL,
                                                        cipher_msg, recv_len,
                                                        NULL, 0, nonce, shared_sk)) < 0)
        {
            char* error_msg = "Decryption failed";
            log_message_str(*log_file, error_msg, TRUE);
            return DECRYPTION_ERROR;
        }
        else
        {
            printf("%.*s", (int)decrypted_len, decrypted_msg);
        }

        if((error = send_nonce(conn_fd, nonce, sizeof(nonce))) < 0)
        {
            return error;
        }
    }

    log_message_str(*log_file, "Transmission finished", FALSE);
    return 0;
}

void close_all(FILE** log_file, const int* listen_fd, const int* conn_fd)
{
    if(*log_file)
        fclose(*log_file);

    if(*listen_fd >= 0)
        close(*listen_fd);

    if(*conn_fd >= 0)
        close(*conn_fd);

}

int main(int argc, char* argv[])
{
    FILE* log_file = NULL;
    struct sockaddr_in serv_addr, user_addr;
    int listen_fd = -1, conn_fd = -1, error;
    unsigned char      shared_sk[crypto_box_SECRETKEYBYTES];

    memset(&serv_addr, 0, sizeof(serv_addr));
    memset(&user_addr, 0, sizeof(user_addr));


    if((error = initiate(&argc, &argv, &log_file)) < 0)
    {
        close_all(&log_file, &listen_fd, &conn_fd);
        return error;
    }

    if((error = bind_socket(&listen_fd, &serv_addr, &log_file)) < 0)
    {
        close_all(&log_file, &listen_fd, &conn_fd);
        return error;
    }

    listen(listen_fd,10);

    while(1)
    {
        if((error = accept_user(&conn_fd, &listen_fd, &user_addr, &log_file)) < 0)
        {
            close_all(&log_file, &listen_fd, &conn_fd);
            return error;
        }

        if((error = key_exchange(&conn_fd, shared_sk, &log_file)) < 0)
        {
            close_all(&log_file, &listen_fd, &conn_fd);
            return error;
        }

        if((error = shared_key_verify(&conn_fd, &serv_addr, &user_addr, &log_file, shared_sk)) < 0)
        {
            close_all(&log_file, &listen_fd, &conn_fd);
            return error;
        }

        if((error = receive_message(&conn_fd, &log_file, shared_sk)) < 0)
        {
            close_all(&log_file, &listen_fd, &conn_fd);
            return error;
        }
    }

}
