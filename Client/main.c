
#include <sodium.h>
#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <zconf.h>
#include <string.h>
#include <arpa/inet.h>
#include <errno.h>
#include "../Utilities/utilities.h"

int initiate(const int* argc, char** argv[], FILE** log_file, FILE** read_fp)
{
    char* error;
    errno = 0;
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
        error = "Couldn't open file";
        log_message_str(log_file, error);
        log_message_str(log_file, strerror(errno));
        return FILE_ERROR;
    }

    return 0;

}

int server_connect(int* user_fd, FILE** log_file, struct sockaddr_in* serv_addr)
{
    char* error;
    errno = 0;
    if((*user_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
    {
        error = "Error while creating socket";
        log_message_str(log_file, error);
        log_message_str(log_file, strerror(errno));
        return SOCKET_ERROR;
    }

    log_message_str(log_file, "Socket created");

    if((inet_pton(AF_INET, SERVER_ADDRESS, &serv_addr->sin_addr)) <= 0)
    {
        error = "Server address error";
        log_message_str(log_file, error);
        log_message_str(log_file, strerror(errno));
        return ADDRESS_ERROR;
    }
    serv_addr->sin_family = AF_INET;
    serv_addr->sin_port = htons(SERVER_PORT);

    if((connect(*user_fd, (struct sockaddr*)serv_addr, sizeof(*serv_addr))) < 0)
    {
        error = "Error while connecting";
        log_message_str(log_file, error);
        log_message_str(log_file, strerror(errno));
        return CONNECT_ERROR;
    }

    log_message_str(log_file, "Connected to server");

    return 0;
}

int key_exchange(const int* user_fd, FILE** log_file, unsigned char* shared_sk, int shared_sk_len)
{
    errno = 0;
    unsigned char      user_pk[crypto_box_PUBLICKEYBYTES];
    unsigned char      user_sk[crypto_box_SECRETKEYBYTES];
    unsigned char      server_pk[crypto_box_PUBLICKEYBYTES];
    int                key_len = 0;
    char*              error;

    crypto_box_keypair(user_pk, user_sk); // Forming public/secret key pair

    if((send(*user_fd, user_pk, crypto_box_PUBLICKEYBYTES, 0)) < 0) // Sending user public key
    {
        error = "Couldn't send server public key\n";
        log_message_str(log_file, error);
        log_message_str(log_file, strerror(errno));
        return SENDING_ERROR;
    }

    log_message_str(log_file, "Send user public key:");
    log_message_hex(log_file, (const long int*)user_pk);

    if( (key_len = recv(*user_fd, server_pk, shared_sk_len, 0)) <= 0) // Receiving server public key
    {
        error = "Error receiving public key";
        log_message_str(log_file, error);
        log_message_str(log_file, strerror(errno));
        return RECEIVING_ERROR;
    }

    if(key_len != crypto_box_PUBLICKEYBYTES)
    {
        error = "Key wrong length";
        log_message_str(log_file, error);
        log_message_str(log_file, strerror(errno));
        return LENGTH_ERROR;
    }

    log_message_str(log_file, "Received server public key:");
    log_message_hex(log_file, (const long int*)server_pk);

    if(crypto_scalarmult(shared_sk, user_sk, server_pk) != 0) // Making shared secret key
    {
        error = "Shared key calculation error";
        log_message_str(log_file, error);
        log_message_str(log_file, strerror(errno));
        return SHARED_KEY_ERROR;
    }

    log_message_str(log_file, "Calculated shared secret key:");
    log_message_hex(log_file, (const long int*)shared_sk);

    return 0;
}

int send_response(const int* user_fd, char* response, int response_len)
{
    if((send(*user_fd, response, response_len, 0)) < 0) //Send response to server
    {
        return SENDING_ERROR;
    }

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
    char*              error;
    int                error_num, recv_len;

    errno = 0;
    memset(&ip_buf, 0, sizeof(ip_buf));
    memset(&ip_payload, 0, sizeof(ip_payload));
    memset(&MAC_CLIENT, 0, sizeof(MAC_CLIENT));
    memset(&MAC_SERVER, 0, sizeof(MAC_SERVER));

    memcpy(ip_buf, SERVER_ADDRESS, sizeof(SERVER_ADDRESS));

    concat_ip_payload((char*)ip_payload, (char*)ip_buf, (char*)server_payload, sizeof(server_payload));

    if((crypto_auth_hmacsha256(MAC_CLIENT, ip_payload, sizeof(ip_payload), shared_sk) != 0))
    {
        error = "Couldn't encrypt MAC_CLIENT";
        log_message_str(log_file, error);
        return ENCRYPTION_ERROR;
    }


    if((send(*user_fd, MAC_CLIENT, sizeof(MAC_CLIENT), 0)) < 0) //Sending MAC_CLIENT
    {
        error = "Couldn't send MAC_CLIENT";
        log_message_str(log_file, error);
        log_message_str(log_file, strerror(errno));
        return SENDING_ERROR;
    }

    log_message_str(log_file, "Send MAC_CLIENT:");
    log_message_hex(log_file, (const long int*)MAC_CLIENT);

    if((recv_len = recv(*user_fd, MAC_SERVER, sizeof(MAC_SERVER), 0)) < 0) //Receiving MAC_SERVER or response
    {
        error = "Couldn't receive MAC_SERVER";
        log_message_str(log_file, error);
        log_message_str(log_file, strerror(errno));
        return RECEIVING_ERROR;
    }

    if(strcmp((char*)MAC_SERVER, FAILED) == 0)
    {
        log_message_str(log_file, (char*)MAC_SERVER);
        return RESPONSE_ERROR;
    }

    if(MAC_LENGTH != recv_len)
    {
        error = "MAC_SERVER wrong length";
        log_message_str(log_file, error);
        return LENGTH_ERROR;
    }

    log_message_str(log_file, "Received MAC_SERVER:");
    log_message_hex(log_file, (const long int*)MAC_SERVER);

    memset(&ip_payload, 0 , sizeof(ip_payload));

    getsockname(*user_fd, (struct sockaddr*)&user_addr, &len); //Get user IP

    inet_ntop(AF_INET, &user_addr.sin_addr, (char*)ip_buf, sizeof(ip_buf)); //Get dotted-decimal format of user IP

    concat_ip_payload((char*)ip_payload, (char*)ip_buf, (char*)user_payload, sizeof(server_payload));

    if ((crypto_auth_hmacsha256_verify(MAC_SERVER, ip_payload, sizeof(ip_payload), shared_sk)) < 0)
    {
        error = "Verification error";
        log_message_str(log_file, error);
        if((error_num = send_response(user_fd, FAILED, sizeof(FAILED))) < 0)
        {
            error = "Couldn't send response";
            log_message_str(log_file, error);
            log_message_str(log_file, strerror(errno));
            return error_num;
        }
        return VERIFICATION_ERROR;
    }
    else
    {
        if((error_num = send_response(user_fd, SUCCESS, sizeof(SUCCESS))) < 0)
        {
            error = "Couldn't send response";
            log_message_str(log_file, error);
            log_message_str(log_file, strerror(errno));
            return error_num;
        }
    }

    log_message_str(log_file, "Verification successful");
    log_message_str(log_file, "File opened");

    return 0;

}

int send_message(const int* user_fd, FILE** log_file, FILE** read_file, unsigned char* shared_sk)
{
    unsigned char      cipher_msg[MESSAGE_LENGTH + crypto_aead_xchacha20poly1305_ietf_ABYTES];
    unsigned char      nonce[crypto_aead_xchacha20poly1305_ietf_NPUBBYTES];
    unsigned long long cipher_len;
    unsigned char      message_buf[MESSAGE_LENGTH];
    char*              error;

    memset(&message_buf, 0, sizeof(message_buf));

    while(!feof(*read_file))
    {
        if(fgets((char*)message_buf, sizeof(message_buf), *read_file))
        {
            if((recv(*user_fd, nonce, sizeof(nonce), 0)) <= 0)
            {
                return RECEIVING_ERROR;
            }

            crypto_aead_xchacha20poly1305_ietf_encrypt(cipher_msg, &cipher_len, message_buf,
                                                       sizeof(message_buf), NULL, 0,
                                                       NULL, nonce, shared_sk);

            if((send(*user_fd, cipher_msg, cipher_len, 0)) < 0)
            {
                error = "Couldn't send message";
                log_message_str(log_file, error);
                log_message_str(log_file, strerror(errno));
                return SENDING_ERROR;
            }
        }
    }

    log_message_str(log_file, "Message send");

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

