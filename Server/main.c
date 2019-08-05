
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

void log_message(FILE *log_file, char *msg, int bool_error)
{
    if(!log_file)
        printf("%s\n", msg);
    else
    {
        fprintf(log_file, "%s\n", msg);
        if(bool_error)
            fclose(log_file);
    }
}

int main(int argc, char* argv[])
{
    if( argc < 2 || argc > 3 )
    {
        printf("Usage: ./Server <parameter>\n"
               "-c Console logging\n"
               "-f <log_file_name> File logging\n");
        return -1;
    }


    if(sodium_init() < 0)
    {
        perror("No sodium\n");
        return -1;
    }

    FILE* log_file = NULL;

    if ( (strcmp(argv[1], "-f") == 0) && (argc == 3))
    {
        if ( (log_file = fopen(argv[2], "w")) == NULL)
        {
            perror("Couldn't create file\n");
            return -1;
        }
    }
    else if( (strcmp(argv[1], "-c") != 0) || (argc != 2))
    {
        printf("Wrong parameters. Check usage with ./Client\n");
        return -1;
    }

    struct sockaddr_in serv_addr, user_addr;
    int listen_fd = 0, conn_fd = 0, key_len = 0;
    socklen_t cli_len = sizeof(struct sockaddr_in);
    unsigned char      server_payload[4] = {0x00,0x00,0x00,0x01};
    unsigned char      user_payload[4] = {0x00,0x00,0x00,0x02};
    unsigned char      ip_buf[16];                        //Length is 16 because maximum IP length with dots is 15 + '\0'
    unsigned char      ip_payload[9];                     //Length is 9 because 4 digits of IP + 4 digits of payload + '\0'
    unsigned char*     ip_pay_ptr;
    unsigned char      MAC_CLIENT[MAC_LENGTH];
    unsigned char      MAC_SERVER[MAC_LENGTH];
    unsigned char      user_pk[crypto_box_PUBLICKEYBYTES];
    unsigned char      server_pk[crypto_box_PUBLICKEYBYTES];
    unsigned char      server_sk[crypto_box_SECRETKEYBYTES];
    unsigned char      shared_sk[crypto_box_SECRETKEYBYTES];
    unsigned char      nonce[crypto_aead_xchacha20poly1305_ietf_NPUBBYTES];
    unsigned char      decrypted_msg[MESSAGE_LENGTH];
    unsigned long long decrypted_len;
    unsigned char      cipher_msg[MESSAGE_LENGTH + crypto_aead_xchacha20poly1305_ietf_ABYTES];
    unsigned long long cipher_len = MESSAGE_LENGTH + crypto_aead_xchacha20poly1305_ietf_ABYTES;


    memset(&serv_addr, 0, sizeof(serv_addr));
    memset(&user_addr, 0, sizeof(user_addr));
    memset(&ip_buf, 0, sizeof(ip_buf));
    memset(&MAC_CLIENT, 0, sizeof(MAC_CLIENT));
    memset(&MAC_SERVER, 0, sizeof(MAC_SERVER));
    memset(&ip_payload, 0 , sizeof(ip_payload));

    if((listen_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
    {
        char* error = "Error while creating socket";
        log_message(log_file, error, TRUE);
        close(listen_fd);
        return 0;
    }

    log_message(log_file, "Socket created", FALSE);

    inet_pton(AF_INET, SERVER_ADDRESS, &serv_addr.sin_addr);
    //serv_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(PORT);

    if((bind(listen_fd, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) ) < 0)
    {
        char* error = "Binding";
        log_message(log_file, error, TRUE);
        close(listen_fd);
        return -1;
    }

    listen(listen_fd,10);

    while(1)
    {
        if((conn_fd = accept(listen_fd, (struct sockaddr*)&user_addr, &cli_len) ) < 0)
        {
            char* error = "Error while accepting";
            log_message(log_file, error, TRUE);
            close(conn_fd);
            close(listen_fd);
            return -1;
        }

        log_message(log_file, "User connected", FALSE);

        printf("Connected\n");

        if((key_len = recv(conn_fd, user_pk, sizeof(user_pk), 0)) <= 0) // Receiving user public key
        {
            char* error = "Couldn't receive public key";
            log_message(log_file, error, TRUE);
            close(conn_fd);
            close(listen_fd);
            break;
        }

        log_message(log_file, "Received user public key:", FALSE);
        log_message(log_file, user_pk, FALSE);

        if(key_len != crypto_box_PUBLICKEYBYTES)
        {
            char* error = "Key wrong length";
            log_message(log_file, error, TRUE);
            close(conn_fd);
            close(listen_fd);
            return -1;
        }

        crypto_box_keypair(server_pk, server_sk); // Forming public/secret key pair

        if((send(conn_fd, server_pk, sizeof(server_pk), 0)) < 0) // Sending server public key
        {
            char* error = "Couldn't send server public key";
            log_message(log_file, error, TRUE);
            close(conn_fd);
            close(listen_fd);
            return -1;
        }

        log_message(log_file, "Send server public key:", FALSE);
        log_message(log_file, server_pk, FALSE);

        if(crypto_scalarmult(shared_sk, server_sk, user_pk) != 0) // Making shared secret key
        {
            char* error = "Shared key error";
            log_message(log_file, error, TRUE);
            close(conn_fd);
            close(listen_fd);
            return -1;
        }

        log_message(log_file, "Calculated shared secret key:", FALSE);
        log_message(log_file, shared_sk, FALSE);

        inet_ntop(AF_INET, &serv_addr.sin_addr, (char*)ip_buf, sizeof(ip_buf)); //Get dotted-decimal format of server IP

        if( (recv(conn_fd, MAC_CLIENT, sizeof(MAC_CLIENT), 0)) < 0) //Receiving MAC_CLIENT
        {
            char* error = "Couldn't receive MAC_CLIENT";
            log_message(log_file, error, TRUE);
            close(conn_fd);
            return -1;
        }

        log_message(log_file, "Received MAC_CLIENT:", FALSE);
        log_message(log_file, MAC_CLIENT, FALSE);

        ip_pay_ptr = ip_payload;
        char* delim_ptr = strtok(ip_buf, ".");  //Getting server IP byte sequence
        while (delim_ptr != NULL)
        {
            *ip_pay_ptr++ = atoi(delim_ptr);
            delim_ptr = strtok(NULL, ".");
        }

        for(int i = 0; i < sizeof(server_payload); i++) //Concatenate server ip and server_payload
            *(ip_pay_ptr + i) = server_payload[i];

        if((crypto_auth_hmacsha256_verify(MAC_CLIENT, ip_payload, sizeof(ip_payload), shared_sk)) < 0)
        {
            char* error = "Verification error";
            log_message(log_file, error, TRUE);
            close(conn_fd);
            close(listen_fd);
            return -1;
        }

        log_message(log_file, "Verification successful", FALSE);

        memset(&ip_buf, 0, sizeof(ip_buf));
        memset(&ip_payload, 0 , sizeof(ip_payload));

        inet_ntop(AF_INET, &user_addr.sin_addr, (char*)ip_buf, sizeof(ip_buf)); //Get dotted-decimal format of user IP

        ip_pay_ptr = ip_payload;
        delim_ptr = strtok(ip_buf, ".");  //Getting user IP byte sequence
        while (delim_ptr != NULL)
        {
            *ip_pay_ptr++ = atoi(delim_ptr);
            delim_ptr = strtok(NULL, ".");
        }

        for(int i = 0; i < sizeof(user_payload); i++) //Concatenate user ip and user_payload
            *(ip_pay_ptr + i) = user_payload[i];

        crypto_auth_hmacsha256(MAC_SERVER, ip_payload, sizeof(ip_payload), shared_sk);

        if((send(conn_fd, MAC_SERVER, sizeof(MAC_SERVER), 0) < 0)) // Sending MAC_SERVER
        {
            char* error = "Couldn't send MAC_SERVER";
            log_message(log_file, error, TRUE);
            close(conn_fd);
            close(listen_fd);
            return -1;
        }

        log_message(log_file, "Send MAC_SERVER:", FALSE);
        log_message(log_file, MAC_SERVER, FALSE);

        randombytes_buf_deterministic(nonce, sizeof(nonce), MAC_SERVER);

        while((recv(conn_fd, cipher_msg, sizeof(cipher_msg), 0)) > 0) //Receive encrypted message, decrypt and print it
        {
            if ((crypto_aead_xchacha20poly1305_ietf_decrypt(decrypted_msg, &decrypted_len, NULL,
                                                            cipher_msg, cipher_len,
                                                            NULL, 0, nonce, shared_sk)) < 0)
            {
                char* error = "Decryption failed";
                log_message(log_file, error, TRUE);
                close(conn_fd);
                close(listen_fd);
                return -1;
            }
            else
            {
                printf("%s", decrypted_msg);
            }
        }

        close(conn_fd);
    }

    memset(&user_addr, 0, sizeof(user_addr));
    memset(&ip_buf, 0, sizeof(ip_buf));
    memset(&MAC_CLIENT, 0, sizeof(MAC_CLIENT));
    memset(&MAC_SERVER, 0, sizeof(MAC_SERVER));
    memset(&ip_payload, 0 , sizeof(ip_payload));

    close(conn_fd);
    close(listen_fd);

    return 0;
}
