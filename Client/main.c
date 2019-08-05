
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

    if( argc < 3 || argc > 4 )
    {
        printf("Usage: ./Client <message_file_name> <parameter>\n"
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
    FILE* read_fp = NULL;

    if ( (strcmp(argv[2], "-f") == 0) && (argc == 4))
    {
        if ( (log_file = fopen(argv[3], "w")) == NULL)
        {
            perror("Couldn't create file\n");
            return -1;
        }
    }
    else if( (strcmp(argv[2], "-c") != 0) || (argc != 3))
    {
        printf("Wrong parameters. Check usage with ./Client\n");
        return -1;
    }

    if((read_fp = fopen(argv[1],"r")) == NULL)
    {
        char* error = "Couldn't open file";
        log_message(log_file, error, TRUE);
        return -1;
    }


    struct sockaddr_in serv_addr, user_addr;
    int user_fd = 0;
    unsigned int       len = sizeof(struct sockaddr);
    unsigned char      message_buf[MESSAGE_LENGTH];
    unsigned char      cipher_msg[MESSAGE_LENGTH + crypto_aead_xchacha20poly1305_ietf_ABYTES];
    unsigned char      server_payload[4] = {0x00,0x00,0x00,0x01};
    unsigned char      user_payload[4] = {0x00,0x00,0x00,0x02};
    unsigned char      ip_buf[16];              //Length is 16 because maximum IP length with dots is 15 + '\0'
    unsigned char      ip_payload[9];           //Length is 9 because 4 digits of IP + 4 digits of payload + '\0'
    unsigned char*     ip_pay_ptr = ip_payload;
    unsigned char      MAC_CLIENT[MAC_LENGTH];
    unsigned char      MAC_SERVER[MAC_LENGTH];
    unsigned char      server_pk[crypto_box_PUBLICKEYBYTES];
    unsigned char      user_pk[crypto_box_PUBLICKEYBYTES];
    unsigned char      user_sk[crypto_box_SECRETKEYBYTES];
    unsigned char      shared_sk[crypto_box_SECRETKEYBYTES];
    unsigned char      nonce[crypto_aead_xchacha20poly1305_ietf_NPUBBYTES];
    unsigned long long cipher_len;

    crypto_box_keypair(user_pk, user_sk); // Forming public/secret key pair

    memset(&serv_addr, 0, sizeof(serv_addr));
    memset(&MAC_CLIENT, 0, sizeof(MAC_CLIENT));
    memset(&MAC_SERVER, 0, sizeof(MAC_SERVER));
    memset(&ip_buf, 0, sizeof(ip_buf));
    memset(&ip_payload, 0 , sizeof(ip_payload));
    memset(&message_buf, 0, sizeof(message_buf));

    if((user_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
    {
        char* error = "Error while creating socket";
        log_message(log_file, error, TRUE);
        close(user_fd);
        return -1;
    }

    log_message(log_file, "Socket created", FALSE);

    if((inet_pton(AF_INET, SERVER_ADDRESS, &serv_addr.sin_addr)) <= 0)
    {
        char* error = "Server address error";
        log_message(log_file, error, TRUE);
        close(user_fd);
        return -1;
    }
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(SERVER_PORT);


    inet_ntop(AF_INET, &serv_addr.sin_addr, (char*)ip_buf, sizeof(ip_buf)); //Get dotted-decimal format of server IP

    if((connect(user_fd, (struct sockaddr*)&serv_addr, sizeof(serv_addr))) < 0)
    {
        char* error = "Error while connecting";
        log_message(log_file, error, TRUE);
        close(user_fd);
        return -1;
    }

    log_message(log_file, "Connected to server", FALSE);

    if((send(user_fd, user_pk, sizeof(user_pk), 0)) < 0) // Sending user public key
    {
        char* error = "Couldn't send server public key\n";
        log_message(log_file, error, TRUE);
        close(user_fd);
        return -1;
    }

    log_message(log_file, "Send user public key:", FALSE);
    log_message(log_file, user_pk, FALSE);

    if((recv(user_fd, server_pk, sizeof(server_pk), 0)) <= 0) // Receiving server public key
    {
        char* error = "Error receiving public key";
        log_message(log_file, error, TRUE);
        close(user_fd);
        return -1;
    }

    log_message(log_file, "Received server public key:", FALSE);
    log_message(log_file, server_pk, FALSE);

    if(crypto_scalarmult(shared_sk, user_sk, server_pk) != 0) // Making shared secret key
    {
        char* error = "Shared key calculation error";
        log_message(log_file, error, TRUE);
        close(user_fd);
        return -1;
    }

    log_message(log_file, "Calculated shared secret key:", FALSE);
    log_message(log_file, shared_sk, FALSE);

    char* delim_ptr = strtok(ip_buf, ".");  //Getting server IP byte sequence
    while (delim_ptr != NULL)
    {
        *ip_pay_ptr++ = atoi(delim_ptr);
        delim_ptr = strtok(NULL, ".");
    }

    for(int i = 0; i < sizeof(server_payload); i++) //Concatenate server ip and server_payload
        *(ip_pay_ptr + i) = server_payload[i];

    crypto_auth_hmacsha256(MAC_CLIENT, ip_payload, sizeof(ip_payload), shared_sk);

    if((send(user_fd, MAC_CLIENT, sizeof(MAC_CLIENT), 0)) < 0) //Sending MAC_CLIENT
    {
        char* error = "Couldn't send MAC_CLIENT";
        log_message(log_file, error, TRUE);
        close(user_fd);
        return -1;
    }

    log_message(log_file, "Send MAC_CLIENT:", FALSE);
    log_message(log_file, MAC_CLIENT, FALSE);

    if((recv(user_fd, MAC_SERVER, sizeof(MAC_SERVER), 0)) < 0) //Receiving MAC_SERVER
    {
        char* error = "Couldn't receive MAC_SERVER";
        log_message(log_file, error, TRUE);
        close(user_fd);
        return -1;
    }

    log_message(log_file, "Received MAC_SERVER:", FALSE);
    log_message(log_file, MAC_SERVER, FALSE);

    memset(&ip_buf, 0, sizeof(ip_buf));
    memset(&ip_payload, 0 , sizeof(ip_payload));

    getsockname(user_fd, (struct sockaddr*)&user_addr, &len); //Get user IP

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

    if ((crypto_auth_hmacsha256_verify(MAC_SERVER, ip_payload, sizeof(ip_payload), shared_sk)) < 0)
    {
        char* error = "Verification error";
        log_message(log_file, error, TRUE);
        close(user_fd);
        return -1;
    }

    log_message(log_file, "Verification successful", FALSE);

    log_message(log_file, "File opened", FALSE);

    randombytes_buf_deterministic(nonce, sizeof(nonce), MAC_SERVER); //Generating seeded nonce

    while(!feof(read_fp))
    {
        if(fgets((char*)message_buf, sizeof(message_buf), read_fp))
        {
            crypto_aead_xchacha20poly1305_ietf_encrypt(cipher_msg, &cipher_len, message_buf,
                                                       sizeof(message_buf), NULL, 0, NULL,
                                                       nonce, shared_sk);
            send(user_fd, cipher_msg, sizeof(cipher_msg), 0);
            memset(&message_buf, 0, sizeof(message_buf));
        }
    }

    log_message(log_file, "Message send", FALSE);

    if(log_file)
        fclose(log_file);
    fclose(read_fp);
    close(user_fd);

    return 0;
}

