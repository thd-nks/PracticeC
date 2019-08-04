
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

int main(void)
{

    if(sodium_init() < 0)
    {
        perror("No sodium");
        return -1;
    }
    FILE* fp;
    struct sockaddr_in serv_addr, user_addr;
    int user_fd = 0, key_len = 0;
    unsigned int       len = sizeof(struct sockaddr);
    unsigned char      message_buf[MESSAGE_LENGTH];
    unsigned char      cipher_msg[MESSAGE_LENGTH + crypto_aead_xchacha20poly1305_ietf_ABYTES];
    unsigned char      server_payload[4] = {0x00,0x00,0x00,0x01};
    unsigned char      user_payload[4] = {0x00,0x00,0x00,0x02};
    unsigned char      ip_buf[16];              //Length is 16 because maximum IP length with dots is 15 + '\0'
    unsigned char      ip_payload[9];            //Length is 9 because 4 digits of IP + 4 digits of payload + '\0'
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
        printf("Error while creating socket");
        close(user_fd);
        return -1;
    }

    if((inet_pton(AF_INET, SERVER_ADDRESS, &serv_addr.sin_addr)) <= 0)
    {
        perror("Address error\n");
        close(user_fd);
        return -1;
    }
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(SERVER_PORT);


    inet_ntop(AF_INET, &serv_addr.sin_addr, (char*)ip_buf, sizeof(ip_buf)); //Get dotted-decimal format of server IP

    if((connect(user_fd, (struct sockaddr*)&serv_addr, sizeof(serv_addr))) < 0)
    {
        printf("Error while connecting\n");
        close(user_fd);
        return -1;
    }

    if((key_len = send(user_fd, user_pk, sizeof(user_pk), 0)) < 0) // Sending user public key
    {
        perror("Couldn't send server public key\n");
        close(user_fd);
        return -1;
    }
    printf("%d\n", key_len);
    printf("Send a key\n");

    if((recv(user_fd, server_pk, sizeof(server_pk), 0)) <= 0) // Receiving server public key
    {
        perror("Received empty key\n");
        return -1;
    }

    if(crypto_scalarmult(shared_sk, user_sk, server_pk) != 0) // Making shared secret key
    {
        perror("Shared key error\n");
        close(user_fd);
        return -1;
    }

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
        close(user_fd);
        return -1;
    }

    if((recv(user_fd, MAC_SERVER, sizeof(MAC_SERVER), 0)) < 0) //Receiving MAC_SERVER
    {
        close(user_fd);
        return -1;
    }

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
        perror("Verification error\n");
        close(user_fd);
        return -1;
    }

    if((fp = fopen("CMakeLists.txt","r")) == NULL)
    {
        perror("Couldn't open file\n");
        close(user_fd);
        return -1;
    }

    randombytes_buf_deterministic(nonce, sizeof(nonce), MAC_SERVER);

    while(!feof(fp))
    {
        if(fgets((char*)message_buf, sizeof(message_buf), fp))
        {
            crypto_aead_xchacha20poly1305_ietf_encrypt(cipher_msg, &cipher_len, message_buf,
                                                       sizeof(message_buf), NULL, 0, NULL,
                                                       nonce, shared_sk);
            send(user_fd, cipher_msg, sizeof(cipher_msg), 0);
            memset(&message_buf, 0, sizeof(message_buf));
        }
    }

    fclose(fp);
    close(user_fd);

    return 0;
}