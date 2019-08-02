
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

int main(void) {

    struct sockaddr_in serv_addr, user_addr;
    int listen_fd = 0, conn_fd = 0, key_len = 0;
    socklen_t cli_len = sizeof(struct sockaddr_in);
    unsigned char   server_payload[4] = {0x00,0x00,0x00,0x01};
    unsigned char   user_payload[4] = {0x00,0x00,0x00,0x02};
    unsigned char   ip_buf[16];                        //Length is 16 because maximum IP length with dots is 15 + '\0'
    unsigned char   ip_payload[9];                     //Length is 9 because 4 digits of IP + 4 digits of payload + '\0'
    unsigned char*  ip_pay_ptr = ip_payload;
    unsigned char   MAC_CLIENT[MAC_LENGTH];
    unsigned char   MAC_SERVER[MAC_LENGTH];
    unsigned char   user_pk[crypto_box_PUBLICKEYBYTES];
    unsigned char   server_pk[crypto_box_PUBLICKEYBYTES];
    unsigned char   server_sk[crypto_box_SECRETKEYBYTES];
    unsigned char   shared_sk[crypto_box_SECRETKEYBYTES];

    memset(&serv_addr, 0, sizeof(serv_addr));
    memset(&user_addr, 0, sizeof(user_addr));
    memset(&ip_buf, 0, sizeof(ip_buf));
    memset(&MAC_CLIENT, 0, sizeof(MAC_CLIENT));
    memset(&MAC_SERVER, 0, sizeof(MAC_SERVER));
    memset(&ip_payload, 0 , sizeof(ip_payload));

    if((listen_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
    {
        perror("Error while creating socket\n");
        close(listen_fd);
        return 0;
    }


    inet_pton(AF_INET, SERVER_ADDRESS, &serv_addr.sin_addr);
    //serv_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(PORT);

    if((bind(listen_fd, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) ) < 0)
    {
        perror("Binding\n");
        close(listen_fd);
        return -1;
    }

    listen(listen_fd,10);

    while(1)
    {
        if((conn_fd = accept(listen_fd, (struct sockaddr*)&user_addr, &cli_len) ) < 0)
        {
            perror("Error while accepting\n");
            close(conn_fd);
            close(listen_fd);
            return -1;
        }

        printf("Connected\n");

        if((key_len = recv(conn_fd, user_pk, sizeof(user_pk), 0)) <= 0) // Receiving user public key
        {
            perror("Couldn't receive public key\n");
            break;
        }

        if(key_len != crypto_box_PUBLICKEYBYTES)
        {
            perror("Key wrong length\n");
            return -1;
        }

        printf("%d\n", key_len);

        crypto_box_keypair(server_pk, server_sk); // Forming public/secret key pair

        if((send(conn_fd, server_pk, sizeof(server_pk), 0)) < 0) // Sending server public key
        {
            perror("Couldn't send server public key\n");
            close(conn_fd);
            close(listen_fd);
            return -1;
        }

        if(crypto_scalarmult(shared_sk, server_sk, user_pk) != 0) // Making shared secret key
        {
            perror("Shared key error\n");
            close(conn_fd);
            close(listen_fd);
            return -1;
        }


        inet_ntop(AF_INET, &serv_addr.sin_addr, (char*)ip_buf, sizeof(ip_buf)); //Get dotted-decimal format of server IP

        recv(conn_fd, MAC_CLIENT, sizeof(MAC_CLIENT), 0);

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
            perror("Verification error\n");
            close(conn_fd);
            close(listen_fd);
            return -1;
        }

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

        send(conn_fd, MAC_SERVER, sizeof(MAC_SERVER), 0);

        close(conn_fd);
    }

    close(conn_fd);
    close(listen_fd);

    return 0;
}
