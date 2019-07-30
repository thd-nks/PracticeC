
#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <zconf.h>
#include <string.h>
#include <sodium.h>

#define PORT 5000

int main(void) {

    struct sockaddr_in serv_addr;
    int listen_fd = 0, conn_fd = 0;
    unsigned char user_pk[crypto_box_PUBLICKEYBYTES];
    unsigned char server_pk[crypto_box_PUBLICKEYBYTES];
    unsigned char server_sk[crypto_box_SECRETKEYBYTES];
    unsigned char shared_sk[crypto_box_SECRETKEYBYTES];

    //memset(buff,'0', sizeof(buff));
    memset(&serv_addr, 0, sizeof(serv_addr));

    if((listen_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
    {
        printf("Error while creating socket");
        close(listen_fd);
        return 0;
    }

    serv_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(PORT);

    if((bind(listen_fd, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) ) < 0)
    {
        perror("Binding\n");
        return -1;
    }

    listen(listen_fd,10);

    while(1)
    {
        if((conn_fd = accept(listen_fd, NULL, NULL) ) < 0)
        {
            printf("Error while accepting");
            close(conn_fd);
            close(listen_fd);
            return -1;
        }

        printf("Connected\n");

        int n = recv(conn_fd, user_pk, sizeof(user_pk), 0);
        printf("%d\n", n);

        crypto_box_keypair(server_pk, server_sk);

        if(n <=0)
            break;

        send(conn_fd, server_pk, sizeof(server_pk), 0);

        if( crypto_scalarmult(shared_sk, server_sk, user_pk) != 0)
        {
            perror("Shared key error");
            close(conn_fd);
            close(listen_fd);
            return -1;
        }

        close(conn_fd);
    }

    close(conn_fd);
    close(listen_fd);

    return 0;
}
