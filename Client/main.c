
#include <sodium.h>
#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <zconf.h>
#include <string.h>
#include <arpa/inet.h>

#define PORT 5000


int main(void)
{

    if(sodium_init() < 0)
    {
        perror("No sodium");
        return -1;
    }

    unsigned char server_pk[crypto_box_PUBLICKEYBYTES];
    unsigned char user_pk[crypto_box_PUBLICKEYBYTES];
    unsigned char user_sk[crypto_box_SECRETKEYBYTES];
    unsigned char shared_sk[crypto_box_SECRETKEYBYTES];

    crypto_box_keypair(user_pk, user_sk); // Формирование публичного и секретного ключа

    struct sockaddr_in user_addr;
    int user_fd = 0;
    char buff[33];

    memset(buff,'0', sizeof(buff));
    buff[32] = '\n';
    memset(&user_addr, 0, sizeof(user_addr));

    if((user_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
    {
        printf("Error while creating socket");
        close(user_fd);
        return -1;
    }

    if( (inet_pton(AF_INET, "127.0.0.1", &user_addr.sin_addr)) <= 0)
    {
        perror("Address error\n");
        close(user_fd);
        return -1;
    }
    user_addr.sin_family = AF_INET;
    user_addr.sin_port = htons(PORT);

    if((connect(user_fd, (struct sockaddr*)&user_addr, sizeof(user_addr))) < 0)
    {
        printf("Error while connecting");
        close(user_fd);
        return -1;
    }

    int n = send(user_fd, user_pk, sizeof(user_pk), 0); // Отправка публичного ключа пользователя
    printf("%d\n", n);
    printf("Send a message\n");

    recv(user_fd, server_pk, sizeof(server_pk), 0); // Получение публичного ключа сервера

    if(crypto_scalarmult(shared_sk, user_sk, server_pk) != 0) // Формирование общего секретного ключа
    {
        perror("Shared key error");
        close(user_fd);
        return -1;
    }

    close(user_fd);
    return 0;
}