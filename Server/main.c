
#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <zconf.h>
#include <string.h>
#include <sodium.h>
#include <arpa/inet.h>
#include <errno.h>
#include <asm/ioctls.h>
#include <sys/ioctl.h>
#include "../Utilities/utilities.h"

#define MAX_USERS 5
#define FINISHED 1

enum State
{
    USER_PK,
    VERIFY_MAC,
    GET_RESPONSE,
    RECEIVE_MESSAGE,
    DONE
};

typedef struct
{
    struct sockaddr_in* user_addr;
    int user_fd;
    enum State state;
    unsigned char shared_sk[crypto_box_SECRETKEYBYTES];
} user_info;

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
        if ( (*log_file = fopen((*argv)[2], "w")) == NULL)
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
    char* error, argp;
    errno = 0;
    socklen_t size = sizeof(*serv_addr);

    if((*listen_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
    {
        error = "Error while creating socket";
        log_message_str(log_file, error);
        log_message_str(log_file, strerror(errno));
        return SOCKET_ERROR;
    }

    log_message_str(log_file, "Socket created");

    inet_pton(AF_INET, SERVER_ADDRESS, &serv_addr->sin_addr);
    serv_addr->sin_family = AF_INET;
    serv_addr->sin_port = htons(SERVER_PORT);

    if((ioctl(*listen_fd, FIONBIO, &argp)) < 0)  //Setting socket to be non-blocking
    {
        error = "ioctl error";
        log_message_str(log_file, error);
        log_message_str(log_file, strerror(errno));
        return IOCTL_ERROR;
    }

    if((bind(*listen_fd, (struct sockaddr*)serv_addr, size) ) < 0)
    {
        error = "Binding error";
        log_message_str(log_file, error);
        log_message_str(log_file, strerror(errno));
        return BINDING_ERROR;
    }

    return 0;
}

int accept_user(int* conn_fd, const int* listen_fd, struct sockaddr_in* user_addr, FILE** log_file)
{
    char* error;
    socklen_t cli_len = sizeof(struct sockaddr_in);

    if((*conn_fd = accept(*listen_fd, (struct sockaddr*)user_addr, &cli_len) ) < 0)
    {
        error = "Couldn't accept user";
        log_message_str(log_file, error);
        log_message_str(log_file, strerror(errno));
        return ACCEPT_ERROR;
    }

    log_message_str(log_file, "User connected");

    return 0;
}

int key_exchange(const int* conn_fd, unsigned char* shared_sk, FILE** log_file)
{
    int                key_len = 0;
    char*              error;
    unsigned char      user_pk[crypto_box_PUBLICKEYBYTES];
    unsigned char      server_pk[crypto_box_PUBLICKEYBYTES];
    unsigned char      server_sk[crypto_box_SECRETKEYBYTES];

    errno = 0;

    if((key_len = recv(*conn_fd, user_pk, sizeof(user_pk), 0)) <= 0) // Receiving user public key
    {
        error = "Couldn't receive public key";
        log_message_str(log_file, error);
        log_message_str(log_file, strerror(errno));
        return RECEIVING_ERROR;
    }

    log_message_str(log_file, "Received user public key:");
    log_message_hex(log_file, (const long int*)user_pk);

    if(key_len != crypto_box_PUBLICKEYBYTES)
    {
        error = "Key wrong length";
        log_message_str(log_file, error);
        return LENGTH_ERROR;
    }

    crypto_box_keypair(server_pk, server_sk); // Forming public/secret key pair

    if((send(*conn_fd, server_pk, sizeof(server_pk), 0)) < 0) // Sending server public key
    {
        error = "Couldn't send server public key";
        log_message_str(log_file, error);
        log_message_str(log_file, strerror(errno));
        return SENDING_ERROR;
    }

    log_message_str(log_file, "Send server public key:");
    log_message_hex(log_file, (const long int*)server_pk);

    if(crypto_scalarmult(shared_sk, server_sk, user_pk) != 0) // Making shared secret key
    {
        error = "Shared key error";
        log_message_str(log_file, error);
        log_message_str(log_file, strerror(errno));
        return SHARED_KEY_ERROR;
    }

    log_message_str(log_file, "Calculated shared secret key:");
    log_message_hex(log_file, (const long int*)shared_sk);

    return 0;
}

int send_response(const int* conn_fd, char* response, int response_len)
{
    if((send(*conn_fd, response, response_len, 0)) < 0) //Send response to server
    {
        return SENDING_ERROR;
    }

    return 0;
}

int verify_mac_client(user_info* user, struct sockaddr_in* serv_addr, FILE** log_file)
{
    unsigned char      server_payload[4] = {0x00,0x00,0x00,0x01};
    unsigned char      user_payload[4] = {0x00,0x00,0x00,0x02};
    unsigned char      MAC_CLIENT[MAC_LENGTH];
    unsigned char      MAC_SERVER[MAC_LENGTH];
    unsigned char      ip_buf[16];                      //Length is 16 because maximum IP length with dots is 15 + '\0'
    unsigned char      ip_payload[9];                   //Length is 9 because 4 digits of IP + 4 digits of payload + '\0'
    char*              error;
    int                error_num, recv_len;

    errno = 0;
    memset(&ip_buf, 0, sizeof(ip_buf));
    memset(&MAC_CLIENT, 0, sizeof(MAC_CLIENT));
    memset(&MAC_SERVER, 0, sizeof(MAC_SERVER));
    memset(&ip_payload, 0 , sizeof(ip_payload));

    inet_ntop(AF_INET, &serv_addr->sin_addr, (char*)ip_buf, sizeof(ip_buf)); //Get dotted-decimal format of server IP

    if( (recv_len = recv(user->user_fd, MAC_CLIENT, sizeof(MAC_CLIENT), 0)) < 0) //Receiving MAC_CLIENT
    {
        error = "Couldn't receive MAC_CLIENT";
        log_message_str(log_file, error);
        log_message_str(log_file, strerror(errno));
        return RECEIVING_ERROR;
    }

    if(MAC_LENGTH != recv_len)
    {
        error = "MAC_CLIENT wrong length";
        log_message_str(log_file, error);
        return LENGTH_ERROR;
    }

    log_message_str(log_file, "Received MAC_CLIENT:");
    log_message_hex(log_file, (const long int*)MAC_CLIENT);

    concat_ip_payload((char*)ip_payload, (char*)ip_buf, (char*)server_payload, sizeof(server_payload));

    if((crypto_auth_hmacsha256_verify(MAC_CLIENT, ip_payload, sizeof(ip_payload), user->shared_sk)) < 0)
    {
        error = "Verification error";
        log_message_str(log_file, error);
        if((error_num = send_response(&user->user_fd, FAILED, sizeof(FAILED))) < 0)
        {
            error = "Couldn't send response";
            log_message_str(log_file, error);
            log_message_str(log_file, strerror(errno));
            return error_num;
        }
        return VERIFICATION_ERROR;
    }

    memset(&ip_buf, 0, sizeof(ip_buf));
    memset(&ip_payload, 0 , sizeof(ip_payload));

    inet_ntop(AF_INET, &user->user_addr->sin_addr, (char*)ip_buf, sizeof(ip_buf)); //Get dotted-decimal format of user IP

    concat_ip_payload((char*)ip_payload, (char*)ip_buf, (char*)user_payload, sizeof(user_payload));

    if((crypto_auth_hmacsha256(MAC_SERVER, ip_payload, sizeof(ip_payload), user->shared_sk) != 0))
    {
        error = "Couldn't encrypt MAC_SERVER";
        log_message_str(log_file, error);
        return ENCRYPTION_ERROR;
    }

    if((send(user->user_fd, MAC_SERVER, sizeof(MAC_SERVER), 0) < 0)) // Sending MAC_SERVER
    {
        error = "Couldn't send MAC_SERVER";
        log_message_str(log_file, error);
        log_message_str(log_file, strerror(errno));
        return SENDING_ERROR;
    }

    log_message_str(log_file, "Send MAC_SERVER:");
    log_message_hex(log_file, (const long int*)MAC_SERVER);

    return 0;
}

int get_response(const int* user_fd, FILE** log_file)
{
    char    response[8];
    char*   error;

    memset(&response, 0, sizeof(response));

    if((recv(*user_fd, response, sizeof(response), 0)) < 0)
    {
        error = "Couldn't receive user response";
        log_message_str(log_file, error);
        log_message_str(log_file, strerror(errno));
        return RECEIVING_ERROR;
    }

    if(strcmp(response, SUCCESS) == 0);
    else if(strcmp(response, FAILED) == 0)
    {
        log_message_str(log_file, response);
        return RESPONSE_ERROR;
    }
    else
    {
        error = "Unknown response";
        log_message_str(log_file, error);
        return RESPONSE_ERROR;
    }

    log_message_str(log_file, "Verification successful");

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
    int                recv_len = 0, error_num = 0;
    char*              error;

    if((error_num = send_nonce(conn_fd, nonce, sizeof(nonce))) < 0)
    {
        error = "Couldn't send nonce";
        log_message_str(log_file, error);
        return error_num;
    }

    if ((recv_len = recv(*conn_fd, cipher_msg, sizeof(cipher_msg), 0)) >
           0) //Receive encrypted message, decrypt and print it
    {
        if ((crypto_aead_xchacha20poly1305_ietf_decrypt(decrypted_msg, &decrypted_len, NULL,
                                                        cipher_msg, recv_len, NULL,
                                                        0, nonce, shared_sk)) < 0)
        {
            error = "Decryption failed";
            log_message_str(log_file, error);
            return DECRYPTION_ERROR;
        }
        else
        {
            printf("%.*s", (int) decrypted_len, decrypted_msg);
        }
    }
    else
    {
        log_message_str(log_file, "Transmission finished");
        return FINISHED;
    }

    return 0;
}

void close_all(FILE** log_file, const int* listen_fd, const int* conn_fd)
{
    if((NULL != log_file) && (*log_file))
        fclose(*log_file);

    if((NULL != listen_fd) && (*listen_fd >= 0))
        close(*listen_fd);

    if((NULL != conn_fd) && (*conn_fd >= 0))
        close(*conn_fd);

}

int handle_connection(user_info* user, FILE** log_file, struct sockaddr_in* serv_addr)
{
    int  error;
    char ip_buf[16]; //Length is 16 because maximum IP length with dots is 15 + '\0'
    char user_log[21]; //Length is 21 because maximum IP length + '#' + fd + ':' + '\0'

    inet_ntop(AF_INET, &user->user_addr->sin_addr, ip_buf, sizeof(ip_buf)); //Get dotted-decimal format of server IP

    sprintf(user_log, "%s#%d:", ip_buf, user->user_fd);

    log_message_str(log_file, user_log);

    switch (user->state) {
        case (USER_PK):
            if ((error = key_exchange(&user->user_fd, user->shared_sk, log_file)) < 0)
                return error;
            user->state = VERIFY_MAC;
            break;
        case (VERIFY_MAC):
            if ((error = verify_mac_client(user, serv_addr, log_file) < 0))
                return error;
            user->state = GET_RESPONSE;
            break;
        case (GET_RESPONSE):
            if ((error = get_response(&user->user_fd, log_file) < 0))
                return error;
            user->state = RECEIVE_MESSAGE;
            break;
        case (RECEIVE_MESSAGE):
            if ((error = receive_message(&user->user_fd, log_file, user->shared_sk)) < 0)
                return error;

            if(FINISHED == error)
                user->state = DONE;
            break;
        case (DONE):
            break;
    }
    return 0;
}

void disconnect_user(user_info* user, fd_set* writing_set, fd_set* master_set, int* max_fd)
{
    close_all(NULL, NULL, &user->user_fd);
    if(RECEIVE_MESSAGE == user->state || DONE == user->state)
        FD_CLR(user->user_fd, writing_set);
    FD_CLR(user->user_fd, master_set);

    if (user->user_fd == *max_fd)
    {
        while (!FD_ISSET(*max_fd, master_set))
            (*max_fd)--;
    }

    sodium_memzero(user->shared_sk, sizeof(user->shared_sk));
    free(user->user_addr);
    free(user);
}


int main(int argc, char* argv[])
{
    FILE* log_file = NULL;
    struct sockaddr_in  serv_addr;
    struct sockaddr_in* user_addr;
    int                 listen_fd = -1, conn_fd = -1, connected_users = 0, current_user = 0, search_user_fd = 0,
                        error, max_fd, select_num, i;
    char*               error_msg;
    fd_set              master_set, working_set, writing_set, temp_set;
    user_info*          users[MAX_USERS];


    memset(&serv_addr, 0, sizeof(serv_addr));
    memset(users, 0, sizeof(users));


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

    if((listen(listen_fd, MAX_USERS) < 0))
    {
        error_msg = "Couldn't listen";
        log_message_str(&log_file, error_msg);
        close_all(&log_file, &listen_fd, &conn_fd);
        return LISTEN_ERROR;
    }

    FD_ZERO(&master_set);
    FD_ZERO(&writing_set);
    max_fd = listen_fd;
    FD_SET(listen_fd, &master_set);

    while(1)
    {
         memcpy(&working_set, &master_set, sizeof(master_set));
         memcpy(&writing_set, &temp_set, sizeof(temp_set));

        select_num = select(max_fd + 1, &working_set, &writing_set, NULL, NULL);

        if (select_num <= 0)
        {
            perror("select() failed");
            break;
        }

        for(i = 0; i <= max_fd && select_num > 0; i++)
        {
            if (FD_ISSET(i, &working_set) || FD_ISSET(i, &writing_set)) //Checking if fd is ready to read or write
            {
                select_num--;

                if(i == listen_fd) //New user trying to connect
                {
                    if(MAX_USERS != connected_users) //Checking if new connection is available
                    {
                        for(int j = 0; j < MAX_USERS; j++)
                            if(NULL == users[j])
                            {
                                current_user = j;
                                break;
                            }
                    }
                    else break;

                    user_addr = (struct sockaddr_in*)calloc(1, sizeof(struct sockaddr_in));

                    if (accept_user(&conn_fd, &listen_fd, user_addr, &log_file) < 0)
                        continue; //Couldn't accept new user
                    else
                    {
                        if (conn_fd > max_fd)
                            max_fd = conn_fd;
                        users[current_user] = (user_info *) malloc(sizeof(user_info));
                        users[current_user]->user_addr = user_addr;
                        users[current_user]->user_fd = conn_fd;
                        users[current_user]->state = USER_PK;

                        FD_SET(conn_fd, &master_set); //Adding new user to the select pool
                        connected_users++;
                    }
                }
                else //Handle existing connection
                {
                    for(search_user_fd = 0; search_user_fd < MAX_USERS; search_user_fd++)
                    {
                        if(NULL != users[search_user_fd])
                            if(i == users[search_user_fd]->user_fd)
                                break;
                    }

                    error = handle_connection(users[search_user_fd], &log_file, &serv_addr);

                    if(error < 0 || DONE == users[search_user_fd]->state) //Closing connection
                    {
                        disconnect_user(users[search_user_fd], &temp_set, &master_set, &max_fd);
                        users[search_user_fd] = NULL;
                        connected_users--;
                    }
                    else if(RECEIVE_MESSAGE == users[search_user_fd]->state)
                        FD_SET(users[search_user_fd]->user_fd,&temp_set); //Adding user to writing set, because user waits for nonce
                }
            }
        }
        
        close(conn_fd);
    }
    close_all(&log_file, &listen_fd, NULL);
}