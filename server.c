#include <sys/types.h>
#include <sys/socket.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/un.h>
#include <unistd.h>
#include <string.h>
#include "server.h"

#define VERSION 9999

void unpack_ip(ip_t*, char*);
int check_ip_layer(ip_t*);
void print_error(int);

int main(void)
{
    int server_sockfd , client_sockfd ;
    int server_len , client_len ;
    struct sockaddr_un server_address ;
    struct sockaddr_un client_address ;

    unlink("server_socket");
    server_sockfd = socket(AF_UNIX,SOCK_STREAM,0);
    server_address.sun_family = AF_UNIX ;
    strcpy(server_address.sun_path , "server_socket");
    server_len = sizeof(server_address);
    bind(server_sockfd , (struct sockaddr *)&server_address , server_len);

    listen(server_sockfd , 5);
    char recv_buf[1024];
    int ret_code = 0;
    while(1) {
        printf("server waiting\n");

        client_sockfd = accept(server_sockfd ,
                                (struct sockaddr *)&client_address , &client_len);

        read(client_sockfd,recv_buf,1024);
        printf("recv: %s\n", recv_buf);
        ip_t ip;
        unpack_ip(&ip, recv_buf);
        ret_code = check_ip_layer(&ip);
        if (ret_code != -1) {
            print_error(ret_code);
            close(client_sockfd);
            continue;
        }
        close(client_sockfd);
    }
}


void unpack_ip(ip_t *ret_ptr, char *msg_ptr)
{
    char type[5];
    char version[5];
    char ttl[5];

    strncpy(type, msg_ptr, 4);
    type[4] = '\0';
    strncpy(version, msg_ptr+4, 4);
    version[4] = '\0';
    strncpy(ttl, msg_ptr+8, 4);
    ttl[4] = '\0';

    ret_ptr -> type = atoi(type);
    ret_ptr -> version = atoi(version);
    ret_ptr -> ttl = atoi(ttl);
}


int check_ip_layer(ip_t *ip_ptr)
{
    if(ip_ptr -> ttl <= 0){
        // packet is dead :(
        return e_ttl;
    }
    if (ip_ptr -> version != VERSION) {
        // version mismatch
        return e_version;
    };
    if (ip_ptr -> type != 0 && ip_ptr -> type != 1) {
        // invalid type
        return e_type;
    }
    return -1;
}


void print_error(int code)
{
    printf("[error]: %s\n", error_messages[code]);
}