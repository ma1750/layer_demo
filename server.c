#include <sys/types.h>
#include <sys/socket.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/un.h>
#include <unistd.h>
#include <string.h>
#include "server.h"
#include "global.h"
#include "md5.h"

#define VERSION 9999
#define APP_TYPE_CODE 1234

void unpack_ip(ip_t*, char*);
void unpack_tcp(tcp_t*, char*);
void unpack_udp(udp_t*, char*);
int check_ip_layer(ip_t*);
int check_tcp_layer(tcp_t*, char*);
int check_udp_layer(udp_t*);
void print_error(int);
void gen_MD5(unsigned char*, char *, int);
void print_IP(ip_t*);
void print_TCP(tcp_t*);
void print_UDP(udp_t*);
void print_APP(char*);

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
    int len = 0;
    int ret_code = 0;
    while(1) {
        printf("server waiting\n");

        client_sockfd = accept(server_sockfd ,
                                (struct sockaddr *)&client_address , &client_len);

        len = read(client_sockfd,recv_buf,1024);
        if (len == -1) {
            perror("read() failed");
            close(client_sockfd);
            continue;
        }
        recv_buf[len] = '\0';
        printf("recv %d: %s\n", len, recv_buf);
        ip_t ip;
        unpack_ip(&ip, recv_buf);
        ret_code = check_ip_layer(&ip);
        if (ret_code != -1) {
            print_error(ret_code);
            close(client_sockfd);
            continue;
        }
        print_IP(&ip);

        if (ip.type == 0) {
            // TCP
            tcp_t tcp;
            unpack_tcp(&tcp, recv_buf);
            ret_code = check_tcp_layer(&tcp, recv_buf);
            if (ret_code != -1) {
                print_error(ret_code);
                close(client_sockfd);
                continue;
            }
            print_TCP(&tcp);

            char msg[tcp.len + 1];
            strncpy(msg, recv_buf+52, tcp.len);
            msg[tcp.len] = '\0';
            print_APP(msg);
        } else if (ip.type == 1) {
            // UDP
            udp_t udp;
            unpack_udp(&udp, recv_buf);
            ret_code = check_udp_layer(&udp);
            if (ret_code != -1) {
                print_error(ret_code);
                close(client_sockfd);
                continue;
            }
            print_UDP(&udp);

            char msg[udp.len +1];
            strncpy(msg, recv_buf+20, udp.len);
            print_APP(msg);
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


void unpack_tcp(tcp_t *ret_ptr, char *msg_ptr)
{
    char type[5];
    char len[5];

    strncpy(type, msg_ptr+12, 4);
    type[4] = '\0';
    strncpy(len, msg_ptr+16, 4);
    len[4] = '\0';
    strncpy(ret_ptr -> digest, msg_ptr+20, 32);
    ret_ptr -> digest[32] = '\0';

    ret_ptr -> type = atoi(type);
    ret_ptr -> len = atoi(len);
}


void unpack_udp(udp_t *ret_ptr, char *msg_ptr)
{
    char type[5];
    char len[5];

    strncpy(type, msg_ptr+12, 4);
    type[4] = '\0';
    strncpy(len, msg_ptr+16, 4);
    len[4] = '\0';

    ret_ptr -> type = atoi(type);
    ret_ptr -> len = atoi(len);

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
        return e_protocol_type;
    }
    return -1;
}


int check_tcp_layer(tcp_t *tcp_ptr, char *msg_ptr)
{
    char payload[tcp_ptr -> len + 1];
    unsigned char md5[16];
    char digest[33];
    if (tcp_ptr -> type != APP_TYPE_CODE) {
        // upper layer type is invalid
        return e_app_type;
    }

    strncpy(payload, msg_ptr+52, tcp_ptr -> len);
    gen_MD5(md5, payload, tcp_ptr -> len);
    char tmp[2];
    for (int i = 0; i < 16; ++i) {
        snprintf(tmp, 4, "%02x", md5[i]);
        digest[2*i] = tmp[0];
        digest[2*i+1] = tmp[1];
    }
    digest[32] = '\0';

    if (strncmp(tcp_ptr -> digest, digest, 32) != 0)
    {
        return e_hash;
    }
    return -1;
}


int check_udp_layer(udp_t *udp_ptr)
{
    if (udp_ptr -> type != APP_TYPE_CODE) {
        // upper layer type is invalid
        return e_app_type;
    }
    return -1;
}

void print_error(int code)
{
    printf("[error]: %s\n", error_messages[code]);
}


void gen_MD5(unsigned char *ret_ptr, char *target_ptr, int target_len)
{
    MD5_CTX context;
    MD5Init(&context);
    MD5Update(&context, target_ptr, target_len);
    MD5Final(ret_ptr, &context);
}


void print_IP(ip_t *ip_ptr)
{
    printf("--- layer1 [IP] ---\n");
    printf("type = %4d\n", ip_ptr -> type);
    printf("version = %4d\n", ip_ptr -> version);
    printf("ttl = %4d\n", ip_ptr -> ttl);
}


void print_TCP(tcp_t *tcp_ptr)
{
    printf("--- layer2 [TCP] ---\n");
    printf("type = %4d\n", tcp_ptr -> type);
    printf("len = %4d\n", tcp_ptr -> len);
    printf("digest = %s\n", tcp_ptr -> digest);
}


void print_UDP(udp_t *udp_ptr)
{
    printf("--- layer2 [UDP] ---\n");
    printf("type = %4d\n", udp_ptr -> type);
    printf("len = %4d\n", udp_ptr -> len);
}


void print_APP(char *msg)
{
    printf("--- layer3 [application] ---\n");
    printf("%s\n", msg);
}