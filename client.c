#include <sys/types.h>
#include <sys/socket.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/un.h>
#include <unistd.h>
#include <string.h>
#include "global.h"
#include "md5.h"

#define VERSION 9999
#define TTL 100
#define APP_TYPE_CODE 1234

int get_file_length(FILE*);
int enclose_ip(char*, char*, int, int, int, int);
int enclose_tcp(char*, char*, int, int);
int enclose_udp(char*, char*, int, int);
void gen_MD5(unsigned char*, char *, int);

int main(int argc, char const *argv[])
{
    if (argc != 3) {
        fprintf(stderr, "[Usage] %s file_name type\n\ttype| TCP: 0, UDP: 1\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    int sockfd ;
    struct sockaddr_un address ;
    FILE *fp = NULL;

    fp = fopen(argv[1], "r");
    if (!fp) {
        perror("fopen() failed");
        exit(EXIT_FAILURE);
    }

    int length = get_file_length(fp);
    char file_buf[length+1];
    size_t ret = fread(file_buf, 1, length, fp);
    file_buf[length+1] = '\0';
    if (ret != length) {
        perror("fread() failed");
        fclose(fp);
        exit(EXIT_FAILURE);
    }
    fclose(fp);

    int type = atoi(argv[2]);
    int buf_length = 0;
    char *sendbuf;
    if (type == 0) {
        // TCP
        sendbuf = (char*)malloc(sizeof(char) * (52+length+1));
        if (sendbuf == NULL) {
            perror("malloc() failed");
            free(sendbuf);
            exit(EXIT_FAILURE);
        }
        char tcp_header[40];
        buf_length = enclose_tcp(tcp_header, file_buf, length, APP_TYPE_CODE);
        if (buf_length != 40+(length+1)) {
            fprintf(stderr, "enclose_tcp() fialed\n");
            free(sendbuf);
            exit(EXIT_FAILURE);
        }

        length = enclose_ip(sendbuf, tcp_header, buf_length, type, VERSION, TTL);
        if (length != 12+buf_length) {
            fprintf(stderr, "enclose_ip() fialed\n");
            free(sendbuf);
            exit(EXIT_FAILURE);
        }
    } else if (type == 1) {
        // UDP
        sendbuf = (char*)malloc(sizeof(char) * (20+length+1));
        if (sendbuf == NULL) {
            perror("malloc() failed");
            free(sendbuf);
            exit(EXIT_FAILURE);
        }
        char udp_header[8];
        buf_length = enclose_udp(udp_header, file_buf, length, APP_TYPE_CODE);
        if (buf_length != 8+(length+1)) {
            fprintf(stderr, "enclose_udp() fialed\n");
            free(sendbuf);
            exit(EXIT_FAILURE);
        }

        length = enclose_ip(sendbuf, udp_header, buf_length, type, VERSION, TTL);
        if (length != 12+buf_length) {
            fprintf(stderr, "enclose_ip() fialed\n");
            free(sendbuf);
            exit(EXIT_FAILURE);
        }
    }

    sockfd = socket(AF_UNIX,SOCK_STREAM,0);
    if (sockfd == -1) {
        perror("socket() failed\n");
        fclose(fp);
        exit(EXIT_FAILURE);
    }

    address.sun_family = AF_UNIX ;
    strcpy(address.sun_path , "server_socket");
    int addr_len = sizeof(address);

    int result = connect(sockfd , (struct sockaddr *)&address , addr_len);
    if ( result == -1 ) {
        perror("connect() failed");
        exit(1);
    }

    write(sockfd, sendbuf, length);
    close(sockfd);
    free(sendbuf);
    exit(0);
}


int get_file_length(FILE *fp)
{
    // seek to file head
    if (fseek(fp, 0, SEEK_SET)) {
        perror("fseek() failed");
    }

    // seek to file tail
    if (fseek(fp , 0, SEEK_END) != 0) {
        perror("fseek() failed");
    }

    int len = ftell(fp);
    // return file head
    if (fseek(fp, 0, SEEK_SET)) {
        perror("fseek() failed");
    }
    return len;
}


int enclose_ip(char *ret_ptr, char *payload_ptr, int payload_len, int type, int version, int ttl)
{
    int ret_len = 0;
    ret_len = snprintf(ret_ptr, 12+payload_len,
                        "%04d%04d%04d%s", type, version, ttl, payload_ptr);
    return ret_len+1;
}


int enclose_tcp(char *ret_ptr, char *payload_ptr, int payload_len, int type)
{
    int ret_len = 0;
    char ret[40+payload_len+1];
    unsigned char digest[16];
    gen_MD5(digest, payload_ptr, payload_len);

    ret_len = snprintf(ret, 9, "%04d%04d", type, payload_len);
    char tmp[2];
    for (int i = 1; i <= 16; ++i) {
        snprintf(tmp, 4, "%02x", digest[i-1]);
        ret[7+2*i-1] = tmp[0];
        ret[7+2*i] = tmp[1];
    }

    ret_len = snprintf(ret_ptr, 40+payload_len+1, "%s%s", ret, payload_ptr);
    return ret_len+1;
}


int enclose_udp(char *ret_ptr, char *payload_ptr, int payload_len, int type)
{
    int ret_len = 0;
    ret_len = snprintf(ret_ptr, 8+payload_len+1, "%04d%04d%s",
                        type, payload_len, payload_ptr);
    return ret_len+1;
}


void gen_MD5(unsigned char *ret_ptr, char *target_ptr, int target_len)
{
    MD5_CTX context;
    MD5Init(&context);
    MD5Update(&context, target_ptr, target_len);
    MD5Final(ret_ptr, &context);
}