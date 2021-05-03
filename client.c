#include <sys/types.h>
#include <sys/socket.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/un.h>
#include <unistd.h>
#include <string.h>

int get_file_length(FILE*);

int main(int argc, char const *argv[])
{
    if (argc != 2) {
        fprintf(stderr, "[Usage] %s file_name", argv[0]);
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
    char file_buf[length];
    size_t ret = fread(file_buf, 1, length, fp);
    if (ret != length) {
        perror("fread() failed");
        fclose(fp);
        exit(EXIT_FAILURE);
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

    write(sockfd, file_buf, sizeof(file_buf));
    close(sockfd);
    fclose(fp);
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