#include <stdio.h>
#include <unistd.h>
#include <cstring>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h> 

#include <shibsp/exceptions.h>
#include <xmltooling/logging.h>


namespace polypseud {
    DECL_XMLTOOLING_EXCEPTION(PolyPseudIOException,SHIBSP_EXCEPTIONAPI(SHIBSP_API),polypseud,xmltooling::XMLToolingException,Exceptions during IO with decryption server.);
    DECL_XMLTOOLING_EXCEPTION(PolyPseudDecryptionException,SHIBSP_EXCEPTIONAPI(SHIBSP_API),polypseud,xmltooling::XMLToolingException,Exceptions during decryption at decryption server.);

    void decrypt(const char* ep, int portno, char* pseudonym) {
        int sockfd = socket(AF_INET, SOCK_STREAM, 0);
        if(sockfd < 0)
            throw PolyPseudIOException("Error opening socket");
        struct hostent *server = gethostbyname("localhost");
        if (server == NULL)
            throw PolyPseudIOException("Could not get hostname for localhost");

        struct sockaddr_in serv_addr;
        bzero((char *) &serv_addr, sizeof(serv_addr));
        serv_addr.sin_family = AF_INET;
        bcopy((char *)server->h_addr, 
                (char *)&serv_addr.sin_addr.s_addr,
                server->h_length);
        serv_addr.sin_port = htons(portno);
        if (connect(sockfd,(struct sockaddr *) &serv_addr,sizeof(serv_addr)) < 0)
            throw PolyPseudIOException("Error connecting");
        int n = write(sockfd, ep, strlen(ep));
        if(n < 0)
            throw PolyPseudIOException("Error writing to socket");
        n = write(sockfd,"\n", 1);
        if(n < 0)
            throw PolyPseudIOException("Error writing to socket");
        char buffer[1024];
        n = read(sockfd, buffer, 2);
        if(n < 0)
            throw PolyPseudIOException("Error reading from socket");
        if(buffer[0] != '0') {
            n = read(sockfd, buffer, 1023);
            if(n < 0)
                throw PolyPseudDecryptionException("Error decrypting");
            buffer[n] = '\0';
            throw PolyPseudDecryptionException(buffer);
        }
        n = read(sockfd, buffer, 1023);
        if(n < 0)
            throw PolyPseudIOException("Error reading from socket");
        if(buffer[n - 1] != '\n')
            throw PolyPseudIOException("Did not read full pseudonym from socket");
        std::strncpy(pseudonym, buffer, n - 1);
        pseudonym[n - 1] = '\0';
        close(sockfd);
    }
}
