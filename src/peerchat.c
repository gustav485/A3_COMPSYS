#include <stdlib.h>
#include <stdio.h>
#include <math.h>
#include <netdb.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <string.h>
#include <time.h>

#ifdef __APPLE__
#include "./endian.h"
#else
#include <endian.h>
#endif

#include "./peer.h"


// Global variables to be used by both the server and client side of the peer.
// Note the addition of mutexs to prevent race conditions.
NetworkAddress_t *my_address;

NetworkAddress_t** network = NULL;
uint32_t peer_count = 0;

/*
 * Function to act as thread for all required client interactions. This thread 
 * will be run concurrently with the server_thread. It will start by requesting
 * the IP and port for another peer to connect to. Once both have been provided
 * the thread will register with that peer and expect a response outlining the
 * complete network. The user will then be prompted to provide a file path to
 * retrieve. This file request will be sent to a random peer on the network.
 * This request/retrieve interaction is then repeated forever.
 */ 


//Send message skal kommenteres.
int send_message(NetworkAddress_t peer_address, int command, char* request_body, int request_len){
    char port_str[PORT_STR_LEN];
    sprintf(port_str, "%d", peer_address.port);  // konverter int → char*
    int clientfd = compsys_helper_open_clientfd(peer_address.ip, port_str); 

    RequestHeader_t header;

    memcpy(header.ip, my_address->ip, IP_LEN);
    header.port = htonl(my_address->port);
    memcpy(header.signature, my_address->signature, SHA256_HASH_SIZE);
    header.command = htonl(command);
    header.length = htonl(request_len);

    char buffer[REQUEST_HEADER_LEN + MAX_MSG_LEN];

    memcpy(buffer, &header, REQUEST_HEADER_LEN);
    if (request_len > 0) {
        memcpy(buffer + REQUEST_HEADER_LEN, request_body, request_len);
    }

    compsys_helper_writen(clientfd, buffer, REQUEST_HEADER_LEN + request_len);

    return clientfd;
}


//client thread skal kommenteres.
void* client_thread()
{
    char peer_ip[IP_LEN];
    fprintf(stdout, "Enter peer IP to connect to: ");
    scanf("%16s", peer_ip);

    // Clean up password string as otherwise some extra chars can sneak in.
    for (int i=strlen(peer_ip); i<IP_LEN; i++)
    {
        peer_ip[i] = '\0';
    }

    char peer_port[PORT_STR_LEN];
    fprintf(stdout, "Enter peer port to connect to: ");
    scanf("%16s", peer_port);

    // Clean up password string as otherwise some extra chars can sneak in.
    for (int i=strlen(peer_port); i<PORT_STR_LEN; i++)
    {
        peer_port[i] = '\0';
    }

    NetworkAddress_t peer_address;
    memcpy(peer_address.ip, peer_ip, IP_LEN);
    peer_address.port = atoi(peer_port);
    
    int clientfd = send_message(peer_address, COMMAND_REGISTER, NULL, 0);
    if (clientfd < 0) {
        fprintf(stderr, "Connection failed\n");
        return NULL;
    }

    compsys_helper_state_t rio;
    compsys_helper_readinitb(&rio, clientfd);  // clientfd fra send_message!

    ReplyHeader_t reply;
    compsys_helper_readnb(&rio, &reply, REPLY_HEADER_LEN);

    // Konverter fra network order
    reply.length = ntohl(reply.length);
    reply.status = ntohl(reply.status);
    reply.this_block = ntohl(reply.this_block);
    reply.block_count = ntohl(reply.block_count);

    printf("Reply: status=%d, length=%d, blocks=%d/%d\n",
        reply.status, reply.length, reply.this_block, reply.block_count);

    close(clientfd);

    // You should never see this printed in your finished implementation
    printf("Client thread done\n");

    return NULL;
}

/*
 * Function to act as basis for running the server thread. This thread will be
 * run concurrently with the client thread, but is infinite in nature.
 */

//Server thread skal kommenteres.
void* server_thread(void *arg) {
    char port_str[PORT_STR_LEN];
    sprintf(port_str, "%d", my_address->port);

    int listenfd = compsys_helper_open_listenfd(port_str);
    if (listenfd < 0) {
        fprintf(stderr, "Failed to open listening socket on port %d\n", my_address->port);
        return NULL;
    }

    printf("Server listening on %s:%d\n", my_address->ip, my_address->port);

    while (1) {
        int connfd = accept(listenfd, NULL, NULL);
        if (connfd < 0) {
            perror("accept");
            continue;
        }
        // Senere: håndter request
        close(connfd);
    }
    return NULL;
}

void get_signature(void* password, int password_len, char* salt, hashdata_t* hash) {
    char combined[PASSWORD_LEN + SALT_LEN];    //Midlertidig buffer
    
    int pwd_len = (password_len > PASSWORD_LEN) ? PASSWORD_LEN : password_len;    //Sætter pwd_len til input hvis det er mindre end max. 
    
    memcpy(combined, password, pwd_len);            //Vi kopiere pwd_len bytes fra password ind 
    memcpy(combined + PASSWORD_LEN, salt, SALT_LEN);   //Kopiere salt_len bytes fra salt ind i combined efter Vores password.
    
    get_data_sha(combined, *hash, PASSWORD_LEN + SALT_LEN, SHA256_HASH_SIZE);   
    //Vi hasher vores kodeord. 
    //Combined er passworded som skal hashes, 
    //*hash er hvor resultatet skal gemmes.
    //PASSWORD_LEN + SALT_LEN er længden / antal bytes der skal hashes. 
    //SHA256_HASH_Size er den hashing funktion vi skal bruge.
}

// combined[32]:
// [ m i t k o d e 1 2 3 4 5 a b c d ] [ 0 1 2 3 4 5 6 7 8 9 A B C D E F ]
//    ^-- 16 bytes password --^   ^---------- 16 bytes salt ----------^

// → SHA-256(combined) → 32-byte hash → skrives til *hash


int main(int argc, char **argv)
{
    // Users should call this script with a single argument describing what 
    // config to use
    if (argc != 3)
    {
        fprintf(stderr, "Usage: %s <IP> <PORT>\n", argv[0]);
        exit(EXIT_FAILURE);
    } 

    my_address = (NetworkAddress_t*)malloc(sizeof(NetworkAddress_t));
    memset(my_address->ip, '\0', IP_LEN);
    memcpy(my_address->ip, argv[1], strlen(argv[1]));
    my_address->port = atoi(argv[2]);

    if (!is_valid_ip(my_address->ip)) {
        fprintf(stderr, ">> Invalid peer IP: %s\n", my_address->ip);
        exit(EXIT_FAILURE);
    }
    
    if (!is_valid_port(my_address->port)) {
        fprintf(stderr, ">> Invalid peer port: %d\n", 
            my_address->port);
        exit(EXIT_FAILURE);
    }

    char password[PASSWORD_LEN];
    fprintf(stdout, "Create a password to proceed: ");
    scanf("%16s", password);

    // Clean up password string as otherwise some extra chars can sneak in.
    for (int i=strlen(password); i<PASSWORD_LEN; i++)
    {
        password[i] = '\0';
    }

    // Most correctly, we should randomly generate our salts, but this can make
    // repeated testing difficult so feel free to use the hard coded salt below
    char salt[SALT_LEN+1] = "0123456789ABCDEF\0";
    //generate_random_salt(salt);
    memcpy(my_address->salt, salt, SALT_LEN);

    get_signature(password, strlen(password), salt, &my_address->signature);      //Tilføjet

    // Setup the client and server threads 
    pthread_t client_thread_id;
    pthread_t server_thread_id;
    pthread_create(&client_thread_id, NULL, client_thread, NULL);
    pthread_create(&server_thread_id, NULL, server_thread, NULL);

    // Wait for them to complete. 
    pthread_join(client_thread_id, NULL);
    pthread_join(server_thread_id, NULL);

    exit(EXIT_SUCCESS);
}