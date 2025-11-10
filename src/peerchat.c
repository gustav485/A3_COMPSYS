#include <stdlib.h>
#include <stdio.h>
#include <math.h>
#include <netdb.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <string.h>
#include <time.h>
#include <pthread.h>

#ifdef __APPLE__
#include "./endian.h"
#else
#include <endian.h>
#endif

#include "./peer.h"

// Global variables
NetworkAddress_t *my_address;
NetworkAddress_t **network = NULL;
uint32_t peer_count = 0;
pthread_mutex_t network_mutex = PTHREAD_MUTEX_INITIALIZER;

/* ============================== UTILITY ============================== */

void get_signature(void *password, int password_len, char *salt, hashdata_t *hash) {
    char combined[PASSWORD_LEN + SALT_LEN];
    int pwd_len = (password_len > PASSWORD_LEN) ? PASSWORD_LEN : password_len;
    memcpy(combined, password, pwd_len);
    memcpy(combined + PASSWORD_LEN, salt, SALT_LEN);
    get_data_sha(combined, *hash, PASSWORD_LEN + SALT_LEN, SHA256_HASH_SIZE);
}

/* ============================== CLIENT ============================== */

int send_message(NetworkAddress_t peer_address, int command, char *request_body, int request_len) {
    char port_str[PORT_STR_LEN];
    sprintf(port_str, "%d", peer_address.port);
    int clientfd = compsys_helper_open_clientfd(peer_address.ip, port_str);
    if (clientfd < 0) return -1;

    RequestHeader_t header;
    memcpy(header.ip, my_address->ip, IP_LEN);
    header.port = htonl(my_address->port);
    memcpy(header.signature, my_address->signature, SHA256_HASH_SIZE);
    header.command = htonl(command);
    header.length = htonl(request_len);

    char buffer[REQUEST_HEADER_LEN + MAX_MSG_LEN];
    memcpy(buffer, &header, REQUEST_HEADER_LEN);
    if (request_len > 0)
        memcpy(buffer + REQUEST_HEADER_LEN, request_body, request_len);

    compsys_helper_writen(clientfd, buffer, REQUEST_HEADER_LEN + request_len);
    return clientfd;
}

void* client_thread() {
    while (1) {
        char peer_ip[IP_LEN];
        fprintf(stdout, "Enter peer IP to connect to: ");
        scanf("%16s", peer_ip);

        char peer_port[PORT_STR_LEN];
        fprintf(stdout, "Enter peer port to connect to: ");
        scanf("%16s", peer_port);

        NetworkAddress_t peer_address;
        memcpy(peer_address.ip, peer_ip, IP_LEN);
        peer_address.port = atoi(peer_port);

        int clientfd = send_message(peer_address, COMMAND_REGISTER, NULL, 0);
        if (clientfd < 0) {
            fprintf(stderr, "Connection failed\n");
            continue;
        }

        compsys_helper_state_t rio;
        compsys_helper_readinitb(&rio, clientfd);

        ReplyHeader_t reply;
        compsys_helper_readnb(&rio, &reply, REPLY_HEADER_LEN);

        reply.length = ntohl(reply.length);
        reply.status = ntohl(reply.status);
        reply.this_block = ntohl(reply.this_block);
        reply.block_count = ntohl(reply.block_count);

        printf("Reply: status=%d, length=%d, blocks=%d/%d\n",
               reply.status, reply.length, reply.this_block, reply.block_count);

        // Læs body, hvis der er noget (fx netværksliste)
        if (reply.length > 0) {
            char *body = malloc(reply.length);
            compsys_helper_readnb(&rio, body, reply.length);

            int offset = 0;
            printf("Peers in network:\n");
            while (offset < reply.length) {
                char ip[IP_LEN + 1];
                memcpy(ip, body + offset, IP_LEN);
                ip[IP_LEN] = '\0';
                offset += IP_LEN;

                uint32_t port;
                memcpy(&port, body + offset, 4);
                port = ntohl(port);
                offset += 4;

                offset += SHA256_HASH_SIZE; // skip signature
                offset += SALT_LEN;         // skip salt

                printf("  %s:%d\n", ip, port);
            }
            free(body);
        }

        close(clientfd);
    }

    return NULL;
}

/* ============================== SERVER ============================== */

// Thread to handle a single client
void *handle_client(void *arg) {
    int connfd = *(int *)arg;
    free(arg);

    compsys_helper_state_t rio;
    compsys_helper_readinitb(&rio, connfd);

    RequestHeader_t req_header;
    if (compsys_helper_readnb(&rio, &req_header, REQUEST_HEADER_LEN) <= 0) {
        close(connfd);
        return NULL;
    }

    req_header.port = ntohl(req_header.port);
    req_header.command = ntohl(req_header.command);
    req_header.length = ntohl(req_header.length);

    if (req_header.command == COMMAND_REGISTER) {
        printf("REGISTER request from %s:%d\n", req_header.ip, req_header.port);

        pthread_mutex_lock(&network_mutex);
        int exists = 0;
        for (uint32_t i = 0; i < peer_count; i++) {
            if (strcmp(network[i]->ip, req_header.ip) == 0 &&
                network[i]->port == req_header.port) {
                exists = 1;
                break;
            }
        }

        if (!exists) {
            peer_count++;
            network = realloc(network, peer_count * sizeof(NetworkAddress_t *));
            network[peer_count - 1] = malloc(sizeof(NetworkAddress_t));
            memcpy(network[peer_count - 1]->ip, req_header.ip, IP_LEN);
            network[peer_count - 1]->port = req_header.port;
            memcpy(network[peer_count - 1]->signature, req_header.signature, SHA256_HASH_SIZE);
            memcpy(network[peer_count - 1]->salt, my_address->salt, SALT_LEN);
        }

        int body_len = peer_count * (IP_LEN + 4 + SHA256_HASH_SIZE + SALT_LEN);
        char *body = malloc(body_len);
        int offset = 0;

        for (uint32_t i = 0; i < peer_count; i++) {
            memcpy(body + offset, network[i]->ip, IP_LEN);
            offset += IP_LEN;
            uint32_t port_net = htonl(network[i]->port);
            memcpy(body + offset, &port_net, 4);
            offset += 4;
            memcpy(body + offset, network[i]->signature, SHA256_HASH_SIZE);
            offset += SHA256_HASH_SIZE;
            memcpy(body + offset, network[i]->salt, SALT_LEN);
            offset += SALT_LEN;
        }
        pthread_mutex_unlock(&network_mutex);

        ReplyHeader_t reply;
        reply.length = htonl(body_len);
        reply.status = htonl(exists ? 2 : 1);
        reply.this_block = htonl(1);
        reply.block_count = htonl(1);
        get_data_sha(body, reply.block_hash, body_len, SHA256_HASH_SIZE);
        memcpy(reply.total_hash, reply.block_hash, SHA256_HASH_SIZE);

        compsys_helper_writen(connfd, &reply, REPLY_HEADER_LEN);
        if (body_len > 0)
            compsys_helper_writen(connfd, body, body_len);

        printf("→ Sent REGISTER reply to %s:%d (status %d, peers=%d)\n",
               req_header.ip, req_header.port, exists ? 2 : 1, peer_count);
               
        pthread_mutex_lock(&network_mutex);
        printf("Current network (%d peers):\n", peer_count);
        for (uint32_t i = 0; i < peer_count; i++) {
            printf("  %s:%d\n", network[i]->ip, network[i]->port);
        }
        pthread_mutex_unlock(&network_mutex);
        free(body);
    } else {
        printf("Unknown command: %d\n", req_header.command);
    }

    close(connfd);
    return NULL;
}

// Main server loop
void *server_thread(void *arg) {
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

        int *connfd_ptr = malloc(sizeof(int));
        *connfd_ptr = connfd;
        pthread_t tid;
        pthread_create(&tid, NULL, handle_client, connfd_ptr);
        pthread_detach(tid); // Ingen join nødvendig
    }

    return NULL;
}

/* ============================== MAIN ============================== */

int main(int argc, char **argv) {
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <IP> <PORT>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    my_address = malloc(sizeof(NetworkAddress_t));
    memset(my_address->ip, '\0', IP_LEN);
    memcpy(my_address->ip, argv[1], strlen(argv[1]));
    my_address->port = atoi(argv[2]);

    if (!is_valid_ip(my_address->ip)) {
        fprintf(stderr, ">> Invalid peer IP: %s\n", my_address->ip);
        exit(EXIT_FAILURE);
    }
    if (!is_valid_port(my_address->port)) {
        fprintf(stderr, ">> Invalid peer port: %d\n", my_address->port);
        exit(EXIT_FAILURE);
    }

    char password[PASSWORD_LEN];
    fprintf(stdout, "Create a password to proceed: ");
    scanf("%16s", password);

    for (int i = strlen(password); i < PASSWORD_LEN; i++)
        password[i] = '\0';

    char salt[SALT_LEN + 1] = "0123456789ABCDEF\0";
    memcpy(my_address->salt, salt, SALT_LEN);
    get_signature(password, strlen(password), salt, &my_address->signature);

    pthread_t client_thread_id, server_thread_id;
    pthread_create(&client_thread_id, NULL, client_thread, NULL);
    pthread_create(&server_thread_id, NULL, server_thread, NULL);

    pthread_join(client_thread_id, NULL);
    pthread_join(server_thread_id, NULL);

    exit(EXIT_SUCCESS);
}
