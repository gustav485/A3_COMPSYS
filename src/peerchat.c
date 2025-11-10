/* ============================== peer.c ============================== */
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <unistd.h>

#ifdef __APPLE__
#include "./endian.h"
#else
#include <endian.h>
#endif

#include "./peer.h"

// Global state
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

void add_to_network(NetworkAddress_t *peer) {
    pthread_mutex_lock(&network_mutex);
    network = realloc(network, (peer_count + 1) * sizeof(NetworkAddress_t*));
    if (!network) { pthread_mutex_unlock(&network_mutex); return; }

    network[peer_count] = malloc(sizeof(NetworkAddress_t));
    if (network[peer_count]) {
        memcpy(network[peer_count]->ip, peer->ip, IP_LEN);
        network[peer_count]->port = peer->port;
        memcpy(network[peer_count]->signature, peer->signature, SHA256_HASH_SIZE);
        memcpy(network[peer_count]->salt, peer->salt, SALT_LEN);
        peer_count++;
    }
    pthread_mutex_unlock(&network_mutex);
}

/* ============================== CLIENT ============================== */

int send_message(NetworkAddress_t peer, int command, char *body, int len) {
    char port_str[PORT_STR_LEN];
    sprintf(port_str, "%d", peer.port);
    int fd = compsys_helper_open_clientfd(peer.ip, port_str);
    if (fd < 0) return -1;

    RequestHeader_t header;
    memcpy(header.ip, my_address->ip, IP_LEN);
    header.port = htonl(my_address->port);
    memcpy(header.signature, my_address->signature, SHA256_HASH_SIZE);
    header.command = htonl(command);
    header.length = htonl(len);

    char buffer[REQUEST_HEADER_LEN + MAX_MSG_LEN];
    memcpy(buffer, &header, REQUEST_HEADER_LEN);
    if (len > 0) memcpy(buffer + REQUEST_HEADER_LEN, body, len);

    compsys_helper_writen(fd, buffer, REQUEST_HEADER_LEN + len);
    return fd;
}

void* client_thread(void *arg) {
    (void)arg;

    while (1) {
        char ip[IP_LEN], port_str[PORT_STR_LEN];

        printf("Enter peer IP to connect to: ");
        if (!fgets(ip, sizeof(ip), stdin)) continue;
        ip[strcspn(ip, "\n")] = 0;
        if (strlen(ip) == 0) continue;

        printf("Enter peer port to connect to: ");
        if (!fgets(port_str, sizeof(port_str), stdin)) continue;
        port_str[strcspn(port_str, "\n")] = 0;
        if (strlen(port_str) == 0) continue;

        NetworkAddress_t peer;
        strncpy(peer.ip, ip, IP_LEN - 1);
        peer.ip[IP_LEN - 1] = '\0';
        peer.port = atoi(port_str);

        int fd = send_message(peer, COMMAND_REGISTER, NULL, 0);
        if (fd < 0) {
            printf("Connection failed to %s:%d\n", peer.ip, peer.port);
            continue;
        }

        compsys_helper_state_t rio;
        compsys_helper_readinitb(&rio, fd);

        ReplyHeader_t reply;
        if (compsys_helper_readnb(&rio, &reply, REPLY_HEADER_LEN) != REPLY_HEADER_LEN) {
            printf("Failed to read reply header\n");
            close(fd);
            continue;
        }

        reply.length = ntohl(reply.length);
        reply.status = ntohl(reply.status);
        reply.this_block = ntohl(reply.this_block);
        reply.block_count = ntohl(reply.block_count);

        printf("Reply: status=%d, length=%d, blocks=%d/%d\n",
               reply.status, reply.length, reply.this_block, reply.block_count);

        if (reply.status == STATUS_OK && reply.length > 0) {
            char *body = malloc(reply.length);
            if (!body || compsys_helper_readnb(&rio, body, reply.length) != reply.length) {
                printf("Failed to read network list\n");
                free(body);
                close(fd);
                continue;
            }

            int offset = 0;
            printf("Peers in network:\n");
            while (offset < reply.length) {
                NetworkAddress_t p;
                memcpy(p.ip, body + offset, IP_LEN); offset += IP_LEN;
                memcpy(&p.port, body + offset, 4); p.port = ntohl(p.port); offset += 4;
                memcpy(p.signature, body + offset, SHA256_HASH_SIZE); offset += SHA256_HASH_SIZE;
                memcpy(p.salt, body + offset, SALT_LEN); offset += SALT_LEN;

                printf("  %s:%d\n", p.ip, p.port);
                add_to_network(&p);
            }
            free(body);
        }
        close(fd);
    }
    return NULL;
}

/* ============================== SERVER ============================== */

void send_response(int fd, uint32_t status, char *body, int len) {
    ReplyHeader_t reply;
    memset(&reply, 0, sizeof(reply));
    reply.status = htonl(status);
    reply.length = htonl(len);
    reply.this_block = htonl(0);
    reply.block_count = htonl(1);

    if (len > 0) {
        get_data_sha(body, reply.total_hash, len, SHA256_HASH_SIZE);
        memcpy(reply.block_hash, reply.total_hash, SHA256_HASH_SIZE);
    }

    char buffer[REPLY_HEADER_LEN + MAX_MSG_LEN];
    memcpy(buffer, &reply, REPLY_HEADER_LEN);
    if (len > 0) memcpy(buffer + REPLY_HEADER_LEN, body, len);

    compsys_helper_writen(fd, buffer, REPLY_HEADER_LEN + len);
}

void handle_register(int fd, RequestHeader_t *req) {
    int exists = 0;
    pthread_mutex_lock(&network_mutex);
    for (uint32_t i = 0; i < peer_count; i++) {
        if (strcmp(network[i]->ip, req->ip) == 0 && network[i]->port == req->port) {
            exists = 1;
            break;
        }
    }

    NetworkAddress_t new_peer;
    if (!exists) {
        char salt[SALT_LEN];
        generate_random_salt(salt);
        get_signature(req->signature, SHA256_HASH_SIZE, salt, new_peer.signature);

        memcpy(new_peer.ip, req->ip, IP_LEN);
        new_peer.port = req->port;
        memcpy(new_peer.salt, salt, SALT_LEN);

        add_to_network(&new_peer);
    }
    pthread_mutex_unlock(&network_mutex);

    // Byg netværksliste
    pthread_mutex_lock(&network_mutex);
    int len = peer_count * PEER_ADDR_LEN;
    char *body = malloc(len);
    if (body) {
        for (uint32_t i = 0; i < peer_count; i++) {
            int off = i * PEER_ADDR_LEN;
            memcpy(body + off, network[i]->ip, IP_LEN);
            uint32_t net_port = htonl(network[i]->port);
            memcpy(body + off + IP_LEN, &net_port, 4);
            memcpy(body + off + IP_LEN + 4, network[i]->signature, SHA256_HASH_SIZE);
            memcpy(body + off + IP_LEN + 4 + SHA256_HASH_SIZE, network[i]->salt, SALT_LEN);
        }
    }
    pthread_mutex_unlock(&network_mutex);

    send_response(fd, exists ? STATUS_PEER_EXISTS : STATUS_OK, body, len);
    free(body);
}

void* handle_request_thread(void *arg) {
    int fd = (int)(long)arg;
    pthread_detach(pthread_self());

    compsys_helper_state_t rio;
    compsys_helper_readinitb(&rio, fd);

    RequestHeader_t req;
    if (compsys_helper_readnb(&rio, &req, REQUEST_HEADER_LEN) != REQUEST_HEADER_LEN) {
        close(fd);
        return NULL;
    }

    req.command = ntohl(req.command);
    req.length = ntohl(req.length);
    req.port = ntohl(req.port);

    if (!is_valid_ip(req.ip) || !is_valid_port(req.port)) {
        send_response(fd, STATUS_BAD_REQUEST, NULL, 0);
        close(fd);
        return NULL;
    }

    if (req.command == COMMAND_REGISTER) {
        handle_register(fd, &req);
    } else {
        send_response(fd, STATUS_BAD_REQUEST, NULL, 0);
    }

    close(fd);
    return NULL;
}

void* server_thread(void *arg) {
    (void)arg;
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

        pthread_t tid;
        pthread_create(&tid, NULL, handle_request_thread, (void*)(long)connfd);
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
    if (!my_address) exit(EXIT_FAILURE);

    strncpy(my_address->ip, argv[1], IP_LEN - 1);
    my_address->ip[IP_LEN - 1] = '\0';
    my_address->port = atoi(argv[2]);

    if (!is_valid_ip(my_address->ip) || !is_valid_port(my_address->port)) {
        fprintf(stderr, "Invalid IP or port\n");
        free(my_address);
        exit(EXIT_FAILURE);
    }

    char password[PASSWORD_LEN];
    printf("Create a password to proceed: ");
    if (scanf("%15s", password) != 1) {
        fprintf(stderr, "Failed to read password\n");
        free(my_address);
        exit(EXIT_FAILURE);
    }
    for (int i = strlen(password); i < PASSWORD_LEN; i++) password[i] = '\0';

    char salt[SALT_LEN];
    generate_random_salt(salt);
    memcpy(my_address->salt, salt, SALT_LEN);
    get_signature(password, strlen(password), salt, &my_address->signature);

    pthread_t client_tid, server_tid;
    if (pthread_create(&client_tid, NULL, client_thread, NULL) != 0 ||
        pthread_create(&server_tid, NULL, server_thread, NULL) != 0) {
        fprintf(stderr, "Failed to create threads\n");
        free(my_address);
        exit(EXIT_FAILURE);
    }

    pthread_join(client_tid, NULL);
    pthread_join(server_tid, NULL);

    // Cleanup
    pthread_mutex_lock(&network_mutex);
    for (uint32_t i = 0; i < peer_count; i++) free(network[i]);
    free(network);
    pthread_mutex_unlock(&network_mutex);
    pthread_mutex_destroy(&network_mutex);
    free(my_address);

    return 0;
}