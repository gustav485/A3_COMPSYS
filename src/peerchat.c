/* ============================== peer.c ============================== */
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <time.h>

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
#define BASE_DIR "/Users/frederik/Desktop/CompSys Afleveringer/A3_COMPSYS/python/first_peer/"

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

int select_random_peer(NetworkAddress_t *out) {
    pthread_mutex_lock(&network_mutex);
    if (peer_count <= 1) { pthread_mutex_unlock(&network_mutex); return 0; }

    int idx;
    do { idx = rand() % peer_count; }
    while (strcmp(network[idx]->ip, my_address->ip) == 0 && network[idx]->port == my_address->port);

    memcpy(out, network[idx], sizeof(NetworkAddress_t));
    pthread_mutex_unlock(&network_mutex);
    return 1;
}

/* ============================== CLIENT ============================== */

int send_message(const char *ip, int port, int command, char *body, int len) {
    char port_str[PORT_STR_LEN];
    snprintf(port_str, sizeof(port_str), "%d", port);

    int fd = compsys_helper_open_clientfd(ip, port_str);
    if (fd < 0) {
        printf("getaddrinfo failed (%s:%d): connection refused or invalid\n", ip, port);
        return -1;
    }

    RequestHeader_t header;
    memset(&header, 0, sizeof(header));
    strncpy(header.ip, my_address->ip, IP_LEN - 1);
    header.ip[IP_LEN - 1] = '\0';
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
        ip[strcspn(ip, "\n")] = '\0';
        if (strlen(ip) == 0) continue;

        printf("Enter peer port to connect to: ");
        if (!fgets(port_str, sizeof(port_str), stdin)) continue;
        port_str[strcspn(port_str, "\n")] = '\0';
        if (strlen(port_str) == 0) continue;

        int port = atoi(port_str);
        if (!is_valid_ip(ip) || !is_valid_port(port)) {
            printf("Invalid IP or port\n");
            continue;
        }

        int fd = send_message(ip, port, COMMAND_REGISTER, NULL, 0);
        if (fd < 0) continue;

        compsys_helper_state_t rio;
        compsys_helper_readinitb(&rio, fd);

        ReplyHeader_t reply;
        if (compsys_helper_readnb(&rio, &reply, REPLY_HEADER_LEN) != REPLY_HEADER_LEN) {
            close(fd); continue;
        }

        reply.length = ntohl(reply.length);
        reply.status = ntohl(reply.status);

        if (reply.status == STATUS_OK && reply.length > 0) {
            char *body = malloc(reply.length);
            if (body && compsys_helper_readnb(&rio, body, reply.length) == reply.length) {
                int offset = 0;
                while (offset < reply.length) {
                    NetworkAddress_t p;
                    memcpy(p.ip, body + offset, IP_LEN); offset += IP_LEN;
                    memcpy(&p.port, body + offset, 4); p.port = ntohl(p.port); offset += 4;
                    memcpy(p.signature, body + offset, SHA256_HASH_SIZE); offset += SHA256_HASH_SIZE;
                    memcpy(p.salt, body + offset, SALT_LEN); offset += SALT_LEN;
                    add_to_network(&p);
                }
            }
            free(body);
        }
        close(fd);
        break;
    }

    while (1) {
        printf("\nEnter filename to retrieve (or 'quit'): ");
        char filename[PATH_LEN];
        if (!fgets(filename, sizeof(filename), stdin)) continue;
        filename[strcspn(filename, "\n")] = '\0';
        if (strcmp(filename, "quit") == 0) break;

        NetworkAddress_t target;
        if (!select_random_peer(&target)) {
            printf("No peers available\n");
            continue;
        }

        int fd = send_message(target.ip, target.port, COMMAND_RETREIVE, filename, strlen(filename) + 1);
        if (fd < 0) continue;

        compsys_helper_state_t rio;
        compsys_helper_readinitb(&rio, fd);

        ReplyHeader_t reply;
        if (compsys_helper_readnb(&rio, &reply, REPLY_HEADER_LEN) != REPLY_HEADER_LEN) {
            close(fd); continue;
        }

        reply.status = ntohl(reply.status);
        reply.length = ntohl(reply.length);

        if (reply.status != STATUS_OK || reply.length == 0) {
            printf("File not found (status=%d)\n", reply.status);
            close(fd); continue;
        }

        char *filedata = malloc(reply.length);
        if (!filedata || compsys_helper_readnb(&rio, filedata, reply.length) != reply.length) {
            free(filedata); close(fd); continue;
        }

        FILE *fp = fopen(filename, "wb");
        if (fp) {
            fwrite(filedata, 1, reply.length, fp);
            fclose(fp);
            printf("Saved: %s (%d bytes)\n", filename, reply.length);
        }
        free(filedata);
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

/* ---------- FIXED handle_inform (no double-lock) ---------- */
void handle_inform(RequestHeader_t *req, char *body) {
    if (req->length != PEER_ADDR_LEN) return;
    NetworkAddress_t p;
    int off = 0;
    memcpy(p.ip, body + off, IP_LEN); off += IP_LEN;
    memcpy(&p.port, body + off, 4); p.port = ntohl(p.port); off += 4;
    memcpy(p.signature, body + off, SHA256_HASH_SIZE); off += SHA256_HASH_SIZE;
    memcpy(p.salt, body + off, SALT_LEN); off += SALT_LEN;

    pthread_mutex_lock(&network_mutex);
    int exists = 0;
    for (uint32_t i = 0; i < peer_count; i++) {
        if (strcmp(network[i]->ip, p.ip) == 0 && network[i]->port == p.port) { exists = 1; break; }
    }
    pthread_mutex_unlock(&network_mutex);

    if (!exists) {
        add_to_network(&p);
    }
}

/* ---------- FIXED handle_register (no lock nesting or I/O under lock) ---------- */
void handle_register(int fd, RequestHeader_t *req, char *body) {
    (void)body;
    int exists = 0;

    pthread_mutex_lock(&network_mutex);
    for (uint32_t i = 0; i < peer_count; i++) {
        if (strcmp(network[i]->ip, req->ip) == 0 && network[i]->port == req->port) { exists = 1; break; }
    }
    pthread_mutex_unlock(&network_mutex);

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

    pthread_mutex_lock(&network_mutex);
    int len = peer_count * PEER_ADDR_LEN;
    char *resp = malloc(len);
    if (resp) {
        for (uint32_t i = 0; i < peer_count; i++) {
            int off = i * PEER_ADDR_LEN;
            memcpy(resp + off, network[i]->ip, IP_LEN);
            uint32_t np = htonl(network[i]->port);
            memcpy(resp + off + IP_LEN, &np, 4);
            memcpy(resp + off + IP_LEN + 4, network[i]->signature, SHA256_HASH_SIZE);
            memcpy(resp + off + IP_LEN + 4 + SHA256_HASH_SIZE, network[i]->salt, SALT_LEN);
        }
    }
    pthread_mutex_unlock(&network_mutex);

    send_response(fd, exists ? STATUS_PEER_EXISTS : STATUS_OK, resp, len);
    free(resp);

    if (!exists) {
        pthread_mutex_lock(&network_mutex);
        uint32_t count = peer_count;
        NetworkAddress_t **copy = malloc(count * sizeof(NetworkAddress_t*));
        for (uint32_t i = 0; i < count; i++) {
            copy[i] = malloc(sizeof(NetworkAddress_t));
            memcpy(copy[i], network[i], sizeof(NetworkAddress_t));
        }
        pthread_mutex_unlock(&network_mutex);

        for (uint32_t i = 0; i < count; i++) {
            if (strcmp(copy[i]->ip, new_peer.ip) == 0 && copy[i]->port == new_peer.port) continue;
            if (strcmp(copy[i]->ip, my_address->ip) == 0 && copy[i]->port == my_address->port) continue;
            char inform_body[PEER_ADDR_LEN];
            int off = 0;
            memcpy(inform_body + off, new_peer.ip, IP_LEN); off += IP_LEN;
            uint32_t np = htonl(new_peer.port);
            memcpy(inform_body + off, &np, 4); off += 4;
            memcpy(inform_body + off, new_peer.signature, SHA256_HASH_SIZE); off += SHA256_HASH_SIZE;
            memcpy(inform_body + off, new_peer.salt, SALT_LEN); off += SALT_LEN;
            send_message(copy[i]->ip, copy[i]->port, COMMAND_INFORM, inform_body, PEER_ADDR_LEN);
            free(copy[i]);
        }
        free(copy);
    }
}

void handle_retrieve(int fd, RequestHeader_t *req, char *filename) {
    // Fjern indledende '/' hvis der er nogen
    if (filename[0] == '/') memmove(filename, filename + 1, strlen(filename));

    // Beskyt mod path traversal
    if (strstr(filename, "..") != NULL) {
        send_response(fd, STATUS_BAD_REQUEST, NULL, 0);
        return;
    }

    // Brug BASE_DIR
    char fullpath[PATH_LEN];
    snprintf(fullpath, sizeof(fullpath), "%s%s", BASE_DIR, filename);

    printf("Server trying to open file: %s\n", fullpath); // Debug

    FILE *fp = fopen(fullpath, "rb");
    if (!fp) {
        printf("File not found: %s\n", fullpath); // Debug
        send_response(fd, STATUS_PEER_MISSING, NULL, 0);
        return;
    }

    fseek(fp, 0, SEEK_END);
    long size = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    if (size > MAX_MSG_LEN) {
        fclose(fp);
        send_response(fd, STATUS_OTHER, NULL, 0);
        return;
    }

    char *data = malloc(size);
    if (!data || fread(data, 1, size, fp) != (size_t)size) {
        free(data);
        fclose(fp);
        send_response(fd, STATUS_OTHER, NULL, 0);
        return;
    }
    fclose(fp);

    send_response(fd, STATUS_OK, data, size);
    free(data);
}

void* handle_request_thread(void *arg) {
    int fd = (int)(long)arg;
    pthread_detach(pthread_self());

    compsys_helper_state_t rio;
    compsys_helper_readinitb(&rio, fd);

    RequestHeader_t req;
    if (compsys_helper_readnb(&rio, &req, REQUEST_HEADER_LEN) != REQUEST_HEADER_LEN) { close(fd); return NULL; }

    req.command = ntohl(req.command);
    req.length = ntohl(req.length);
    req.port = ntohl(req.port);

    char *body = NULL;
    if (req.length > 0) {
        body = malloc(req.length);
        if (!body || compsys_helper_readnb(&rio, body, req.length) != req.length) {
            send_response(fd, STATUS_MALFORMED, NULL, 0);
            free(body); close(fd); return NULL;
        }
        if (req.command == COMMAND_RETREIVE) body[req.length - 1] = '\0';
    }

    if (!is_valid_ip(req.ip) || !is_valid_port(req.port)) {
        send_response(fd, STATUS_BAD_REQUEST, NULL, 0);
        free(body); close(fd); return NULL;
    }

    if (req.command == COMMAND_REGISTER) handle_register(fd, &req, body);
    else if (req.command == COMMAND_INFORM) handle_inform(&req, body);
    else if (req.command == COMMAND_RETREIVE) handle_retrieve(fd, &req, body);
    else send_response(fd, STATUS_OTHER, NULL, 0);

    free(body);
    close(fd);
    return NULL;
}

void* server_thread(void *arg) {
    (void)arg;
    char port_str[PORT_STR_LEN];
    snprintf(port_str, sizeof(port_str), "%d", my_address->port);
    int listenfd = compsys_helper_open_listenfd(port_str);
    if (listenfd < 0) {
        fprintf(stderr, "Failed to open listen socket on port %d\n", my_address->port);
        return NULL;
    }

    printf("Server listening on %s:%d\n", my_address->ip, my_address->port);

    while (1) {
        int connfd = accept(listenfd, NULL, NULL);
        if (connfd < 0) continue;
        pthread_t tid;
        pthread_create(&tid, NULL, handle_request_thread, (void*)(long)connfd);
    }
    return NULL;
}

/* ============================== MAIN ============================== */

int main(int argc, char **argv) {
    if (argc != 3) { fprintf(stderr, "Usage: %s <IP> <PORT>\n", argv[0]); exit(1); }

    srand(time(NULL));
    my_address = malloc(sizeof(NetworkAddress_t));
    if (!my_address) exit(1);

    strncpy(my_address->ip, argv[1], IP_LEN - 1);
    my_address->ip[IP_LEN - 1] = '\0';
    my_address->port = atoi(argv[2]);

    if (!is_valid_ip(my_address->ip) || !is_valid_port(my_address->port)) {
        fprintf(stderr, "Invalid IP/port\n"); free(my_address); exit(1);
    }

    char password[PASSWORD_LEN];
    printf("Create a password to proceed: ");
    if (scanf("%15s", password) != 1) exit(1);
    int c; while ((c = getchar()) != '\n' && c != EOF) { } // flush newline

    for (int i = strlen(password); i < PASSWORD_LEN; i++) password[i] = '\0';

    char salt[SALT_LEN];
    generate_random_salt(salt);
    memcpy(my_address->salt, salt, SALT_LEN);
    get_signature(password, strlen(password), salt, &my_address->signature);

    pthread_t client_tid, server_tid;

    if (pthread_create(&server_tid, NULL, server_thread, NULL) != 0) {
        fprintf(stderr, "Failed to create server thread\n");
        free(my_address); exit(1);
    }

    if (pthread_create(&client_tid, NULL, client_thread, NULL) != 0) {
        fprintf(stderr, "Failed to create client thread\n");
        free(my_address); exit(1);
    }

    pthread_join(client_tid, NULL);
    pthread_join(server_tid, NULL);

    for (uint32_t i = 0; i < peer_count; i++) free(network[i]);
    free(network);
    free(my_address);
    return 0;
}
