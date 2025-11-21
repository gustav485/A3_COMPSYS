#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <time.h>
#include <assert.h>

#ifdef __APPLE__
#include "./endian.h"
#else
#include <endian.h>
#endif

#include "./peer.h"

NetworkAddress_t *my_address;
NetworkAddress_t **network = NULL;
uint32_t peer_count = 0;
pthread_mutex_t network_mutex = PTHREAD_MUTEX_INITIALIZER;


//Sammenligner to ip'er byte for byte
int ip_equal(const char a[IP_LEN], const char b[IP_LEN]) {
    return memcmp(a, b, IP_LEN) == 0;
}


//Beregner et hash ud fra vores password og et salt. Den fylder en buffer og hasher hele bufferen. 
void get_signature(void *password, int password_len, char *salt, hashdata_t *hash) {
    char combined[PASSWORD_LEN + SALT_LEN];
    int pwd_len = (password_len > PASSWORD_LEN) ? PASSWORD_LEN : password_len;   //Hvis passwordet er for langt forkortes det til maks længden. Ellers benytter den det originale.
    memset(combined, 0, sizeof(combined));
    memcpy(combined, password, pwd_len);
    memcpy(combined + PASSWORD_LEN, salt, SALT_LEN);
    get_data_sha(combined, *hash, PASSWORD_LEN + SALT_LEN, SHA256_HASH_SIZE);
}

//Tilføjer en peer til netværket.
void add_to_network(NetworkAddress_t *peer) {
    pthread_mutex_lock(&network_mutex);         //Låser så andre threads ikke kan ændre imens vi er igang.
    network = realloc(network, (peer_count + 1) * sizeof(NetworkAddress_t*));    //Allokerer plads til en ekstra peer pointer. (Ikke selve peeren endnu)
    if (!network) {
        pthread_mutex_unlock(&network_mutex);           //tjekker om realloc lykkedes.
        return;
    }

    network[peer_count] = malloc(sizeof(NetworkAddress_t));             //Allokerer plads til den aktuelle peer der skal på netværket.
    if (network[peer_count]) {
        memcpy(network[peer_count], peer, sizeof(NetworkAddress_t));    //Kopierer den nye peer ind i netværket 
        peer_count++;
        printf("- Peer added: %s:%d\n",
               peer->ip, peer->port);
    }
    pthread_mutex_unlock(&network_mutex);       //unlocker sp andre threads kan tilføje andre peers.
}

//Vælger en tilfældig peer
int select_random_peer(NetworkAddress_t *out) {
    pthread_mutex_lock(&network_mutex);             //Låser for at undgå race conditions.
    if (peer_count <= 1) {
        pthread_mutex_unlock(&network_mutex);       //Tjekker om der er flere end én peer.
        return 0;
    }

    int idx;
    do {idx = rand() % peer_count;}             //Giver et tilfældigt index fra 0 til vores peercount 
    while (ip_equal(network[idx]->ip, my_address->ip) && network[idx]->port == my_address->port);       //hvis vi vælger ogs selv, prøver den igen indtil dette ikke er tilfældet.

    memcpy(out, network[idx], sizeof(NetworkAddress_t));    //kopierer hele peeren ind i out.
    pthread_mutex_unlock(&network_mutex);
    return 1;
}

//Printer antallet af kendte peers.
void print_peers() {
    pthread_mutex_lock(&network_mutex);     //Låser for at undgå race conditions.
    printf("-Current peers: %u\n", peer_count);     //printer antallet af peers
    for (uint32_t i = 0; i < peer_count; i++) {
        printf("- %s:%d %s\n", network[i]->ip, network[i]->port,    //printer de individuelle peers der er på netværket.
               (ip_equal(network[i]->ip, my_address->ip) && network[i]->port == my_address->port)? "" : "");
    }
    pthread_mutex_unlock(&network_mutex);      //Unlocker 
}

// Klient send
int send_message(char *ip, int port, int command, char *body, int len) {
    char port_str[PORT_STR_LEN];                            //Omdanner port til en char 
    snprintf(port_str, sizeof(port_str), "%d", port);           //compsys helper tager porten som string og ikke int.

    int fd = compsys_helper_open_clientfd(ip, port_str);    //Opretter forbindelse til en anden peer.
    if (fd < 0) {
        printf("-Connection failed to %s:%d\n", ip, port);
        return -1;
    }

    unsigned char header[REQUEST_HEADER_LEN];           //Midlertidig buffer til headeren.
    int off = 0;                                //Off er et offset der fortæller hvor i headeren vi er nået til.

    memset(header + off, 0, IP_LEN);            //Headeren nulstilles fra tidligere brug.
    size_t myip_len = strlen(my_address->ip);   //Længden af ip'en findes.
    if (myip_len > IP_LEN) {                    //sikrer at ip'en ikke er for lang. 
        myip_len = IP_LEN;
    }   
    memcpy(header + off, my_address->ip, myip_len); //Ip'en kopieres ind i headeren
    off += IP_LEN;              //Offset rykkes 16 bytes frem.

    uint32_t p = htonl(my_address->port);
    memcpy(header + off, &p, 4); 
    off += 4;      //Vores egen port sættes til headeren.

    memcpy(header + off, my_address->signature, SHA256_HASH_SIZE); //Vores signatur 
    off += SHA256_HASH_SIZE;   

    uint32_t cmd = htonl(command);      
    memcpy(header + off, &cmd, 4);          //Kommando så vi ved hvad vi skal gøre.
    off += 4;

    uint32_t ln = htonl(len);
    memcpy(header + off, &ln, 4);   //Længden af vores body, så vi ved hvor meget der skal sendes med.
    off += 4;

    char buffer[REQUEST_HEADER_LEN + MAX_MSG_LEN];      //Vi samler hele beskeden i en stor buffer.
    memcpy(buffer, header, REQUEST_HEADER_LEN);
    if (len > 0) {
        memcpy(buffer + REQUEST_HEADER_LEN, body, len);
    }

    compsys_helper_writen(fd, buffer, REQUEST_HEADER_LEN + len);        //Dette sender vi over netværket til peeren i den anden ende.
    return fd;                                          //Vi returnere så ham der prøver at hente en fil får svar.
}

// Client thread
void* client_thread(void *arg) {
    (void)arg;
    while (1) {
        char ip[IP_LEN] = {0};                          //Opretter tomme strenge til ip og port
        char port_str[PORT_STR_LEN] = {0};

        printf("\nEnter peer IP to connect to: ");         
        if (!fgets(ip, sizeof(ip), stdin)) {            //Læser det der bliver skrevet.
            continue;
        }        
        ip[strcspn(ip, "\n")] = '\0';           //ignorerer newline 
        if (strlen(ip) == 0) {              //error check
            break;
        }

        printf("Enter peer port: ");                                
        if (!fgets(port_str, sizeof(port_str), stdin)) {  //Læser det der bliver skrevet.
            continue;
        }         
        port_str[strcspn(port_str, "\n")] = '\0';           //ignore newline
        if (strlen(port_str) == 0) {
            continue;
        }           

        int port = atoi(port_str);                      //Laver port strengen om til int
        if (!is_valid_ip(ip) || !is_valid_port(port)) {     //Tjekker om ip og port er valid ellers giv besked.
            printf(" Invalid IP or port!\n");
            continue;
        }

        int fd = send_message(ip, port, COMMAND_REGISTER, NULL, 0);     //Sender besked med anmodning om at joine netværk
        if (fd < 0) {
            printf(" Failed to connect.\n");        //Error handling
            continue;
        }

        compsys_helper_state_t rio;             
        compsys_helper_readinitb(&rio, fd);     //Gør klar til at læse fra netværket.

        ReplyHeader_t reply;
        if (compsys_helper_readnb(&rio, &reply, REPLY_HEADER_LEN) == REPLY_HEADER_LEN) {        //Hvis det første vi læser er en reply header fortsætter vi.
            reply.length = ntohl(reply.length);         //Konverter fra network byte order (big-endian) til host byte order.
            reply.status = ntohl(reply.status);         //-||-

            if (reply.status == STATUS_OK && reply.length > 0) {                //Tjekker serverens status: forventer et OK.
                char *body = malloc(reply.length);                          //Allokere plads til indholdet 
                if (body && compsys_helper_readnb(&rio, body, reply.length) == reply.length) { //Vi læser reply.length ind i body'en
                    uint32_t offset = 0;     //Laver et offset
                    while (offset < reply.length) {         //Så længe offset er mindre end reply.length
                        NetworkAddress_t p;
                        memcpy(p.ip, body + offset, IP_LEN); offset += IP_LEN;
                        memcpy(&p.port, body + offset, 4); p.port = ntohl(p.port); offset += 4;
                        memcpy(p.signature, body + offset, SHA256_HASH_SIZE); offset += SHA256_HASH_SIZE;
                        memcpy(p.salt, body + offset, SALT_LEN); offset += SALT_LEN;
                        add_to_network(&p);     //Tilføjer peer til vores egen liste.
                    }
                }                           //Pakker ip, port og signatur ud for en ny peer.
                free(body);     //Free'er pladsen igen 
            }
        }
        close(fd);      //Lukker forbindelse til peeren. 
        print_peers();  //Printer alle peers på netværket.
        break;
    }

    // File retrieval loop
    while (1) {
        printf("\nEnter filename to retrieve (or 'quit' or 'peers'): ");        
        char input[PATH_LEN];               //buffer til filens sti som ønskes downloadet.
        if (!fgets(input, sizeof(input), stdin)) {  //Læser det som bliver skrevet.
            continue;
        }      
        input[strcspn(input, "\n")] = '\0';

        if (strcmp(input, "quit") == 0) {    //Hvis det er quit afbrydes
            break;
        }                              
        if (strcmp(input, "peers") == 0) {        //Hvis "peers" printes nuværende peers på netværket.
            print_peers(); 
            continue; 
        }

        NetworkAddress_t target;
        if (!select_random_peer(&target)) {             //Vælger tilfældig peer. Hvis sig selv sender den error besked
            printf(" No peers available yet\n");
            continue;
        }

        printf(" Retrieving '%s' from %s:%d...\n", input, target.ip, target.port);
        int fd = send_message(target.ip, target.port, COMMAND_RETRIEVE, input, strlen(input));    //Opretter forbindelse til anden peer og sender besked.
        if (fd < 0) {
            continue;
        }

        compsys_helper_state_t rio;
        compsys_helper_readinitb(&rio, fd);     //se 161 og 162. Opretter tom buffer

        ReplyHeader_t reply;
        if (compsys_helper_readnb(&rio, &reply, REPLY_HEADER_LEN) != REPLY_HEADER_LEN) {            //Hvis den ikke læser den præcise header, forsøges igen næste gang via contenuie
            close(fd);                              //Readnb læser data fra fd ned i bufferen.
            continue;                        
        }

        reply.status = ntohl(reply.status);             //Konverter fra netværksformat (big-endian) til din computers format.
        reply.length = ntohl(reply.length);

        if (reply.status != STATUS_OK || reply.length == 0) {                      //hvis vi får en besked som ikke er OK og længden er 0 starter errorhandling
            printf(" File not found or error (status=%d)\n", reply.status);
            close(fd);
            continue;
        }

        char *filedata = malloc(reply.length);          //Allokere plads til den indkomne fil,
        if (!filedata || compsys_helper_readnb(&rio, filedata, reply.length) != reply.length) {     //Indlæser præcis reply.length ind i bufferen. 
            printf(" Failed to download file data\n");
            free(filedata);
            close(fd);
            continue;
        }

        FILE *fp = fopen(input, "wb");          //Vi gemmer filen med samme navn som input.
        if (fp) {
            fwrite(filedata, 1, reply.length, fp);
            fclose(fp);
            printf(" Saved: %s (%d bytes)\n", input, reply.length);
        } 
        else {
            printf(" Could not save file\n");
        }
        free(filedata);             //Frigiver og lukker 
        close(fd);
    }
    return NULL;
}

//Sendelse af beskeder
void send_response(int fd, uint32_t status, char *body, int len) {
    unsigned char header[REPLY_HEADER_LEN] = {0};                        //Tom header buffer 
    int off = 0;                                                         //Offset

    uint32_t be = htonl(len);     memcpy(header + off, &be, 4); off += 4;               
    be = htonl(status);           memcpy(header + off, &be, 4); off += 4;                       //Alle tal konverteres til big endian. netværk format
    be = htonl(0);                memcpy(header + off, &be, 4); off += 4; // Enkelt blok
    be = htonl(1);                memcpy(header + off, &be, 4); off += 4; // Antallet af blocks

    if (len > 0) {
        unsigned char hash[SHA256_HASH_SIZE];
        get_data_sha(body, hash, len, SHA256_HASH_SIZE);
        memcpy(header + off, hash, SHA256_HASH_SIZE); off += SHA256_HASH_SIZE;
        memcpy(header + off, hash, SHA256_HASH_SIZE); off += SHA256_HASH_SIZE;
    } 
    else {
        off += 64; // zero hashes
    }

    char buffer[REPLY_HEADER_LEN + MAX_MSG_LEN];
    memcpy(buffer, header, REPLY_HEADER_LEN);
    if (len > 0) {
        memcpy(buffer + REPLY_HEADER_LEN, body, len);
    }
    compsys_helper_writen(fd, buffer, REPLY_HEADER_LEN + len);
}

void handle_inform(RequestHeader_t *req, char *body) {
    if (req->length != PEER_ADDR_LEN) {
        return;
    }
    NetworkAddress_t p;
    int off = 0;
    memcpy(p.ip, body + off, IP_LEN); off += IP_LEN;
    uint32_t port; memcpy(&port, body + off, 4); p.port = ntohl(port); off += 4;
    memcpy(p.signature, body + off, SHA256_HASH_SIZE); off += SHA256_HASH_SIZE;
    memcpy(p.salt, body + off, SALT_LEN);

    pthread_mutex_lock(&network_mutex);
    for (uint32_t i = 0; i < peer_count; i++) {
        if (ip_equal(network[i]->ip, p.ip) && network[i]->port == p.port) {
            pthread_mutex_unlock(&network_mutex);
            return;
        }
    }
    pthread_mutex_unlock(&network_mutex);
    add_to_network(&p);
}

void handle_register(int fd, RequestHeader_t *req, char *body) {
    (void)body;
    int exists = 0;

    pthread_mutex_lock(&network_mutex);
    for (uint32_t i = 0; i < peer_count; i++) {
        if (ip_equal(network[i]->ip, req->ip) && network[i]->port == req->port) {
            exists = 1; 
            break;
        }
    }
    pthread_mutex_unlock(&network_mutex);

    NetworkAddress_t new_peer = {0};
    if (!exists) {
        char salt[SALT_LEN];
        generate_random_salt(salt);
        get_signature(req->signature, SHA256_HASH_SIZE, salt, &new_peer.signature);
        memcpy(new_peer.ip, req->ip, IP_LEN);
        new_peer.port = req->port;
        memcpy(new_peer.salt, salt, SALT_LEN);
        add_to_network(&new_peer);
    }

    // Send full peer list
    pthread_mutex_lock(&network_mutex);
    int len = peer_count * PEER_ADDR_LEN;
    char *resp = len > 0 ? malloc(len) : NULL;
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

    // Inform others
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
            if (ip_equal(copy[i]->ip, new_peer.ip) && copy[i]->port == new_peer.port) { 
                free(copy[i]); 
                continue; 
            }
            if (ip_equal(copy[i]->ip, my_address->ip) && copy[i]->port == my_address->port) { 
                free(copy[i]); 
                continue; 
            }

            char inform_body[PEER_ADDR_LEN];
            int off = 0;
            memcpy(inform_body + off, new_peer.ip, IP_LEN); off += IP_LEN;
            uint32_t np = htonl(new_peer.port);
            memcpy(inform_body + off, &np, 4); off += 4;
            memcpy(inform_body + off, new_peer.signature, SHA256_HASH_SIZE); off += SHA256_HASH_SIZE;
            memcpy(inform_body + off, new_peer.salt, SALT_LEN);
            send_message(copy[i]->ip, copy[i]->port, COMMAND_INFORM, inform_body, PEER_ADDR_LEN);
            free(copy[i]);
        }
        free(copy);
    }
}

void handle_retrieve(int fd, RequestHeader_t *req, char *filename) {
    (void)req;
    if (!filename || strlen(filename) == 0) {
        send_response(fd, STATUS_BAD_REQUEST, NULL, 0);
        return;
    }

    // Sikker filsti
    char clean[PATH_LEN] = {0};
    strncpy(clean, filename, sizeof(clean)-1);

    // Fjern indledende slash + forbyd ..
    if (clean[0] == '/') {
        memmove(clean, clean + 1, strlen(clean));
    }
    if (strstr(clean, "..") || strchr(clean, '/')) {
        send_response(fd, STATUS_BAD_REQUEST, NULL, 0);
        return;
    }

    printf("Sending file: %s\n", clean);

    FILE *fp = fopen(clean, "rb");
    if (!fp) {
        printf("File not found: %s\n", clean);
        send_response(fd, STATUS_PEER_MISSING, NULL, 0);
        return;
    }

    fseek(fp, 0, SEEK_END);
    long size = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    if (size <= 0 || size > MAX_MSG_LEN) {
        fclose(fp);
        send_response(fd, STATUS_OTHER, NULL, 0);
        return;
    }

    char *data = malloc(size);
    if (!data || fread(data, 1, size, fp) != (size_t)size) {
        free(data); fclose(fp);
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

    unsigned char header_buf[REQUEST_HEADER_LEN];
    if (compsys_helper_readnb(&rio, header_buf, REQUEST_HEADER_LEN) != REQUEST_HEADER_LEN) {
        close(fd); 
        return NULL;
    }

    RequestHeader_t req = {0};
    int off = 0;

    char raw_ip[IP_LEN];
    memcpy(raw_ip, header_buf + off, IP_LEN); off += IP_LEN;
    memcpy(req.ip, raw_ip, IP_LEN);
    req.ip[IP_LEN-1] = '\0';
    for (int i = IP_LEN-2; i >= 0; i--) {
        if (req.ip[i] == '\0' || req.ip[i] == ' ') {
            req.ip[i] = '\0';
        }
        else {
            break;
        }
    }

    uint32_t tmp; memcpy(&tmp, header_buf + off, 4); req.port = ntohl(tmp); off += 4;
    memcpy(req.signature, header_buf + off, SHA256_HASH_SIZE); off += SHA256_HASH_SIZE;
    memcpy(&tmp, header_buf + off, 4); req.command = ntohl(tmp); off += 4;
    memcpy(&tmp, header_buf + off, 4); req.length = ntohl(tmp); off += 4;

    char *body = NULL;
    char filename[PATH_LEN] = {0};

    if (req.length > 0) {
        body = malloc(req.length + 1);
        if (!body || compsys_helper_readnb(&rio, body, req.length) != req.length) {
            send_response(fd, STATUS_MALFORMED, NULL, 0);
            free(body); 
            close(fd); 
            return NULL;
        }
        body[req.length] = '\0';

        if (req.command == COMMAND_RETRIEVE) {
            strncpy(filename, body, sizeof(filename)-1);
        }
    }

    if (!is_valid_ip(req.ip) || !is_valid_port(req.port)) {
        send_response(fd, STATUS_BAD_REQUEST, NULL, 0);
        free(body); 
        close(fd); 
        return NULL;
    }

    if (req.command == COMMAND_REGISTER) {
        handle_register(fd, &req, body);
    }
    else if (req.command == COMMAND_INFORM) {
        handle_inform(&req, body);
    }
    else if (req.command == COMMAND_RETRIEVE) {
        handle_retrieve(fd, &req, filename);
    }
    else {
        send_response(fd, STATUS_OTHER, NULL, 0);
    }

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
        fprintf(stderr, "Failed to bind to port %d\n", my_address->port);
        return NULL;
    }
    printf("Server listening on %s:%d\n", my_address->ip, my_address->port);

    while (1) {
        int connfd = accept(listenfd, NULL, NULL);
        if (connfd >= 0) {
            pthread_t tid;
            pthread_create(&tid, NULL, handle_request_thread, (void*)(long)connfd);
        }
    }
    return NULL;
}

int main(int argc, char **argv) {
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <IP> <PORT>\n", argv[0]);
        exit(1);
    }

    srand(time(NULL));
    my_address = calloc(1, sizeof(NetworkAddress_t));
    strncpy(my_address->ip, argv[1], IP_LEN-1);
    my_address->port = atoi(argv[2]);

    if (!is_valid_ip(my_address->ip) || !is_valid_port(my_address->port)) {
        fprintf(stderr, "Invalid IP or port\n");
        exit(1);
    }

    char password[PASSWORD_LEN];
    printf("Create a password to proceed: ");
    if (scanf("%15s", password) != 1) {
        exit(1);
    }
    getchar(); // eat newline

    char salt[SALT_LEN];
    generate_random_salt(salt);
    memcpy(my_address->salt, salt, SALT_LEN);
    get_signature(password, strlen(password), salt, &my_address->signature);

    // Add ourselves to network list
    add_to_network(my_address);

    pthread_t server_tid, client_tid;
    pthread_create(&server_tid, NULL, server_thread, NULL);
    pthread_create(&client_tid, NULL, client_thread, NULL);

    pthread_join(client_tid, NULL);
    pthread_join(server_tid, NULL);

    // Cleanup
    for (uint32_t i = 0; i < peer_count; i++) {
        free(network[i]);
    }
    free(network);
    free(my_address);
    return 0;
}