#include <stdio.h>
#include <netdb.h>
#include <arpa/inet.h>

int main() {
    struct hostent *h = gethostbyname("localhost");
    if (h && h->h_addr_list[0]) {
        printf("IP: %s\n", inet_ntoa(*(struct in_addr*)h->h_addr_list[0]));
    } else {
        printf("Failed to resolve localhost\n");
    }
    return 0;
}
