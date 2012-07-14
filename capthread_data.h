#ifndef CAPTHREAD_DATA_H
#define CAPTHREAD_DATA_H

struct ListData
{
    char time[20];
    char Protocol[50];
    char sIP[16],sMac[19],sPort[10];
    char dIP[16],dMac[19],dPort[10];
    char Len[10];
    char Text[50];
};

typedef struct S_port
{
    bool activated;
    int port_num;
}S_port;

typedef struct D_port
{
    bool activated;
    int port_num;
}D_port;

struct Filter
{
    bool activated;

    bool arp;
    bool rarp;
    bool ip;

    bool icmp;
    bool tcp;
    bool udp;

    S_port s_port;
    D_port d_port;
};

#endif // CAPTHREAD_DATA_H
