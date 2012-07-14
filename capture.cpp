#include <QtCore>

#include "capture.h"
#include "packethead.h"
#include "datatype.h"

void Capture_thread::set_parameter(const int i,
                                   const Filter f,
                                   const int cm,
                                   const int e
                                   )
{
    interface_num = i;
    filter = f;
    capture_mode = cm;
    each_pkt_size = e;
    emit start_cap();
}

Capture_thread::Capture_thread()
{
}

void Capture_thread::run()
{
    forever
    {
        open_and_get();
    }
}

int Capture_thread::get_interface_amount(void)
{
    int i;
    i = 0;
    pcap_if_t* d; //�豸�б�ָ��

    for(d = alldevs; d; d = d->next)
    {
        ++i;
    }

    if(0 == i)
    {
        sprintf(errbuf, "δ�ҵ��豸�� ��ȷ��WinPcap�Ѱ�װ");
        return -1;
    }
    else
    {
        return i;
    }
}

int Capture_thread::get_interface_item(void)
{
    if(-1 == (pcap_findalldevs_ex(PCAP_SRC_IF_STRING,
                                  NULL, &alldevs, errbuf)))
    {
        sprintf(errbuf, "�����豸ʱʧ��");
        return -1;
    }
    return 0;
}

void Capture_thread::open_and_get()
{
    if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1)
    {
        sprintf(errbuf,"Error in pcap_findalldevs");
        return;
    }

    //��ת��ָ��������
    pcap_if_t* d;
    d = alldevs;
    int i;

    for(i = 0; i < interface_num; ++i)
    {
        d = d->next;
    }

    //���豸
    pcap_t* adhandle;
    adhandle = pcap_open(d->name, //�豸��
                         each_pkt_size, //65535��֤�ܲ��񵽲�ͬ������·���ϵ�ÿ�����ݰ���ȫ������
                         capture_mode, //����������ģʽ
                         1000, //��ȡ��ʱʱ��
                         NULL, //��Ϊ��ʹ��Զ�̲�������Զ�̻�����֤Ϊ��
                         errbuf //���󻺳�
                         );

    if(NULL == adhandle)
    {
        sprintf(errbuf, "�޷���������. %s����WinPcap֧��", d->name);
        pcap_freealldevs(alldevs);
        return;
    }

    pcap_freealldevs(alldevs);

    pcap_dumper_t* dumpfile;
    dumpfile = pcap_dump_open(adhandle, "tmp.pcap");

    if(NULL == dumpfile)
    {
        sprintf(errbuf, "�޷�����ʱ�ļ�");
        return;
    }

    int res;
    struct pcap_pkthdr *header;
    const u_char *pkt_data;
    while((res = pcap_next_ex(adhandle, &header, &pkt_data)) >= 0)
    {
        if(0 == res)
        {
            continue;
        }
        pcap_dump((u_char*)dumpfile, header, pkt_data);
        analysis(header, pkt_data, filter);
    }
}

void Capture_thread::analysis(const pcap_pkthdr *header,
                              const u_char *pkt_data,
                              const Filter filter)
{
    struct ether_header* eth;
    struct iphead* IPHead;
    struct arphead* ARPHead;
    unsigned int ptype;
    u_char* mac_string;
    in_addr ipaddr;
    struct tm* ltime;
    char timestr[16];
    time_t local_tv_sec;
    ListData list;
    QString anadetial;
    bool analysised = false;

    itoa(header->caplen, list.Len, 10);

    local_tv_sec = header->ts.tv_sec;
    ltime = localtime(&local_tv_sec);
    strftime(timestr, sizeof(timestr), "%H:%M:%S", ltime);
    sprintf(list.time, "%s.%.3ld", timestr, header->ts.tv_usec);

    eth = (struct ether_header*)pkt_data;
    mac_string=eth->ether_shost;
    sprintf(list.sMac, "%02x:%02x:%02x:%02x:%02x:%02x",
            *mac_string,
            *(mac_string + 1),
            *(mac_string + 2),
            *(mac_string + 3),
            *(mac_string + 4),
            *(mac_string + 5));
    mac_string=eth->ether_dhost;
    sprintf(list.dMac, "%02x:%02x:%02x:%02x:%02x:%02x",
            *mac_string,
            *(mac_string + 1),
            *(mac_string + 2),
            *(mac_string + 3),
            *(mac_string + 4),
            *(mac_string + 5));
    ptype = qFromBigEndian(eth->ether_type);
    memcpy(list.Text, pkt_data, 45);
    list.Text[45] = '\0';
    decodechar(list.Text, 45);

    switch(ptype)
    {
    case ETHERTYPE_ARP:
    {
        if(filter.activated && filter.arp)
        {
            analysised = false;
            break;
        }
        analysised = true;
        strcpy(list.Protocol, "ARP");
        ARPHead = (arphead*)(pkt_data+14);

        sprintf(list.sIP, "%d.%d.%d.%d",
                ARPHead->arp_source_ip_address[0],
                ARPHead->arp_source_ip_address[1],
                ARPHead->arp_source_ip_address[2],
                ARPHead->arp_source_ip_address[3]);
        sprintf(list.dIP, "%d.%d.%d.%d",
                ARPHead->arp_destination_ip_address[0],
                ARPHead->arp_destination_ip_address[1],
                ARPHead->arp_destination_ip_address[2],
                ARPHead->arp_destination_ip_address[3]);
        strcpy(list.sPort, "--");
        strcpy(list.dPort, "--");
        break;
    }

    case ETHERTYPE_REVARP:
    {
        if(filter.activated && filter.rarp)
        {
            analysised = false;
            break;
        }
        analysised = true;
        strcpy(list.Protocol, "RARP");
        break;
    }

    case ETHERTYPE_IP:
    {
        if(filter.activated && filter.ip)
        {
            analysised = false;
            break;
        }
        IPHead = (iphead *)(pkt_data + 14);
        ipaddr = IPHead->ip_souce_address;
        sprintf(list.sIP, "%d.%d.%d.%d",
                ipaddr.S_un.S_un_b.s_b1,
                ipaddr.S_un.S_un_b.s_b2,
                ipaddr.S_un.S_un_b.s_b3,
                ipaddr.S_un.S_un_b.s_b4);
        ipaddr = IPHead->ip_destination_address;
        sprintf(list.dIP, "%d.%d.%d.%d",
                ipaddr.S_un.S_un_b.s_b1,
                ipaddr.S_un.S_un_b.s_b2,
                ipaddr.S_un.S_un_b.s_b3,
                ipaddr.S_un.S_un_b.s_b4);

        switch(IPHead->ip_protocol)
        {
        case 1:
        {
            if(filter.activated && filter.icmp)
            {
                analysised = false;
                break;
            }
            analysised = true;
            strcpy(list.Protocol, "ICMP");
            strcpy(list.sPort, "--");
            strcpy(list.dPort, "--");
            break;
        }

        case 6:
        {
            if(filter.activated && filter.tcp)
            {
                analysised = false;
                break;
            }
            analysised = true;
            strcpy(list.Protocol, "TCP");

            int s_port = qFromBigEndian(((tcphead*)(pkt_data + 16 + 20))->th_sport);
            if(filter.activated && s_port == filter.s_port.port_num)
            {
                analysised = false;
                break;
            }
            analysised = true;
            sprintf(list.sPort, "%d", s_port);

            int d_port = qFromBigEndian(((tcphead*)(pkt_data + 16 + 20))->th_dport);
            if(filter.activated && d_port == filter.d_port.port_num)
            {
                analysised = false;
                break;
            }
            analysised = true;
            sprintf(list.dPort, "%d", d_port);
            break;
        }

        case 17:
        {
            if(filter.activated && filter.udp)
            {
                analysised = false;
                break;
            }
            analysised = true;
            strcpy(list.Protocol, "UDP");

            int s_port = qFromBigEndian(((udphead*)(pkt_data + 16 + 20))->udp_source_port);
            if(filter.activated && s_port == filter.s_port.port_num)
            {
                analysised = false;
                break;
            }
            analysised = true;
            sprintf(list.sPort, "%d", s_port);

            int d_port = qFromBigEndian(((udphead*)(pkt_data + 16 + 20))->udp_destinanion_port);
            if(filter.activated && d_port == filter.d_port.port_num)
            {
                analysised = false;
                break;
            }
            analysised = true;
            sprintf(list.dPort, "%d", d_port);
            break;
        }

        default:
        {
            analysised = true;
            strcpy(list.Protocol, "δ֪IP��");
            strcpy(list.sIP, "----------");
            strcpy(list.dIP, "----------");
            strcpy(list.sPort, "--");
            strcpy(list.dPort, "--");
            break;
        }
        }
        break;
    }

    case ETHERTYPE_PUP:
    {
        analysised = true;
        strcpy(list.Protocol, "PUP");
        strcpy(list.sIP, "----------");
        strcpy(list.dIP, "----------");
        strcpy(list.sPort, "--");
        strcpy(list.dPort, "--");
        break;
    }

    case ETHERTYPE_PPPoE_SESSION:
    {
        analysised = true;
        strcpy(list.Protocol, "ETHERTYPE_PPPoE_SESSION");
        strcpy(list.sIP, "----------");
        strcpy(list.dIP, "----------");
        strcpy(list.sPort, "--");
        strcpy(list.dPort, "--");
        break;
    }

    default:
    {
        analysised = true;
        strcpy(list.Protocol, "δ֪��̫��");
        strcpy(list.sIP, "----------");
        strcpy(list.dIP, "----------");
        strcpy(list.sPort, "--");
        strcpy(list.dPort, "--");
        break;
    }
    }

    if(analysised)
    {
        anadetial = analysis_detial(header, pkt_data);
        emit show_listdata(list, anadetial);
        analysised = false;
    }
}

QString Capture_thread::analysis_detial(const pcap_pkthdr* header,
                                        const u_char* pkt_data)
{
    QString anadetial;
    char tmp[128];

    struct ether_header *eth;
    unsigned int ptype;
    char mac_addr[19];
    u_char* mac_string;
    struct iphead *IPHead;
    struct arphead *ARPHead;

    sprintf(tmp, "<p>��̫��֡����:%d</p>", header->caplen);
    anadetial.append(QString(tmp));

    eth=(struct ether_header *)pkt_data;
    mac_string=eth->ether_shost;
    sprintf(mac_addr,"%02X:%02X:%02X:%02X:%02X:%02X",
            *mac_string,
            *(mac_string + 1),
            *(mac_string + 2),
            *(mac_string + 3),
            *(mac_string + 4),
            *(mac_string + 5));
    sprintf(tmp, "<p>ԴMAC��ַ:%s</p>", mac_addr);
    anadetial.append(QString(tmp));

    mac_string=eth->ether_dhost;
    sprintf(mac_addr, "%02X:%02X:%02X:%02X:%02X:%02X",
            *mac_string,
            *(mac_string + 1),
            *(mac_string + 2),
            *(mac_string + 3),
            *(mac_string + 4),
            *(mac_string + 5));
    sprintf(tmp, "<p>Ŀ��MAC��ַ:%s</p>", mac_addr);
    anadetial.append(QString(tmp));

    anadetial.append(QString("<p>��̫��֡����:</p>"));
    ptype = qFromBigEndian(eth->ether_type);
    switch(ptype)
    {
    case ETHERTYPE_ARP:
    {
        sprintf(tmp, "<p>ARP��</p>");
        anadetial.append(QString(tmp));

        sprintf(tmp, "<p>---------------------</p>");
        anadetial.append(QString(tmp));

        ARPHead = (arphead*)(pkt_data + 14);

        sprintf(tmp, "<p>Ӳ������:%d Byte</p>",
                qFromBigEndian(ARPHead->arp_hardware_type));
        anadetial.append(QString(tmp));

        sprintf(tmp, "<p>ARP��Э������:%d</p>",
                qFromBigEndian(ARPHead->arp_protocol_type));
        anadetial.append(QString(tmp));

        sprintf(tmp, "<p>Ӳ������:%d</p>",
                qFromBigEndian(ARPHead->arp_hardware_length));
        anadetial.append(QString(tmp));

        sprintf(tmp, "<p>Э�鳤��:%d</p>",
                qFromBigEndian(ARPHead->arp_protocol_length));
        anadetial.append(QString(tmp));

        sprintf(tmp, "<p>ARP������:%d (����1,�ش�2)</p>",
                qFromBigEndian(ARPHead->arp_operation_code));
        anadetial.append(QString(tmp));

        mac_string=ARPHead->arp_source_ethernet_address;
        sprintf(tmp, "<p>ARP�����ͷ�MAC:%02X:%02X:%02X:%02X:%02X:%02X</p>",
                *mac_string,
                *(mac_string + 1),
                *(mac_string + 2),
                *(mac_string + 3),
                *(mac_string + 4),
                *(mac_string + 5));
        anadetial.append(QString(tmp));

        sprintf(tmp, "<p>ARP�����ͷ�IP:%d.%d.%d.%d</p>",
                ARPHead->arp_source_ip_address[0],
                ARPHead->arp_source_ip_address[1],
                ARPHead->arp_source_ip_address[2],
                ARPHead->arp_source_ip_address[3]);
        anadetial.append(QString(tmp));

        mac_string=ARPHead->arp_destination_ethernet_address;
        sprintf(tmp, "<p>ARP�����շ�MAC:%02X:%02X:%02X:%02X:%02X:%02X</p>",
                *mac_string,
                *(mac_string + 1),
                *(mac_string + 2),
                *(mac_string + 3),
                *(mac_string + 4),
                *(mac_string + 5));
        anadetial.append(QString(tmp));

        sprintf(tmp, "<p>ARP�����շ�IP:%d.%d.%d.%d</p>",
                ARPHead->arp_destination_ip_address[0],
                ARPHead->arp_destination_ip_address[1],
                ARPHead->arp_destination_ip_address[2],
                ARPHead->arp_destination_ip_address[3]);
        anadetial.append(QString(tmp));

        break;
    }

    case ETHERTYPE_REVARP:
    {
        sprintf(tmp, "<p>RARP��</p>");
        anadetial.append(QString(tmp));

        break;
    }

    case ETHERTYPE_IP:
    {
        sprintf(tmp, "<p>IP��</p>");
        anadetial.append(QString(tmp));
        IPHead=(iphead *)(pkt_data+14);
        sprintf(tmp, "<p>---------------------</p>");
        anadetial.append(QString(tmp));

        sprintf(tmp, "<p>IPͷ��:%d BYTE</p>", (IPHead->ip_header_length) *4 );
        anadetial.append(QString(tmp));

        sprintf(tmp, "<p>IP�汾��:%d</p>", IPHead->ip_version);
        anadetial.append(QString(tmp));

        sprintf(tmp, "<p>IP��������:%d</p>", qFromBigEndian(IPHead->ip_tos));
        anadetial.append(QString(tmp));

        sprintf(tmp, "<p>IP���ܳ���:%d</p>", qFromBigEndian(IPHead->ip_length));
        anadetial.append(QString(tmp));

        sprintf(tmp, "<p>IP����ʶ:%d</p>", qFromBigEndian(IPHead->ip_id));
        anadetial.append(QString(tmp));

        sprintf(tmp, "<p>IP����Ƭ��־(DF):%d</p>", (qFromBigEndian(IPHead->ip_off) & 0X4000) >> 14);
        anadetial.append(QString(tmp));

        sprintf(tmp, "<p>IP����Ƭ��־(MF):%d</p>", (qFromBigEndian(IPHead->ip_off) & 0X2000) >> 13);
        anadetial.append(QString(tmp));

        sprintf(tmp, "<p>IP����Ƭƫ��:%d Byte</p>", 8 * (qFromBigEndian(IPHead->ip_off) & 0X1FFF));
        anadetial.append(QString(tmp));

        sprintf(tmp, "<p>IP������ʱ��:%d</p>", (IPHead->ip_ttl));
        anadetial.append(QString(tmp));

        sprintf(tmp, "<p>IP�������:%0X</p>", qFromBigEndian(IPHead->ip_checksum));
        anadetial.append(QString(tmp));

        sprintf(tmp, "<p>IP��ԴIP:%d.%d.%d.%d</p>",
                IPHead->ip_souce_address.S_un.S_un_b.s_b1,
                IPHead->ip_souce_address.S_un.S_un_b.s_b2,
                IPHead->ip_souce_address.S_un.S_un_b.s_b3,
                IPHead->ip_souce_address.S_un.S_un_b.s_b4);
        anadetial.append(QString(tmp));

        sprintf(tmp, "<p>IP��Ŀ��IP:%d.%d.%d.%d</p>",
                IPHead->ip_destination_address.S_un.S_un_b.s_b1,
                IPHead->ip_destination_address.S_un.S_un_b.s_b2,
                IPHead->ip_destination_address.S_un.S_un_b.s_b3,
                IPHead->ip_destination_address.S_un.S_un_b.s_b4);
        anadetial.append(QString(tmp));

        sprintf(tmp, "<p>IPЭ��:");
        anadetial.append(QString(tmp));

        switch(IPHead->ip_protocol)
        {
        case 1:
        {
            sprintf(tmp, "ICMP</p>");
            anadetial.append(QString(tmp));

            break;
        }

        case 6:
        {
            sprintf(tmp, "TCP</p>");
            anadetial.append(QString(tmp));

            break;
        }

        case 17:
        {
            sprintf(tmp, "UDP</p>");
            anadetial.append(QString(tmp));

            break;
        }

        default:
        {
            sprintf(tmp, "%d(δ֪)</p>", IPHead->ip_protocol);
            anadetial.append(QString(tmp));

            break;
        }
        }
        break;
    }

    case ETHERTYPE_PUP:
    {
        sprintf(tmp, "<p>PUP</p>");
        anadetial.append(QString(tmp));

        break;
    }

    default:
    {
        sprintf(tmp, "<p>δ֪</p>");
        anadetial.append(QString(tmp));

        break;
    }
    }

    return anadetial;
}

void Capture_thread::decodechar(char *data, DWORD len)
{
    DWORD i;
    for(i = 0; i < len; i++)
        if('\0' == data[i])
            data[i] = '.';
}

void Capture_thread::analysis_offline(const char *filename)
{
    pcap_t* fp;
    struct pcap_pkthdr* header;
    const u_char* data;
    struct ether_header* eth;
    u_char* mac_string;
    struct iphead* IPHead;
    struct arphead* ARPHead;
    time_t local_tv_sec;
    struct tm* ltime;
    char timestr[16];
    in_addr ipaddr;
    ListData list;
    QString anadetial;

    if((fp = pcap_open_offline(filename, errbuf)) == NULL)
    {
        return;
    }

    while(pcap_next_ex(fp, &header, &data) > 0)
    {
        local_tv_sec = header->ts.tv_sec;
        ltime = localtime(&local_tv_sec);
        strftime(timestr, sizeof(timestr), "%H:%M:%S", ltime);
        sprintf(list.time, "%s.%.3ld", timestr, header->ts.tv_usec);

        eth = (ether_header*)data;
        mac_string = eth->ether_shost;
        sprintf(list.sMac, "%02X:%02X:%02X:%02X:%02X:%02X",
                *mac_string,
                *(mac_string+1),
                *(mac_string+2),
                *(mac_string+3),
                *(mac_string+4),
                *(mac_string+5));
        mac_string = eth->ether_dhost;
        sprintf(list.dMac, "%02X:%02X:%02X:%02X:%02X:%02X",
                *mac_string,
                *(mac_string+1),
                *(mac_string+2),
                *(mac_string+3),
                *(mac_string+4),
                *(mac_string+5));
        itoa(header->caplen, list.Len, 10);
        memcpy(list.Text, data, 45);
        list.Text[45] = '\0';
        decodechar(list.Text,45);

        switch(qFromBigEndian(eth->ether_type))
        {
        case ETHERTYPE_ARP:
        {
            strcpy(list.Protocol, "ARP");
            ARPHead=(arphead*)(data+14);

            sprintf(list.sIP, "%d.%d.%d.%d",
                    ARPHead->arp_source_ip_address[0],
                    ARPHead->arp_source_ip_address[1],
                    ARPHead->arp_source_ip_address[2],
                    ARPHead->arp_source_ip_address[3]);
            sprintf(list.dIP, "%d.%d.%d.%d",
                    ARPHead->arp_destination_ip_address[0],
                    ARPHead->arp_destination_ip_address[1],
                    ARPHead->arp_destination_ip_address[2],
                    ARPHead->arp_destination_ip_address[3]);
            strcpy(list.sPort,"--");
            strcpy(list.dPort,"--");
            break;
        }

        case ETHERTYPE_REVARP:
        {
            strcpy(list.Protocol, "RARP");
            break;
        }

        case ETHERTYPE_IP:
        {
            IPHead = (iphead*)(data + 14);
            ipaddr = IPHead->ip_souce_address;
            sprintf(list.sIP, "%d.%d.%d.%d",
                    ipaddr.S_un.S_un_b.s_b1,
                    ipaddr.S_un.S_un_b.s_b2,
                    ipaddr.S_un.S_un_b.s_b3,
                    ipaddr.S_un.S_un_b.s_b4);
            ipaddr = IPHead->ip_destination_address;
            sprintf(list.dIP, "%d.%d.%d.%d",
                    ipaddr.S_un.S_un_b.s_b1,
                    ipaddr.S_un.S_un_b.s_b2,
                    ipaddr.S_un.S_un_b.s_b3,
                    ipaddr.S_un.S_un_b.s_b4);

            switch(IPHead->ip_protocol)
            {
            case 1:
            {
                strcpy(list.Protocol, "ICMP");
                strcpy(list.sPort, "--");
                strcpy(list.dPort, "--");
                break;
            }

            case 6:
            {
                strcpy(list.Protocol, "TCP");
                sprintf(list.sPort, "%d", qFromBigEndian(((tcphead*)(data + 16 + 20))->th_sport));
                sprintf(list.dPort, "%d", qFromBigEndian(((tcphead*)(data + 16 + 20))->th_dport));
                break;
            }

            case 17:
            {
                strcpy(list.Protocol, "UDP");
                sprintf(list.sPort, "%d", qFromBigEndian(((udphead*)(data + 16 + 20))->udp_source_port));
                sprintf(list.dPort, "%d", qFromBigEndian(((udphead*)(data + 16 + 20))->udp_destinanion_port));
                break;
            }

            default:
            {
                strcpy(list.Protocol, "δ֪IP��");
                strcpy(list.sIP, "----------");
                strcpy(list.dIP, "----------");
                strcpy(list.sPort, "--");
                strcpy(list.dPort, "--");
                break;
            }
            }
            break;
        }

        case ETHERTYPE_PUP:
        {
            strcpy(list.Protocol ,"PUP");
            strcpy(list.sIP, "----------");
            strcpy(list.dIP, "----------");
            strcpy(list.sPort, "--");
            strcpy(list.dPort, "--");
            break;
        }

        default:
        {
            strcpy(list.Protocol, "δ֪��̫��");
            strcpy(list.sIP, "----------");
            strcpy(list.dIP, "----------");
            strcpy(list.sPort, "--");
            strcpy(list.dPort, "--");
            break;
        }
        }
        anadetial = analysis_detial(header, data);
        emit show_listdata(list, anadetial);
    }
}
