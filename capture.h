#ifndef CAPTURE_H
#define CAPTURE_H

#include <QThread>

#define HAVE_REMOTE
#include "pcap.h"

#include "capthread_data.h"
#include "capthread_data.h"

class Capture_thread : public QThread
{
    Q_OBJECT

public:
    pcap_if_t* alldevs; //�豸�б��������豸����ϸ��Ϣ

    void set_parameter(const int interface_num, //������
                       const Filter filter, //�������
                       const int capture_mode, //����ģʽ
                       const int each_pkt_size
                       );
    void open_and_get();
    void analysis_offline(const char* filename);
    int get_interface_item(void);
    int get_interface_amount(void);
    char* get_error()
    {
        return errbuf;
    }

    Capture_thread();

signals:
    void show_listdata(const ListData listdata, QString anadetial);
    void start_cap();

protected:
    void run();

private:
    int interface_num; //������
    Filter filter; //�������
    int capture_mode; //����ģʽ
    int each_pkt_size; //ÿ����������С
    int kernel_cache;
    char errbuf[PCAP_ERRBUF_SIZE]; //�������
    void analysis(const struct pcap_pkthdr* header,
                  const u_char* pkt_data,
                  const Filter filter);
    QString analysis_detial(const struct pcap_pkthdr* header,
                            const u_char* pkt_data);
    void decodechar(char* data, DWORD len);
};

#endif // CAPTURE_H
