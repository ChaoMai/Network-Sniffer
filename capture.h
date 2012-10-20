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
    pcap_if_t* alldevs; //设备列表，包含了设备的详细信息

    void set_parameter(const int interface_num, //网卡号
                       const Filter filter, //捕获过滤
                       const int capture_mode, //网卡模式
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
    int interface_num; //网卡号
    Filter filter; //捕获过滤
    int capture_mode; //网卡模式
    int each_pkt_size; //每个包的最大大小
    int kernel_cache;
    char errbuf[PCAP_ERRBUF_SIZE]; //保存错误
    void analysis(const struct pcap_pkthdr* header,
                  const u_char* pkt_data,
                  const Filter filter);
    QString analysis_detial(const struct pcap_pkthdr* header,
                            const u_char* pkt_data);
    void decodechar(char* data, long long len);
};

#endif // CAPTURE_H
