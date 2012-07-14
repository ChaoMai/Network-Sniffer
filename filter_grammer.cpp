#include "filter_grammer.h"
#include <stdio.h>

Filter_grammer::Filter_grammer(QObject *parent)
    : QObject(parent)
{
}

Filter Filter_grammer::convert(const char* filter)
{
    Filter f;
    f.activated = false;
    f.arp = false;
    f.rarp = false;
    f.ip = false;
    f.icmp = false;
    f.tcp = false;
    f.udp = false;
    f.s_port.activated = false;
    f.d_port.activated = false;
    f.s_port.port_num = -1;
    f.s_port.port_num = -1;

    protocols = get_pro((string)filter);
    if(0 != protocols.size())
    {
        f.activated = true;
    }
    for(vector<vector<string> >::size_type i = 0; i != protocols.size(); ++i)
    {
        for(vector<string>::size_type j = 0; j != protocols[i].size(); ++j)
        {
            if("arp" == protocols[i][j])
            {
                f.arp = true;
            }
            if("rarp" == protocols[i][j])
            {
                f.rarp = true;
            }
            if("ip" == protocols[i][j])
            {
                f.ip = true;
            }
            if("icmp" == protocols[i][j])
            {
                f.icmp = true;
            }
            if("tcp" == protocols[i][j])
            {
                f.tcp = true;
            }
            if("udp" == protocols[i][j])
            {
                f.udp = true;
            }
            if("s:" == protocols[i][j])
            {
                f.s_port.activated = true;
                sscanf(protocols[i][j + 1].c_str(), "%d", &f.s_port.port_num);
            }
            if("d:" == protocols[i][j])
            {
                f.d_port.activated = true;
                sscanf(protocols[i][j + 1].c_str(), "%d", &f.d_port.port_num);
            }
        }
    }
    return f;
}

vector<vector<string> > Filter_grammer::get_pro(const string filter)
{
    vector<vector<string> > protos;
    string tmp;
    stringstream f(filter);
    while(f >> tmp)
    {
        if("and" == tmp)
        {
            continue;
        }
        else if(";" != tmp)
        {
            int priority;
            if(-1 == (priority = get_priority(tmp)))
            {
                emit grammer_error();
                return vector<vector<string> >(1);
            }

            if((vector<vector<string> >::size_type)priority == protos.size())
            {
                protos.push_back(vector<string>(1, tmp));
            }
            else if((vector<vector<string> >::size_type)priority > protos.size())
            {
                for(vector<vector<string> >::size_type i = 0;
                    i <= (vector<vector<string> >::size_type)priority;
                    ++i)
                {
                    protos.push_back(vector<string>(1));
                }
                protos[priority].push_back(tmp);
            }
            else
            {
                protos[priority].push_back(tmp);
            }
        }
        else if(";" == tmp)
        {
            while(f >> tmp)
            {
                if("s:" == tmp)
                {
                    protos.push_back(vector<string>(1, tmp));
                    f >> tmp;
                    protos[protos.size() - 1].push_back(tmp);
                    f >> tmp;
                }
                else if("d:" == tmp)
                {
                    protos.push_back(vector<string>(1, tmp));
                    f >> tmp;
                    protos[protos.size() - 1].push_back(tmp);
                    f >> tmp;
                }
                else
                {
                    emit grammer_error();
                    return vector<vector<string> >(1);
                }
            }
        }
        else
        {
            emit grammer_error();
            return vector<vector<string> >(1);
        }
    }
    emit grammer_ok();
    return protos;
}

int Filter_grammer::get_priority(const string p)
{
    if("arp" == p || "ARP" == p ||
            "rarp" == p || "RARP" == p ||
            "ip" == p || "IP" == p ||
            "pup" == p || "PUP" == p
            )
    {
        return 0;
    }
    else if("icmp" == p || "ICMP" == p ||
            "tcp" == p || "TCP" == p ||
            "udp" == p || "UDP" == p
            )
    {
        return 1;
    }
    else
    {
        return -1;
    }
}
