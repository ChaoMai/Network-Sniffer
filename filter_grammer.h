#ifndef FILTER_GRAMMER_H
#define FILTER_GRAMMER_H

#include <QObject>
#include <iostream>
#include <vector>
#include <string>
#include <sstream>

#include "capthread_data.h"

using namespace std;

class Filter_grammer : public QObject
{
    Q_OBJECT

public:
    Filter_grammer(QObject *parent = 0);
    Filter convert(const char* filter);

signals:
    void grammer_error();
    void grammer_ok();

private:
    vector<vector<string> > protocols;
    vector<vector<string> > get_pro(const string filter);
    int get_priority(const string p);
};

#endif // FILTER_GRAMMER_H
