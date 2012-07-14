#include <QMetaType>

#include "capthread_data.h"

int i = qRegisterMetaType<ListData>("ListData");

int j = qRegisterMetaType<Filter>("Filter");
