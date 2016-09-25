#include <QtGui>

#define HAVE_REMOTE
#include "pcap.h"

#include "cap_optdialog.h"

Optdialog::Optdialog(QWidget* parent)
    : QDialog(parent)
{
    createdialog();
}

int Optdialog::get_combox_item(int i)
{
    switch(i)
    {
    case 0:
    {
        return 1;
    }
    case 1:
    {
        return 8;
    }
    case 2:
    {
        return 16;
    }
    }
    return 0;
}

int Optdialog::createdialog()
{
    if(-1 == capture.get_interface_item())
    {
        sprintf(errbuf, capture.get_error());
        return -1;
    }

    int i;
    i = capture.get_interface_amount();
    if(-1 == i)
    {
        sprintf(errbuf, capture.get_error());
        return -1;
    }

    QLabel* label1 = new QLabel(tr("device"));
    QLabel* label2 = new QLabel(tr("filter"));
    QLabel* label3 = new QLabel(tr("nic"));
    QLabel* label4 = new QLabel(tr("max size of each package"));

    QVBoxLayout* tmp1 = new QVBoxLayout;
    tmp1->addWidget(label1);
    tmp1->addWidget(label2);
    tmp1->addWidget(label3);
    tmp1->addWidget(label4);

    combox1 = new QComboBox();
    pcap_if_t* d;
    i = 0;
    for(d = capture.alldevs; d; d=d->next)
    {
        combox1->insertItems(i, QStringList(tr(d->description)));
        ++i;
    }
    lineedit = new QLineEdit();
    combox2 = new QComboBox();
    combox2->insertItems(0, QStringList()
                         << tr("PROMISCUOUS") //1
                         << tr("NOCAPTURE_LOCAL") //8
                         << tr("MAX_RESPONSIVENESS") //16
                         );
    spinbox = new QSpinBox();
    spinbox->setRange(1, 65535);
    spinbox->setSuffix((" bytes"));
    spinbox->setValue(65535);

    QVBoxLayout* tmp2 = new QVBoxLayout;
    tmp2->addWidget(combox1);
    tmp2->addWidget(lineedit);
    tmp2->addWidget(combox2);
    tmp2->addWidget(spinbox);

    QHBoxLayout* up = new QHBoxLayout;
    up->addLayout(tmp1);
    up->addLayout(tmp2);

    QSpacerItem* spacer = new QSpacerItem(40,
                                          20,
                                          QSizePolicy::Expanding,
                                          QSizePolicy::Minimum);
    button1 = new QPushButton(tr("start"));
    button2 = new QPushButton(tr("cancel"));

    QHBoxLayout* low = new QHBoxLayout;
    low->addItem(spacer);
    low->addWidget(button1);
    low->addWidget(button2);

    QVBoxLayout* mainlayout = new QVBoxLayout;
    mainlayout->addLayout(up);
    mainlayout->addLayout(low);
    setLayout(mainlayout);

    connect(button1, SIGNAL(clicked()),
            this, SLOT(startbutton()));
    connect(button2, SIGNAL(clicked()),
            this, SLOT(reject()));
    pcap_freealldevs(capture.alldevs);
    return 0;
}

void Optdialog::startbutton()
{
    filter = new Filter_grammer(this);
    connect(filter, SIGNAL(grammer_error()),
            this, SLOT(handle_grammererror()));
    connect(filter, SIGNAL(grammer_ok()),
            this, SLOT(handle_grammerok()));

    filter->convert(lineedit->text().toUtf8().constData());
}

void Optdialog::handle_grammererror()
{
    QMessageBox::warning(this,
                         "parameter error",
                         "parameter error, check help for more information",
                         QMessageBox::Ok);
    delete(filter);
}

void Optdialog::handle_grammerok()
{
    filter = new Filter_grammer();
    emit set_para(combox1->currentIndex(),
                  filter->convert(lineedit->text().toUtf8().constData()),
                  get_combox_item(combox2->currentIndex()),
                  spinbox->value()
                  );
    delete(filter);
}
