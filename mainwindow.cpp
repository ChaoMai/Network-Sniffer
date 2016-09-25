#include <QtGui>
#include <QFile>

#define HAVE_REMOTE
#include "pcap.h"

#include "mainwindow.h"

MainWindow::MainWindow(QWidget* parent)
    : QMainWindow(parent)
{
    capture = NULL;
    is_table_changed = false;
    is_cap_para_setted = false;
    is_file_opened = false;
    createactions();
    createmenus();
    createcontexmnu();
    createtoolbars();
    createstatusbar();
    createshowarea();
    createdialogs();
}

MainWindow::~MainWindow()
{
}

void MainWindow::closeEvent(QCloseEvent* event)
{
    if(handle_tablechange())
    {
        event->accept();
    }
    else
    {
        event->ignore();
    }
}

void MainWindow::open()
{
    if(handle_tablechange())
    {
        if(is_table_changed)
        {
            remove_listitems();
        }

        QString filename = QFileDialog::getOpenFileName(this,
                                                        tr("open"), ".",
                                                        tr("pcap file (*.pcap)"));
        if(!filename.isEmpty())
        {
            is_file_opened = true;
            createcapthread();
            capture->analysis_offline(filename.toUtf8().constData());
            delete capture;
            capture = NULL;
        }
    }
}

bool MainWindow::save()
{
    QString filename = QFileDialog::getSaveFileName(this,
                                                    tr("save"), ".",
                                                    tr("pcap file (*.pcap)"));
    if(filename.isEmpty())
    {
        return false;
    }
    bool status;
    status = savefile(filename);
    return status;
}

void MainWindow::open_recent()
{
}

void MainWindow::close_file()
{
    if(is_file_opened)
    {
        if(handle_tablechange())
        {
            is_file_opened = false;
            remove_listitems();
        }
    }
    else
    {
        QMessageBox::warning(this,
                             tr("warning"),
                             tr("cannot open file"));
    }
}

void MainWindow::start_capture()
{
    if(handle_tablechange())
    {
        if(is_file_opened)
        {
            remove_listitems();
            createcapthread();
            opt_dialog->exec();
        }
        else if(NULL == capture && is_cap_para_setted)
        {
            remove_listitems();
            createcapthread();
            opt_dialog->exec();
        }
        else if(!is_cap_para_setted)
        {
            createcapthread();
            opt_dialog->exec();
        }
        else if(capture->isRunning())
        {
            QMessageBox::warning(this,
                                 tr("warning"),
                                 tr("please stop capturing first"));
        }
    }
}

void MainWindow::restart_capture()
{
    if(handle_tablechange())
    {
        if(NULL != capture)
        {
            capture->terminate();
            capture->wait();
            delete capture;
            capture = NULL;
            remove_listitems();
            createcapthread();
            capture->start();
        }
        else if(NULL == capture && is_cap_para_setted)
        {
            QMessageBox::warning(this,
                                 tr("warning"),
                                 tr("restart capture is valid only in capture mode"));
        }
        else
        {
            QMessageBox::warning(this,
                                 tr("warning"),
                                 tr("capture parameter isn't set"));
        }
    }
}

void MainWindow::stop_capture()
{
    if(NULL == capture)
    {
        QMessageBox::warning(this,
                             tr("warning"),
                             tr("capturing didn't start yet"));
    }
    else
    {
        capture->terminate();
        capture->wait();
        delete capture;
        capture = NULL;
    }
}

void MainWindow::capture_option()
{
    opt_dialog->exec();
}

void MainWindow::show_avalible()
{
    QMessageBox::about(this,
                       tr("the program can analysis following package type:"),
                       tr("<h2>network layer</h2>"
                          "<p>ARP</p>"
                          "<p>RARP</p>"
                          "<p>IP</p>"
                          "<h2>transport layer</h2>"
                          "<p>TCP</p>"
                          "<p>UDP</p>"
                          "<p>ICMP</p>"));
}

void MainWindow::show_manual()
{
}

void MainWindow::about()
{
    QMessageBox::about(this,
                       tr("About Network Sniffer"),
                       tr("<h2>Network Sniffer 1.0</h2>"
                          "<p>Copyright &copy; 2012</p>"
                          "<p>Networ Sniffer is a small application that "
                          "be able to capture and analysis"
                          "network packets.</p>"
                          "<p>Developed by</p>"
                          "<p>Maichao, Zhanglei,"
                          " Tiansongsong, Yangxuyin</p>"));
}

void MainWindow::update_show(const ListData data, QString anadetial)
{
    is_table_changed = true;
    ListData list_tmp(data);
    int current = table->rowCount();
    table->insertRow(current);
    table->setItem(current, 0, new QTableWidgetItem(QString(tr(list_tmp.time))));
    table->setItem(current, 1, new QTableWidgetItem(QString(tr(list_tmp.sIP))));
    table->setItem(current, 2, new QTableWidgetItem(QString(tr(list_tmp.sPort))));
    table->setItem(current, 3, new QTableWidgetItem(QString(tr(list_tmp.sMac))));
    table->setItem(current, 4, new QTableWidgetItem(QString(tr(list_tmp.dIP))));
    table->setItem(current, 5, new QTableWidgetItem(QString(tr(list_tmp.dPort))));
    table->setItem(current, 6, new QTableWidgetItem(QString(tr(list_tmp.dMac))));
    table->setItem(current, 7, new QTableWidgetItem(QString(tr(list_tmp.Protocol))));
    table->setItem(current, 8, new QTableWidgetItem(QString(tr(list_tmp.Len))));
    table->setItem(current, 9, new QTableWidgetItem(QString(tr(list_tmp.Text))));
    table->setItem(current, 10, new QTableWidgetItem(anadetial));
    char status[50];
    sprintf(status, "captured：%d", current + 1);
    statusBar()->showMessage(QString(status));
}

void MainWindow::set_cap_para(const int interface_num,
                              const Filter filter,
                              const int capture_mode,
                              const int each_pkt_size
                              )
{
    is_cap_para_setted = true;
    capture->set_parameter(interface_num,
                           filter,
                           capture_mode,
                           each_pkt_size
                           );
}

void MainWindow::start_thread()
{
    capture->start();
}

void MainWindow::show_listtext(int r, int c)
{
    textbrowser1->setText(table->item(r, 9)->text());
    textbrowser2->setText(table->item(r, 10)->text());
}

void MainWindow::createactions()
{
    open_action = new QAction(tr("open"), this);
    open_action->setShortcut(QKeySequence::New);
    open_action->setStatusTip(tr("open new pcap file"));
    connect(open_action, SIGNAL(triggered()), this, SLOT(open()));

    save_action = new QAction(tr("save"), this);
    save_action->setShortcut(QKeySequence::Open);
    save_action->setStatusTip(tr("save data to disk"));
    connect(save_action, SIGNAL(triggered()), this, SLOT(save()));

    for(int i = 0; i < max_recentfiles; ++i)
    {
        recentfiles_actions[i] = new QAction(this);
        recentfiles_actions[i]->setVisible(false);
        connect(recentfiles_actions[i], SIGNAL(triggered()),
                this, SLOT(open_recent()));
    }

    close_action = new QAction(tr("close"), this);
    close_action->setStatusTip(tr("close current file"));
    connect(close_action, SIGNAL(triggered()), this, SLOT(close_file()));

    exit_action = new QAction(tr("quit"), this);
    exit_action->setShortcut(tr("Ctrl+Q"));
    exit_action->setStatusTip(tr("quit program"));
    connect(exit_action, SIGNAL(triggered()), this, SLOT(close()));

    start_action = new QAction(tr("start"), this);
    start_action->setStatusTip(tr("start to capture package"));
    connect(start_action, SIGNAL(triggered()),
            this, SLOT(start_capture()));

    restart_action = new QAction(tr("restart"), this);
    restart_action->setStatusTip(tr("restart to capture package"));
    connect(restart_action, SIGNAL(triggered()),
            this, SLOT(restart_capture()));

    stop_action = new QAction(tr("stop"), this);
    stop_action->setStatusTip(tr("stop"));
    connect(stop_action, SIGNAL(triggered()),
            this, SLOT(stop_capture()));

    avalible_action = new QAction(tr("available packages"), this);
    avalible_action->setStatusTip(tr("show packages that program cannot analysis"));
    connect(avalible_action, SIGNAL(triggered()),
            this, SLOT(show_avalible()));

    manual_action = new QAction(tr("help"), this);
    manual_action->setStatusTip(tr("help"));
    connect(manual_action, SIGNAL(triggered()),
            this, SLOT(show_manual()));

    about_action = new QAction(tr("about"), this);
    about_action->setStatusTip(tr("about"));
    connect(about_action, SIGNAL(triggered()),
            this, SLOT(about()));

    aboutqt_action = new QAction(tr("about Qt"), this);
    aboutqt_action->setStatusTip(tr("about Qt"));
    connect(aboutqt_action, SIGNAL(triggered()),
            qApp, SLOT(aboutQt()));
}

void MainWindow::createmenus()
{
    file_menu = menuBar()->addMenu(tr("file"));
    file_menu->addAction(open_action);
    file_menu->addAction(save_action);
    file_menu->addAction(close_action);
    separatoraction = file_menu->addSeparator();
    for(int i = 0; i < max_recentfiles; ++i)
    {
        file_menu->addAction(recentfiles_actions[i]);
    }
    file_menu->addSeparator();
    file_menu->addAction(exit_action);

    capture_menu = menuBar()->addMenu(tr("capture"));
    capture_menu->addAction(start_action);
    capture_menu->addAction(restart_action);
    capture_menu->addAction(stop_action);

    analysis_menu = menuBar()->addMenu(tr("analysis"));
    analysis_menu->addAction(avalible_action);

    menuBar()->addSeparator();

    help_menu =  menuBar()->addMenu(tr("help"));
    help_menu->addAction(manual_action);
    help_menu->addAction(about_action);
    help_menu->addAction(aboutqt_action);
}

void MainWindow::createcontexmnu()
{
}

void MainWindow::createtoolbars()
{
    capture_toolbar = addToolBar(tr("Capture"));
    capture_toolbar->addAction(open_action);
    capture_toolbar->addAction(save_action);
    capture_toolbar->addAction(close_action);
    capture_toolbar->addSeparator();
    capture_toolbar->addAction(start_action);
    capture_toolbar->addAction(restart_action);
    capture_toolbar->addAction(stop_action);
}

void MainWindow::createstatusbar()
{
    status_label = new QLabel(" Status ");
    status_label->setAlignment(Qt::AlignHCenter);
    status_label->setMinimumSize(status_label->sizeHint());

    statusBar()->addWidget(status_label);
}

void MainWindow::createshowarea()
{
    resize(1000, 700);
    centralwidget = new QWidget(this);
    gridlayout = new QGridLayout(centralwidget);

    table = new QTableWidget(centralwidget);
    table->setColumnCount(11);
    table->setColumnHidden(9, true);
    table->setColumnHidden(10, true);
    QStringList headers;
    headers << tr("time") << tr("source IP") << tr("source Port") << tr("source MAC")
            << tr("target IP")  << tr("target Port")<< tr("target MAC") <<tr("protocol")
            << tr("length");
    table->setHorizontalHeaderLabels(headers);
    table->setSelectionBehavior(QAbstractItemView::SelectRows);
    table->setEditTriggers(QAbstractItemView::NoEditTriggers);
    table->setSelectionMode(QAbstractItemView::SingleSelection);
    table->horizontalHeader()->setResizeMode(QHeaderView::Stretch);
    gridlayout->addWidget(table, 0, 0);

    textbrowser1 = new QTextBrowser(centralwidget);
    textbrowser2 = new QTextBrowser(centralwidget);
    QHBoxLayout* hlay = new QHBoxLayout();
    hlay->addWidget(textbrowser1);
    hlay->addWidget(textbrowser2);
    gridlayout->addLayout(hlay, 1, 0);
    setCentralWidget(centralwidget);

    connect(table, SIGNAL(cellClicked(int,int)),
            this, SLOT(show_listtext(int,int)));
}

void MainWindow::createdialogs()
{
    opt_dialog = new Optdialog(this);
    connect(opt_dialog,
            SIGNAL(set_para(const int, const Filter, const int, const int)),
            this,
            SLOT(set_cap_para(const int, const Filter, const int, const int)));
    connect(opt_dialog,
            SIGNAL(set_para(const int, const Filter, const int, const int)),
            opt_dialog,
            SLOT(accept()));
}

void MainWindow::createcapthread()
{
    capture = new Capture_thread;
    connect(capture, SIGNAL(start_cap()),
            this, SLOT(start_thread()));
    connect(capture, SIGNAL(show_listdata(const ListData, QString)),
            this, SLOT(update_show(const ListData, QString)), Qt::QueuedConnection);

}

bool MainWindow::handle_tablechange()
{
    if(is_table_changed)
    {
        int r;
        r = QMessageBox::warning(this,
                                 tr("warning"),
                                 tr("captured data isn't saved yet，save?"),
                                 QMessageBox::Yes | QMessageBox::No | QMessageBox::Cancel);
        if(QMessageBox::Yes == r)
        {
            bool status;
            status = save();
            return status;
        }
        else if(QMessageBox::Cancel == r)
        {
            return false;
        }
    }
    return true;
}

bool MainWindow::savefile(QString filename)
{
    QFile file;
    bool status;
    status = file.rename(QString("/tmp.pcap"), filename);
    if(status)
    {
        statusBar()->showMessage(QString("successfully"), 2000);
        return true;
    }
    else
    {
        statusBar()->showMessage(QString("failed"), 2000);
        return false;
    }
}

void MainWindow::remove_listitems()
{
    is_table_changed = false;
    for(int i = table->rowCount(); i > 0; --i)
    {
        table->removeRow(i);
    }
    table->removeRow(0);
}
