#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QtGui/QMainWindow>
#include <QTableWidget>
#include <QGridLayout>
#include <QTextBrowser>
#include <QListWidget>

#include "capture.h"
#include "cap_optdialog.h"
#include "capthread_data.h"
#include "capthread_data.h"

class QAction;
class QLabel;

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    MainWindow(QWidget *parent = 0);
    ~MainWindow();

protected:
    void closeEvent(QCloseEvent * event);

private slots:
    void open();
    bool save();
    void open_recent();
    void close_file();
    void start_capture();
    void restart_capture();
    void stop_capture();
    void capture_option();
    void show_avalible();
    void show_manual();
    void about();
    void update_show(const ListData data, QString anadetial);
    void set_cap_para(const int interface_num,
                      const Filter filter,
                      const int capture_mode,
                      const int each_pkt_size
                      );
    void start_thread();
    void show_listtext(int r, int c);

private:
    void createactions();
    void createmenus();
    void createcontexmnu();
    void createtoolbars();
    void createstatusbar();
    void createshowarea();
    void createdialogs();
    void createcapthread();

    bool handle_tablechange();
    bool savefile(QString filename);
    void remove_listitems();

    Capture_thread* capture;

    bool is_table_changed;
    bool is_cap_para_setted;
    bool is_file_opened;

    Optdialog* opt_dialog;

    QLabel* status_label;

    enum
    {
        max_recentfiles = 5
    };
    QAction* recentfiles_actions[max_recentfiles];
    QAction* separatoraction;

    QWidget* centralwidget;
    QGridLayout* gridlayout;
    QTableWidget* table;
    QTextBrowser* textbrowser1;
    QTextBrowser* textbrowser2;

    QMenu* file_menu;
    QMenu* capture_menu;
    QMenu* analysis_menu;
    QMenu* help_menu;
    QToolBar* capture_toolbar;
    QAction* open_action;
    QAction* save_action;
    QAction* close_action;
    QAction* exit_action;
    QAction* start_action;
    QAction* restart_action;
    QAction* stop_action;
    QAction* avalible_action;
    QAction* manual_action;
    QAction* about_action;
    QAction* aboutqt_action;
};

#endif // MAINWINDOW_H
