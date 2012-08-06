#ifndef CAP_OPTDIALOG_H
#define CAP_OPTDIALOG_H

#include <QDialog>

#include "capture.h"
#include "filter_grammer.h"

class QLabel;
class QPushButton;
class QComboBox;
class QLineEdit;
class QSpinBox;

class Optdialog : public QDialog
{
    Q_OBJECT

public:
    Optdialog(QWidget* parent = 0);
    char* get_error()
    {
        return errbuf;
    }

signals:
    void set_para(const int i, //网卡号
                  const Filter f, //捕获过滤
                  const int c, //网卡模式
                  const int e //每个包的最大大小
                  );

private slots:
    void startbutton();
    void handle_grammererror();
    void handle_grammerok();

private:
    int createdialog();
    int get_combox_item(int i);

    Capture_thread capture;
    Filter_grammer* filter;
    char errbuf[256];

    QComboBox* combox1;
    QLineEdit* lineedit;
    QComboBox* combox2;
    QSpinBox* spinbox;
    QSpinBox* spinbox2;
    QPushButton* button1;
    QPushButton* button2;
};

#endif // CAP_OPTDIALOG_H
