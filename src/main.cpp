#include "mainwindow.h"

#include <QApplication>
#include <QFile>
#include <QIcon>

int main(int argc, char *argv[])
{
    QApplication app(argc, argv);
    app.setStyle(QStringLiteral("Fusion"));
    app.setWindowIcon(QIcon(QStringLiteral(":/icons/logo.png")));

    QFile styleFile(QStringLiteral(":/style.qss"));
    if(styleFile.open(QIODevice::ReadOnly))
    {
        app.setStyleSheet(QString::fromUtf8(styleFile.readAll()));
    }

    MainWindow window;
    window.show();
    return app.exec();
}
