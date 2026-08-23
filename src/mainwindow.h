#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include "2johnformats.h"

#include <QMap>
#include <QMainWindow>
#include <QProcess>

class QLabel;
class QComboBox;
class QLineEdit;
class QPushButton;
class QTextEdit;
class QCheckBox;
class QFrame;
class QVBoxLayout;

struct ParamRow
{
    QLabel            *label;
    QLineEdit         *lineEdit;
    QCheckBox         *checkBox;
    QPushButton       *browseButton;
    QLabel            *requiredMark;
    ScriptParameterType type;
    QString             commandLinePrefix;
};

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    explicit MainWindow(QWidget *parent = 0);

protected:
    void dragEnterEvent(QDragEnterEvent *event);
    void dropEvent(QDropEvent *event);

private slots:
    void browseInputFile();
    void browseOutputFile();
    void browseJtrDir();
    void categoryChanged(int index);
    void formatChanged(int index);
    void scanNewFormats();
    void convert();
    void conversionFinished(int exitCode, QProcess::ExitStatus status);
    void copyResult();
    void browseParamFile();

private:
    void buildUi();
    void rebuildParameterRows();
    void guessFormatFromFile();
    void populateFormatCombo();
    bool addDiscoveredFormat(const QString &scriptBase);
    void setStatus(const QString &text, bool error = false);
    void updateHashcatLabel();

    QLabel          *m_fileLabel;
    QFrame          *m_dropArea;
    QLineEdit       *m_inputFileEdit;
    QPushButton     *m_browseInputButton;
    QComboBox       *m_formatCombo;
    QComboBox       *m_categoryCombo;
    QLabel          *m_hashcatLabel;
    QVBoxLayout     *m_paramsLayout;
    QWidget         *m_paramsCard;
    QLineEdit       *m_outputEdit;
    QPushButton     *m_browseOutputButton;
    QPushButton     *m_scanButton;
    QPushButton     *m_convertButton;
    QTextEdit       *m_resultText;
    QPushButton     *m_copyButton;
    QLabel          *m_statusLabel;
    QLineEdit       *m_jtrDirEdit;
    QPushButton     *m_browseJtrButton;

    QMap<QString, ConversionScript> m_scripts;
    QList<QPair<QString, QStringList> > m_categories;
    QList<ParamRow>                 m_paramRows;
    QStringList                     m_discoveredScripts;
    QProcess                        m_process;
    bool                            m_converting;
};

#endif // MAINWINDOW_H
