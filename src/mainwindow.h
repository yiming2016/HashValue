#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include "2johnformats.h"

#include <QMap>
#include <QMainWindow>
#include <QProcess>
#include <QVector>

class QLabel;
class QTimer;
class QComboBox;
class QLineEdit;
class QPushButton;
class QTextEdit;
class QCheckBox;
class QFrame;
class QVBoxLayout;
class QTabWidget;
class QTableWidget;
class QProgressBar;

struct ParamRow
{
    ParamRow()
        : label(0), lineEdit(0), checkBox(0), browseButton(0),
          requiredMark(0), type(TEXT_PARAM)
    {
    }
    QLabel            *label;
    QLineEdit         *lineEdit;
    QCheckBox         *checkBox;
    QPushButton       *browseButton;
    QLabel            *requiredMark;
    ScriptParameterType type;
    QString             commandLinePrefix;
};

struct BatchItem
{
    int         id;
    QString     filePath;
    QString     category;
    QString     format;
    QString     hashcatMode;
    QString     hash;
    QString     outputSuffix;
    QString     outputDir;
    QString     outputPath;
    QString     status;
    QString     error;
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
    void openInputLocation();
    void openOutputLocation();
    void outputSuffixChanged(int index);
    void browseJtrDir();
    void categoryChanged(int index);
    void formatChanged(int index);
    void scanNewFormats();
    void convert();
    void conversionFinished(int exitCode, QProcess::ExitStatus status);
    void copyResult();
    void browseParamFile();
    void addBatchFiles();
    void removeSelectedBatchRows();
    void clearBatch();
    void startBatchConversion();
    void batchConversionFinished(int exitCode, QProcess::ExitStatus status);
    void batchSuffixChanged(int index);
    void browseBatchLocation();
    void batchCellClicked(int row, int column);
    void batchCellDoubleClicked(int row, int column);
    void showBatchRowMenu(const QPoint &pos);
    void sendCurrentToBatch();

private:
    void buildUi();
    void rebuildParameterRows();
    void guessFormatFromFile();
    void populateFormatCombo();
    bool addDiscoveredFormat(const QString &scriptBase);
    void setStatus(const QString &text, bool error = false);
    void updateHashcatLabel();
    QString currentSuffix() const;
    QString guessFormatForFile(const QString &file) const;
    bool buildConversionCommand(const QString &inputFile,
                                const QString &formatName, QString &program,
                                QStringList &args, QString &error);
    void addBatchItems(const QStringList &files);
    void refreshBatchTable();
    void updateBatchSuffixCombo();
    void updateBatchLocationLabel();
    void runNextBatchItem();
    void loadItemForDetailedSettings(int index);
    int batchItemIndexById(int id) const;
    void setBatchItemStatus(int id, const QString &status,
                            const QString &error = QString());
    void finishBatch();
    void showToast(const QString &text, bool success = true);

    QLineEdit       *m_inputFileEdit;
    QPushButton     *m_browseInputButton;
    QPushButton     *m_openInputLocationButton;
    QLabel          *m_fileLabel;
    QLabel          *m_fileRequiredMark;
    QComboBox       *m_formatCombo;
    QComboBox       *m_categoryCombo;
    QLabel          *m_hashcatLabel;
    QVBoxLayout     *m_paramsLayout;
    QWidget         *m_paramsCard;
    QLineEdit       *m_outputEdit;
    QComboBox       *m_outputSuffixCombo;
    QPushButton     *m_browseOutputButton;
    QPushButton     *m_openOutputLocationButton;
    QLabel          *m_outputPosLabel;
    QLabel          *m_outputRequiredMark;
    QPushButton     *m_sendButton;
    QPushButton     *m_scanButton;
    QPushButton     *m_convertButton;
    QTextEdit       *m_resultText;
    QPushButton     *m_copyButton;
    QLabel          *m_statusLabel;
    QLineEdit       *m_jtrDirEdit;
    QPushButton     *m_browseJtrButton;
    QTabWidget      *m_tabs;
    QTableWidget    *m_batchTable;
    QPushButton     *m_batchAddButton;
    QPushButton     *m_batchRemoveButton;
    QPushButton     *m_batchClearButton;
    QPushButton     *m_batchConvertButton;
    QComboBox       *m_batchSuffixCombo;
    QPushButton     *m_batchLocationButton;
    QProgressBar    *m_batchProgress;
    QLabel          *m_toast;
    QTimer          *m_toastTimer;

    QMap<QString, ConversionScript> m_scripts;
    QList<QPair<QString, QStringList> > m_categories;
    QList<ParamRow>                 m_paramRows;
    QStringList                     m_discoveredScripts;
    QProcess                        m_process;
    bool                            m_converting;
    QVector<BatchItem>              m_batchItems;
    QProcess                        m_batchProcess;
    bool                            m_batchRunning;
    bool                            m_batchRefreshing;
    int                             m_batchItemIdCounter;
    int                             m_batchCurrentId;
};

#endif // MAINWINDOW_H
