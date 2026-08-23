#include "mainwindow.h"
#include "hashcathelper.h"

#include <QApplication>
#include <QCheckBox>
#include <QClipboard>
#include <QComboBox>
#include <QDir>
#include <QDragEnterEvent>
#include <QDropEvent>
#include <QFile>
#include <QFileDialog>
#include <QFileInfo>
#include <QFrame>
#include <QHBoxLayout>
#include <QLabel>
#include <QLineEdit>
#include <QMessageBox>
#include <QMimeData>
#include <QPushButton>
#include <QRegExp>
#include <QSettings>
#include <QStandardPaths>
#include <QTextEdit>
#include <QUrl>
#include <QVBoxLayout>
#include <QtAlgorithms>

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent),
      m_converting(false)
{
    setWindowTitle(QStringLiteral("哈希提取工具"));
    resize(980, 760);

    QList<ConversionScript> scripts;
    declare2johnFormats(scripts);
    foreach(const ConversionScript &script, scripts)
    {
        QString name = script.name;
        name.replace(QRegExp("2john|.py|.pl"), "");
        m_scripts.insert(name, script);
    }

    buildUi();
    setAcceptDrops(true);

    // Restore settings
    QSettings settings(QCoreApplication::applicationDirPath() +
                           QStringLiteral("/HashValue.ini"),
                       QSettings::IniFormat);
    QString jtrDir = settings.value("jtrDir").toString();
    if(jtrDir.isEmpty())
    {
        // Try to auto-detect a run folder next to the app or in Downloads.
        QStringList candidates;
        candidates << QCoreApplication::applicationDirPath() + "/run"
                   << QCoreApplication::applicationDirPath() + "/JtR/run"
                   << QDir::homePath() + "/Downloads/john/run";
        foreach(const QString &candidate, candidates)
        {
            if(QFile::exists(candidate + "/john.exe") ||
               QFile::exists(candidate + "/john"))
            {
                jtrDir = candidate;
                break;
            }
        }
    }
    m_jtrDirEdit->setText(jtrDir);
}

void MainWindow::buildUi()
{
    QWidget *central = new QWidget(this);
    QVBoxLayout *root = new QVBoxLayout(central);
    root->setContentsMargins(20, 18, 20, 18);
    root->setSpacing(14);
    setCentralWidget(central);

    // Title
    QLabel *title = new QLabel(QStringLiteral("哈希提取工具"), central);
    title->setObjectName(QStringLiteral("titleLabel"));
    title->setStyleSheet(QStringLiteral(
        "font-size: 26px; font-weight: bold; color: #1f2430;"));
    QLabel *subtitle =
        new QLabel(QStringLiteral(
                       "把加密文件（zip/7z/rar/Office/PDF 等）转换成 hashcat "
                       "可直接使用的哈希文件"),
                   central);
    subtitle->setStyleSheet(QStringLiteral("color: #5a6478;"));
    root->addWidget(title);
    root->addWidget(subtitle);

    // Card 1: input file
    m_paramsCard = new QWidget(central);
    m_paramsCard->setObjectName(QStringLiteral("card"));
    QVBoxLayout *inputLayout = new QVBoxLayout(m_paramsCard);
    inputLayout->setContentsMargins(16, 14, 16, 14);
    inputLayout->setSpacing(10);

    QLabel *step1 = new QLabel(QStringLiteral("① 选择加密文件"), m_paramsCard);
    step1->setStyleSheet(QStringLiteral("font-weight: bold; color: #2b3245;"));
    inputLayout->addWidget(step1);

    m_dropArea = new QFrame(m_paramsCard);
    m_dropArea->setObjectName(QStringLiteral("dropArea"));
    m_dropArea->setMinimumHeight(72);
    QVBoxLayout *dropLayout = new QVBoxLayout(m_dropArea);
    m_fileLabel = new QLabel(
        QStringLiteral("将文件拖拽到这里，或点击下方按钮选择"),
        m_dropArea);
    m_fileLabel->setAlignment(Qt::AlignCenter);
    m_fileLabel->setStyleSheet(QStringLiteral("color: #7a8499;"));
    dropLayout->addWidget(m_fileLabel);
    inputLayout->addWidget(m_dropArea);

    QHBoxLayout *fileRow = new QHBoxLayout();
    m_inputFileEdit = new QLineEdit(m_paramsCard);
    m_inputFileEdit->setPlaceholderText(
        QStringLiteral("例如：C:\\加密文件\\123.zip"));
    m_browseInputButton = new QPushButton(QStringLiteral("浏览…"), m_paramsCard);
    fileRow->addWidget(m_inputFileEdit, 1);
    fileRow->addWidget(m_browseInputButton);
    inputLayout->addLayout(fileRow);
    root->addWidget(m_paramsCard);

    // Card 2: format + parameters
    QWidget *formatCard = new QWidget(central);
    formatCard->setObjectName(QStringLiteral("card"));
    QVBoxLayout *formatLayout = new QVBoxLayout(formatCard);
    formatLayout->setContentsMargins(16, 14, 16, 14);
    formatLayout->setSpacing(10);

    QLabel *step2 = new QLabel(QStringLiteral("② 文件格式与参数"), formatCard);
    step2->setStyleSheet(QStringLiteral("font-weight: bold; color: #2b3245;"));
    formatLayout->addWidget(step2);

    QHBoxLayout *formatRow = new QHBoxLayout();
    QLabel *formatLabel = new QLabel(QStringLiteral("文件格式："), formatCard);
    m_formatCombo = new QComboBox(formatCard);
    m_formatCombo->setMinimumWidth(220);
    QStringList names = m_scripts.keys();
    qSort(names);
    m_formatCombo->addItems(names);
    m_hashcatLabel = new QLabel(QStringLiteral("hashcat：—"), formatCard);
    m_hashcatLabel->setStyleSheet(
        QStringLiteral("color: #4a6cf7; font-weight: bold;"));
    formatRow->addWidget(formatLabel);
    formatRow->addWidget(m_formatCombo);
    formatRow->addWidget(m_hashcatLabel);
    formatRow->addStretch(1);
    formatLayout->addLayout(formatRow);

    m_paramsLayout = new QVBoxLayout();
    m_paramsLayout->setSpacing(8);
    formatLayout->addLayout(m_paramsLayout);
    root->addWidget(formatCard);

    // Card 3: output
    QWidget *outputCard = new QWidget(central);
    outputCard->setObjectName(QStringLiteral("card"));
    QVBoxLayout *outputLayout = new QVBoxLayout(outputCard);
    outputLayout->setContentsMargins(16, 14, 16, 14);
    outputLayout->setSpacing(10);
    QLabel *step3 =
        new QLabel(QStringLiteral("③ 输出哈希文件（hashcat 可直接使用）"),
                   outputCard);
    step3->setStyleSheet(QStringLiteral("font-weight: bold; color: #2b3245;"));
    outputLayout->addWidget(step3);
    QHBoxLayout *outputRow = new QHBoxLayout();
    m_outputEdit = new QLineEdit(outputCard);
    m_outputEdit->setPlaceholderText(
        QStringLiteral("输出 .txt 文件路径（默认与源文件同目录）"));
    m_browseOutputButton = new QPushButton(QStringLiteral("浏览…"), outputCard);
    outputRow->addWidget(m_outputEdit, 1);
    outputRow->addWidget(m_browseOutputButton);
    outputLayout->addLayout(outputRow);
    root->addWidget(outputCard);

    // Convert button
    m_convertButton = new QPushButton(QStringLiteral("提取哈希"), central);
    m_convertButton->setObjectName(QStringLiteral("primaryButton"));
    m_convertButton->setMinimumHeight(46);
    m_convertButton->setStyleSheet(QStringLiteral(
        "QPushButton { background: #4a6cf7; color: #ffffff; border: none; "
        "border-radius: 10px; font-size: 17px; font-weight: bold; }"
        "QPushButton:hover { background: #3f5fd8; }"
        "QPushButton:pressed { background: #3550c0; }"
        "QPushButton:disabled { background: #b9c2d6; }"));
    root->addWidget(m_convertButton);

    // Result card
    QWidget *resultCard = new QWidget(central);
    resultCard->setObjectName(QStringLiteral("card"));
    QVBoxLayout *resultLayout = new QVBoxLayout(resultCard);
    resultLayout->setContentsMargins(16, 14, 16, 14);
    resultLayout->setSpacing(10);
    QHBoxLayout *resultTitleRow = new QHBoxLayout();
    QLabel *resultTitle = new QLabel(QStringLiteral("提取结果"), resultCard);
    resultTitle->setStyleSheet(
        QStringLiteral("font-weight: bold; color: #2b3245;"));
    m_copyButton = new QPushButton(QStringLiteral("复制哈希"), resultCard);
    m_copyButton->setEnabled(false);
    resultTitleRow->addWidget(resultTitle);
    resultTitleRow->addStretch(1);
    resultTitleRow->addWidget(m_copyButton);
    resultLayout->addLayout(resultTitleRow);
    m_resultText = new QTextEdit(resultCard);
    m_resultText->setReadOnly(true);
    m_resultText->setMinimumHeight(120);
    m_resultText->setPlaceholderText(
        QStringLiteral("提取出的哈希会显示在这里…"));
    resultLayout->addWidget(m_resultText);
    root->addWidget(resultCard);

    // Status + JtR settings
    QHBoxLayout *bottomRow = new QHBoxLayout();
    m_statusLabel = new QLabel(QStringLiteral("就绪"), central);
    m_statusLabel->setStyleSheet(QStringLiteral("color: #5a6478;"));
    bottomRow->addWidget(m_statusLabel, 1);
    QLabel *jtrLabel = new QLabel(QStringLiteral("JtR 目录："), central);
    m_jtrDirEdit = new QLineEdit(central);
    m_jtrDirEdit->setPlaceholderText(
        QStringLiteral("john-packages 解压后的 run 目录（含 2john 脚本）"));
    m_jtrDirEdit->setMinimumWidth(360);
    m_browseJtrButton = new QPushButton(QStringLiteral("选择…"), central);
    bottomRow->addWidget(jtrLabel);
    bottomRow->addWidget(m_jtrDirEdit, 1);
    bottomRow->addWidget(m_browseJtrButton);
    root->addLayout(bottomRow);

    // Connections
    connect(m_browseInputButton, SIGNAL(clicked()), this,
            SLOT(browseInputFile()));
    connect(m_browseOutputButton, SIGNAL(clicked()), this,
            SLOT(browseOutputFile()));
    connect(m_browseJtrButton, SIGNAL(clicked()), this, SLOT(browseJtrDir()));
    connect(m_formatCombo, SIGNAL(currentIndexChanged(int)), this,
            SLOT(formatChanged(int)));
    connect(m_convertButton, SIGNAL(clicked()), this, SLOT(convert()));
    connect(m_copyButton, SIGNAL(clicked()), this, SLOT(copyResult()));
    connect(&m_process, SIGNAL(finished(int, QProcess::ExitStatus)), this,
            SLOT(conversionFinished(int, QProcess::ExitStatus)));

    m_formatCombo->setCurrentIndex(0);
    formatChanged(0);
}

void MainWindow::rebuildParameterRows()
{
    // Clear old rows
    m_paramRows.clear();
    while(QLayoutItem *item = m_paramsLayout->takeAt(0))
    {
        if(QWidget *w = item->widget())
            delete w;
        delete item;
    }

    QString scriptName = m_formatCombo->currentText();
    if(!m_scripts.contains(scriptName))
        return;
    const ConversionScript &script = m_scripts[scriptName];

    foreach(const ConversionScriptParameter &param, script.parameters)
    {
        QWidget *row = new QWidget(m_paramsCard);
        QHBoxLayout *lay = new QHBoxLayout(row);
        lay->setContentsMargins(0, 0, 0, 0);
        lay->setSpacing(8);

        ParamRow pr;
        pr.type = param.type;
        pr.commandLinePrefix = param.commandLinePrefix;

        pr.requiredMark = new QLabel(QStringLiteral("*"), row);
        bool required =
            (param.type != CHECKABLE_PARAM) &&
            param.commandLinePrefix.isEmpty() &&
            !param.name.contains(QStringLiteral("（可选）")) &&
            !param.name.contains(QStringLiteral("(Optional)"));
        pr.requiredMark->setStyleSheet(
            QStringLiteral("color: #e53935; font-weight: bold;"));
        pr.requiredMark->setVisible(required);
        lay->addWidget(pr.requiredMark);

        pr.label = new QLabel(param.name, row);
        pr.label->setMinimumWidth(220);
        lay->addWidget(pr.label);

        if(param.type == CHECKABLE_PARAM)
        {
            pr.checkBox = new QCheckBox(row);
            lay->addWidget(pr.checkBox);
            lay->addStretch(1);
        }
        else
        {
            pr.lineEdit = new QLineEdit(row);
            pr.lineEdit->setMinimumWidth(280);
            lay->addWidget(pr.lineEdit, 1);
        }

        if(param.type == FILE_PARAM || param.type == FOLDER_PARAM)
        {
            pr.browseButton = new QPushButton(QStringLiteral("浏览…"), row);
            pr.browseButton->setProperty("rowIndex", m_paramRows.size());
            connect(pr.browseButton, SIGNAL(clicked()), this,
                    SLOT(browseParamFile()));
            lay->addWidget(pr.browseButton);
        }

        m_paramsLayout->addWidget(row);
        m_paramRows.append(pr);
    }
}

void MainWindow::formatChanged(int)
{
    rebuildParameterRows();
    updateHashcatLabel();
}

void MainWindow::updateHashcatLabel()
{
    QString name = m_formatCombo->currentText();
    m_hashcatLabel->setText(QStringLiteral("hashcat：") +
                            hashcatModeFor2johnScript(name));
}

void MainWindow::guessFormatFromFile()
{
    QString file = m_inputFileEdit->text();
    QString ext = QFileInfo(file).suffix().toLower();
    QString guess;
    if(ext == "zip")
        guess = "zip";
    else if(ext == "7z")
        guess = "7z";
    else if(ext == "rar")
        guess = "rar";
    else if(ext == "pdf")
        guess = "pdf";
    else if(ext == "docx" || ext == "xlsx" || ext == "pptx" || ext == "doc" ||
            ext == "xls" || ext == "ppt")
        guess = "office";
    else if(ext == "kdbx" || ext == "kdb")
        guess = "keepass";
    else if(ext == "odt" || ext == "ods" || ext == "odp" || ext == "sxc" ||
            ext == "sxw")
        guess = "odf";
    else if(ext == "pfx" || ext == "p12")
        guess = "pfx";
    else if(ext == "dmg")
        guess = "dmg";
    else if(ext == "gpg" || ext == "asc")
        guess = "gpg";
    else if(ext == "jks" || ext == "keystore")
        guess = "keystore";
    else if(ext == "psafe3")
        guess = "pwsafe";
    else if(ext == "pcap")
        guess = "vncpcap";
    else if(ext == "ppk")
        guess = "putty";
    else if(ext == "kwl")
        guess = "kwallet";

    if(!guess.isEmpty())
    {
        int index = m_formatCombo->findText(guess);
        if(index >= 0)
            m_formatCombo->setCurrentIndex(index);
    }

    // Suggest an output file next to the source.
    if(!file.isEmpty() && m_outputEdit->text().isEmpty())
    {
        QFileInfo info(file);
        m_outputEdit->setText(info.absolutePath() + "/" +
                              info.completeBaseName() + ".txt");
    }
}

void MainWindow::dragEnterEvent(QDragEnterEvent *event)
{
    if(event->mimeData()->hasUrls())
        event->acceptProposedAction();
}

void MainWindow::dropEvent(QDropEvent *event)
{
    QList<QUrl> urls = event->mimeData()->urls();
    if(urls.isEmpty())
        return;
    QString file = urls.first().toLocalFile();
    if(!file.isEmpty())
    {
        m_inputFileEdit->setText(file);
        m_fileLabel->setText(QFileInfo(file).fileName());
        guessFormatFromFile();
        setStatus(QStringLiteral("已选择文件：%1").arg(file));
    }
}

void MainWindow::browseInputFile()
{
    QString file = QFileDialog::getOpenFileName(
        this, QStringLiteral("选择加密文件"),
        QFileInfo(m_inputFileEdit->text()).absolutePath());
    if(file.isEmpty())
        return;
    m_inputFileEdit->setText(file);
    m_fileLabel->setText(QFileInfo(file).fileName());
    guessFormatFromFile();
    setStatus(QStringLiteral("已选择文件：%1").arg(file));
}

void MainWindow::browseOutputFile()
{
    QString file = QFileDialog::getSaveFileName(
        this, QStringLiteral("保存哈希文件"),
        m_outputEdit->text(), QStringLiteral("文本文件 (*.txt)"));
    if(!file.isEmpty())
        m_outputEdit->setText(file);
}

void MainWindow::browseJtrDir()
{
    QString dir = QFileDialog::getExistingDirectory(
        this, QStringLiteral("选择 JtR 的 run 目录"),
        m_jtrDirEdit->text());
    if(dir.isEmpty())
        return;
    // If the user picked a root that contains a run folder, use it.
    if(QFile::exists(dir + "/run/john.exe") || QFile::exists(dir + "/run/john"))
        dir += "/run";
    m_jtrDirEdit->setText(dir);
    QSettings settings(QCoreApplication::applicationDirPath() +
                           QStringLiteral("/HashValue.ini"),
                       QSettings::IniFormat);
    settings.setValue("jtrDir", dir);
    setStatus(QStringLiteral("JtR 目录已设置：%1").arg(dir));
}

void MainWindow::browseParamFile()
{
    QPushButton *button = qobject_cast<QPushButton *>(sender());
    if(!button)
        return;
    int index = button->property("rowIndex").toInt();
    if(index < 0 || index >= m_paramRows.size())
        return;
    ParamRow &row = m_paramRows[index];
    QString file;
    if(row.type == FOLDER_PARAM)
    {
        file = QFileDialog::getExistingDirectory(
            this, QStringLiteral("选择文件夹"), row.lineEdit->text());
    }
    else
    {
        file = QFileDialog::getOpenFileName(
            this, QStringLiteral("选择文件"),
            QFileInfo(row.lineEdit->text()).absolutePath());
    }
    if(!file.isEmpty())
        row.lineEdit->setText(file);
}

void MainWindow::setStatus(const QString &text, bool error)
{
    m_statusLabel->setText(text);
    m_statusLabel->setStyleSheet(error ? QStringLiteral("color: #e53935;")
                                       : QStringLiteral("color: #5a6478;"));
}

void MainWindow::convert()
{
    if(m_converting)
        return;

    QString inputFile = m_inputFileEdit->text().trimmed();
    QString outputFile = m_outputEdit->text().trimmed();
    QString runDir = m_jtrDirEdit->text().trimmed();
    QString formatName = m_formatCombo->currentText();

    if(inputFile.isEmpty())
    {
        setStatus(QStringLiteral("请先选择要提取的加密文件"), true);
        return;
    }
    if(outputFile.isEmpty())
    {
        setStatus(QStringLiteral("请指定输出哈希文件路径"), true);
        return;
    }
    if(runDir.isEmpty())
    {
        setStatus(QStringLiteral("请先设置 JtR 目录（john-packages 的 run 目录）"),
                  true);
        return;
    }
    if(!m_scripts.contains(formatName))
    {
        setStatus(QStringLiteral("未知的文件格式"), true);
        return;
    }

    const ConversionScript &script = m_scripts[formatName];
    QString scriptFullName = script.name + script.extension;
    QString program;
    QStringList args;

    if(script.extension == ".py")
    {
        program = QStringLiteral("python");
        args << runDir + "/" + scriptFullName;
    }
    else if(script.extension == ".pl")
    {
        program = QStringLiteral("perl");
        args << runDir + "/" + scriptFullName;
    }
    else
    {
        program = runDir + "/" + scriptFullName;
#ifdef Q_OS_WIN
        if(script.extension.isEmpty())
            program += ".exe";
#endif
    }

    // Check the script exists (or that the interpreter is available).
    if(script.extension == ".py" || script.extension == ".pl")
    {
        if(!QFile::exists(runDir + "/" + scriptFullName))
        {
            setStatus(QStringLiteral("未找到脚本：%1").arg(scriptFullName), true);
            return;
        }
    }
    else if(!QFile::exists(program))
    {
        setStatus(QStringLiteral("未找到转换程序：%1").arg(program), true);
        return;
    }

    // Auto-fill the first empty FILE/FOLDER parameter with the input file.
    bool filled = false;
    for(int i = 0; i < m_paramRows.size(); i++)
    {
        if(i >= script.parameters.size())
            break;
        const ParamRow &row = m_paramRows[i];
        if((row.type == FILE_PARAM || row.type == FOLDER_PARAM) &&
           row.lineEdit->text().trimmed().isEmpty() && !filled)
        {
            m_paramRows[i].lineEdit->setText(inputFile);
            filled = true;
        }
    }

    // Collect parameters (in script order) and check required ones.
    QStringList missing;
    for(int i = 0; i < m_paramRows.size(); i++)
    {
        const ParamRow &row = m_paramRows[i];
        if(i >= script.parameters.size())
            break;
        if(row.type == CHECKABLE_PARAM)
        {
            if(row.checkBox->isChecked())
                args << row.commandLinePrefix;
        }
        else
        {
            QString value = row.lineEdit->text().trimmed();
            if(!value.isEmpty())
            {
                if(!row.commandLinePrefix.isEmpty())
                    args << row.commandLinePrefix;
                args << value;
            }
            bool required =
                (row.type != CHECKABLE_PARAM) &&
                row.commandLinePrefix.isEmpty() &&
                !row.label->text().contains(QStringLiteral("（可选）")) &&
                !row.label->text().contains(QStringLiteral("(Optional)"));
            if(required && value.isEmpty())
                missing << row.label->text();
        }
    }

    if(!missing.isEmpty())
    {
        setStatus(QStringLiteral("请先填写必填项：%1").arg(missing.join("、")),
                  true);
        return;
    }

    // Persist the JtR dir.
    QSettings settings(QCoreApplication::applicationDirPath() +
                           QStringLiteral("/HashValue.ini"),
                       QSettings::IniFormat);
    settings.setValue("jtrDir", runDir);

    m_resultText->clear();
    m_convertButton->setEnabled(false);
    m_copyButton->setEnabled(false);
    m_converting = true;
    setStatus(QStringLiteral("正在提取哈希，请稍候…"));
    m_process.start(program, args);
}

void MainWindow::conversionFinished(int exitCode, QProcess::ExitStatus)
{
    m_converting = false;
    m_convertButton->setEnabled(true);

    QString out = QString::fromUtf8(m_process.readAllStandardOutput());
    QString err = QString::fromUtf8(m_process.readAllStandardError());

    if(exitCode != 0 || out.trimmed().isEmpty())
    {
        m_resultText->setPlainText(
            QStringLiteral("转换失败。脚本输出（原文）：\n%1").arg(
                err.isEmpty() ? out : err));
        setStatus(QStringLiteral("转换失败，请检查参数或 JtR 目录"), true);
        return;
    }

    // Strip the "filename:" prefix so hashcat can use the hash directly.
    QString inputFile = m_inputFileEdit->text().trimmed();
    QString prefix = QFileInfo(inputFile).fileName() + ":";
    QString cleaned;
    foreach(const QString &rawLine, out.split(QRegExp("\\r?\\n")))
    {
        QString line = rawLine;
        if(line.startsWith(prefix))
            line.remove(0, prefix.length());
        cleaned += line + "\n";
    }
    cleaned = cleaned.trimmed() + "\n";

    // Save to the output file.
    QFile file(m_outputEdit->text().trimmed());
    if(!file.open(QIODevice::WriteOnly | QIODevice::Text))
    {
        setStatus(QStringLiteral("无法写入输出文件"), true);
        return;
    }
    file.write(cleaned.toUtf8());
    file.close();

    m_resultText->setPlainText(cleaned);
    m_copyButton->setEnabled(true);
    setStatus(QStringLiteral(
        "转换成功！哈希已保存到 %1（hashcat 命令：hashcat -m %2 %1）")
                  .arg(m_outputEdit->text().trimmed())
                  .arg(hashcatModeFor2johnScript(m_formatCombo->currentText())));
}

void MainWindow::copyResult()
{
    QApplication::clipboard()->setText(m_resultText->toPlainText());
    setStatus(QStringLiteral("哈希已复制到剪贴板"));
}
