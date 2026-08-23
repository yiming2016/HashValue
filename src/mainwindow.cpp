#include "mainwindow.h"
#include "hashcathelper.h"

#include <QAbstractItemView>
#include <QApplication>
#include <QBrush>
#include <QCheckBox>
#include <QClipboard>
#include <QColor>
#include <QComboBox>
#include <QDir>
#include <QDragEnterEvent>
#include <QDropEvent>
#include <QFile>
#include <QFileDialog>
#include <QFileInfo>
#include <QFrame>
#include <QHeaderView>
#include <QHBoxLayout>
#include <QLabel>
#include <QLineEdit>
#include <QMenu>
#include <QMessageBox>
#include <QMimeData>
#include <QProgressBar>
#include <QPushButton>
#include <QRegExp>
#include <QSettings>
#include <QShortcut>
#include <QStandardPaths>
#include <QTableWidget>
#include <QTabWidget>
#include <QTextEdit>
#include <QTextOption>
#include <QTimer>
#include <QUrl>
#include <QVBoxLayout>
#include <QtAlgorithms>
#include <QtEndian>

// Table item that sorts numerically by an explicit key (used for the
// "hashcat" and "状态" columns so "17200" sorts after "2100" numerically).
class BatchSortItem : public QTableWidgetItem
{
public:
    BatchSortItem(const QString &text, int sortKey = 0)
        : QTableWidgetItem(text), m_sortKey(sortKey)
    {
    }
    bool operator<(const QTableWidgetItem &other) const
    {
        const BatchSortItem *o = dynamic_cast<const BatchSortItem *>(&other);
        if(o)
            return m_sortKey < o->m_sortKey;
        return QTableWidgetItem::operator<(other);
    }

private:
    int m_sortKey;
};

// ---------------------------------------------------------------------------
// WPA / PMKID output conversion.
//
// wpapcap2john / hccap2john / hccapx2john print hashes in John's own
// "$WPAPSK$" / "ESSID:pmkid*..." formats, which hashcat mode 22000 does not
// fully accept.  We convert the EAPOL line into hashcat's "WPA*02*..." line
// and keep the PMKID segment (hashcat 22000 accepts the old PMKID format
// "pmkid*apmac*climac*essidhex" directly).
// ---------------------------------------------------------------------------

// Decode John's base64 variant (crypt() alphabet "./0-9A-Za-z") used by
// wpapcap2john/hccap2john for the hccap payload.
static QByteArray decodeJohnBase64(const QString &text)
{
    static const char alpha[] =
        "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    static int table[256];
    static bool tableReady = false;
    if(!tableReady)
    {
        for(int i = 0; i < 256; i++)
            table[i] = -1;
        for(int i = 0; i < 64; i++)
            table[(unsigned char)alpha[i]] = i;
        tableReady = true;
    }

    QByteArray out;
    out.reserve(text.size() * 3 / 4 + 4);
    int n = text.size();
    int i = 0;
    while(i + 3 < n)
    {
        int c1 = table[(unsigned char)text.at(i).toLatin1()];
        int c2 = table[(unsigned char)text.at(i + 1).toLatin1()];
        int c3 = table[(unsigned char)text.at(i + 2).toLatin1()];
        int c4 = table[(unsigned char)text.at(i + 3).toLatin1()];
        if(c1 < 0 || c2 < 0 || c3 < 0 || c4 < 0)
            return QByteArray();
        out.append((char)((c1 << 2) | (c2 >> 4)));
        out.append((char)(((c2 & 0x0f) << 4) | (c3 >> 2)));
        out.append((char)(((c3 & 0x03) << 6) | c4));
        i += 4;
    }
    if(i + 2 < n)
    {
        int c1 = table[(unsigned char)text.at(i).toLatin1()];
        int c2 = table[(unsigned char)text.at(i + 1).toLatin1()];
        int c3 = table[(unsigned char)text.at(i + 2).toLatin1()];
        if(c1 < 0 || c2 < 0 || c3 < 0)
            return QByteArray();
        out.append((char)((c1 << 2) | (c2 >> 4)));
        out.append((char)(((c2 & 0x0f) << 4) | (c3 >> 2)));
    }
    return out;
}

// Convert one raw line to a hashcat 22000 compatible line, or return an empty
// string when the line does not contain a usable hash.
static QString cleanWpaHashLine(const QString &rawLine)
{
    QString line = rawLine.trimmed();
    if(line.isEmpty())
        return QString();

    int dollar = line.indexOf(QStringLiteral("$WPAPSK$"));
    if(dollar >= 0)
    {
        // "ESSID:$WPAPSK$ESSID#<blob>:<mac2>:<mac1>:<mac1>::WPA..., verified:..."
        int hash = line.indexOf('#', dollar);
        int colon = line.indexOf(':', hash);
        if(hash < 0 || colon < 0)
            return QString();
        QString essid = line.mid(dollar + 8, hash - dollar - 8);
        QByteArray blob = decodeJohnBase64(
            line.mid(hash + 1, colon - hash - 1));
        // The blob is the hccap payload from offset 36:
        //   [0..5]   mac1 (AP)
        //   [6..11]  mac2 (STA)
        //   [12..43] nonce1 (snonce)
        //   [44..75] nonce2 (anonce)
        //   [76..331] eapol[256]
        //   [332..335] eapol_size (uint32 LE)
        //   [336..339] keyver (uint32 LE)
        //   [340..355] keymic[16]
        if(blob.size() != 356)
            return QString();

        quint32 eapolSize;
        memcpy(&eapolSize, blob.constData() + 332, 4);
#if Q_BYTE_ORDER == Q_BIG_ENDIAN
        eapolSize = qFromLittleEndian(eapolSize);
#endif
        if(eapolSize == 0 || eapolSize > 256)
            return QString();
        QByteArray eapol = blob.mid(76, (int)eapolSize);
        if(eapol.size() < 99) // minimum EAPOL auth packet size
            return QString();

        QString micHex = QString::fromLatin1(blob.mid(340, 16).toHex());
        QString macApHex = QString::fromLatin1(blob.mid(0, 6).toHex());
        QString macStaHex = QString::fromLatin1(blob.mid(6, 6).toHex());
        QString essidHex =
            QString::fromLatin1(essid.toUtf8().toHex());
        QString anonceHex = QString::fromLatin1(blob.mid(44, 32).toHex());
        QString eapolHex = QString::fromLatin1(eapol.toHex());
        // wpapcap2john reports "Dumping M3/M2", i.e. M2+M3 with EAPOL from
        // M2 (challenge) -> message pair 0x02.
        return QStringLiteral("WPA*02*%1*%2*%3*%4*%5*%6*02")
            .arg(micHex, macApHex, macStaHex, essidHex, anonceHex, eapolHex);
    }

    // PMKID line: "ESSID:pmkid*apmac*climac*essidhex:...:PMKID:..."
    int first = line.indexOf(':');
    int second = line.indexOf(':', first + 1);
    if(first >= 0 && second > first)
    {
        QString seg = line.mid(first + 1, second - first - 1);
        if(seg.contains('*'))
            return seg;
    }
    return QString();
}

// Clean raw tool output into hashcat-ready lines.  WPA tools get the special
// conversion above; other formats use the generic "$..."/pkzip cleaning.
static QString cleanConversionOutput(const QString &output,
                                     const QString &formatName)
{
    bool isWpa = (formatName == QStringLiteral("wpapcap") ||
                  formatName == QStringLiteral("hccap") ||
                  formatName == QStringLiteral("hccapx"));
    QString cleaned;
    foreach(const QString &rawLine, output.split(QRegExp("\\r?\\n")))
    {
        QString line = rawLine.trimmed();
        if(line.isEmpty())
            continue;
        if(isWpa)
        {
            line = cleanWpaHashLine(line);
            if(line.isEmpty())
                continue;
        }
        else
        {
            int dollar = line.indexOf('$');
            if(dollar >= 0)
            {
                line = line.mid(dollar);
                int endMarker = line.indexOf(QStringLiteral("$/pkzip$"));
                if(endMarker >= 0)
                    line = line.left(endMarker + 8);
            }
        }
        cleaned += line + "\n";
    }
    return cleaned.trimmed() + "\n";
}

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent),
      m_converting(false),
      m_batchRunning(false),
      m_batchRefreshing(false),
      m_batchItemIdCounter(1),
      m_batchCurrentId(-1)
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

    // Format categories: category -> format display names.
    m_categories << qMakePair(QStringLiteral("压缩包"),
                              QStringList() << "zip" << "7z" << "rar");
    m_categories << qMakePair(
        QStringLiteral("办公文档/PDF"),
        QStringList() << "office" << "pdf" << "odf" << "sxc" << "lotus");
    m_categories << qMakePair(
        QStringLiteral("密码管理器"),
        QStringList() << "keepass" << "1password" << "lastpass" << "pwsafe"
                      << "keychain" << "keyring" << "kwallet" << "mozilla");
    m_categories << qMakePair(
        QStringLiteral("磁盘/加密容器"),
        QStringList() << "luks" << "truecrypt" << "dmg" << "encfs"
                      << "ecryptfs" << "androidfde" << "openbsd_softraid");
    m_categories << qMakePair(QStringLiteral("加密货币钱包"),
                              QStringList() << "bitcoin" << "blockchain");
    m_categories << qMakePair(
        QStringLiteral("密钥/证书"),
        QStringList() << "ssh" << "sshng" << "putty" << "pfx" << "keystore"
                      << "gpg" << "openssl");
    m_categories << qMakePair(
        QStringLiteral("系统/网络/其他"),
        QStringList() << "unshadow" << "unafs" << "aix" << "cracf"
                      << "htdigest" << "krbpa" << "ikescan" << "sap" << "racf"
                      << "mcafee_epo" << "sipdump" << "kdcdump"
                      << "known_hosts" << "uaf" << "strip" << "lion"
                      << "ml2john" << "apex" << "hccap" << "hccapx"
                      << "wpapcap");

    buildUi();
    setAcceptDrops(true);

    // Standalone mode: prefer the bundled run folder next to the executable.
    QSettings settings(QCoreApplication::applicationDirPath() +
                           QStringLiteral("/HashValue.ini"),
                       QSettings::IniFormat);
    QString bundled = QCoreApplication::applicationDirPath() + "/run";
    QString jtrDir;
    if(QFile::exists(bundled + "/zip2john.exe") ||
       QFile::exists(bundled + "/zip2john") ||
       QFile::exists(bundled + "/john.exe") ||
       QFile::exists(bundled + "/john"))
    {
        jtrDir = bundled;
    }
    if(jtrDir.isEmpty())
        jtrDir = settings.value("jtrDir").toString();
    if(jtrDir.isEmpty())
    {
        // Fallback: try common locations.
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
    if(!jtrDir.isEmpty() &&
       QFileInfo(jtrDir).absoluteFilePath() ==
           QFileInfo(bundled).absoluteFilePath())
    {
        setStatus(QStringLiteral("独立运行模式正在使用内置 run 目录"));
    }

    // Restore previously discovered formats (persisted in the ini).
    QStringList discovered = settings.value("discoveredFormats").toStringList();
    foreach(const QString &base, discovered)
    {
        addDiscoveredFormat(base);
    }
    // Restore the output suffix choice.
    QString savedSuffix = settings.value("outputSuffix").toString();
    int suffixIndex = m_outputSuffixCombo->findText(savedSuffix);
    if(suffixIndex >= 0)
        m_outputSuffixCombo->setCurrentIndex(suffixIndex);
    int batchSuffixIndex = m_batchSuffixCombo->findText(savedSuffix);
    if(batchSuffixIndex >= 0)
        m_batchSuffixCombo->setCurrentIndex(batchSuffixIndex);
}

void MainWindow::buildUi()
{
    QWidget *central = new QWidget(this);
    QVBoxLayout *root = new QVBoxLayout(central);
    root->setContentsMargins(20, 18, 20, 18);
    root->setSpacing(14);
    setCentralWidget(central);

    m_tabs = new QTabWidget(central);

    // ======================= 单选模式 =======================
    QWidget *singleTab = new QWidget(m_tabs);
    QVBoxLayout *singleLayout = new QVBoxLayout(singleTab);
    singleLayout->setContentsMargins(0, 8, 0, 0);
    singleLayout->setSpacing(12);

    // Card 1: input file
    m_paramsCard = new QWidget(singleTab);
    m_paramsCard->setObjectName(QStringLiteral("card"));
    QVBoxLayout *inputLayout = new QVBoxLayout(m_paramsCard);
    inputLayout->setContentsMargins(16, 14, 16, 14);
    inputLayout->setSpacing(10);

    QHBoxLayout *fileRow = new QHBoxLayout();
    QLabel *filePosLabel = new QLabel(QStringLiteral("文件位置"), m_paramsCard);
    filePosLabel->setStyleSheet(
        QStringLiteral("font-weight: bold; color: #000000;"));
    m_inputFileEdit = new QLineEdit(m_paramsCard);
    m_inputFileEdit->setAcceptDrops(false);
    m_inputFileEdit->setPlaceholderText(
        QStringLiteral("例如 C:\\加密文件\\123.zip"));
    m_browseInputButton = new QPushButton(QStringLiteral("浏览…"), m_paramsCard);
    fileRow->addWidget(filePosLabel);
    fileRow->addWidget(m_inputFileEdit, 1);
    fileRow->addWidget(m_browseInputButton);
    inputLayout->addLayout(fileRow);
    singleLayout->addWidget(m_paramsCard);

    // Card 2: format + parameters
    QWidget *formatCard = new QWidget(singleTab);
    formatCard->setObjectName(QStringLiteral("card"));
    QVBoxLayout *formatLayout = new QVBoxLayout(formatCard);
    formatLayout->setContentsMargins(16, 14, 16, 14);
    formatLayout->setSpacing(10);

    QHBoxLayout *formatRow = new QHBoxLayout();
    QLabel *categoryLabel = new QLabel(QStringLiteral("类别"), formatCard);
    m_categoryCombo = new QComboBox(formatCard);
    m_categoryCombo->setMinimumWidth(150);
    QLabel *formatLabel = new QLabel(QStringLiteral("文件格式"), formatCard);
    m_formatCombo = new QComboBox(formatCard);
    m_formatCombo->setMinimumWidth(200);
    m_hashcatLabel = new QLabel(QStringLiteral("hashcat—"), formatCard);
    m_hashcatLabel->setStyleSheet(
        QStringLiteral("color: #4a6cf7; font-weight: bold;"));
    formatRow->addWidget(categoryLabel);
    formatRow->addWidget(m_categoryCombo);
    formatRow->addWidget(formatLabel);
    formatRow->addWidget(m_formatCombo);
    formatRow->addWidget(m_hashcatLabel);
    formatRow->addStretch(1);
    formatLayout->addLayout(formatRow);

    m_paramsLayout = new QVBoxLayout();
    m_paramsLayout->setSpacing(8);
    formatLayout->addLayout(m_paramsLayout);
    singleLayout->addWidget(formatCard);

    // Card 3: output
    QWidget *outputCard = new QWidget(singleTab);
    outputCard->setObjectName(QStringLiteral("card"));
    QVBoxLayout *outputLayout = new QVBoxLayout(outputCard);
    outputLayout->setContentsMargins(16, 14, 16, 14);
    outputLayout->setSpacing(10);
    QHBoxLayout *outputRow = new QHBoxLayout();
    QLabel *outputPosLabel = new QLabel(QStringLiteral("输出位置"), outputCard);
    outputPosLabel->setStyleSheet(
        QStringLiteral("font-weight: bold; color: #000000;"));
    m_outputEdit = new QLineEdit(outputCard);
    m_outputEdit->setPlaceholderText(
        QStringLiteral("输出哈希文件路径（默认与源文件同目录）"));
    m_outputSuffixCombo = new QComboBox(outputCard);
    m_outputSuffixCombo->addItem(QStringLiteral(".txt"));
    m_outputSuffixCombo->addItem(QStringLiteral(".lst"));
    m_outputSuffixCombo->addItem(QStringLiteral(".hash"));
    m_outputSuffixCombo->addItem(QStringLiteral("无后缀"));
    m_outputSuffixCombo->setToolTip(
        QStringLiteral("输出哈希文件的后缀（内容均为纯文本哈希）"));
    m_browseOutputButton = new QPushButton(QStringLiteral("浏览…"), outputCard);
    m_sendButton = new QPushButton(QStringLiteral("发送"), outputCard);
    m_sendButton->setToolTip(
        QStringLiteral("把当前单选设置发送到批量列表"));
    outputRow->addWidget(outputPosLabel);
    outputRow->addWidget(m_outputEdit, 1);
    outputRow->addWidget(m_outputSuffixCombo);
    outputRow->addWidget(m_browseOutputButton);
    outputRow->addWidget(m_sendButton);
    outputLayout->addLayout(outputRow);
    singleLayout->addWidget(outputCard);

    // Convert button
    m_convertButton = new QPushButton(QStringLiteral("提取哈希"), singleTab);
    m_convertButton->setObjectName(QStringLiteral("primaryButton"));
    m_convertButton->setMinimumHeight(46);
    m_convertButton->setStyleSheet(QStringLiteral(
        "QPushButton { background: #4a6cf7; color: #ffffff; border: none; "
        "border-radius: 10px; font-size: 17px; font-weight: bold; }"
        "QPushButton:hover { background: #3f5fd8; }"
        "QPushButton:pressed { background: #3550c0; }"
        "QPushButton:disabled { background: #b9c2d6; }"));
    singleLayout->addWidget(m_convertButton);

    // Result card
    QWidget *resultCard = new QWidget(singleTab);
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
    m_resultText->setWordWrapMode(QTextOption::WrapAnywhere);
    m_resultText->setPlaceholderText(
        QStringLiteral("提取出的哈希会显示在这里…"));
    resultLayout->addWidget(m_resultText);
    singleLayout->addWidget(resultCard);
    singleLayout->addStretch(1);
    m_tabs->addTab(singleTab, QStringLiteral("单选"));

    // ======================= 批量模式 =======================
    QWidget *batchTab = new QWidget(m_tabs);
    QVBoxLayout *batchLayout = new QVBoxLayout(batchTab);
    batchLayout->setContentsMargins(0, 8, 0, 0);
    batchLayout->setSpacing(12);

    QHBoxLayout *batchToolRow = new QHBoxLayout();
    m_batchAddButton = new QPushButton(QStringLiteral("添加文件…"), batchTab);
    m_batchRemoveButton =
        new QPushButton(QStringLiteral("移除选中"), batchTab);
    m_batchClearButton = new QPushButton(QStringLiteral("清空列表"), batchTab);
    batchToolRow->addWidget(m_batchAddButton);
    batchToolRow->addWidget(m_batchRemoveButton);
    batchToolRow->addWidget(m_batchClearButton);
    batchToolRow->addStretch(1);
    // “保存位置：xxxx”显示批量文件的统一输出目录，点击可修改全部。
    m_batchLocationButton =
        new QPushButton(QStringLiteral("保存位置："), batchTab);
    m_batchLocationButton->setStyleSheet(QStringLiteral(
        "QPushButton { border: none; background: transparent; "
        "color: #2b3245; font-weight: bold; text-align: left; }"
        "QPushButton:hover { color: #4a6cf7; }"));
    m_batchLocationButton->setMinimumWidth(220);
    m_batchLocationButton->setCursor(Qt::PointingHandCursor);
    m_batchLocationButton->setToolTip(
        QStringLiteral("点击保存位置可批量修改输出目录；各行位置不一致时显示空白"));
    // 分配伸缩权重：窗口变宽时按钮跟着变宽，显示更多路径。
    batchToolRow->addWidget(m_batchLocationButton, 1);
    QLabel *batchSuffixTip =
        new QLabel(QStringLiteral("全部后缀"), batchTab);
    m_batchSuffixCombo = new QComboBox(batchTab);
    m_batchSuffixCombo->addItem(QStringLiteral(".txt"));
    m_batchSuffixCombo->addItem(QStringLiteral(".lst"));
    m_batchSuffixCombo->addItem(QStringLiteral(".hash"));
    m_batchSuffixCombo->addItem(QStringLiteral("无后缀"));
    batchToolRow->addWidget(batchSuffixTip);
    batchToolRow->addWidget(m_batchSuffixCombo);
    batchLayout->addLayout(batchToolRow);

    m_batchTable = new QTableWidget(batchTab);
    m_batchTable->setColumnCount(7);
    m_batchTable->setHorizontalHeaderLabels(
        QStringList() << QStringLiteral("文件名") << QStringLiteral("输出后缀")
                      << QStringLiteral("类别") << QStringLiteral("hashcat")
                      << QStringLiteral("哈希值")
                      << QStringLiteral("状态")
                      << QStringLiteral("输出位置"));
    m_batchTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_batchTable->setSelectionMode(QAbstractItemView::ExtendedSelection);
    m_batchTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    m_batchTable->setAlternatingRowColors(true);
    m_batchTable->setMinimumHeight(320);
    m_batchTable->setSortingEnabled(true);
    m_batchTable->horizontalHeader()->setSectionResizeMode(
        0, QHeaderView::Interactive);
    m_batchTable->setColumnWidth(0, 180);
    m_batchTable->horizontalHeader()->setSectionResizeMode(
        1, QHeaderView::ResizeToContents);
    m_batchTable->horizontalHeader()->setSectionResizeMode(
        2, QHeaderView::ResizeToContents);
    m_batchTable->horizontalHeader()->setSectionResizeMode(
        3, QHeaderView::ResizeToContents);
    m_batchTable->horizontalHeader()->setSectionResizeMode(
        4, QHeaderView::ResizeToContents);
    m_batchTable->horizontalHeader()->setSectionResizeMode(
        5, QHeaderView::ResizeToContents);
    m_batchTable->horizontalHeader()->setSectionResizeMode(
        6, QHeaderView::Interactive);
    m_batchTable->setColumnWidth(6, 420);
    m_batchTable->setContextMenuPolicy(Qt::CustomContextMenu);
    batchLayout->addWidget(m_batchTable, 1);

    QHBoxLayout *batchBottomRow = new QHBoxLayout();
    m_batchProgress = new QProgressBar(batchTab);
    m_batchProgress->setRange(0, 1);
    m_batchProgress->setValue(0);
    m_batchProgress->setFormat(QStringLiteral("%v / %m"));
    batchBottomRow->addWidget(m_batchProgress, 1);
    m_batchConvertButton =
        new QPushButton(QStringLiteral("批量提取"), batchTab);
    m_batchConvertButton->setObjectName(QStringLiteral("primaryButton"));
    m_batchConvertButton->setMinimumHeight(42);
    m_batchConvertButton->setStyleSheet(QStringLiteral(
        "QPushButton { background: #4a6cf7; color: #ffffff; border: none; "
        "border-radius: 10px; font-size: 17px; font-weight: bold; }"
        "QPushButton:hover { background: #3f5fd8; }"
        "QPushButton:pressed { background: #3550c0; }"
        "QPushButton:disabled { background: #b9c2d6; }"));
    batchBottomRow->addWidget(m_batchConvertButton);
    batchLayout->addLayout(batchBottomRow);

    QLabel *batchHint = new QLabel(
        QStringLiteral("提示：可拖拽多个文件到窗口自动加入列表；"
                       "点击“哈希值”可复制完整哈希；"
                       "点击“输出位置”可修改保存目录；"
                       "右键行可删除、重试、查看完整哈希或打开输出位置"),
        batchTab);
    batchHint->setStyleSheet(
        QStringLiteral("color: #7a8499; font-weight: normal;"));
    batchHint->setWordWrap(true);
    batchLayout->addWidget(batchHint);

    m_tabs->addTab(batchTab, QStringLiteral("批量"));
    root->addWidget(m_tabs, 1);

    // Status + JtR settings
    QHBoxLayout *bottomRow = new QHBoxLayout();
    m_scanButton = new QPushButton(QStringLiteral("扫描新格式"), central);
    bottomRow->addWidget(m_scanButton);
    m_statusLabel = new QLabel(QStringLiteral("就绪"), central);
    m_statusLabel->setStyleSheet(QStringLiteral("color: #5a6478;"));
    // Long status text must not force the window to grow.
    m_statusLabel->setSizePolicy(QSizePolicy::Ignored, QSizePolicy::Preferred);
    bottomRow->addWidget(m_statusLabel, 1);
    QLabel *jtrLabel = new QLabel(QStringLiteral("JtR 目录"), central);
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
    connect(m_sendButton, SIGNAL(clicked()), this,
            SLOT(sendCurrentToBatch()));
    connect(m_outputSuffixCombo, SIGNAL(currentIndexChanged(int)), this,
            SLOT(outputSuffixChanged(int)));
    connect(m_browseJtrButton, SIGNAL(clicked()), this, SLOT(browseJtrDir()));
    connect(m_inputFileEdit, &QLineEdit::textChanged, this,
            &MainWindow::guessFormatFromFile);
    for(const auto &cat : m_categories)
    {
        m_categoryCombo->addItem(cat.first);
    }
    connect(m_categoryCombo, SIGNAL(currentIndexChanged(int)), this,
            SLOT(categoryChanged(int)));
    connect(m_formatCombo, SIGNAL(currentIndexChanged(int)), this,
            SLOT(formatChanged(int)));
    connect(m_scanButton, SIGNAL(clicked()), this, SLOT(scanNewFormats()));
    m_categoryCombo->setCurrentIndex(0);
    populateFormatCombo();
    connect(m_convertButton, SIGNAL(clicked()), this, SLOT(convert()));
    connect(m_copyButton, SIGNAL(clicked()), this, SLOT(copyResult()));
    connect(&m_process, SIGNAL(finished(int, QProcess::ExitStatus)), this,
            SLOT(conversionFinished(int, QProcess::ExitStatus)));
    connect(m_batchAddButton, SIGNAL(clicked()), this,
            SLOT(addBatchFiles()));
    connect(m_batchRemoveButton, SIGNAL(clicked()), this,
            SLOT(removeSelectedBatchRows()));
    connect(m_batchClearButton, SIGNAL(clicked()), this,
            SLOT(clearBatch()));
    connect(m_batchConvertButton, SIGNAL(clicked()), this,
            SLOT(startBatchConversion()));
    connect(m_batchSuffixCombo, SIGNAL(currentIndexChanged(int)), this,
            SLOT(batchSuffixChanged(int)));
    connect(m_batchLocationButton, SIGNAL(clicked()), this,
            SLOT(browseBatchLocation()));
    connect(m_batchTable, SIGNAL(cellClicked(int, int)), this,
            SLOT(batchCellClicked(int, int)));
    connect(m_batchTable, SIGNAL(cellDoubleClicked(int, int)), this,
            SLOT(batchCellDoubleClicked(int, int)));
    connect(m_batchTable, SIGNAL(customContextMenuRequested(QPoint)), this,
            SLOT(showBatchRowMenu(QPoint)));
    // Delete 键删除选中的批量行（仅当表格或其子控件获得焦点时生效）。
    QShortcut *delShortcut =
        new QShortcut(QKeySequence::Delete, m_batchTable);
    delShortcut->setContext(Qt::WidgetWithChildrenShortcut);
    connect(delShortcut, &QShortcut::activated, this,
            &MainWindow::removeSelectedBatchRows);
    connect(m_batchTable->horizontalHeader(),
            SIGNAL(sortIndicatorChanged(int, Qt::SortOrder)), this,
            SLOT(refreshBatchTable()));
    // 拖拽表头调整列宽时，“输出后缀”列里的下拉框要实时跟随列移动
    // （Qt 默认只在松开鼠标后才重排单元格控件位置）。
    connect(m_batchTable->horizontalHeader(),
            &QHeaderView::sectionResized, this,
            [this](int, int, int) {
                for(int r = 0; r < m_batchTable->rowCount(); r++)
                {
                    QWidget *w = m_batchTable->cellWidget(r, 1);
                    QTableWidgetItem *it = m_batchTable->item(r, 1);
                    if(w && it)
                    {
                        QRect cell = m_batchTable->visualItemRect(it);
                        if(!cell.isNull())
                            w->setGeometry(cell);
                    }
                }
            });
    connect(&m_batchProcess, SIGNAL(finished(int, QProcess::ExitStatus)),
            this,
            SLOT(batchConversionFinished(int, QProcess::ExitStatus)));

    m_formatCombo->setCurrentIndex(0);
    formatChanged(0);

    // Floating "toast" hint shown in the middle of the window (no dialog).
    m_toast = new QLabel(
        0, Qt::Tool | Qt::FramelessWindowHint | Qt::WindowStaysOnTopHint);
    m_toast->setAttribute(Qt::WA_ShowWithoutActivating);
    m_toast->setAlignment(Qt::AlignCenter);
    m_toast->setWordWrap(true);
    m_toast->hide();
    m_toastTimer = new QTimer(this);
    m_toastTimer->setSingleShot(true);
    connect(m_toastTimer, &QTimer::timeout, m_toast, &QLabel::hide);
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

    // The first required main-input FILE/FOLDER parameter duplicates the
    // top "选择加密文件" field, so hide it (it is still auto-filled).
    int mainInputIndex = -1;
    for(int i = 0; i < script.parameters.size(); i++)
    {
        const ConversionScriptParameter &p = script.parameters[i];
        bool required =
            (p.type != CHECKABLE_PARAM) && p.commandLinePrefix.isEmpty() &&
            !p.name.contains(QStringLiteral("（可选）")) &&
            !p.name.contains(QStringLiteral("(Optional)"));
        if(required && (p.type == FILE_PARAM || p.type == FOLDER_PARAM))
        {
            mainInputIndex = i;
            break;
        }
    }

    for(int i = 0; i < script.parameters.size(); i++)
    {
        const ConversionScriptParameter &param = script.parameters[i];
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
        if(i == mainInputIndex)
            row->hide();
        m_paramRows.append(pr);
    }
}

void MainWindow::categoryChanged(int)
{
    populateFormatCombo();
}

void MainWindow::populateFormatCombo()
{
    QString previous = m_formatCombo->currentText();
    m_formatCombo->blockSignals(true);
    m_formatCombo->clear();
    int cat = m_categoryCombo->currentIndex();
    if(cat >= 0 && cat < m_categories.size())
    {
        foreach(const QString &name, m_categories[cat].second)
        {
            if(m_scripts.contains(name))
                m_formatCombo->addItem(name);
        }
    }
    int idx = m_formatCombo->findText(previous);
    m_formatCombo->setCurrentIndex(idx >= 0 ? idx : 0);
    m_formatCombo->blockSignals(false);
    formatChanged(0);
}

void MainWindow::formatChanged(int)
{
    rebuildParameterRows();
    updateHashcatLabel();
}

void MainWindow::updateHashcatLabel()
{
    QString name = m_formatCombo->currentText();
    QString mode = hashcatModeFor2johnScript(name);
    if(mode == QStringLiteral("—"))
    {
        m_hashcatLabel->setText(
            QStringLiteral("hashcat 未知（请查 hashcat 手册）"));
    }
    else
    {
        m_hashcatLabel->setText(QStringLiteral("hashcat ") + mode);
    }
}

bool MainWindow::addDiscoveredFormat(const QString &scriptBase)
{
    if(scriptBase.isEmpty())
        return false;
    if(m_discoveredScripts.contains(scriptBase))
        return false;
    QString display = scriptBase;
    display.replace(QRegExp("2john|.py|.pl"), "");
    if(m_scripts.contains(display))
        return false;

    QString runDir = m_jtrDirEdit->text().trimmed();
    QString ext;
    if(QFile::exists(runDir + "/" + scriptBase + ".py"))
        ext = ".py";
    else if(QFile::exists(runDir + "/" + scriptBase + ".pl"))
        ext = ".pl";
    else if(QFile::exists(runDir + "/" + scriptBase + ".exe") ||
            QFile::exists(runDir + "/" + scriptBase))
        ext = "";
    else
        return false; // script not present in the run dir

    ConversionScript script(
        scriptBase, ext,
        QList<ConversionScriptParameter>()
            << ConversionScriptParameter("输入文件", FILE_PARAM)
            << ConversionScriptParameter("附加参数（可选，按脚本用法填写）",
                                         TEXT_PARAM));
    script.generic = true;
    m_scripts.insert(display, script);
    m_discoveredScripts.append(scriptBase);

    // Make sure the "新发现" category exists and contains this format.
    bool hasCategory = false;
    for(int i = 0; i < m_categories.size(); i++)
    {
        if(m_categories[i].first == QStringLiteral("新发现"))
            hasCategory = true;
    }
    if(!hasCategory)
        m_categories.append(
            qMakePair(QStringLiteral("新发现"), QStringList()));
    for(int i = 0; i < m_categories.size(); i++)
    {
        if(m_categories[i].first == QStringLiteral("新发现"))
            m_categories[i].second.append(display);
    }

    // Refresh the category combo (keep the current selection).
    QString currentCategory = m_categoryCombo->currentText();
    m_categoryCombo->blockSignals(true);
    m_categoryCombo->clear();
    for(const auto &cat : m_categories)
    {
        m_categoryCombo->addItem(cat.first);
    }
    int idx = m_categoryCombo->findText(currentCategory);
    m_categoryCombo->setCurrentIndex(idx >= 0 ? idx : 0);
    m_categoryCombo->blockSignals(false);
    populateFormatCombo();
    return true;
}

void MainWindow::scanNewFormats()
{
    QString runDir = m_jtrDirEdit->text().trimmed();
    if(runDir.isEmpty())
    {
        QMessageBox::information(this, QStringLiteral("扫描新格式"),
                                 QStringLiteral("请先设置 JtR 目录。"));
        return;
    }

    QDir dir(runDir);
    QStringList allFiles = dir.entryList(QDir::Files, QDir::Name);
    QSet<QString> knownScripts;
    foreach(const ConversionScript &script, m_scripts)
    {
        knownScripts << script.name;
    }

    QStringList newlyFound;
    foreach(const QString &file, allFiles)
    {
        if(!file.contains(QStringLiteral("2john"), Qt::CaseInsensitive))
            continue;
        QString base = QFileInfo(file).completeBaseName();
        if(base.isEmpty())
            continue;
        if(knownScripts.contains(base) ||
           m_discoveredScripts.contains(base))
            continue;
        if(addDiscoveredFormat(base))
            newlyFound << base;
    }

    QSettings settings(QCoreApplication::applicationDirPath() +
                           QStringLiteral("/HashValue.ini"),
                       QSettings::IniFormat);
    settings.setValue("discoveredFormats", m_discoveredScripts);

    if(newlyFound.isEmpty())
    {
        QMessageBox::information(
            this, QStringLiteral("扫描新格式"),
            QStringLiteral("没有发现新的 2john 脚本。"));
    }
    else
    {
        QMessageBox::information(
            this, QStringLiteral("扫描新格式"),
            QStringLiteral("发现 %1 个新格式\n%2")
                .arg(newlyFound.size())
                .arg(newlyFound.join(QStringLiteral("、"))));
    }
}

QString MainWindow::guessFormatForFile(const QString &file) const
{
    QString ext = QFileInfo(file).suffix().toLower();
    if(ext == "zip")
        return "zip";
    else if(ext == "7z")
        return "7z";
    else if(ext == "rar")
        return "rar";
    else if(ext == "pdf")
        return "pdf";
    else if(ext == "docx" || ext == "xlsx" || ext == "pptx" || ext == "doc" ||
            ext == "xls" || ext == "ppt")
        return "office";
    else if(ext == "kdbx" || ext == "kdb")
        return "keepass";
    else if(ext == "odt" || ext == "ods" || ext == "odp" || ext == "sxc" ||
            ext == "sxw")
        return "odf";
    else if(ext == "pfx" || ext == "p12")
        return "pfx";
    else if(ext == "dmg")
        return "dmg";
    else if(ext == "gpg" || ext == "asc")
        return "gpg";
    else if(ext == "jks" || ext == "keystore")
        return "keystore";
    else if(ext == "psafe3")
        return "pwsafe";
    else if(ext == "pcap" || ext == "cap" || ext == "pcapng" ||
            ext == "ivs2")
        return "wpapcap";
    else if(ext == "hccap")
        return "hccap";
    else if(ext == "hccapx")
        return "hccapx";
    else if(ext == "ppk")
        return "putty";
    else if(ext == "kwl")
        return "kwallet";
    return QString();
}

void MainWindow::guessFormatFromFile()
{
    QString file = m_inputFileEdit->text();
    QString guess = guessFormatForFile(file);

    if(!guess.isEmpty())
    {
        // Switch to the category that contains the guessed format.
        for(int c = 0; c < m_categories.size(); c++)
        {
            if(m_categories[c].second.contains(guess))
            {
                m_categoryCombo->setCurrentIndex(c);
                break;
            }
        }
        int index = m_formatCombo->findText(guess);
        if(index >= 0)
        {
            m_formatCombo->setCurrentIndex(index);
            setStatus(QStringLiteral("已识别格式 %1").arg(guess));
        }
    }

    // Suggest an output file next to the source.
    if(!file.isEmpty() && m_outputEdit->text().isEmpty())
    {
        QFileInfo info(file);
        m_outputEdit->setText(info.absolutePath() + "/" +
                              info.completeBaseName() + currentSuffix());
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
    QStringList files;
    foreach(const QUrl &url, urls)
    {
        QString file = url.toLocalFile();
        if(!file.isEmpty())
            files << file;
    }
    if(files.isEmpty())
        return;

    // Multiple files (or batch tab active) -> add to the batch list.
    if(files.size() > 1 || m_tabs->currentIndex() == 1)
    {
        addBatchItems(files);
        return;
    }

    m_inputFileEdit->setText(files.first());
    guessFormatFromFile();
    setStatus(QStringLiteral("已选择文件 %1").arg(files.first()));
}

void MainWindow::browseInputFile()
{
    QString file = QFileDialog::getOpenFileName(
        this, QStringLiteral("选择加密文件"),
        QFileInfo(m_inputFileEdit->text()).absolutePath());
    if(file.isEmpty())
        return;
    m_inputFileEdit->setText(file);
    guessFormatFromFile();
    setStatus(QStringLiteral("已选择文件 %1").arg(file));
}

void MainWindow::browseOutputFile()
{
    QString file = QFileDialog::getSaveFileName(
        this, QStringLiteral("保存哈希文件"),
        m_outputEdit->text(), QStringLiteral("文本文件 (*.txt)"));
    if(!file.isEmpty())
    {
        m_outputEdit->setText(file);
        outputSuffixChanged(0);
    }
}

QString MainWindow::currentSuffix() const
{
    if(!m_outputSuffixCombo)
        return QStringLiteral(".txt");
    QString text = m_outputSuffixCombo->currentText();
    if(text == QStringLiteral("无后缀"))
        return QString();
    return text;
}

void MainWindow::outputSuffixChanged(int)
{
    QString out = m_outputEdit->text().trimmed();
    if(!out.isEmpty())
    {
        QFileInfo info(out);
        QString dir = info.path();
        QString base = info.completeBaseName();
        QString newPath = (dir == QStringLiteral("."))
                              ? base
                              : dir + "/" + base;
        m_outputEdit->setText(newPath + currentSuffix());
    }
    QSettings settings(QCoreApplication::applicationDirPath() +
                           QStringLiteral("/HashValue.ini"),
                       QSettings::IniFormat);
    settings.setValue("outputSuffix", m_outputSuffixCombo->currentText());
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
    setStatus(QStringLiteral("JtR 目录已设置 %1").arg(dir));
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
    QString program;
    QStringList args;
    QString error;
    if(!buildConversionCommand(inputFile, formatName, program, args, error))
    {
        setStatus(error, true);
        return;
    }

    // Persist the JtR dir.
    QSettings settings(QCoreApplication::applicationDirPath() +
                           QStringLiteral("/HashValue.ini"),
                       QSettings::IniFormat);
    settings.setValue("jtrDir", m_jtrDirEdit->text().trimmed());

    m_resultText->clear();
    m_convertButton->setEnabled(false);
    m_copyButton->setEnabled(false);
    m_converting = true;
    setStatus(QStringLiteral("正在提取哈希，请稍候…"));
    m_process.start(program, args);
}

bool MainWindow::buildConversionCommand(const QString &inputFile,
                                        const QString &formatName,
                                        QString &program, QStringList &args,
                                        QString &error)
{
    QString runDir = m_jtrDirEdit->text().trimmed();
    if(runDir.isEmpty())
    {
        error = QStringLiteral(
            "请先设置 JtR 目录（john-packages 的 run 目录）");
        return false;
    }
    if(!m_scripts.contains(formatName))
    {
        error = QStringLiteral("未知的文件格式");
        return false;
    }

    const ConversionScript &script = m_scripts[formatName];
    QString scriptFullName = script.name + script.extension;

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

    if(script.extension == ".py" || script.extension == ".pl")
    {
        if(!QFile::exists(runDir + "/" + scriptFullName))
        {
            error = QStringLiteral("未找到脚本 %1").arg(scriptFullName);
            return false;
        }
    }
    else if(!QFile::exists(program))
    {
        error = QStringLiteral("未找到转换程序 %1").arg(program);
        return false;
    }

    // When the file's format matches the current single-mode selection, use
    // the values the user entered there; otherwise fall back to defaults
    // (only the input file is auto-filled).
    bool useUiParams = (formatName == m_formatCombo->currentText());

    // Find the UI value for a parameter name (line edit or check box).
    auto uiValue = [&](const QString &name, bool &isChecked) -> QString {
        for(int r = 0; r < m_paramRows.size(); r++)
        {
            const ParamRow &row = m_paramRows[r];
            if(row.label && row.label->text() == name)
            {
                if(row.checkBox)
                {
                    isChecked = row.checkBox->isChecked();
                    return QString();
                }
                if(row.lineEdit)
                    return row.lineEdit->text().trimmed();
            }
        }
        return QString();
    };

    bool filled = false;
    QStringList missing;
    for(int i = 0; i < script.parameters.size(); i++)
    {
        const ConversionScriptParameter &param = script.parameters[i];
        bool required =
            (param.type != CHECKABLE_PARAM) &&
            param.commandLinePrefix.isEmpty() &&
            !param.name.contains(QStringLiteral("（可选）")) &&
            !param.name.contains(QStringLiteral("(Optional)"));

        if(param.type == CHECKABLE_PARAM)
        {
            bool checked = false;
            if(useUiParams)
                uiValue(param.name, checked);
            if(checked)
                args << param.commandLinePrefix;
            continue;
        }

        QString value;
        bool isChecked = false;
        if((param.type == FILE_PARAM || param.type == FOLDER_PARAM) &&
           required && !filled)
        {
            value = inputFile;
            filled = true;
        }
        else if(useUiParams)
        {
            value = uiValue(param.name, isChecked);
        }

        if(!value.isEmpty())
        {
            if(!param.commandLinePrefix.isEmpty())
                args << param.commandLinePrefix;
            if(script.generic && param.type == TEXT_PARAM)
            {
                // Generic extra args: split on whitespace so options
                // like "-o out.txt" are passed as separate arguments.
                args << value.split(QRegExp("\\s+"), QString::SkipEmptyParts);
            }
            else
            {
                args << value;
            }
        }
        if(required && value.isEmpty())
            missing << param.name;
    }

    if(!missing.isEmpty())
    {
        error = QStringLiteral("请先填写必填项 %1").arg(missing.join("、"));
        return false;
    }
    return true;
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
            QStringLiteral("转换失败。脚本输出（原文）\n%1").arg(
                err.isEmpty() ? out : err));
        setStatus(QStringLiteral("转换失败，请检查参数或 JtR 目录"), true);
        return;
    }

    // Clean each line so hashcat can use the hash directly: drop any
    // "filename:..." prefix and trailing file-info text.  WPA formats are
    // converted into hashcat 22000 lines.
    QString cleaned =
        cleanConversionOutput(out, m_formatCombo->currentText());

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
        "转换成功！哈希已保存到 %1（hashcat 命令 hashcat -m %2 %1）")
                  .arg(m_outputEdit->text().trimmed())
                  .arg(hashcatModeFor2johnScript(m_formatCombo->currentText())));
}

void MainWindow::copyResult()
{
    QApplication::clipboard()->setText(m_resultText->toPlainText());
    setStatus(QStringLiteral("哈希已复制到剪贴板"));
}

void MainWindow::addBatchFiles()
{
    if(m_batchRunning)
        return;
    QStringList files = QFileDialog::getOpenFileNames(
        this, QStringLiteral("选择加密文件"));
    if(files.isEmpty())
        return;
    addBatchItems(files);
}

void MainWindow::addBatchItems(const QStringList &files)
{
    m_tabs->setCurrentIndex(1);
    foreach(const QString &file, files)
    {
        BatchItem item;
        item.id = m_batchItemIdCounter++;
        item.filePath = file;
        QString guess = guessFormatForFile(file);
        if(guess.isEmpty())
        {
            item.category = QStringLiteral("未知");
            item.format = QStringLiteral("未知");
            item.hashcatMode = QStringLiteral("—");
        }
        else
        {
            item.format = guess;
            item.category = QStringLiteral("未知");
            for(int c = 0; c < m_categories.size(); c++)
            {
                if(m_categories[c].second.contains(guess))
                {
                    item.category = m_categories[c].first;
                    break;
                }
            }
            item.hashcatMode = hashcatModeFor2johnScript(guess);
        }
        item.outputSuffix = m_outputSuffixCombo->currentText();
        // 默认输出到源文件所在目录。
        item.outputDir = QFileInfo(file).absolutePath();
        item.status = QStringLiteral("待处理");
        m_batchItems.append(item);
    }
    refreshBatchTable();
    setStatus(QStringLiteral("已添加 %1 个文件到批量列表").arg(files.size()));
}

void MainWindow::removeSelectedBatchRows()
{
    if(m_batchRunning)
        return;
    QList<int> ids;
    foreach(const QModelIndex &idx,
            m_batchTable->selectionModel()->selectedRows())
    {
        if(QTableWidgetItem *item = m_batchTable->item(idx.row(), 0))
            ids << item->data(Qt::UserRole).toInt();
    }
    if(ids.isEmpty())
    {
        setStatus(QStringLiteral("请先选中要移除的行"), true);
        return;
    }
    foreach(int id, ids)
    {
        int index = batchItemIndexById(id);
        if(index >= 0)
            m_batchItems.remove(index);
    }
    refreshBatchTable();
    setStatus(QStringLiteral("已移除 %1 行").arg(ids.size()));
}

void MainWindow::clearBatch()
{
    if(m_batchRunning)
        return;
    if(m_batchItems.isEmpty())
        return;
    m_batchItems.clear();
    m_batchProgress->setRange(0, 1);
    m_batchProgress->setValue(0);
    refreshBatchTable();
    setStatus(QStringLiteral("已清空批量列表"));
}

void MainWindow::refreshBatchTable()
{
    if(m_batchRefreshing)
        return;
    m_batchRefreshing = true;
    m_batchTable->setSortingEnabled(false);
    m_batchTable->setRowCount(0);
    m_batchTable->setRowCount(m_batchItems.size());

    for(int r = 0; r < m_batchItems.size(); r++)
    {
        const BatchItem &item = m_batchItems[r];
        QFileInfo info(item.filePath);

        QTableWidgetItem *nameItem =
            new QTableWidgetItem(info.fileName());
        nameItem->setData(Qt::UserRole, item.id);
        nameItem->setToolTip(item.filePath);
        m_batchTable->setItem(r, 0, nameItem);

        QString suffixShown = item.outputSuffix;
        QTableWidgetItem *suffixItem =
            new QTableWidgetItem(suffixShown);
        suffixItem->setData(Qt::UserRole, item.id);
        suffixItem->setTextAlignment(Qt::AlignCenter);
        m_batchTable->setItem(r, 1, suffixItem);

        QComboBox *suffixCombo = new QComboBox(m_batchTable);
        suffixCombo->addItem(QStringLiteral(".txt"));
        suffixCombo->addItem(QStringLiteral(".lst"));
        suffixCombo->addItem(QStringLiteral(".hash"));
        suffixCombo->addItem(QStringLiteral("无后缀"));
        int itemId = item.id;
        suffixCombo->setCurrentText(item.outputSuffix);
        connect(suffixCombo, &QComboBox::currentTextChanged, this,
                [this, itemId](const QString &text) {
                    int idx = batchItemIndexById(itemId);
                    if(idx >= 0)
                    {
                        m_batchItems[idx].outputSuffix = text;
                        // Keep the underlying item text in sync so sorting
                        // by the suffix column uses the new value.
                        for(int r = 0; r < m_batchTable->rowCount(); r++)
                        {
                            QTableWidgetItem *it =
                                m_batchTable->item(r, 1);
                            if(it &&
                               it->data(Qt::UserRole).toInt() == itemId)
                            {
                                it->setText(text);
                                break;
                            }
                        }
                        // 全局后缀不再统一时，右上方的“全部后缀”应显示空白。
                        updateBatchSuffixCombo();
                    }
                });
        m_batchTable->setCellWidget(r, 1, suffixCombo);

        QTableWidgetItem *catItem = new QTableWidgetItem(item.category);
        catItem->setData(Qt::UserRole, item.id);
        m_batchTable->setItem(r, 2, catItem);

        int hcKey = 999999;
        if(item.hashcatMode != QStringLiteral("—") &&
           !item.hashcatMode.isEmpty())
        {
            QString digits;
            foreach(QChar ch, item.hashcatMode)
            {
                if(ch.isDigit())
                    digits += ch;
                else
                    break;
            }
            if(!digits.isEmpty())
                hcKey = digits.toInt();
        }
        QTableWidgetItem *hcItem =
            new BatchSortItem(item.hashcatMode, hcKey);
        hcItem->setData(Qt::UserRole, item.id);
        hcItem->setTextAlignment(Qt::AlignCenter);
        m_batchTable->setItem(r, 3, hcItem);

        QString hashShown = item.hash;
        if(hashShown.size() > 30)
            hashShown = hashShown.left(30) + QStringLiteral("…");
        QTableWidgetItem *hashItem = new QTableWidgetItem(hashShown);
        hashItem->setData(Qt::UserRole, item.id);
        if(!item.hash.isEmpty())
        {
            hashItem->setToolTip(item.hash);
            hashItem->setForeground(QBrush(QColor("#4a6cf7")));
        }
        m_batchTable->setItem(r, 4, hashItem);

        int stKey = 0;
        QColor stColor(QStringLiteral("#2b3245"));
        if(item.status == QStringLiteral("待处理"))
            stKey = 0;
        else if(item.status == QStringLiteral("处理中"))
        {
            stKey = 1;
            stColor = QColor(QStringLiteral("#4a6cf7"));
        }
        else if(item.status == QStringLiteral("成功"))
        {
            stKey = 2;
            stColor = QColor(QStringLiteral("#2e7d32"));
        }
        else if(item.status == QStringLiteral("失败"))
        {
            stKey = 3;
            stColor = QColor(QStringLiteral("#e53935"));
        }
        QTableWidgetItem *stItem =
            new BatchSortItem(item.status, stKey);
        stItem->setData(Qt::UserRole, item.id);
        stItem->setForeground(QBrush(stColor));
        if(!item.error.isEmpty())
            stItem->setToolTip(item.error);
        m_batchTable->setItem(r, 5, stItem);

        QString dirShown =
            item.outputDir.isEmpty() ? info.absolutePath()
                                     : item.outputDir;
        QTableWidgetItem *dirItem = new QTableWidgetItem(dirShown);
        dirItem->setData(Qt::UserRole, item.id);
        dirItem->setToolTip(
            QStringLiteral("点击可修改输出位置\n%1").arg(dirShown));
        m_batchTable->setItem(r, 6, dirItem);
    }

    m_batchTable->setSortingEnabled(true);
    int sortColumn = m_batchTable->horizontalHeader()->sortIndicatorSection();
    if(sortColumn < 0)
        sortColumn = 0;
    m_batchTable->sortItems(
        sortColumn, m_batchTable->horizontalHeader()->sortIndicatorOrder());
    m_batchRefreshing = false;
    updateBatchSuffixCombo();
    updateBatchLocationLabel();
}

void MainWindow::updateBatchSuffixCombo()
{
    if(!m_batchSuffixCombo)
        return;
    QString common;
    bool first = true;
    bool unified = true;
    foreach(const BatchItem &bi, m_batchItems)
    {
        if(first)
        {
            common = bi.outputSuffix;
            first = false;
        }
        else if(bi.outputSuffix != common)
        {
            unified = false;
            break;
        }
    }
    m_batchSuffixCombo->blockSignals(true);
    if(m_batchItems.isEmpty())
    {
        m_batchSuffixCombo->setCurrentIndex(
            m_outputSuffixCombo->currentIndex());
    }
    else if(unified)
    {
        m_batchSuffixCombo->setCurrentText(common);
    }
    else
    {
        // 各行后缀不统一时显示空白，表示“全部后缀”未生效。
        m_batchSuffixCombo->setCurrentIndex(-1);
    }
    m_batchSuffixCombo->blockSignals(false);
}

void MainWindow::updateBatchLocationLabel()
{
    if(!m_batchLocationButton)
        return;
    QString common;
    bool first = true;
    bool unified = true;
    foreach(const BatchItem &bi, m_batchItems)
    {
        QString dir = bi.outputDir.isEmpty()
                          ? QFileInfo(bi.filePath).absolutePath()
                          : bi.outputDir;
        if(first)
        {
            common = dir;
            first = false;
        }
        else if(dir != common)
        {
            unified = false;
            break;
        }
    }

    if(m_batchItems.isEmpty() || !unified || common.isEmpty())
    {
        // 各行输出位置不统一（或列表为空）时，“xxxx”显示空白。
        m_batchLocationButton->setText(QStringLiteral("保存位置："));
        m_batchLocationButton->setToolTip(
            QStringLiteral("点击保存位置可批量修改输出目录；各行位置不一致时显示空白"));
        return;
    }

    // 直接显示完整路径，由按钮根据实际宽度自动省略（窗口变宽会显示更多）。
    m_batchLocationButton->setText(
        QStringLiteral("保存位置：%1").arg(common));
    m_batchLocationButton->setToolTip(
        QStringLiteral("点击修改输出位置\n%1").arg(common));
}

void MainWindow::browseBatchLocation()
{
    if(m_batchRunning)
    {
        setStatus(QStringLiteral("批量处理中，请稍后再试"), true);
        return;
    }
    if(m_batchItems.isEmpty())
    {
        setStatus(QStringLiteral("请先添加文件"), true);
        return;
    }
    QString current;
    foreach(const BatchItem &bi, m_batchItems)
    {
        current = bi.outputDir.isEmpty()
                      ? QFileInfo(bi.filePath).absolutePath()
                      : bi.outputDir;
        if(!current.isEmpty())
            break;
    }
    QString dir = QFileDialog::getExistingDirectory(
        this, QStringLiteral("选择批量输出位置"), current);
    if(dir.isEmpty())
        return;
    for(int i = 0; i < m_batchItems.size(); i++)
        m_batchItems[i].outputDir = dir;
    refreshBatchTable();
    setStatus(QStringLiteral("已为全部 %1 行设置输出位置 %2")
                  .arg(m_batchItems.size())
                  .arg(dir));
}

int MainWindow::batchItemIndexById(int id) const
{
    for(int i = 0; i < m_batchItems.size(); i++)
    {
        if(m_batchItems[i].id == id)
            return i;
    }
    return -1;
}

void MainWindow::setBatchItemStatus(int id, const QString &status,
                                    const QString &error)
{
    int index = batchItemIndexById(id);
    if(index < 0)
        return;
    m_batchItems[index].status = status;
    if(!error.isEmpty())
        m_batchItems[index].error = error;

    int done = 0;
    foreach(const BatchItem &item, m_batchItems)
    {
        if(item.status == QStringLiteral("成功") ||
           item.status == QStringLiteral("失败"))
            done++;
    }
    m_batchProgress->setRange(0, m_batchItems.size());
    m_batchProgress->setValue(done);
    refreshBatchTable();
}

void MainWindow::startBatchConversion()
{
    if(m_batchRunning)
        return;
    if(m_batchItems.isEmpty())
    {
        setStatus(QStringLiteral("批量列表为空，请先添加文件"), true);
        return;
    }
    if(m_jtrDirEdit->text().trimmed().isEmpty())
    {
        setStatus(QStringLiteral(
                      "请先设置 JtR 目录（john-packages 的 run 目录）"),
                  true);
        return;
    }

    for(int i = 0; i < m_batchItems.size(); i++)
    {
        if(m_batchItems[i].status != QStringLiteral("成功"))
        {
            m_batchItems[i].status = QStringLiteral("待处理");
            m_batchItems[i].error.clear();
        }
    }

    m_batchRunning = true;
    m_batchConvertButton->setEnabled(false);
    m_batchAddButton->setEnabled(false);
    m_batchRemoveButton->setEnabled(false);
    m_batchClearButton->setEnabled(false);
    m_batchProgress->setRange(0, m_batchItems.size());
    m_batchProgress->setValue(0);
    refreshBatchTable();
    setStatus(QStringLiteral("开始批量提取…"));
    runNextBatchItem();
}

void MainWindow::runNextBatchItem()
{
    int next = -1;
    for(int i = 0; i < m_batchItems.size(); i++)
    {
        // Only pick items that have not been attempted yet.  Already-failed
        // rows are skipped so they cannot be retried in a loop (which used
        // to hang the app when a file could not be converted).
        if(m_batchItems[i].status == QStringLiteral("待处理"))
        {
            next = i;
            break;
        }
    }
    if(next < 0)
    {
        finishBatch();
        return;
    }

    BatchItem &item = m_batchItems[next];
    item.status = QStringLiteral("处理中");
    item.error.clear();
    m_batchCurrentId = item.id;
    refreshBatchTable();

    QString program;
    QStringList args;
    QString error;
    if(!buildConversionCommand(item.filePath, item.format, program, args,
                               error))
    {
        setBatchItemStatus(item.id, QStringLiteral("失败"), error);
        runNextBatchItem();
        return;
    }

    QFileInfo info(item.filePath);
    QString suffix = item.outputSuffix;
    if(suffix == QStringLiteral("无后缀"))
        suffix.clear();
    QString outDir = item.outputDir.isEmpty() ? info.absolutePath()
                                              : item.outputDir;
    item.outputPath =
        outDir + "/" + info.completeBaseName() + suffix;
    setStatus(QStringLiteral("正在处理 %1").arg(info.fileName()));
    m_batchProcess.start(program, args);
}

void MainWindow::batchConversionFinished(int exitCode, QProcess::ExitStatus)
{
    int index = batchItemIndexById(m_batchCurrentId);
    if(index < 0)
    {
        finishBatch();
        return;
    }

    QString out = QString::fromUtf8(m_batchProcess.readAllStandardOutput());
    QString err = QString::fromUtf8(m_batchProcess.readAllStandardError());

    BatchItem &item = m_batchItems[index];

    if(exitCode != 0 || out.trimmed().isEmpty())
    {
        QString reason = err.trimmed().isEmpty() ? out.trimmed()
                                                 : err.trimmed();
        setBatchItemStatus(item.id, QStringLiteral("失败"),
                           reason.isEmpty() ? QStringLiteral("转换失败")
                                            : reason);
        runNextBatchItem();
        return;
    }

    QString cleaned = cleanConversionOutput(out, item.format);

    QFile file(item.outputPath);
    if(!file.open(QIODevice::WriteOnly | QIODevice::Text))
    {
        setBatchItemStatus(item.id, QStringLiteral("失败"),
                           QStringLiteral("无法写入输出文件"));
        runNextBatchItem();
        return;
    }
    file.write(cleaned.toUtf8());
    file.close();

    item.hash = cleaned.trimmed();
    setBatchItemStatus(item.id, QStringLiteral("成功"));
    runNextBatchItem();
}

void MainWindow::finishBatch()
{
    m_batchRunning = false;
    m_batchCurrentId = -1;
    m_batchConvertButton->setEnabled(true);
    m_batchAddButton->setEnabled(true);
    m_batchRemoveButton->setEnabled(true);
    m_batchClearButton->setEnabled(true);

    int ok = 0;
    int failed = 0;
    QStringList failedNames;
    foreach(const BatchItem &item, m_batchItems)
    {
        if(item.status == QStringLiteral("成功"))
            ok++;
        else if(item.status == QStringLiteral("失败"))
        {
            failed++;
            failedNames << QFileInfo(item.filePath).fileName();
        }
    }
    m_batchProgress->setValue(m_batchItems.size());
    setStatus(QStringLiteral("批量完成 成功 %1 失败 %2").arg(ok).arg(failed));

    QString msg = QStringLiteral("批量提取完成\n\n成功 %1 个，失败 %2 个")
                      .arg(ok)
                      .arg(failed);
    if(!failedNames.isEmpty())
        msg += QStringLiteral("\n失败文件\n%1")
                   .arg(failedNames.join(QStringLiteral("\n")));
    QMessageBox::information(this, QStringLiteral("批量提取"), msg);
}

void MainWindow::batchSuffixChanged(int)
{
    // 选择“全部后缀”会把该后缀应用到列表中的每一行。
    QString suffix = m_batchSuffixCombo->currentText();
    for(int i = 0; i < m_batchItems.size(); i++)
        m_batchItems[i].outputSuffix = suffix;
    m_outputSuffixCombo->blockSignals(true);
    m_outputSuffixCombo->setCurrentIndex(
        m_batchSuffixCombo->currentIndex());
    m_outputSuffixCombo->blockSignals(false);
    refreshBatchTable();
    QSettings settings(QCoreApplication::applicationDirPath() +
                           QStringLiteral("/HashValue.ini"),
                       QSettings::IniFormat);
    settings.setValue("outputSuffix", m_batchSuffixCombo->currentText());
}

void MainWindow::batchCellClicked(int row, int column)
{
    if(column != 3 && column != 4 && column != 6)
        return;
    QTableWidgetItem *item = m_batchTable->item(row, column);
    if(!item)
        return;
    int id = item->data(Qt::UserRole).toInt();
    int index = batchItemIndexById(id);
    if(index < 0)
        return;

    if(column == 6) // 输出位置：点击修改该行保存目录
    {
        if(m_batchRunning)
        {
            setStatus(QStringLiteral("批量处理中，请稍后再试"), true);
            return;
        }
        QFileInfo info(m_batchItems[index].filePath);
        QString current =
            m_batchItems[index].outputDir.isEmpty()
                ? info.absolutePath()
                : m_batchItems[index].outputDir;
        QString dir = QFileDialog::getExistingDirectory(
            this, QStringLiteral("选择输出位置"), current);
        if(dir.isEmpty())
            return;
        m_batchItems[index].outputDir = dir;
        refreshBatchTable();
        setStatus(QStringLiteral("已设置 %1 的输出位置 %2")
                      .arg(info.fileName())
                      .arg(dir));
        return;
    }

    if(column == 3) // hashcat
    {
        QString mode = m_batchItems[index].hashcatMode;
        if(mode.isEmpty() || mode == QStringLiteral("—"))
        {
            showToast(QStringLiteral("该文件没有可复制的 hashcat 模式"), false);
            return;
        }
        QApplication::clipboard()->setText(mode);
        showToast(QStringLiteral("已复制 hashcat %1").arg(mode));
    }
    else // 哈希值
    {
        if(m_batchItems[index].hash.isEmpty())
        {
            showToast(QStringLiteral("该文件还没有提取出哈希"), false);
            return;
        }
        QApplication::clipboard()->setText(m_batchItems[index].hash);
        showToast(QStringLiteral("已复制 %1 的哈希")
                      .arg(QFileInfo(m_batchItems[index].filePath)
                               .fileName()));
    }
}

void MainWindow::batchCellDoubleClicked(int row, int column)
{
    // 双击“文件名”跳转到单选模式，载入该文件进行详细设置。
    if(column != 0)
        return;
    QTableWidgetItem *item = m_batchTable->item(row, 0);
    if(!item)
        return;
    int id = item->data(Qt::UserRole).toInt();
    int index = batchItemIndexById(id);
    if(index < 0)
        return;

    loadItemForDetailedSettings(index);
}

void MainWindow::loadItemForDetailedSettings(int index)
{
    if(index < 0 || index >= m_batchItems.size())
        return;
    const BatchItem &bi = m_batchItems[index];
    QString file = bi.filePath;
    m_inputFileEdit->setText(file);

    int catIdx = m_categoryCombo->findText(bi.category);
    if(catIdx >= 0)
        m_categoryCombo->setCurrentIndex(catIdx);
    int fmtIdx = m_formatCombo->findText(bi.format);
    if(fmtIdx >= 0)
        m_formatCombo->setCurrentIndex(fmtIdx);

    m_outputSuffixCombo->blockSignals(true);
    m_outputSuffixCombo->setCurrentIndex(
        m_outputSuffixCombo->findText(bi.outputSuffix));
    m_outputSuffixCombo->blockSignals(false);

    QString suffix = bi.outputSuffix;
    if(suffix == QStringLiteral("无后缀"))
        suffix.clear();
    QFileInfo info(file);
    QString dir = bi.outputDir.isEmpty() ? info.absolutePath()
                                         : bi.outputDir;
    m_outputEdit->setText(dir + "/" + info.completeBaseName() + suffix);

    m_tabs->setCurrentIndex(0);
    setStatus(QStringLiteral("已在单选模式载入 %1，调整后可点击“发送”更新批量列表")
                  .arg(info.fileName()));
}

void MainWindow::sendCurrentToBatch()
{
    QString file = m_inputFileEdit->text().trimmed();
    if(file.isEmpty())
    {
        setStatus(QStringLiteral("请先在单选模式选择加密文件"), true);
        return;
    }
    if(!QFile::exists(file))
    {
        setStatus(QStringLiteral("文件不存在：%1").arg(file), true);
        return;
    }

    QString format = m_formatCombo->currentText();
    QString category = m_categoryCombo->currentText();
    QString suffix = m_outputSuffixCombo->currentText();
    QString outText = m_outputEdit->text().trimmed();
    QString outDir = outText.isEmpty()
                         ? QFileInfo(file).absolutePath()
                         : QFileInfo(outText).absolutePath();
    QFileInfo info(file);
    QString absFile = info.absoluteFilePath();

    // 批量列表中已有同一文件时更新该行，避免重复添加。
    int existing = -1;
    for(int i = 0; i < m_batchItems.size(); i++)
    {
        if(QFileInfo(m_batchItems[i].filePath).absoluteFilePath() == absFile)
        {
            existing = i;
            break;
        }
    }

    if(existing >= 0)
    {
        BatchItem &item = m_batchItems[existing];
        item.format = format;
        item.category = category;
        item.hashcatMode = hashcatModeFor2johnScript(format);
        item.outputSuffix = suffix;
        item.outputDir = outDir;
        item.outputPath.clear();
        item.hash.clear();
        item.error.clear();
        item.status = QStringLiteral("待处理");
        refreshBatchTable();
        m_tabs->setCurrentIndex(1);
        setStatus(QStringLiteral("已更新批量列表中的 %1").arg(info.fileName()));
        return;
    }

    BatchItem item;
    item.id = m_batchItemIdCounter++;
    item.filePath = file;
    item.category = category;
    item.format = format;
    item.hashcatMode = hashcatModeFor2johnScript(format);
    item.outputSuffix = suffix;
    item.outputDir = outDir;
    item.status = QStringLiteral("待处理");
    m_batchItems.append(item);
    refreshBatchTable();
    m_tabs->setCurrentIndex(1);
    setStatus(QStringLiteral("已发送 %1 到批量列表").arg(info.fileName()));
}

void MainWindow::showToast(const QString &text, bool success)
{
    if(!m_toast)
        return;
    m_toast->setText(text);
    m_toast->setStyleSheet(
        success ? QStringLiteral(
                      "background: rgba(255,255,255,0.96); color: #2e7d32; "
                      "border: 2px solid #2e7d32; border-radius: 10px; "
                      "padding: 12px 26px; font-size: 17px; font-weight: bold;")
                : QStringLiteral(
                      "background: rgba(255,255,255,0.96); color: #e53935; "
                      "border: 2px solid #e53935; border-radius: 10px; "
                      "padding: 12px 26px; font-size: 17px; font-weight: bold;"));
    m_toast->adjustSize();
    QWidget *host = centralWidget();
    QPoint center =
        host->mapToGlobal(host->rect().center());
    m_toast->move(center.x() - m_toast->width() / 2,
                  center.y() - m_toast->height() / 2);
    m_toast->show();
    m_toast->raise();
    m_toastTimer->start(3000);
}

void MainWindow::showBatchRowMenu(const QPoint &pos)
{
    QTableWidgetItem *item = m_batchTable->itemAt(pos);
    if(!item)
        return;
    int id = item->data(Qt::UserRole).toInt();
    int index = batchItemIndexById(id);
    if(index < 0)
        return;

    QMenu menu(this);
    QAction *retryAction = menu.addAction(QStringLiteral("重新提取"));
    QAction *detailAction = menu.addAction(QStringLiteral("详细设置"));
    QAction *viewAction = menu.addAction(QStringLiteral("查看完整哈希"));
    QAction *copyAction = menu.addAction(QStringLiteral("复制完整哈希"));
    QMenu *suffixMenu = menu.addMenu(QStringLiteral("更改后缀"));
    QAction *sfxTxt = suffixMenu->addAction(QStringLiteral(".txt"));
    QAction *sfxLst = suffixMenu->addAction(QStringLiteral(".lst"));
    QAction *sfxHash = suffixMenu->addAction(QStringLiteral(".hash"));
    QAction *sfxNone = suffixMenu->addAction(QStringLiteral("无后缀"));
    QMenu *selectMenu = 0;
    QMenu *byCatMenu = 0;
    QMenu *byStatusMenu = 0;
    bool singleRow =
        (m_batchTable->selectionModel()->selectedRows().size() <= 1);
    if(singleRow)
    {
        selectMenu = menu.addMenu(QStringLiteral("选择类别"));
        byCatMenu = selectMenu->addMenu(QStringLiteral("按类别"));
        byStatusMenu = selectMenu->addMenu(QStringLiteral("按状态"));
        QStringList cats;
        QStringList statuses;
        foreach(const BatchItem &bi, m_batchItems)
        {
            if(!cats.contains(bi.category))
                cats << bi.category;
            if(!statuses.contains(bi.status))
                statuses << bi.status;
        }
        foreach(const QString &cat, cats)
        {
            QAction *a = byCatMenu->addAction(cat);
            a->setData(QStringLiteral("cat:") + cat);
        }
        foreach(const QString &st, statuses)
        {
            QAction *a = byStatusMenu->addAction(st);
            a->setData(QStringLiteral("st:") + st);
        }
    }
    QAction *openDirAction = menu.addAction(QStringLiteral("打开输出位置"));
    QAction *openFileAction = menu.addAction(QStringLiteral("打开文件位置"));
    QAction *deleteAction = menu.addAction(QStringLiteral("删除该行"));
    QAction *chosen =
        menu.exec(m_batchTable->viewport()->mapToGlobal(pos));
    if(!chosen)
        return;

    if(chosen == retryAction)
    {
        if(m_batchRunning)
        {
            setStatus(QStringLiteral("批量处理中，请稍后再试"), true);
            return;
        }
        setBatchItemStatus(id, QStringLiteral("待处理"));
        setStatus(QStringLiteral("已加入重新提取队列"));
    }
    else if(chosen == detailAction)
    {
        // 跳转到单选模式载入该行，进行详细设置。
        loadItemForDetailedSettings(index);
    }
    else if(chosen == viewAction)
    {
        if(m_batchItems[index].hash.isEmpty())
            setStatus(QStringLiteral("该文件还没有提取出哈希"), true);
        else
            QMessageBox::information(this, QStringLiteral("完整哈希"),
                                     m_batchItems[index].hash);
    }
    else if(chosen == copyAction)
    {
        if(m_batchItems[index].hash.isEmpty())
            setStatus(QStringLiteral("该文件还没有提取出哈希"), true);
        else
        {
            QApplication::clipboard()->setText(m_batchItems[index].hash);
            showToast(QStringLiteral("已复制哈希到剪贴板"));
        }
    }
    else if(chosen == openDirAction)
    {
        QString out = m_batchItems[index].outputPath;
        if(out.isEmpty())
        {
            QFileInfo info(m_batchItems[index].filePath);
            QString suffix = m_batchItems[index].outputSuffix;
            if(suffix == QStringLiteral("无后缀"))
                suffix.clear();
            out = info.absolutePath() + "/" + info.completeBaseName() +
                  suffix;
        }
        if(!QFile::exists(out))
        {
            setStatus(QStringLiteral("输出文件尚不存在"), true);
            return;
        }
        QProcess::startDetached(
            QStringLiteral("explorer.exe"),
            QStringList() << QStringLiteral("/select,")
                          << QDir::toNativeSeparators(out));
    }
    else if(chosen == openFileAction)
    {
        QString path = m_batchItems[index].filePath;
        if(!QFile::exists(path))
        {
            setStatus(QStringLiteral("源文件不存在"), true);
            return;
        }
        QProcess::startDetached(
            QStringLiteral("explorer.exe"),
            QStringList() << QStringLiteral("/select,")
                          << QDir::toNativeSeparators(path));
    }
    else if(chosen == sfxTxt || chosen == sfxLst || chosen == sfxHash ||
            chosen == sfxNone)
    {
        if(m_batchRunning)
        {
            setStatus(QStringLiteral("批量处理中，请稍后再试"), true);
            return;
        }
        // Apply to the right-clicked row plus any selected rows.
        QList<int> ids;
        foreach(const QModelIndex &selIdx,
                m_batchTable->selectionModel()->selectedRows())
        {
            if(QTableWidgetItem *selItem =
                   m_batchTable->item(selIdx.row(), 0))
            {
                int selId = selItem->data(Qt::UserRole).toInt();
                if(!ids.contains(selId))
                    ids << selId;
            }
        }
        if(!ids.contains(id))
            ids << id;
        QString suffix = chosen->text();
        foreach(int sid, ids)
        {
            int sidx = batchItemIndexById(sid);
            if(sidx >= 0)
                m_batchItems[sidx].outputSuffix = suffix;
        }
        refreshBatchTable();
        setStatus(QStringLiteral("已为 %1 行设置后缀 %2")
                      .arg(ids.size())
                      .arg(suffix));
    }
    else if(selectMenu && (chosen->parent() == byCatMenu ||
                           chosen->parent() == byStatusMenu))
    {
        QString key = chosen->data().toString();
        bool byCategory = key.startsWith(QStringLiteral("cat:"));
        QString value = key.mid(4);
        int col = byCategory ? 2 : 5;
        int count = 0;
        m_batchTable->clearSelection();
        for(int r = 0; r < m_batchTable->rowCount(); r++)
        {
            QTableWidgetItem *it = m_batchTable->item(r, col);
            if(it && it->text() == value)
            {
                m_batchTable->selectionModel()->select(
                    m_batchTable->model()->index(r, 0),
                    QItemSelectionModel::Select | QItemSelectionModel::Rows);
                count++;
            }
        }
        setStatus(QStringLiteral("已按%1选中 %2 行")
                      .arg(byCategory ? QStringLiteral("类别")
                                      : QStringLiteral("状态"))
                      .arg(count));
    }
    else if(chosen == deleteAction)
    {
        if(m_batchRunning)
        {
            setStatus(QStringLiteral("批量处理中，请稍后再试"), true);
            return;
        }
        int removeIndex = batchItemIndexById(id);
        if(removeIndex >= 0)
        {
            m_batchItems.remove(removeIndex);
            refreshBatchTable();
        }
    }
}
