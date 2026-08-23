/*
 * Helper to map John the Ripper formats and *2john script names to
 * hashcat modes. Modes are heuristic and cover the most common formats.
 */

#ifndef HASHCATHELPER_H
#define HASHCATHELPER_H

#include <QHash>
#include <QRegExp>
#include <QString>
#include <QStringList>

// Map a single John format token (e.g. "Raw-MD5") to a hashcat mode.
inline QString hashcatModeForJohnFormatToken(const QString &token)
{
    static const QHash<QString, QString> modes = {
        {"raw-md5", "0"},        {"raw-sha1", "100"},
        {"raw-sha224", "1300"},  {"raw-sha256", "1400"},
        {"raw-sha384", "10800"}, {"raw-sha512", "1700"},
        {"md5crypt", "500"},     {"md5apr1", "1600"},
        {"sha256crypt", "7400"}, {"sha512crypt", "1800"},
        {"descrypt", "1500"},    {"bsdicrypt", "1500"},
        {"crypt", "1500"},       {"bcrypt", "3200"},
        {"nt", "1000"},          {"lm", "3000"},
        {"mscash", "1100"},      {"mscash2", "2100"},
        {"mysql", "200"},        {"mysql-sha1", "300"},
        {"mssql", "131"},        {"mssql05", "132"},
        {"mssql12", "1731"},     {"oracle11", "112"},
        {"xsha", "122"},         {"sha1crypt", "10900"},
        {"sunmd5", "3300"},      {"drupal7", "7900"},
        {"phpass", "400"},       {"wpapsk", "22000"},
        {"wpa", "2500"},         {"netntlm", "5500"},
        {"netntlmv2", "5600"},   {"krb5pa-sha1", "7500"},
        {"krb5tgs", "13100"},    {"ssh", "22921"},
        {"pdf", "10400"},        {"office2007", "9600"},
        {"office2010", "9700"},  {"office2013", "9710"},
        {"office2016", "9720"},  {"keepass", "13400"},
        {"7z", "11600"},         {"rar", "13000"},
        {"rar3", "125"},         {"zip", "17200"},
        {"dmg", "16200"},        {"agilekeychain", "15600"},
        {"keychain", "23100"},   {"lastpass", "6800"},
        {"bitcoin", "11300"},    {"blockchain", "83400"},
        {"gpg", "17000"},        {"luks", "14600"},
        {"truecrypt", "6211"},   {"encfs", "11700"},
        {"ecryptfs", "12200"},   {"odf", "18200"},
        {"pwsafe", "7600"},      {"kwallet", "13800"},
        {"keystore", "15500"},   {"hccap", "22000"},
        {"hccapx", "22000"},
        {"htdigest", "1410"},    {"sapb", "7700"},
        {"lotus5", "8600"},      {"racf", "8500"},
        {"aix-smd5", "6300"},    {"aix-ssha1", "6400"},
        {"aix-ssha256", "6500"}, {"aix-ssha512", "6600"},
        {"androidfde", "8800"}};
    return modes.value(token.toLower());
}

// Map a Formats-column value (possibly several formats) to hashcat modes.
inline QString hashcatModeForJohnFormat(const QString &formats)
{
    if(formats.isEmpty())
        return QString();
    QStringList tokens =
        formats.split(QRegExp("[,\\s]+"), QString::SkipEmptyParts);
    QStringList modes;
    foreach(const QString &token, tokens)
    {
        QString mode = hashcatModeForJohnFormatToken(token);
        if(!mode.isEmpty() && !modes.contains(mode))
            modes << mode;
    }
    return modes.join(",");
}

// Map a *2john script display name (e.g. "zip", "7z", "rar") to a hashcat mode.
inline QString hashcatModeFor2johnScript(const QString &scriptName)
{
    static const QHash<QString, QString> modes = {
        {"zip", "17200"},         {"7z", "11600"},
        {"rar", "13000（或 125）"}, {"office", "9600 等"},
        {"pdf", "10400 等"},      {"1password", "15600"},
        {"keepass", "13400"},     {"dmg", "16200"},
        {"bitcoin", "11300"},     {"blockchain", "83400"},
        {"gpg", "17000 等"},      {"truecrypt", "6211"},
        {"luks", "14600"},        {"odf", "18200"},
        {"sxc", "18200"},         {"encfs", "11700"},
        {"ecryptfs", "12200"},    {"pwsafe", "7600"},
        {"keychain", "23100"},    {"lastpass", "6800"},
        {"hccap", "22000"},       {"hccapx", "22000"},
        {"htdigest", "1410"},
        {"ssh", "22921"},         {"sshng", "22921"},
        {"wpapcap", "22000"},     {"sap", "7700"},
        {"lotus", "8600"},        {"racf", "8500"},
        {"aix", "6300"},          {"androidfde", "8800"},
        {"krbpa", "7500"},        {"kwallet", "13800"},
        {"keystore", "15500"},    {"ikescan", "5300"}};
    QString mode = modes.value(scriptName.toLower());
    return mode.isEmpty() ? QStringLiteral("—") : mode;
}

#endif // HASHCATHELPER_H
