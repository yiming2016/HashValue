/*
 * *2john conversion script descriptions (ported from Johnny, Chinese labels).
 */

#include "2johnformats.h"

void declare2johnFormats(QList<ConversionScript> &scripts)
{
    scripts
        << ConversionScript("unafs", "",
                            QList<ConversionScriptParameter>()
                                << ConversionScriptParameter("数据库文件",
                                                             FILE_PARAM)
                                << ConversionScriptParameter("单元名称",
                                                             TEXT_PARAM))

        << ConversionScript("unshadow", "",
                            QList<ConversionScriptParameter>()
                                << ConversionScriptParameter("密码文件",
                                                             FILE_PARAM)
                                << ConversionScriptParameter("影子密码文件",
                                                             FILE_PARAM))

        << ConversionScript("1password2john", ".py",
                            QList<ConversionScriptParameter>()
                                << ConversionScriptParameter("1Password Agile 钥匙串文件",
                                                             FILE_PARAM))

        << ConversionScript("7z2john", ".pl",
                            QList<ConversionScriptParameter>()
                                << ConversionScriptParameter("加密的 7-Zip 文件",
                                                             FILE_PARAM))

        << ConversionScript("aix2john", ".py",
                            QList<ConversionScriptParameter>()
                                << ConversionScriptParameter(
                                       "AIX 密码文件（/etc/security/passwd）",
                                       FILE_PARAM))

        << ConversionScript(
               "androidfde2john", ".py",
               QList<ConversionScriptParameter>()
                   << ConversionScriptParameter("数据分区 / 镜像",
                                                FILE_PARAM)
                   << ConversionScriptParameter("尾部（footer）分区 / 镜像",
                                                FILE_PARAM))

        << ConversionScript("apex2john", ".py",
                            QList<ConversionScriptParameter>()
                                << ConversionScriptParameter("apex-hashes.txt 文件",
                                                             FILE_PARAM))

        << ConversionScript("bitcoin2john", ".py",
                            QList<ConversionScriptParameter>()
                                << ConversionScriptParameter("比特币（bitcoin）钱包文件",
                                                             FILE_PARAM))

        << ConversionScript("blockchain2john", ".py",
                            QList<ConversionScriptParameter>()
                                << ConversionScriptParameter(
                                       "（可选）输入是否为 base64 格式？",
                                       CHECKABLE_PARAM, "--json")
                                << ConversionScriptParameter("区块链钱包文件",
                                                             FILE_PARAM))

        << ConversionScript("cracf2john", ".py",
                            QList<ConversionScriptParameter>()
                                << ConversionScriptParameter("CRACF.TXT 文件",
                                                             FILE_PARAM))

        << ConversionScript("dmg2john", "",
                            QList<ConversionScriptParameter>()
                                << ConversionScriptParameter("DMG 文件",
                                                             FILE_PARAM))

        << ConversionScript(
               "ecryptfs2john", ".py",
               QList<ConversionScriptParameter>()
                   << ConversionScriptParameter("加密口令（wrapped-passphrase）",
                                                FILE_PARAM)
                   << ConversionScriptParameter("（可选）.ecryptfsrc 文件",
                                                FILE_PARAM))

        << ConversionScript("encfs2john", ".py",
                            QList<ConversionScriptParameter>()
                                << ConversionScriptParameter("EncFS 文件夹",
                                                             FOLDER_PARAM))

        << ConversionScript("gpg2john", "",
                            QList<ConversionScriptParameter>()
                                << ConversionScriptParameter("GPG 私钥文件",
                                                             FILE_PARAM))

        << ConversionScript("hccap2john", ".py",
                            QList<ConversionScriptParameter>()
                                << ConversionScriptParameter("hccap 文件",
                                                             FILE_PARAM))

        << ConversionScript("htdigest2john", ".py",
                            QList<ConversionScriptParameter>()
                                << ConversionScriptParameter("htdigest 文件",
                                                             FILE_PARAM))

        << ConversionScript(
               "ikescan2john", ".py",
               QList<ConversionScriptParameter>()
                   << ConversionScriptParameter("psk 参数文件", FILE_PARAM)
                   << ConversionScriptParameter("（可选）Nortel 用户名",
                                                TEXT_PARAM))

        << ConversionScript("kdcdump2john", ".py",
                            QList<ConversionScriptParameter>()
                                << ConversionScriptParameter("转储文件（dump）",
                                                             FILE_PARAM))

        << ConversionScript(
               "keepass2john", "",
               QList<ConversionScriptParameter>()
                   << ConversionScriptParameter("（可选）内联阈值（默认 1024）",
                                                TEXT_PARAM, "-i")
                   << ConversionScriptParameter("（可选）密钥文件",
                                                FILE_PARAM, "-k")
                   << ConversionScriptParameter("kdbx 数据库文件", FILE_PARAM))

        << ConversionScript("keychain2john", "",
                            QList<ConversionScriptParameter>()
                                << ConversionScriptParameter("钥匙串文件",
                                                             FILE_PARAM))

        << ConversionScript("keyring2john", "",
                            QList<ConversionScriptParameter>()
                                << ConversionScriptParameter("GNOME Keyring 文件",
                                                             FILE_PARAM))

        << ConversionScript("keystore2john", ".py",
                            QList<ConversionScriptParameter>()
                                << ConversionScriptParameter(".keystore / .jks 文件",
                                                             FILE_PARAM))

        << ConversionScript(
               "known_hosts2john", ".py",
               QList<ConversionScriptParameter>()
                   << ConversionScriptParameter("known_hosts 文件", FILE_PARAM))

        << ConversionScript("krbpa2john", ".py",
                            QList<ConversionScriptParameter>()
                                << ConversionScriptParameter(".pdml 文件",
                                                             FILE_PARAM))

        << ConversionScript("kwallet2john", "",
                            QList<ConversionScriptParameter>()
                                << ConversionScriptParameter(".kwl 文件",
                                                             FILE_PARAM))

        << ConversionScript(
               "lastpass2john", ".py",
               QList<ConversionScriptParameter>()
                   << ConversionScriptParameter("电子邮件地址", TEXT_PARAM)
                   << ConversionScriptParameter("LastPass 的 *._lpall.slps 文件",
                                                FILE_PARAM))

        << ConversionScript("lion2john", ".pl",
                            QList<ConversionScriptParameter>()
                                << ConversionScriptParameter("PLIST 文件",
                                                             FILE_PARAM)
                                << ConversionScriptParameter("密码文件",
                                                             FILE_PARAM))

        << ConversionScript("lotus2john", ".py",
                            QList<ConversionScriptParameter>()
                                << ConversionScriptParameter("Lotus Notes ID 文件",
                                                             FILE_PARAM))

        << ConversionScript(
               "luks2john", ".py",
               QList<ConversionScriptParameter>()
                   << ConversionScriptParameter("（可选）内联阈值（默认 1024）",
                                                TEXT_PARAM, "-i")
                   << ConversionScriptParameter("LUKS 文件 / 磁盘",
                                                FILE_PARAM))

        << ConversionScript("mcafee_epo2john", ".py",
                            QList<ConversionScriptParameter>()
                                << ConversionScriptParameter("dbo.OrionUsers CSV 导出文件",
                                                             FILE_PARAM))

        << ConversionScript("ml2john", ".py",
                            QList<ConversionScriptParameter>()
                                << ConversionScriptParameter("Mountain Lion 的 .plist 文件",
                                                             FILE_PARAM))

        << ConversionScript("mozilla2john", ".py",
                            QList<ConversionScriptParameter>()
                                << ConversionScriptParameter("key3.db 文件",
                                                             FILE_PARAM))

        << ConversionScript("odf2john", ".py",
                            QList<ConversionScriptParameter>()
                                << ConversionScriptParameter("ODF 文件",
                                                             FILE_PARAM))

        << ConversionScript("office2john", ".py",
                            QList<ConversionScriptParameter>()
                                << ConversionScriptParameter("加密的 Office 文件",
                                                             FILE_PARAM))

        << ConversionScript("openbsd_softraid2john", ".py",
                            QList<ConversionScriptParameter>()
                                << ConversionScriptParameter("磁盘镜像",
                                                             FILE_PARAM))

        << ConversionScript(
               "openssl2john", ".py",
               QList<ConversionScriptParameter>()
                   << ConversionScriptParameter("（可选）加密算法（cipher）", TEXT_PARAM,
                                                "-c")
                   << ConversionScriptParameter("（可选）消息摘要（md）", TEXT_PARAM,
                                                "-m")
                   << ConversionScriptParameter("（可选）明文",
                                                TEXT_PARAM, "-p")
                   << ConversionScriptParameter("OpenSSL 加密文件",
                                                FILE_PARAM))

        << ConversionScript("pdf2john", ".py",
                            QList<ConversionScriptParameter>()
                                << ConversionScriptParameter("PDF 文件",
                                                             FILE_PARAM))

        << ConversionScript("pfx2john", "",
                            QList<ConversionScriptParameter>()
                                << ConversionScriptParameter(".pfx / .p12 文件",
                                                             FILE_PARAM))

        << ConversionScript("putty2john", "",
                            QList<ConversionScriptParameter>()
                                << ConversionScriptParameter(".ppk PuTTY 私钥文件",
                                                             FILE_PARAM))

        << ConversionScript("pwsafe2john", "",
                            QList<ConversionScriptParameter>()
                                << ConversionScriptParameter(".psafe3 文件",
                                                             FILE_PARAM))

        << ConversionScript(
               "racf2john", "",
               QList<ConversionScriptParameter>()
                   << ConversionScriptParameter("RACF 二进制文件", FILE_PARAM))

        << ConversionScript(
               "rar2john", "",
               QList<ConversionScriptParameter>()
                   << ConversionScriptParameter("（可选）内联阈值（默认 1024）",
                                                TEXT_PARAM, "-i")
                   << ConversionScriptParameter("RAR 文件", FILE_PARAM))

        << ConversionScript("sap2john", ".pl",
                            QList<ConversionScriptParameter>()
                                << ConversionScriptParameter("输入文件",
                                                             FILE_PARAM)
                                << ConversionScriptParameter(
                                       "提取 SAP CODVN(A|B|D|E|F|H) 哈希：默认为 BFE",
                                       TEXT_PARAM))

        << ConversionScript("sipdump2john", ".py",
                            QList<ConversionScriptParameter>()
                                << ConversionScriptParameter("sipdump 转储文件",
                                                             FILE_PARAM))

        << ConversionScript("ssh2john", "",
                            QList<ConversionScriptParameter>()
                                << ConversionScriptParameter("密钥文件",
                                                             FILE_PARAM))

        << ConversionScript("sshng2john", ".py",
                            QList<ConversionScriptParameter>()
                                << ConversionScriptParameter("RSA/DSA 私钥文件",
                                                             FILE_PARAM))

        << ConversionScript("strip2john", ".py",
                            QList<ConversionScriptParameter>()
                                << ConversionScriptParameter("STRIP 文件",
                                                             FILE_PARAM))

        << ConversionScript("sxc2john", ".py",
                            QList<ConversionScriptParameter>()
                                << ConversionScriptParameter("SXC 文件",
                                                             FILE_PARAM))

        << ConversionScript("truecrypt2john", ".py",
                            QList<ConversionScriptParameter>()
                                << ConversionScriptParameter("卷文件（volume）",
                                                             TEXT_PARAM)
                                << ConversionScriptParameter("密钥文件",
                                                             FILE_PARAM))

        << ConversionScript("uaf2john", "",
                            QList<ConversionScriptParameter>()
                                << ConversionScriptParameter("uaf 文件",
                                                             FILE_PARAM))

        << ConversionScript("vncpcap2john", "",
                            QList<ConversionScriptParameter>()
                                << ConversionScriptParameter("pcap 抓包文件",
                                                             FILE_PARAM))

        << ConversionScript("wpapcap2john", "",
                            QList<ConversionScriptParameter>()
                                << ConversionScriptParameter(
                                       "仅显示完整的认证（不完整的可能不是正确密码，但可破解其中已尝试过的密码）",
                                       CHECKABLE_PARAM, "-c")
                                << ConversionScriptParameter("文件",
                                                             FILE_PARAM))

        << ConversionScript(
               "zip2john", "",
               QList<ConversionScriptParameter>()
                   << ConversionScriptParameter("（可选）内联阈值（默认 1024）",
                                                TEXT_PARAM, "-i")
                   << ConversionScriptParameter(
                          "使用 ASCII 模式并附带文件名（仅旧版 PKZIP）",
                          FILE_PARAM, "-a")
                   << ConversionScriptParameter("仅使用 .zip 中的该文件（仅旧版 PKZIP）",
                                                FILE_PARAM, "-o")
                   << ConversionScriptParameter(
                          "创建仅含校验和的哈希（仅旧版 PKZIP）",
                          CHECKABLE_PARAM, "-c")
                   << ConversionScriptParameter("不查找任何魔术文件类型（仅旧版 PKZIP）",
                                                CHECKABLE_PARAM, "-n")
                   << ConversionScriptParameter("强制计算 2 字节校验和（仅旧版 PKZIP）",
                                                CHECKABLE_PARAM, "-2")
                   << ConversionScriptParameter("zip 文件", FILE_PARAM));
}
