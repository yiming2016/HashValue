/*
 * *2john conversion script descriptions (ported from Johnny).
 */

#ifndef HASHVALUE_2JOHNFORMATS_H
#define HASHVALUE_2JOHNFORMATS_H

#include <QList>
#include <QString>

enum ScriptParameterType
{
    FILE_PARAM,
    TEXT_PARAM,
    CHECKABLE_PARAM,
    FOLDER_PARAM
};

class ConversionScriptParameter
{
public:
    ConversionScriptParameter(const QString &name, ScriptParameterType type,
                              const QString &commandLinePrefix = "")
        : name(name), type(type), commandLinePrefix(commandLinePrefix)
    {
    }
    QString             name;
    ScriptParameterType type;
    QString             commandLinePrefix;
};

class ConversionScript
{
public:
    ConversionScript() : generic(false) {}
    ConversionScript(const QString &name, const QString &extension,
                     const QList<ConversionScriptParameter> &parameters)
        : name(name), extension(extension), parameters(parameters),
          generic(false)
    {
    }
    QString                          name;
    QString                          extension;
    QList<ConversionScriptParameter> parameters;
    bool                             generic;
};

void declare2johnFormats(QList<ConversionScript> &scripts);

#endif // HASHVALUE_2JOHNFORMATS_H
