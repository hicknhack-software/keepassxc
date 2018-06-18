#ifndef GROUPSHARINGWIDGET_H
#define GROUPSHARINGWIDGET_H

#include <QPointer>
#include <QWidget>
#include <QStandardItemModel>

class Group;
class CustomData;

namespace Ui
{
    class GroupSharingWidget;
}

class GroupSharingWidget : public QWidget
{
    Q_OBJECT
public:
    explicit GroupSharingWidget(QWidget* parent = nullptr);
    ~GroupSharingWidget();

    void setGroup(const Group* group);
    void setCustomData(CustomData* customData);

private:
    void showSharingState();
private slots:
    void update();
    void selectType();
    void selectPassword();
    void selectPath();
    void setPath(const QString& path);
    void setGeneratedPassword(const QString& password);
    void setVerificationExporter(const QString& exporter);
    void togglePasswordGeneratorButton(bool checked);

private:
    QScopedPointer<Ui::GroupSharingWidget> m_ui;
    QPointer<const Group> m_currentGroup;
    QPointer<CustomData> m_customData;
    QScopedPointer<QStandardItemModel> m_verificationModel;
};

#endif // GROUPSHARINGWIDGET_H
