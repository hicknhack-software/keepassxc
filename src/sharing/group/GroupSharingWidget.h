#ifndef GROUPSHARINGWIDGET_H
#define GROUPSHARINGWIDGET_H

#include <QPointer>
#include <QWidget>
#include <QStandardItemModel>

#include "gui/group/EditGroupWidget.h"

class Group;
class CustomData;

namespace Ui
{
    class GroupSharingWidget;
}

class GroupSharingPage : public IEditGroupPage
{
public:
    GroupSharingPage(EditGroupWidget *widget);
    QString name() override;
    QIcon icon() override;
    QWidget *createWidget() override;
    void set(QWidget *widget, Group *temporaryGroup, Database *db) override;
    void assign(QWidget *widget) override;
};

class GroupSharingWidget : public QWidget
{
    Q_OBJECT
public:
    explicit GroupSharingWidget(QWidget* parent = nullptr);
    ~GroupSharingWidget();

    void setGroup(Group *temporaryGroup, Database *database);

private:
    void showSharingState();
private slots:
    void update();
    void selectType();
    void selectPassword();
    void selectPath();
    void setPath(const QString& path);
    void setGeneratedPassword(const QString& password);
    void togglePasswordGeneratorButton(bool checked);

private:
    QScopedPointer<Ui::GroupSharingWidget> m_ui;
    QPointer<Group> m_temporaryGroup;
    QPointer<Database> m_database;
};

#endif // GROUPSHARINGWIDGET_H
