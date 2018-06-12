#ifndef GROUPSHARINGWIDGET_H
#define GROUPSHARINGWIDGET_H

#include <QPointer>
#include <QWidget>
#include <QAbstractItemModel>

class Group;
class CustomData;

namespace Ui
{
    class GroupSharingWidget;
}

class GroupSharingVerificationModel : public QAbstractItemModel
{
    Q_OBJECT

public:
    explicit GroupSharingVerificationModel(QObject *parent = nullptr);
    QModelIndex index(int row, int column, const QModelIndex &parent) const;
    QModelIndex parent(const QModelIndex &child) const;
    int rowCount(const QModelIndex &parent) const;
    int columnCount(const QModelIndex &parent) const;
    QVariant data(const QModelIndex &index, int role) const;

};

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
    void togglePasswordGeneratorButton(bool checked);

private:
    QScopedPointer<Ui::GroupSharingWidget> m_ui;
    QPointer<const Group> m_currentGroup;
    QPointer<CustomData> m_customData;
    QPointer<GroupSharingVerificationModel> m_verificationModel;
};

#endif // GROUPSHARINGWIDGET_H
