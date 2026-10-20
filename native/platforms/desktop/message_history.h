#pragma once
#include <QListWidget>
#include <QJsonArray>
class MessageHistory final:public QListWidget {
 Q_OBJECT
public:
 explicit MessageHistory(QWidget* parent=nullptr);
 void setRows(const QJsonArray&);
 QString textContent() const;
};
