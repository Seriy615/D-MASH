#include "message_history.h"
#include <QStyledItemDelegate>
#include <QTextDocument>
#include <QTextOption>
#include <QPainter>
#include <QDateTime>
#include <QJsonObject>
#include <algorithm>
namespace {
QString statusText(const QString& value){if(value=="LOCAL")return QObject::tr("Saved");if(value=="NODE_ACCEPTED")return QObject::tr("Queued");return value;}
struct Bubble {QString text,meta;int width,height;QString date;};
Bubble measure(const QStyleOptionViewItem& option,const QModelIndex& index,int available){
 const auto text=index.data().toString();const auto state=statusText(index.data(Qt::UserRole+1).toString());const auto timestamp=index.data(Qt::UserRole+3).toLongLong();const auto time=timestamp>0?QDateTime::fromMSecsSinceEpoch(timestamp).toLocalTime().toString("HH:mm"):QString();const QString meta=time.isEmpty()?state:time+"  ·  "+state;
 const auto metrics=QFontMetrics(option.font);int natural=120;for(const auto& line:text.split('\n'))natural=qMax(natural,metrics.horizontalAdvance(line)+24);
 const int width=qMin(qMax(160,int(available*.72)),qMax(natural,metrics.horizontalAdvance(meta)+24));
 QTextDocument document;document.setDefaultFont(option.font);QTextOption wrap;wrap.setWrapMode(QTextOption::WrapAtWordBoundaryOrAnywhere);document.setDefaultTextOption(wrap);document.setPlainText(text);document.setTextWidth(width-24);
 return {text,meta,width,int(document.size().height())+32,index.data(Qt::UserRole+4).toString()};
}
class BubbleDelegate final:public QStyledItemDelegate {
public:
 explicit BubbleDelegate(QListWidget* owner):QStyledItemDelegate(owner),view(owner){}
 QSize sizeHint(const QStyleOptionViewItem& option,const QModelIndex& index)const override{const auto b=measure(option,index,view->viewport()->width()-20);return {view->viewport()->width(),b.height+8+(b.date.isEmpty()?0:34)};}
 void paint(QPainter* painter,const QStyleOptionViewItem& option,const QModelIndex& index)const override{
  const auto b=measure(option,index,view->viewport()->width()-20);const bool outgoing=index.data(Qt::UserRole).toString()=="out";const int x=outgoing?option.rect.right()-b.width-10:option.rect.left()+10;const QRectF box(x,option.rect.top()+4+(b.date.isEmpty()?0:34),b.width,b.height);
  painter->save();painter->setRenderHint(QPainter::Antialiasing);if(!b.date.isEmpty()){auto font=option.font;font.setPixelSize(12);painter->setFont(font);auto width=QFontMetrics(font).horizontalAdvance(b.date)+24;QRectF dateBox(option.rect.center().x()-width/2,option.rect.top()+2,width,24);painter->setPen(Qt::NoPen);painter->setBrush(QColor("#a6b69c"));painter->drawRoundedRect(dateBox,12,12);painter->setPen(Qt::white);painter->drawText(dateBox,Qt::AlignCenter,b.date);}painter->setPen(Qt::NoPen);painter->setBrush(outgoing?QColor("#effdde"):QColor("#ffffff"));painter->drawRoundedRect(box,8,8);
  QTextDocument doc;doc.setDefaultFont(option.font);QTextOption wrap;wrap.setWrapMode(QTextOption::WrapAtWordBoundaryOrAnywhere);doc.setDefaultTextOption(wrap);doc.setPlainText(b.text);doc.setTextWidth(b.width-24);painter->translate(box.left()+12,box.top()+9);doc.drawContents(painter);painter->restore();
  painter->save();auto font=option.font;font.setPixelSize(11);painter->setFont(font);painter->setPen(QColor("#6a9562"));painter->drawText(QRectF(box.left()+12,box.bottom()-22,box.width()-24,16),Qt::AlignRight|Qt::AlignVCenter,b.meta);painter->restore();
 }
private:QListWidget* view;
};
}
MessageHistory::MessageHistory(QWidget* p):QListWidget(p){setItemDelegate(new BubbleDelegate(this));setEditTriggers(QAbstractItemView::NoEditTriggers);setSelectionMode(QAbstractItemView::NoSelection);setVerticalScrollMode(QAbstractItemView::ScrollPerPixel);setHorizontalScrollBarPolicy(Qt::ScrollBarAlwaysOff);setStyleSheet("background:#dce3d5;border:0;padding:14px 28px");}
void MessageHistory::setRows(const QJsonArray& rows){clear();QList<QJsonObject> ordered;for(const auto& value:rows)ordered.append(value.toObject());std::stable_sort(ordered.begin(),ordered.end(),[](const auto& a,const auto& b){return a.value("sequence").toInteger()<b.value("sequence").toInteger();});QString previousDate;for(const auto& row:ordered){auto* item=new QListWidgetItem(row.value("text").toString(),this);item->setData(Qt::UserRole,row.value("direction").toString());item->setData(Qt::UserRole+1,row.value("state").toString());item->setData(Qt::UserRole+2,row.value("sequence").toInteger());item->setData(Qt::UserRole+3,row.value("time").toVariant());auto timestamp=row.value("time").toVariant().toLongLong();auto date=timestamp>0?QDateTime::fromMSecsSinceEpoch(timestamp).toLocalTime().toString("d MMMM"):QString();if(date!=previousDate){item->setData(Qt::UserRole+4,date);previousDate=date;}}scrollToBottom();}
QString MessageHistory::textContent()const{QStringList lines;for(int i=0;i<count();i++)lines.append(item(i)->text());return lines.join('\n');}
