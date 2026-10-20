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
struct Bubble {QString text,meta;int width,height;};
Bubble measure(const QStyleOptionViewItem& option,const QModelIndex& index,int available){
 const auto text=index.data().toString();const auto state=statusText(index.data(Qt::UserRole+1).toString());const auto timestamp=index.data(Qt::UserRole+3).toLongLong();const auto time=timestamp>0?QDateTime::fromMSecsSinceEpoch(timestamp).toLocalTime().toString("HH:mm"):QString();const QString meta=time.isEmpty()?state:time+"  ·  "+state;
 const auto metrics=QFontMetrics(option.font);int natural=120;for(const auto& line:text.split('\n'))natural=qMax(natural,metrics.horizontalAdvance(line)+24);
 const int width=qMin(qMax(160,int(available*.72)),qMax(natural,metrics.horizontalAdvance(meta)+24));
 QTextDocument document;document.setDefaultFont(option.font);QTextOption wrap;wrap.setWrapMode(QTextOption::WrapAtWordBoundaryOrAnywhere);document.setDefaultTextOption(wrap);document.setPlainText(text);document.setTextWidth(width-24);
 return {text,meta,width,int(document.size().height())+36};
}
class BubbleDelegate final:public QStyledItemDelegate {
public:
 explicit BubbleDelegate(QListWidget* owner):QStyledItemDelegate(owner),view(owner){}
 QSize sizeHint(const QStyleOptionViewItem& option,const QModelIndex& index)const override{const auto b=measure(option,index,view->viewport()->width()-20);return {view->viewport()->width(),b.height+12};}
 void paint(QPainter* painter,const QStyleOptionViewItem& option,const QModelIndex& index)const override{
  const auto b=measure(option,index,view->viewport()->width()-20);const bool outgoing=index.data(Qt::UserRole).toString()=="out";const int x=outgoing?option.rect.right()-b.width-10:option.rect.left()+10;const QRectF box(x,option.rect.top()+6,b.width,b.height);
  painter->save();painter->setRenderHint(QPainter::Antialiasing);painter->setPen(Qt::NoPen);painter->setBrush(outgoing?QColor("#d3ede6"):QColor("#ffffff"));painter->drawRoundedRect(box,12,12);
  QTextDocument doc;doc.setDefaultFont(option.font);QTextOption wrap;wrap.setWrapMode(QTextOption::WrapAtWordBoundaryOrAnywhere);doc.setDefaultTextOption(wrap);doc.setPlainText(b.text);doc.setTextWidth(b.width-24);painter->translate(box.left()+12,box.top()+9);doc.drawContents(painter);painter->restore();
  painter->save();auto font=option.font;font.setPixelSize(11);painter->setFont(font);painter->setPen(QColor("#657f7b"));painter->drawText(QRectF(box.left()+12,box.bottom()-22,box.width()-24,16),Qt::AlignRight|Qt::AlignVCenter,b.meta);painter->restore();
 }
private:QListWidget* view;
};
}
MessageHistory::MessageHistory(QWidget* p):QListWidget(p){setItemDelegate(new BubbleDelegate(this));setEditTriggers(QAbstractItemView::NoEditTriggers);setSelectionMode(QAbstractItemView::NoSelection);setVerticalScrollMode(QAbstractItemView::ScrollPerPixel);setHorizontalScrollBarPolicy(Qt::ScrollBarAlwaysOff);setStyleSheet("background:#edf5f3;border:0;border-radius:10px;padding:8px");}
void MessageHistory::setRows(const QJsonArray& rows){clear();QList<QJsonObject> ordered;for(const auto& value:rows)ordered.append(value.toObject());std::stable_sort(ordered.begin(),ordered.end(),[](const auto& a,const auto& b){return a.value("sequence").toInteger()<b.value("sequence").toInteger();});for(const auto& row:ordered){auto* item=new QListWidgetItem(row.value("text").toString(),this);item->setData(Qt::UserRole,row.value("direction").toString());item->setData(Qt::UserRole+1,row.value("state").toString());item->setData(Qt::UserRole+2,row.value("sequence").toInteger());item->setData(Qt::UserRole+3,row.value("time").toVariant());}scrollToBottom();}
QString MessageHistory::textContent()const{QStringList lines;for(int i=0;i<count();i++)lines.append(item(i)->text());return lines.join('\n');}
