/*
 * Code By Magnus Jonsson / SA2BRJ / fot@fot.nu
 * Released under GPL. See LICENSE
 */

#ifndef MMQ_H
#define MMQ_H

#include <QCoreApplication>
#include <QObject>
#include <QTcpSocket>
#include <QAbstractSocket>
#include <QDebug>
#include <QJsonDocument>
#include <QJsonObject>
#include <QMessageAuthenticationCode>
#include <QWaitCondition>
#include <QMutex>

class MMQ : public QObject
{
    Q_OBJECT
public:
    explicit MMQ(QObject *parent = 0);
    void doConnect(QString hostname, int port);
	 bool subscribe(QString queue);
	 bool send(QString queue, QJsonValue data);
	 void setKey(QString key);
	 void setTimeout(int sec);
	 bool waitId(qint64 id);
	 bool waitId(qint64 id, QJsonObject &obj);

signals:
	 void packet(QString queue,QJsonValue data);
	 void authenticated();
    void connected();
    void disconnected();

public slots:
    void tcp_connected();
    void tcp_disconnected();
    void readyRead();
	 bool auth();

private:
    QTcpSocket *socket;
	 QMutex statusMutex;
	 QWaitCondition statusCondition;
	 int process(QByteArray &line);
	 qint64 authId;
	 qint64 sendseq;
	 qint64 sendMsg(QJsonObject);
	 QMap<qint64, QJsonObject> status;
	 bool isAuth;
	 QByteArray key;
	 int timeout;
};

#endif // MMQ_H
