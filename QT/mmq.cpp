/*
 * Code By Magnus Jonsson / SA2BRJ / fot@fot.nu
 * Released under GPL. See LICENSE
 */

#include "mmq.h"

#include <QDateTime>

MMQ::MMQ(QObject *parent) :
	QObject(parent)
{
	authId  = -1;
	sendseq = 0;
	isAuth  = false;
	timeout = 5;
}

void MMQ::doConnect(QString hostname, int port)
{
	socket = new QTcpSocket(this);

	connect(socket, SIGNAL(connected()),this, SLOT(tcp_connected()));
	connect(socket, SIGNAL(disconnected()),this, SLOT(tcp_disconnected()));
	connect(socket, SIGNAL(readyRead()),this, SLOT(readyRead()));

	// this is not blocking call
	socket->connectToHost(hostname, port);

	// we need to wait...
	if(!socket->waitForConnected(5000))
	{
		qDebug() << "Error: " << socket->errorString();
	}
}

void MMQ::tcp_connected()
{
	emit connected();
}

void MMQ::tcp_disconnected()
{
	emit disconnected();
}

void MMQ::readyRead()
{
	while(socket->canReadLine()) {
		int size = socket->bytesAvailable() + 1;
		QByteArray line = socket->readLine(size);
		line.replace("\r","");
		line.replace("\n","");
		if(!process(line)) {
			socket->close();
		}
	}
	// remove old status...
	statusMutex.lock();
	foreach(QJsonObject v, status.values()) {
		if(v["_timestamp_"].toInt()+10 < QDateTime::currentMSecsSinceEpoch() / 1000) {
			status.remove(v["id"].toInt());
		}
	}
	statusMutex.unlock();
}

int MMQ::process(QByteArray &line) {
	QByteArray decoded = QByteArray::fromBase64(line);
	qDebug() << decoded.data();
	QJsonDocument jsonDoc = QJsonDocument::fromJson(decoded);
	if(!jsonDoc.isObject()) {
		return 0;
	}
	QJsonObject msg = jsonDoc.object();
	if(!msg.contains("id")) {
		return 0;
	}
	if(!msg.contains("type")) {
		return 0;
	}
	if(msg["type"].toString() == "AUTH") {
		if(!msg.contains("challange")) {
			return 0;
		}
		QJsonObject response;
		response["type"] = QString("AUTH");
		QMessageAuthenticationCode code(QCryptographicHash::Sha1);
		code.setKey(key);
		QByteArray challange;
		challange.append(msg["challange"].toString());
		code.addData(challange);
		QString challangeStr(code.result().toHex());
		response["key"] = challangeStr;
		authId = sendMsg(response);
		if(authId == -1) {
			return 0;
		}
		return 1;
	}
	if(msg["type"].toString() == "STATUS") {
		if(!msg.contains("status")) {
			return 0;
		}
		if(msg["status"] != QString("OK")) {
			return 0;
		}
		if(msg["id"].toInt() == authId) {
			isAuth = true;
			emit authenticated();
			return 1;
		}
		msg["_timestamp_"] = (int)(QDateTime::currentMSecsSinceEpoch()/1000);
		statusMutex.lock();
		status.insert(msg["id"].toInt(),msg);
		statusCondition.wakeAll();
		statusMutex.unlock();
		return 1;
	}
	if(!auth()) {
		return 0;
	}
	// TODO: Not implemented yet!
	if(msg["type"].toString() == "RPC") {
		return 0;
	}
	if(msg["type"].toString() == "PACKET") {
		if(!msg.contains("queue")) {
			return 0;
		}
		if(!msg.contains("data")) {
			return 0;
		}
		emit packet(QString(msg["queue"].toString()),msg["data"]);
		return 1;
	}
	return 0;
}

bool MMQ::auth() {
	return isAuth;
}

qint64 MMQ::sendMsg(QJsonObject msg) {
	if(!msg.contains("id")) {
		msg["id"] = sendseq++;
	}
	qint64 id = msg["id"].toInt();
	QJsonDocument doc(msg);
	QByteArray data = doc.toJson(QJsonDocument::Compact).toBase64(QByteArray::Base64Encoding);
	data.append("\r\n");
	if(socket->write(data) == -1) {
		return -1;
	}
	return id;
}

bool MMQ::subscribe(QString queue) {
	QJsonObject msg;
	msg["type"] = QString("SUBSCRIBE");
	msg["queue"] = queue;
	qint64 id = sendMsg(msg);
	if(id) {
		// TODO wait for ID to return :-|
	}
	return true;
}

void MMQ::setKey(QString key) {
	this->key.clear();
	this->key.append(key);
}

void MMQ::setTimeout(int sec) {
	timeout = sec;
}

bool MMQ::send(QString queue, QJsonValue data) {
	QJsonObject response;
	response["type"] = QString("PACKET");
	response["queue"] = queue;
	response["data"] = data;
	qint64 id = sendMsg(response);
	if(id == -1) {
		return false;
	}
	return waitId(id);
}

bool MMQ::waitId(qint64 id, QJsonObject &obj) {
	qint64 start = QDateTime::currentMSecsSinceEpoch();	
	while(start+timeout*1000 > QDateTime::currentMSecsSinceEpoch()) {
		if(!statusMutex.tryLock(1000)) {
			continue;
		}
		if(!statusCondition.wait(&statusMutex,1000)) {
			statusMutex.unlock();
			continue;
		}
		if(!status.contains(id)) {
			statusMutex.unlock();
			continue;
		}
		obj = status[id];
		status.remove(id);
		statusMutex.unlock();
		qDebug() << "Got Id :" << id;
		return true;
	}
	qDebug() << "Fail to get Id :" << id;
	return false;
}

bool MMQ::waitId(qint64 id) {
	qDebug() << "Waiting for: " << id;
	qint64 start = QDateTime::currentMSecsSinceEpoch();	
	while(start+timeout*1000 > QDateTime::currentMSecsSinceEpoch()) {
		QCoreApplication::processEvents();
		continue;
		if(!statusMutex.tryLock(1000)) {
			continue;
		}
		if(!statusCondition.wait(&statusMutex,1000)) {
			statusMutex.unlock();
			continue;
		}
		if(!status.contains(id)) {
			statusMutex.unlock();
			continue;
		}
		status.remove(id);
		statusMutex.unlock();
		qDebug() << "Got Id :" << id;
		return true;
	}
	qDebug() << "Fail to get Id :" << id;
	return false;
}

