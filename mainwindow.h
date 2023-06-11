#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QFuture>
#include <QtConcurrent/QtConcurrent>
#include <QString>
#include <QByteArray>
#include <QFileDialog>
#include <QMessageBox>
#include "cipher_include/ciphermode.h"

namespace Ui {
class MainWindow;
}

class MainWindow : public QMainWindow
{
    Q_OBJECT
signals:
    void sendCipherResult(QByteArray cipherText);
    void sendDeCipherResult(QByteArray deCipherText);
    void sendCipherBlockCount(unsigned long long blockCount);
    void sendDeCipherBlockCount(unsigned long long blockCount);
public:
    explicit MainWindow(QWidget *parent = 0);
    ~MainWindow();
    void encryptText();
    void encryptFile();
    void decryptFile();
public slots:
    void startCipher();
    void receiveCipherResult(QByteArray cipherText);
    void receiveDeCipherResult(QByteArray deCipherText);
    void receiveCipherBlockCount(unsigned long long blockCount);
    void receiveDeCipherBlockCount(unsigned long long blockCount);
    void getEncryptPlainFileName();
    void getEncryptCipherFileName();
    void getDecryptPlainFileName();
    void getDecryptCipherFileName();
    void textRandomGeneration();

private:
    CipherMode::tMode getMode();
    std::vector<unsigned char> qByteArrayToStdVector(const QByteArray byteArray);
    QByteArray stdVectorToQByteArray(const std::vector<unsigned char> stdVector);

    QByteArray byteArrayCipherText;
    Ui::MainWindow *ui;
    QLabel *statusCipherResult;
    QLabel *statusDeCipherResult;
    QFuture<void> future;
};

#endif // MAINWINDOW_H
