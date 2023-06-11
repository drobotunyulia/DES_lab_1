#include "mainwindow.h"
#include "ui_mainwindow.h"

MainWindow::MainWindow(QWidget *parent) :
    QMainWindow(parent),
    ui(new Ui::MainWindow)
{
    ui->setupUi(this);
    ui->tabWidget->setCurrentIndex(0);
    connect(ui->startPushButton, SIGNAL(clicked(bool)), this, SLOT(startCipher()));
    connect(ui->randomGenerationPushButton, SIGNAL(clicked(bool)), this, SLOT(textRandomGeneration()));
    connect(this, SIGNAL(sendCipherResult(QByteArray)), this, SLOT(receiveCipherResult(QByteArray)));
    connect(this, SIGNAL(sendDeCipherResult(QByteArray)), this, SLOT(receiveDeCipherResult(QByteArray)));
    connect(this, SIGNAL(sendCipherBlockCount(unsigned long long)), this, SLOT(receiveCipherBlockCount(unsigned long long)));
    connect(this, SIGNAL(sendDeCipherBlockCount(unsigned long long)), this, SLOT(receiveDeCipherBlockCount(unsigned long long)));

    connect(ui->encryptPlainFileOpenButton, SIGNAL(clicked(bool)), this, SLOT(getEncryptPlainFileName()));
    connect(ui->encryptCipherFileOpenButton, SIGNAL(clicked(bool)), this, SLOT(getEncryptCipherFileName()));
    connect(ui->decryptPlainFileOpenButton, SIGNAL(clicked(bool)), this, SLOT(getDecryptPlainFileName()));
    connect(ui->decryptCipherFileOpenButton, SIGNAL(clicked(bool)), this, SLOT(getDecryptCipherFileName()));

    statusCipherResult = new QLabel;
    statusDeCipherResult = new QLabel;
    statusCipherResult->setFixedWidth(220);
    statusDeCipherResult->setFixedWidth(220);
    ui->statusBar->addWidget(statusCipherResult);
    ui->statusBar->addWidget(statusDeCipherResult);
}

MainWindow::~MainWindow()
{
    delete ui;
}

void MainWindow::encryptText()
//зашифровывание и расшифровывание текста
{
    CipherMode cipher(qByteArrayToStdVector(ui->keyLineEdit->text().toLatin1()), getMode(), qByteArrayToStdVector(ui->initVectorLineEdit->text().toUtf8()));
    std::vector<unsigned char> plainText = qByteArrayToStdVector(ui->plainTextEdit->document()->toPlainText().toUtf8());
    std::vector<unsigned char> cipherText;
    unsigned long long numBlocks = cipher.encrypt(plainText, cipherText);
    emit sendCipherBlockCount(numBlocks);
    emit sendCipherResult(stdVectorToQByteArray(cipherText));
    numBlocks = cipher.decrypt(cipherText, plainText);
    emit sendDeCipherBlockCount(numBlocks);
    emit sendDeCipherResult(stdVectorToQByteArray(plainText));
}

void MainWindow::encryptFile()
//зашифровывание файла
{
    CipherMode cipher(qByteArrayToStdVector(ui->keyLineEdit->text().toLatin1()), getMode(), qByteArrayToStdVector(ui->initVectorLineEdit->text().toUtf8()));
    unsigned long long numBlocks = cipher.encrypt(ui->encryptPlainFileNameLineEdit->text().toStdString(), ui->encryptCipherFileNameLineEdit->text().toStdString());
    emit sendCipherBlockCount(numBlocks);
}

void MainWindow::decryptFile()
//расшифровывание файла
{
    CipherMode cipher(qByteArrayToStdVector(ui->keyLineEdit->text().toLatin1()), getMode(), qByteArrayToStdVector(ui->initVectorLineEdit->text().toUtf8()));
    unsigned long long numBlocks = cipher.decrypt(ui->decryptCipherFileNameLineEdit->text().toStdString(), ui->decryptPlainFileNameLineEdit->text().toStdString());
    emit sendDeCipherBlockCount(numBlocks);
}

void MainWindow::startCipher()
//нажатие на кнопку "Шифровать"
{
    if(future.isRunning())
    //проверка идет шифрование или нет (выполняется поток или нет)
    {
        QMessageBox::information(this, "Внимание!", "Дождитесь окончания процесса шифрования.",
                                               QMessageBox::Ok, QMessageBox::Ok);
        return;
    }
    if(ui->keyLineEdit->text().isEmpty())
    //проверка ключа
    {
        QMessageBox::critical(this, "Внимание!", "Необходимо ввести ключ шифрования!",
                                               QMessageBox::Ok, QMessageBox::Ok);
        return;
    }
    if(ui->initVectorLineEdit->text().isEmpty() &&
            (getMode() == CipherMode::CBC ||
            getMode() == CipherMode::CFB ||
            getMode() == CipherMode::OFB ||
            getMode() == CipherMode::CTR))
    //проверка вектора инициализации
    {
        QMessageBox::critical(this, "Внимание!", "Необходимо ввести вектор инициализации!",
                                               QMessageBox::Ok, QMessageBox::Ok);
        return;
    }
    if(ui->tabWidget->currentIndex() == 0)
    {
        ui->cipherTextEdit->clear();
        ui->decryptTextEdit->clear();
    }
    statusCipherResult->setText("");
    statusDeCipherResult->setText("");
    switch (ui->tabWidget->currentIndex()) {
    case 0:
        //если открыта вкладка "Зашифровать текст"
        //шифруем текст в отдельном потоке
        future = QtConcurrent::run([this] { encryptText(); });
        break;
    case 1:
        //если открыта вкладка "Зашифровать файл"
        //шифруем файл в отдельном потоке
        future = QtConcurrent::run([this] { encryptFile(); });
        break;
    case 2:
        //если открыта вкладка "Расшифровать файл"
        //расшифровываем файл в отдельном потоке
        future = QtConcurrent::run([this] { decryptFile(); });
        break;
    default:
        break;
    }
}

CipherMode::tMode MainWindow::getMode()
//определяем режим шифрования (возвращает значение из перечисления)
{
    return static_cast<CipherMode::tMode>(ui->modeComboBox->currentIndex());
}

std::vector<unsigned char> MainWindow::qByteArrayToStdVector(const QByteArray byteArray)
//преобразование массива типа QByteArray в массив типа std::vector<unsigned char>
{
    std::vector<unsigned char> stdVector;
    for(int i = 0; i < byteArray.size(); i++)
    {
        stdVector.push_back(byteArray[i]);
    }
    return stdVector;
}

QByteArray MainWindow::stdVectorToQByteArray(const std::vector<unsigned char> stdVector)
//преобразование массива типа std::vector<unsigned char> в массив типа QByteArray
{
    QByteArray byteArray;
    for(size_t i = 0; i < stdVector.size(); i++)
    {
        byteArray.push_back(stdVector[i]);
    }
    return byteArray;
}

void MainWindow::receiveCipherResult(QByteArray cipherText)
//слот приема зашифрованного текста для его отображения
{
    ui->cipherTextEdit->clear();
    ui->cipherTextEdit->document()->setPlainText(QString(cipherText));
}

void MainWindow::receiveDeCipherResult(QByteArray deCipherText)
//слот приема расшифрованного текста для его отображения
{
    ui->decryptTextEdit->clear();
    ui->decryptTextEdit->document()->setPlainText(QString(deCipherText));
}

void MainWindow::receiveCipherBlockCount(unsigned long long blockCount)
//слот приема числа зашифрованных блоков
{
    statusCipherResult->setText(QString("Зашифровано блоков: " + QString::number(blockCount)));
}

void MainWindow::receiveDeCipherBlockCount(unsigned long long blockCount)
//слот приема числа расшифрованных блоков
{
    statusDeCipherResult->setText(QString("Расшифровано блоков: " + QString::number(blockCount)));
}

void MainWindow::getEncryptPlainFileName()
//получение имени файла с открытым текстом
{
    if(future.isRunning())
    {
        QMessageBox::information(this, "Внимание!", "Дождитесь окончания процесса шифрования.",
                                               QMessageBox::Ok, QMessageBox::Ok);
        return;
    }
    ui->encryptPlainFileNameLineEdit->setText(QFileDialog::getOpenFileName(0, tr("Файл с открытым текстом"), "source", "*.*"));
}

void MainWindow::getEncryptCipherFileName()
//получение имени файла для зашифровывания
{
    if(future.isRunning())
    {
        QMessageBox::information(this, "Внимание!", "Дождитесь окончания процесса шифрования.",
                                               QMessageBox::Ok, QMessageBox::Ok);
        return;
    }
    ui->encryptCipherFileNameLineEdit->setText(QFileDialog::getOpenFileName(0, tr("Зашифрованный файл"), "source", "*.*"));
}

void MainWindow::getDecryptPlainFileName()
//получение имени файла с зашифрованным текстом
{
    if(future.isRunning())
    {
        QMessageBox::information(this, "Внимание!", "Дождитесь окончания процесса шифрования.",
                                               QMessageBox::Ok, QMessageBox::Ok);
        return;
    }
    ui->decryptPlainFileNameLineEdit->setText(QFileDialog::getOpenFileName(0, tr("Файл с открытым текстом"), "source", "*.*"));
}

void MainWindow::getDecryptCipherFileName()
//получение имени файла для расшифровывания
{
    if(future.isRunning())
    {
        QMessageBox::information(this, "Внимание!", "Дождитесь окончания процесса шифрования.",
                                               QMessageBox::Ok, QMessageBox::Ok);
        return;
    }
    ui->decryptCipherFileNameLineEdit->setText(QFileDialog::getOpenFileName(0, tr("Зашифрованный файл"), "source", "*.*"));
}

void MainWindow::textRandomGeneration()
//генерация псевдослучайного текста для демонстрации шифрования
{
    if(ui->tabWidget->currentIndex() != 0)
    {
        return;
    }
    if(future.isRunning())
    {
        QMessageBox::information(this, "Внимание!", "Дождитесь окончания процесса шифрования.",
                                               QMessageBox::Ok, QMessageBox::Ok);
        return;
    }
    const QString charactersLine("QWERTYUIOP{}[]ASDFGHJKL;':ZXCVBNM,.<>/?1234567890qwertyuiopasdfghjklzxcvbnm@#!&?*()-+=_|");
    QString randomString;
    std::srand(std::time(nullptr));
    for(int i = 0; i < ui->randomCharactersSpinBox->value(); i++)
    {
        QChar nextCharacter = charactersLine.at(std::rand() % charactersLine.size());
        randomString.push_back(nextCharacter);
    }
    ui->plainTextEdit->clear();
    ui->plainTextEdit->document()->setPlainText(randomString);
}
