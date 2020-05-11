import sys
from PyQt5 import QtWidgets
from maket2 import Ui_MainWindow  # импорт нашего сгенерированного файла
from OpenSSL import crypto
from PyQt5.QtWidgets import *

class mywindow(QtWidgets.QMainWindow):
    def __init__(self):
        super(mywindow, self).__init__()
        self.ui = Ui_MainWindow()
        self.ui.setupUi(self)
        self.ui.pushButton.clicked.connect(self.create_signed_cert)
        self.ui.sertificateButton.clicked.connect(self.getFileNameSertificate)
        self.ui.pushButton_3.clicked.connect(self.getFileNameKey)
        self.ui.pushButton_2.clicked.connect(self.create_self_signed_cert)#подписанный сертификат
        self.key = None
        self.sertificate = None


    def getFileNameSertificate(self):
        filename,filetype = QFileDialog.getOpenFileName(self,
                             "Выбрать файл",
                             ".",
                             "(*.crt)")
        self.sertificate = filename


    def getFileNameKey(self):
        filename, filetype = QFileDialog.getOpenFileName(self,
                             "Выбрать файл",
                             ".",
                             "(*.key)")
        self.key =filename


    def create_signed_cert(self):
        KEY_FILE = "signet.key"
        CERT_FILE = "signet.crt"
        #  Загружаем промежуточный сертификат для подписи
        ca_cert = crypto.load_certificate(crypto.FILETYPE_PEM, open(self.sertificate).read())
        #  Загружаем промежуточный ключ, последний параметр пароль
        ca_key = crypto.load_privatekey(crypto.FILETYPE_PEM, open(self.key).read())

        k = crypto.PKey()
        k.generate_key(crypto.TYPE_RSA, 2048)  # размер может быть 2048, 4196

        cert = crypto.X509()
        cert.get_subject().C = self.ui.lineEdit.text()
        cert.get_subject().ST = self.ui.lineEdit_2.text()
        cert.get_subject().L = self.ui.lineEdit_3.text()
        cert.get_subject().O = self.ui.lineEdit_4.text()
        cert.get_subject().OU = self.ui.lineEdit_5.text()
        cert.get_subject().CN = self.ui.lineEdit_6.text()
        cert.set_serial_number(1000)
        cert.gmtime_adj_notBefore(0)
        cert.gmtime_adj_notAfter(10 * 365 * 24 * 60 * 60)  # срок "жизни" сертификата
        cert.set_issuer(ca_cert.get_subject())
        cert.set_pubkey(k)
        cert.sign(ca_key, "sha1")

        open(CERT_FILE, "wb").write((crypto.dump_certificate(crypto.FILETYPE_PEM, cert)))
        open(KEY_FILE, "wb").write((crypto.dump_privatekey(crypto.FILETYPE_PEM, k)))
        sys.exit(app.exec())

    def create_self_signed_cert(self):
        CERT_FILE = "selfsigned.crt"
        KEY_FILE = "selfsignet.key"

        # create a key pair
        k = crypto.PKey()
        k.generate_key(crypto.TYPE_RSA, 2048)

        # create a self-signed cert
        cert = crypto.X509()
        cert.get_subject().C = self.ui.lineEdit.text()
        cert.get_subject().ST = self.ui.lineEdit_2.text()
        cert.get_subject().L = self.ui.lineEdit_3.text()
        cert.get_subject().O = self.ui.lineEdit_4.text()
        cert.get_subject().OU = self.ui.lineEdit_5.text()
        cert.get_subject().CN = self.ui.lineEdit_6.text()
        cert.set_serial_number(1000)
        cert.gmtime_adj_notBefore(0)
        cert.gmtime_adj_notAfter(10 * 365 * 24 * 60 * 60)
        cert.set_issuer(cert.get_subject())
        cert.set_pubkey(k)
        cert.sign(k, 'sha1')

        open(CERT_FILE, "wb").write((crypto.dump_certificate(crypto.FILETYPE_PEM, cert)))
        open(KEY_FILE, "wb").write((crypto.dump_privatekey(crypto.FILETYPE_PEM, k)))
        sys.exit(app.exec())


app = QtWidgets.QApplication([])
application = mywindow()
application.show()

sys.exit(app.exec())
