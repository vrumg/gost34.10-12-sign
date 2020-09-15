package crypto

// #cgo CFLAGS: -O3 -m64 -I ../include
// #cgo LDFLAGS: -pthread -L. -lmesprox -lc
// #include "mespro.h"
// #include <time.h>
// #include <sys/timeb.h>
// #include <stdlib.h>
import "C"
import (
	"unsafe"

	"github.com/juju/errors"
)

//Для инициализации библиотеки требуется указать директории и сертификаты
var (
	rootDir          string //корневой путь
	containerDir     string //путь к контейнеру контейнерами
	caDir            string //путь к корневым сертификатам CA
	certSenderPath   string //путь к открытому сертификату, на котором производится подпись 
	certRecieverPath string //путь к открытому сертификату, на котором производится проверка подписи
	crlDir           string //путь к списку отозванных сертификатов
)

//InitCryptoCerts инициализация переменных, директорий и само-проверка работы библиотеки
func InitCryptoCerts(root string, container string, ca string, certSender string, certReciever string, crl string) error {
	//Инициализация путей
	rootDir = root
	containerDir = container
	caDir = ca
	certSenderPath = certSender
	certRecieverPath = certReciever
	crlDir = crl

	//Инициализация библиотеки
	errC := C.PKCS7Init(C.CString(containerDir), 0)
	if errC != 0 {
		return errors.Annotate(errors.New("external call PKCS7Init"), "Failed to initialize crypto pkcs")
	}

	//Самопроверка
	err := selfCheckVars()
	if err != nil {
		return errors.Annotate(err, "Crypto self-check failed")
	}

	return nil
}

//FreeCryptoVars освободить подключение к динамической библиотеке
func FreeCryptoVars() {
	C.PKCS7Final()
}

//selfCheckVars самопроверка функции подписи буфера
func selfCheckVars() error {
	text := "Hello world!"
	_, err := MakeSignatureFromString(&text)
	if err != nil {
		return errors.Annotate(err, "Failed to self-generate signature")
	}

	return nil
}

//GetSignAlgoString получить наименование алгоритма для подписи
func GetSignAlgoString() string {
	return "GOST3410-12-512"
}

//MakeSignatureFromString подпись текста
//Return singnature string, error
func MakeSignatureFromString(text *string) (string, error) {
	//Установка алгоритма
	C.SetDigestAlgorithm(C.CString("MP_HASH_ALG_NAME_GOST_2012_512"))
	C.InsertCertificateToSign(C.int(0))
	C.InsertSigningTimeToSign(C.int(0))

	//Функции подписи и проверки подписи с использованием ключей СКЗИ.
	//Формирование подписи.
	//Считываем из СКЗИ секретный ключ автора подписи.
	//Ключи СКЗИ могут быть считаны также функциями
	//AddPSEPrivateKeyFromBuffer() и AddPSEPrivateKeys()
	err := C.AddPSEPrivateKey(C.CString(containerDir), nil)
	if err != 0 {
		return "", errors.Annotate(errors.New("external call AddPSEPrivateKey"), "Failed to add private key")
	}

	//Считываем в память сертификаты Удостоверяющего центра (УЦ)
	//для проверки сертификата автора подписи и списков отозванных сертификатов.
	err = C.AddCAs(C.CString(caDir))
	if err != 0 {
		return "", errors.Annotate(errors.New("external call AddCAs"), "Failed to add certificate authority")
	}

	//Создание контекста подписи.
	sgnCtx := C.GetSignCTX()
	if sgnCtx == nil {
		return "", errors.Annotate(errors.New("external call GetSignCTX"), "Failed to creat signature context")
	}

	//Добавление автора подписи в контекст. Задаем флаг C.BY_FILE, есть и другие варианты.
	err = C.AddSigner(sgnCtx, C.BY_FILE, unsafe.Pointer(C.CString(certSenderPath)), nil)
	if err != 0 {
		return "", errors.Annotate(errors.New("external call AddSigner"), "Failed to add signer to contex")
	}

	//В данном примере подпись формируется отдельно от данных (шестой параметр)
	//Буфер для подписи будет выделен внутри функции "SignBufferEx"
	//т.к. указатель на буфер buf равен нулю.
	buf := make([]byte, 0)
	bufLenC := C.int(0)
	cbuf := C.CBytes(buf)
	ctext := C.CBytes([]byte(*text))

	//Получаем размер буфера для подписи
	err = C.SignBufferEx(sgnCtx, ctext, C.int(0), &cbuf, &bufLenC, C.int(1))
	//SignBufferEx returns code 160 because we dont allocate buffer memory and are waiting for bufLenC to allocate exact amount of bytes
	if err != 0 && err != 160 {
		return "", errors.Annotatef(errors.New("external call SignBufferEx error"), "Failed to calculate buffer size: error - %d", err)
	}
	//Выделяем буфер
	buf = make([]byte, bufLenC)
	cbuf = C.CBytes(buf)

	//Вызываем повторно с точным размером буфера и получаем подпись
	err = C.SignBufferEx(sgnCtx, ctext, C.int(len(*text)), &cbuf, &bufLenC, C.int(1))
	if err != 0 {
		return "", errors.Annotate(errors.New("external call SignBufferEx"), "Failed to retrieve signature out of context")
	}

	//Освобождаем контекст подписи.
	C.FreeSignCTX(sgnCtx)
	sgnCtx = nil

	//Конвертируем результат
	buf = C.GoBytes(cbuf, bufLenC)
	retString := string(buf)

	return retString, nil
}

//CheckSignatureByString compare text and crypted signature for compliance.
//Return true on success signature check, false and error on failure
func CheckSignatureByString(text *string, sig *string) (bool, error) {
	//Проверка подписи.
	//Считываем в память сертификаты Удостоверяющего центра
	//для проверки сертификата автора подписи и списков отозванных сертификатов.
	err := C.AddCAs(C.CString(caDir))
	if err != 0 {
		return false, errors.Annotate(errors.New("external call AddCAs"), "Failed to add certificate authority")
	}

	//Считываем в память списки отозванных сертификатов.
	err = C.AddCRLs(C.CString(crlDir))
	if err != 0 {
		return false, errors.New("AddCRLs")
	}

	//Создание контекста проверки подписи.
	sgnCtx := C.GetSignCTX()
	if sgnCtx == nil {
		return false, errors.Annotate(errors.New("external call GetSignCTX"), "Failed to create signature context")
	}

	//Добавление автора подписи в контекст (задаем файл его сертификата).
	err = C.AddSigner(sgnCtx, C.BY_FILE, unsafe.Pointer(C.CString(certRecieverPath)), nil)
	if err != 0 {
		return false, errors.Annotate(errors.New("external call AddSigner"), "Failed to add signer to contex")
	}

	//Проверка подписи блока данных.
	ctext := C.CBytes([]byte(*text))
	csig := C.CBytes([]byte(*sig))
	err = C.CheckBufferSignEx(sgnCtx, csig, C.int(len(*sig)), nil, nil, 0, ctext, C.int(len(*text)))
	if err != 0 {
		return false, errors.Annotate(errors.New("external call CheckBufferSignEx"), "Failed to check signature out of context")
	}

	//Освобождаем контекст проверки подписи.
	C.FreeSignCTX(sgnCtx)
	sgnCtx = nil

	return true, nil
}
