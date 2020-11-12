# Пример использования криптопровайдера НУЦ РК Kalkancrypt в iOS

Библиотека криптопровайдера выдается по запросу при обращении в НУЦ РК.

**ВНИМАНИЕ!**
Обдумывайте каждую скопированную строчку! Тщательно обрабатывайте коды ошибок! Пример был слеплен на скорую руку!

### Зависимости

------

libkalkancrypt

libxml2

### Функции

------

- Генерация ключевых пар (ГОСТ 34.310-2004, RSA) и запись в PEM
- Подпись XML (ГОСТ 34.310-2004, RSA)

### Запуск

------

В *Build Settings* проекта указаны

```
HEADER_SEARCH_PATHS = $(PROJECT_DIR)/include
                      $(SDKROOT)/usr/include/libxml2
LIBRARY_SEARCH_PATHS = $(PROJECT_DIR)/lib
```

т.е. библиотеку и заголовочные файлы криптопровайдера нужно положить в папку проекта.

Также в папку **XmlTest** нужно положить файл(ы) хранилища PKCS#12, добавить в *Build Phases* -> *Copy Bundle Resources*, затем во **ViewController.m** исправить `pkcs12_path` на название файла, которое было добавлено.

