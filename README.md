# Дополнительное задание по дисциплине "Методы и средства криптографической защиты информации"

## Задание выдано:
    - Асадову Руслану Эмилевичу
    - Обухову Алексею Сергеевичу

## Задание:
    1. Графическая форма с полями для ввода ключа, расширения, кнопкой для загрузки и выгрузки драйвера;
    2. Приложение должно уметь сворачиваться в трей;
    3. Приложение должно управлять драйвером при помощи API (без использования консольных команд);
## Техническая информация по заданию
1. Клиентское приложение сохраняет ключ и расширение в файл по пути:
   `%USERPROFILE%\ptsettings.pts`
   в формате:\
   1-я строка - ключ\
   2-я строка - расширение\
   Файл шифруется при помощи шифрования AES со статичными ключом и IV
