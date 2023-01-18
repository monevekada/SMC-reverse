# SMC-reverse
## 1. Begin

Данное приложение может помочь с обнаружением наличия самомодифицирующегося кода в выбранном exe-файле, а также подсветить некоторые подозрительные паттерны ассемблерного кода.

## 2. Exploitation

1. Запускаем test_reverse.py.

2. Нажимаем на кнопку Browse и загружаем файл.

![screen1](../main/Screenshots/screen1.jpg)

3. В выводе мы можем увидеть используемые "подозрительные" Windows API функции и их вызовы (если найдены).

![screen2](../main/Screenshots/screen2.jpg)

![screen3](../main/Screenshots/screen3.jpg)

4. Также в выводе показывается, используется ли явное связывание DLL.

![screen7](../main/Screenshots/screen7.jpg)

![screen8](../main/Screenshots/screen8.jpg)

5. Далее мы можем увидеть, используется ли неявный вызов процедур и сокрытие машинного кода в exe-файле.

Пример 1:

![screen4](../main/Screenshots/screen4.jpg)

Пример 2:

![screen5](../main/Screenshots/screen5.jpg)

Пример 3:

![screen6](../main/Screenshots/screen6.jpg)

## 3. References

Самомодифицирующийся код (win32): https://habr.com/ru/post/272619/ <br/>
SMC под Linux: https://tproger.ru/translations/writing-a-self-mutating-program/ <br/>
Связывание исполняемого файла с библиотекой DLL: https://learn.microsoft.com/ru-ru/cpp/build/linking-an-executable-to-a-dll?view=msvc-170 <br/>
Функция VirtualProtect: https://learn.microsoft.com/ru-ru/windows/win32/api/memoryapi/nf-memoryapi-virtualprotect <br/>
Advanced self-modifying code: https://migeel.sk/blog/2007/08/02/advanced-self-modifying-code/ <br/>
Фундаментальные основы хакерства. Боремся с дизассемблерами и затрудняем реверс программ: https://xakep.ru/2022/08/25/nezumi-hacking-guide-27/ <br/>
