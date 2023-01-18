import pefile
from capstone import *
from capstone.x86 import *
import PySimpleGUI as sg
import r2pipe
import json
import re, os

current_dir = '\\'.join(os.path.abspath(__file__).split('\\')[:-1]) + '\\'


def dissasemble_function(r2):
    
    r2.cmd('aaa') # Обязательная строка
    # Создадим список всех функций exe-файла
    r2.cmd('afl')
    aflj = re.sub(" +", " ", r2.cmd('aflj'))
    aflj = aflj.split('\r\n')
    i = 0
    for line in aflj:
        aflj[i] = line.split(' ')
        i += 1
    aflj.pop()

    # Дизассемблируем каждую из функций и запишем получившийся код в файл
    with open (current_dir + 'disassembled_exe.txt', 'w') as file_disassembled_exe:
        for func in aflj:
            r2.cmd('pdfj @ {}'.format(func[3]))
            dissasembled_function = json.loads(r2.cmd('pdfj @ {}'.format(func[3])))
            file_disassembled_exe.write('\t<{}>\n'.format(dissasembled_function['name']))
            for item in dissasembled_function['ops']:
                file_disassembled_exe.write("0x%x:\t%s" %(item['offset'], item['opcode']) + "\n")
        file_disassembled_exe.close()

    #r2.quit()


def find_call_in_disassembled_exe(call_function, function_name, function_address):
    is_the_end = 1
    str_counter = 0
    str_counter_begin = 0
    call_address = ''

#0x403f08:	jmp dword [0x408180]
#0x403f08:	call dword [0x408180]
#0x40150c:    mov edi, dword [0x40813c]
    with open (current_dir + 'disassembled_exe.txt', 'r') as file_disassembled_exe:
        for line in file_disassembled_exe:
            call_function.append(line.replace('\t', '    ').replace('\n', ''))
            if len(call_function) > 1:
                call_function.remove(call_function[0])
            if str(function_address) in line: 
                if ('jmp') in line:
                    call_address = call_function[0][:8]
                    call_function = []
                break
        file_disassembled_exe.close()

    if call_address == '':
        call_address = function_address

    with open (current_dir + 'disassembled_exe.txt', 'r') as file_disassembled_exe:
        for line in file_disassembled_exe:
            str_counter += 1
            call_function.append(line.replace('\t', '    ').replace('\n', ''))
            if len(call_function) > 10 and is_the_end == 1: # Записываются 5 последних строк файла, чтобы вывести найденный вызов функции вместе с push ее параметров
                call_function.remove(call_function[0])
            if (str_counter - str_counter_begin == 20) and str_counter != 20:
                break
            if str(call_address) in line and 'jmp' not in line: # можно подписать, в какой функции это происходит
                str_counter_begin = str_counter - 9
                is_the_end = 0
                #break
        file_disassembled_exe.close()


    if is_the_end == 0:
        for item in call_function:
            item = item + ' '
            if (' 0x40 ' in item) and (function_name != 'GetProcAddress'):
                window['OUTPUT'].update('\t{}\t{}\n'.format(str_counter_begin, item), text_color_for_value ='green', font=('Courier', 11), append=True)
            elif str(call_address) in item:
                window['OUTPUT'].update('\t{}\t{}\n'.format(str_counter_begin, item), text_color_for_value ='green', font=('Courier', 11), append=True)
            else:
                window['OUTPUT'].update('\t{}\t{}\n'.format(str_counter_begin, item), font=('Courier', 11), append=True)
            str_counter_begin += 1
    else:
        window['OUTPUT'].update('Не найден вызов функции в открытом виде.\n', text_color_for_value ='red', append=True)



def find_in_disassembled_exe(r2):
    
    # Ищем неявный вызов функций
    r2.cmd('aaa') # Обязательная строка
    list_of_implicit_function = []
    list_of_invalid_sumbols = []
    registers_list = [['a', 'b', 'c', 'd'],['e', 'r']]
    check_if_empty = 0
    for i in registers_list[0]:
        for j in registers_list[1]:
            r2.cmd('/ad/ call {}{}x'.format(j, i)) # если строка выглядит как call <регистр общего назначения>, 
            raw_list = r2.cmd('/ad/ call {}{}x'.format(j, i)).split('\r\n') # то файл содержит неявный вызов процедур
            if raw_list != []:
                raw_list.pop()
                for line in raw_list:
                    list_of_implicit_function.append(line.split('                 '))
                    check_if_empty = 1
                    break # Так как слишком долго обрабатывает
            if check_if_empty == 1:
                break
        if check_if_empty == 1:
            break

    if list_of_implicit_function != []:
        window['OUTPUT'].update(('\nДанный exe-файл содержит неявный вызов процедур.\n'), text_color_for_value ='blue', font=('Courier', 11), append=True)
    else:
        window['OUTPUT'].update(('\nДанный exe-файл НЕ содержит неявного вызова процедур.\n'), text_color_for_value ='blue', font=('Courier', 11), append=True)

    # Ищем сокрытие машинного кода (XOR отдельных функций и сегментов)
    r2.cmd('s 0x00401000')
    r2.cmd('pd')
    raw_list = r2.cmd('pd').split('\r\n')
    if raw_list != []:
        raw_list.pop()
        i = 0
        for line in raw_list:
            if str(';-- section..text:') in line:
                element = ['/ 0: section..text:', []]
                list_of_invalid_sumbols.append(element)
            if line.startswith('/'):
                element = [line, []]
                list_of_invalid_sumbols.append(element)
                i += 1
            if str('invalid') in line:
                list_of_invalid_sumbols[i][1].append(line)

    check_if_empty = 0
    if list_of_invalid_sumbols != []:    
        for elem in list_of_invalid_sumbols:
            if elem[1] != []:
                check_if_empty = 1
                window['OUTPUT'].update(('\nДанный exe-файл содержит сокрытие машинного кода в функции {}. Это было определено по следующим строкам:\n'.format(elem[0])), text_color_for_value ='blue', font=('Courier', 11), append=True)
                for line in elem[1]:
                    window['OUTPUT'].update(('\t{}\n').format(line), text_color_for_value ='blue', font=('Courier', 11), append=True)
    if check_if_empty == 0:
        window['OUTPUT'].update(('\nДанный exe-файл скорее всего НЕ содержит сокрытия машинного кода.\n'), text_color_for_value ='blue', font=('Courier', 11), append=True)

    r2.quit()



layout = [
    [sg.Text('Выберите .exe-файл:', font=('Courier', 11)), sg.InputText(font=('Courier', 11)), sg.FileBrowse()],
    [sg.Submit()],
    [sg.Multiline(font=('Courier'), key='OUTPUT', size=(100, 20))],
]

window = sg.Window('ДОП_Новикова_Тохсыров_191-351', layout)
while True:
    event, values = window.read()
    if event in (None, 'Exit'):
        break

    if event == 'Submit':
        exe_file_path = isitago = None
        if values[0]:
            exe_file_path = re.findall('.+:\/.+\.+.*', values[0])
            isitago = 1
            if not exe_file_path and exe_file_path is not None:
                window['OUTPUT'].update('Ошибка: не существует такого файла.\n', text_color_for_value ='red', append=True)
                isitago = 0
            if exe_file_path[0][-3:] != 'exe':
                window['OUTPUT'].update('Ошибка: у файла должно быть расширение .exe.\n', text_color_for_value ='red', append=True)
                isitago = 0
            elif isitago == 1:
                window['OUTPUT'].update('\n\n.\n.\n.\n\nВыбранный файл существует.', text_color_for_value ='green', append=True)
                window['OUTPUT'].update('\n{}\n'.format(exe_file_path), font=('Courier', 11), append=True)
                try:
                    exe = pefile.PE(exe_file_path[0])
                    try:
                        try:
                            r2 = r2pipe.open(exe_file_path[0])
                        except:
                            window['OUTPUT'].update('Ошибка: не получается открыть файл с помощью radare2.\n', text_color_for_value ='red', append=True)
                        dissasemble_function(r2)
                    except:
                        window['OUTPUT'].update('Что-то не так с этим файлом exe.\n', text_color_for_value ='red', append=True)
                except:
                    window['OUTPUT'].update('PEfile не может распарсить файл.\n', text_color_for_value ='red', append=True)

                window['OUTPUT'].update('\nНайдены следующие функции, на которые следует обратить внимание:\n', append=True)
                check_if_SMC = False
                for itm in exe.DIRECTORY_ENTRY_IMPORT:
                    for fun in itm.imports:
                        if (fun.name == b'VirtualProtect'): 
                            window['OUTPUT'].update('\n{}\t{}\t{}\n'.format(itm.dll, hex(fun.address), fun.name), font=('Courier', 13), text_color_for_value ='green', append=True)
                            VirtualProtect_address = hex(fun.address)
                            window['OUTPUT'].update('Функция VirtualProtect (memoryapi.h)\n', font=('Courier', 13, 'bold'), append=True)
                            window['OUTPUT'].update('Изменяет защиту в области зафиксированных страниц в виртуальном адресном пространстве вызывающего процесса.\n', font=('Courier', 11), append=True)
                            window['OUTPUT'].update('\tBOOL VirtualProtect(\n'
                            '\t  [in]  LPVOID lpAddress,\n'
                            '\t  [in]  SIZE_T dwSize,\n'
                            '\t  [in]  DWORD  flNewProtect,\n'
                            '\t  [out] PDWORD lpflOldProtect\n'
                            '\t);\n', font=('Courier', 11), append=True)
                            window['OUTPUT'].update('Наиболее интересен здесь параметр защиты памяти flNewProtect. Этот параметр может быть одной из констант защиты памяти.'
                            ' В нашем случае это должна быть константа PAGE_EXECUTE_READWRITE с кодом 0x40.'
                            ' Она включает выполнение, доступ только для чтения или чтения и записи к зафиксированной области страниц.\n', font=('Courier', 11), append=True)
                            window['OUTPUT'].update('Вызов функции VirtualProtect:\n', font=('Courier', 11), append=True)
                            call_VirtualProtect = []
                            find_call_in_disassembled_exe(call_VirtualProtect, 'VirtualProtect', VirtualProtect_address)
                            check_if_SMC = True

                        if (fun.name == b'VirtualAlloc'):
                            window['OUTPUT'].update('\n{}\t{}\t{}\n'.format(itm.dll, hex(fun.address), fun.name), font=('Courier', 13), text_color_for_value ='green', append=True)
                            VirtualAlloc_address = hex(fun.address)
                            window['OUTPUT'].update('Функция VirtualAlloc (memoryapi.h)\n', font=('Courier', 13, 'bold'), append=True)
                            window['OUTPUT'].update('Резервирует, фиксирует или изменяет состояние области страниц в виртуальном адресном пространстве вызывающего процесса.'
                            ' Память, выделенная этой функцией, автоматически инициализируется нулем.\n', font=('Courier', 11), append=True)
                            window['OUTPUT'].update('\tLPVOID VirtualAlloc(\n'
                            '\t  [in, optional] LPVOID lpAddress,\n'
                            '\t  [in]           SIZE_T dwSize,\n'
                            '\t  [in]           DWORD  flAllocationType,\n'
                            '\t  [in]           DWORD  flProtect\n'
                            '\t);\n', font=('Courier', 11), append=True)
                            window['OUTPUT'].update('Наиболее интересен здесь параметр защиты памяти для области выделяемых страниц flProtect. Этот параметр может быть одной из констант защиты памяти.'
                            ' В нашем случае это должна быть константа PAGE_EXECUTE_READWRITE с кодом 0x40.'
                            ' Она включает выполнение, доступ только для чтения или чтения и записи к зафиксированной области страниц.\n', font=('Courier', 11), append=True)
                            window['OUTPUT'].update('\nВызов функции VirtualAlloc:\n', font=('Courier', 11), append=True)
                            call_VirtualAlloc = []
                            find_call_in_disassembled_exe(call_VirtualAlloc, 'VirtualAlloc', VirtualAlloc_address)
                            check_if_SMC = True

                        # Дополнительные функции
                        if (fun.name == b'IsDebuggerPresent'):
                            window['OUTPUT'].update('\n{}\t{}\t{}\n'.format(itm.dll, hex(fun.address), fun.name), font=('Courier', 13), text_color_for_value ='green', append=True)
                            IsDebuggerPresent_address = hex(fun.address)
                            window['OUTPUT'].update('Функция IsDebuggerPresent function (debugapi.h)\n', font=('Courier', 13, 'bold'), append=True)
                            window['OUTPUT'].update('Определяет, отлаживается ли вызывающий процесс отладчиком пользовательского режима.\n', font=('Courier', 11), append=True)
                            window['OUTPUT'].update('\tBOOL IsDebuggerPresent();\n', font=('Courier', 11), append=True)
                            window['OUTPUT'].update('Если текущий процесс выполняется в контексте отладчика, возвращаемое значение не равно нулю.\n', font=('Courier', 11), append=True)

                        if (fun.name == b'WriteProcessMemory'):
                            window['OUTPUT'].update('\n{}\t{}\t{}\n'.format(itm.dll, hex(fun.address), fun.name), font=('Courier', 13), text_color_for_value ='green', append=True)
                            WriteProcessMemory_address = hex(fun.address)
                            window['OUTPUT'].update('Функция WriteProcessMemory function (memoryapi.h)\n', font=('Courier', 13, 'bold'), append=True)
                            window['OUTPUT'].update('Записывает данные в область памяти в указанном процессе. Вся область для записи должна быть доступна, иначе операция завершится ошибкой.\n', font=('Courier', 11), append=True)
                            window['OUTPUT'].update('\tBOOL WriteProcessMemory(\n'
                            '\t  [in]  HANDLE  hProcess,\n'
                            '\t  [in]  LPVOID  lpBaseAddress,\n'
                            '\t  [in]  LPCVOID lpBuffer,\n'
                            '\t  [in]  SIZE_T  nSize,\n'
                            '\t  [out] SIZE_T  *lpNumberOfBytesWritten\n'
                            '\t);\n', font=('Courier', 11), append=True)
                            window['OUTPUT'].update('Если функция завершается успешно, возвращаемое значение не равно нулю.\n', font=('Courier', 11), append=True)

                        if (fun.name == b'GetProcAddress'):
                            window['OUTPUT'].update('\n{}\t{}\t{}\n'.format(itm.dll, hex(fun.address), fun.name), font=('Courier', 13), text_color_for_value ='green', append=True)
                            GetProcAddress_address = hex(fun.address)
                            window['OUTPUT'].update('Функция GetProcAddress (libloaderapi.h)\n', font=('Courier', 13, 'bold'), append=True)
                            window['OUTPUT'].update('Извлекает адрес экспортированной функции (также называемой процедурой) или переменной из '
                            'указанной библиотеки динамической компоновки (DLL).\n', font=('Courier', 11), append=True)
                            window['OUTPUT'].update('\tFARPROC GetProcAddress(\n'
                            '\t  [in] HMODULE hModule,\n'
                            '\t  [in] LPCSTR  lpProcName\n'
                            '\t);\n', font=('Courier', 11), append=True)
                            window['OUTPUT'].update('Если функция завершается успешно, возвращаемое значение является адресом экспортированной функции или переменной.'
                            ' Параметр lpProcName может идентифицировать функцию DLL, указав порядковый номер, связанный с функцией, в операторе EXPORTS.\n', font=('Courier', 11), append=True)
                            window['OUTPUT'].update('\nВызов функции GetProcAddress:\n', font=('Courier', 11), append=True)
                            call_GetProcAddress = []
                            find_call_in_disassembled_exe(call_GetProcAddress, 'GetProcAddress', GetProcAddress_address)
                
                find_in_disassembled_exe(r2)

                if (check_if_SMC == True):
                    window['OUTPUT'].update('\nЕсть большая вероятность, что данный exe-файл включает в себя самомодифицирующийся код.\n', text_color_for_value ='red', font=('Courier', 13), append=True)
                else:
                    window['OUTPUT'].update('\nЕсть большая вероятность, что данный exe-файл НЕ включает в себя самомодифицирующийся код.\n', text_color_for_value ='red', font=('Courier', 13), append=True)

        else:
            window['OUTPUT'].update('Пожалуйста, выберите файл.\n', text_color_for_value ='red', append=True)
window.close()



            













