from KlAkOAPI.AdmServer import KlAkAdmServer
from KlAkOAPI import Updates
from KlAkOAPI import HostGroup
from KlAkOAPI import ChunkAccessor



import urllib3  #
import socket   #
import struct   #
import csv      # вывод результатов в формате CSV
import passwd   # файл с логинами/паролями, которй в GIT не идёт
import argparse # разбор командной строки
import console     # модуль сообщений для опций командной строки


#!!!!!!!!!!!!!!!!!!!!!
#TODO Можно сделать ...
#!!!!!!!!!

username = passwd.username
password = passwd.password

def ConnectKSC(ip):
    while True:
        try:
            connect = KlAkAdmServer.Create(ip, username, password, verify=False, vserver='')
            return connect
        except Exception as e:
            print(e)
            return None


def get_status_hosts(server, ip):
#получение информации о датах обновлений
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        params = []
        if server is not None:
            straccessor = Updates.KlAkUpdates(server).GetUpdatesInfo(pFilter=params)
            ncount = straccessor.RetVal()
            if ip == KSC_LIST['WINDOWS']:
                data = ncount[1]
                print('')
                print('KSC ======== [ {} ] ========'.format(KSC_LIST['WINDOWS']))
                print('Дата создания: {}'.format(data['Date'] + timedelta(hours=3)))
                print('Дата получения: {}'.format(data['KLUPDSRV_BUNDLE_DWL_DATE'] + timedelta(hours=3)))
                print('============================')
            elif ip == KSC_LIST['LINUX']:
                data = ncount[2]
                print('')
                print('KSC ======== [ {} ] ========'.format(KSC_LIST['LINUX']))
                print('Дата создания: {}'.format(data['Date'] + timedelta(hours=3)))
                print('Дата получения: {}'.format(data['KLUPDSRV_BUNDLE_DWL_DATE'] + timedelta(hours=3)))
                print('============================')
        else:
            print('Ошибка доступа к серверу')

def get_KSC_from_file(ioInFile):
#читаем списко ip-адресов KSC из файла и возвращаем в виде списка
    KSC_LIST= [line.strip()  for line in ioInFile if line.strip() != '']
    return KSC_LIST
#return ioInFile.readlines()
#    with ioInFile as file:
        # for line_number, line in enumerate(file, start=1):
        #     print(f"Строка {line_number}: {line.strip()}")
        # for line in file:
        #     KSC_LIST = ','.join(part.strip() for part in line.split(','))
        #     print(cf)
def get_hostes_from_file(ioInFile):
# получаем из файла имена устройств
    HOSTS_LIST= [line.strip()  for line in ioInFile if line.strip() != '']
    return HOSTS_LIST

def convert_int_to_ip(n):
# convert integer to IP4 address
# IP4 addresses can be represented in big-endian byte order,
    return socket.inet_ntoa(struct.pack('<I', n))

def convert_KLHST_WKS_STATUS_ID(n):
    match n:
      case 0:
        return "OK"
      case 1:
        return "Критический"
      case 2:
        return "Предупреждение"
      case _:
        return n

def convert_KLHST_WKS_STATUS(n):
    status = []
    status.append("Видим в сети") if n & 0b1 else  status.append("НЕ в сети")
    status.append("Агент администрирования установлен") if n & 0b100 else status.append("Агент администрирования НЕ установлен")
    status.append("Агент администрирования запущен") if n & 0b1000 else status.append("Агент администрирования НЕ запущен")
    status.append("Постоянная защита установлена") if n & 0b10000 else status.append("Постоянная защита НЕ установлена")
    return status

def convert_KLHST_WKS_RTP_STATE(n):
    match n:
      case 0:
        return "Неизвестно"
      case 1:
        return "Остановлена"
      case 2:
        return "Suspended"
      case 3:
        return "Стартует"
      case 4:
        return "Запущена"
      case 5:
        return "Запущена с максимальной защитой"
      case 6:
        return "Запущена с максимальной производительностью"
      case 7:
        return "Запущена с рекомендуемыми настройками"
      case 8:
        return "Запущена с пользовательскими настройками"
      case 9:
        return "Ошибка"
      case _:
        return n

def save_to_csv(lstHostsData, ioOutFile):
# сохраняем список с данными хостов в файл формата CSV
    # список заголовков для данных хоста
    replacements = {
    "KLHST_WKS_DN": 'Имя',
    "KLHST_WKS_IP": 'IP',
    "KLHST_WKS_GROUPID": 'Группа',
    "grp_full_name":'Полное название группы',
    "KLHST_WKS_FROM_UNASSIGNED":'The parameter accepts true if host is located in "Unassigned computers" or its subgroup.',
    "KLHST_WKS_LAST_VISIBLE": 'Последнее появление в сети',
    "KLHST_WKS_FQDN":'DNS-имя',
    "KLHST_WKS_OS_NAME": 'Тип операционной системы',
    "KLHST_WKS_COMMENT": 'Описание',
    "KLHST_WKS_STATUS_ID": 'Дополнительная информация о статусе',
    "KLHST_WKS_STATUS": 'Статус',
    "KLHST_WKS_RTP_STATE": 'Статус постоянной защиты'}
    # Extract all unique keys (headers)
    fieldnames = set()
    for entry in lstHostsData:
        fieldnames.update(entry.keys())
    fieldnames = list(fieldnames)
    # For replace the field names (headers)
#    fieldnames = ["KLHST_WKS_DN", "KLHST_WKS_IP", "KLHST_WKS_GROUPID"]
    headers = {x:replacements.get(x) for x in fieldnames}

#my_list = list(map(lambda x: new_value if x == old_value else x, my_list))
    # Writing to CSV
#    with open(strFileName, mode='w', newline='') as file:
#    with ioOutFile as file:
    writer = csv.DictWriter(ioOutFile, fieldnames=fieldnames)
# протестируем наличие строк в файле, если есть, заголовок добавлять не будем
    ioOutFile.seek(0, 2) # go to end of file
    if ioOutFile.tell(): # if current position is true (i.e != 0)
        pass
    else:   #file is empty
        writer.writerow(headers)    # write the header
    #writer.writeheader(headers)  # Write header row
    writer.writerows(lstHostsData)  # Write data rows

def get_host_info(server, strQueryString):
#получение информации об устройстве
# strQueryString - Host display name
# примеры strQueryString: "*Name*", "nAME",
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    params = []
    if server is not None:
        oHostGroup = HostGroup.KlAkHostGroup(server)
        strAccessor = oHostGroup.FindHosts(
            'KLHST_WKS_DN = "' + strQueryString + '"',
            ["KLHST_WKS_GROUPID", "grp_full_name", "KLHST_WKS_FROM_UNASSIGNED", "KLHST_WKS_DN",
             "KLHST_WKS_IP", "KLHST_WKS_LAST_VISIBLE", "KLHST_WKS_FQDN", "KLHST_WKS_OS_NAME",
             "KLHST_WKS_COMMENT",  "KLHST_WKS_STATUS_ID", "KLHST_WKS_STATUS", "KLHST_WKS_RTP_STATE"],
            [], {'KLGRP_FIND_FROM_CUR_VS_ONLY': True},
            lMaxLifeTime=60 * 60 * 3).OutPar('strAccessor')

        nStart = 0
        nStep = 100
        oChunkAccessor = ChunkAccessor.KlAkChunkAccessor(server)
        nCount = oChunkAccessor.GetItemsCount(strAccessor).RetVal()
#        print("Found hosts count:", nCount)
        result = []
        while nStart < nCount:
            oChunk = oChunkAccessor.GetItemsChunk(strAccessor, nStart, nStep)
            parHosts = oChunk.OutPar('pChunk')['KLCSP_ITERATOR_ARRAY']
#по-хорошему надо получить все ключи через oObj.GetNames, а потом значения через GetValue. Но мне для формирования выходной структуры удобнее так
            for oObj in parHosts:
                host = {}
                host["KLHST_WKS_DN"] = oObj['KLHST_WKS_DN']
                host["KLHST_WKS_IP"] = convert_int_to_ip(oObj['KLHST_WKS_IP'])
                host["KLHST_WKS_GROUPID"] = oHostGroup.GetGroupInfo(oObj['KLHST_WKS_GROUPID']).retval.GetValue('name')
                host["grp_full_name"] = oObj['grp_full_name']
                host["KLHST_WKS_FROM_UNASSIGNED"] = oObj['KLHST_WKS_FROM_UNASSIGNED']
                host["KLHST_WKS_LAST_VISIBLE"] = oObj['KLHST_WKS_LAST_VISIBLE'].strftime("%d.%m.%Y %H:%M")
                host["KLHST_WKS_FQDN"] = oObj['KLHST_WKS_FQDN']
                host["KLHST_WKS_OS_NAME"] = oObj['KLHST_WKS_OS_NAME']
                host["KLHST_WKS_COMMENT"] = oObj.data.get('KLHST_WKS_COMMENT',"")
                host["KLHST_WKS_STATUS_ID"] = convert_KLHST_WKS_STATUS_ID(oObj['KLHST_WKS_STATUS_ID'])
                host["KLHST_WKS_STATUS"] = convert_KLHST_WKS_STATUS(oObj['KLHST_WKS_STATUS'])
                host["KLHST_WKS_RTP_STATE"] = convert_KLHST_WKS_RTP_STATE(oObj['KLHST_WKS_RTP_STATE'])
                result.append(host)
#                print('Found host: ' + oObj['KLHST_WKS_DN'])
#                print('Host IPv4 address with network byte order: ',  convert_int_to_ip(oObj['KLHST_WKS_IP']))
#                print('Group : ' + oHostGroup.GetGroupInfo(oObj['KLHST_WKS_GROUPID']).retval.GetValue('name'))
            nStart += nStep
        return result
    else:
        print('Ошибка доступа к серверу')

def get_args():
# получим данные от пользователя через командную строку
    parser = argparse.ArgumentParser(formatter_class=argparse.RawDescriptionHelpFormatter, description=console.helpme)  # Initialize arguments parser
    parser.add_argument('-v', action='version', version='%(prog)s 2.0')
    group_ksc = parser.add_mutually_exclusive_group()
    group_host = parser.add_mutually_exclusive_group()
    group_ksc.add_argument(  # Adding optional argument
        "-s",
        type=str,
        metavar="KSCip",
        help=console.help_s)
    group_ksc.add_argument(  # Adding optional argument
        "-k",
        type=argparse.FileType('r'),
        metavar="KSCip_file",
        help=console.help_k)
    group_host.add_argument(  # Adding optional argument
        "-n",
        type=str,
        metavar="HostName",
        help=console.help_host_name)
    group_host.add_argument(  # Adding optional argument
        "-i",
        type=argparse.FileType('r'),
        metavar="HostName_file",
        help=console.help_i)
    parser.add_argument(    # Adding optional argument
        "-o",
        type=argparse.FileType('w'),
        default=console.default_out,
        metavar="output_file",
        help=console.help_out)
    parser.add_argument(  # Adding optional argument
        "-l",
        type=argparse.FileType('w'),
        default=console.default_log,
        #default=sys.stdout
        metavar="log_file",
        help=console.help_log)
    args = parser.parse_args()  # Read arguments from command line
   # args = parser.parse_args(["-s", "192.168.122.181", "-n", "*win*"])

    # if args.i == None:
    #     pass
    # print("Необходимо указать ip адрес KSC: % s" % args)
    return args

if __name__ == '__main__':
    args = get_args()
    if args.k:
        KSC_LIST = get_KSC_from_file(args.k)
    else:
        KSC_LIST = [args.s]
    if args.n:
        lstFindHostes = [str(args.n)]
    else:
        lstFindHostes = get_hostes_from_file(args.i)
#    for KSCip in KSC_LIST.values():
    LogFile = args.l # для удобства сделаем alias
    for nextKSC in KSC_LIST:
        KSCip = 'https://' + nextKSC + ':13299'
        server = ConnectKSC(KSCip)
        if server:
            LogFile.write('Успешно подключился к {}\n'.format(KSCip))
            for FindWhat in lstFindHostes:
                HostData = get_host_info(server, FindWhat)
                LogFile.write('Для запроса "' +FindWhat + '" найдено устройств: {}\n'.format(len(HostData)))
                save_to_csv(HostData, args.o)
            server.Disconnect()
        else:
            LogFile.write('Ошибка подключения к {}\n'.format(KSCip))

