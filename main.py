from KlAkOAPI.AdmServer import KlAkAdmServer
#from KlAkOAPI.TotpUserSettings import ClearUserSecret, IfCanClearUser2FaSecret
from KlAkOAPI.Params import KlAkParams, KlAkArray
from KlAkOAPI.SrvView import KlAkSrvView

#import inspect

import urllib3  #
import passwd   # файл с логинами/паролями, которй в GIT не идёт
import argparse # разбор командной строки
import console     # модуль сообщений для опций командной строки
import requests
import base64
import json

#!!!!!!!!!!!!!!!!!!!!!
#TODO Можно сделать ...
#!!!!!!!!!

# username = passwd.username
# password = passwd.password
username = 'OpenAPI_2FA'
password = '1qazXSW@'
username2changeQR = 'WIN-IOTUM83MVJE\OpenAPI_2FA_1'

def ConnectKSC_2FA_Token(ip):
    # connect to KSC  with two-factor Token authentication using TOTP codes
    # The Token (KlAkAdmServer.CreateByToken) can be used for logon purposes to Administration Server for a short time (3 minutes by default).
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    url_login = ip + "/api/v1.0/login"
    url_CreateToken = ip + "/api/v1.0/Session.CreateToken"
    user = base64.b64encode(username.encode("utf-8")).decode("utf-8")
    passwd = base64.b64encode(password.encode("utf-8")).decode("utf-8")
    session = requests.Session()
    auth_headers = {
        "Authorization": 'KSCBasic user="'
        + user
        + '", pass="'
        + passwd
        + '", internal="0"',
        "Content-Type": "application/json",
    }
    data = {}
    connect = None
    response = session.post(
        url=url_login, headers=auth_headers, data=data, verify=False
    )
    if response.status_code == 401 and response.text == "Authentication not finished":
        totp = input("Enter a TOTP: ")
        auth_headers = {
            "Authorization": 'KSCMFA totp="' + totp + '"',
            "Content-Type": "application/json",
        }
        data = {}
        response = session.post(
            url=url_login, headers=auth_headers, data=data, verify=False
        )
        if response.status_code == 200:
            response = session.post(
                url=url_CreateToken, headers="", data=data, verify=False
            )
            if response.status_code == 200:
                Token = json.loads(response.text)["PxgRetVal"]
                connect = KlAkAdmServer.CreateByToken(
                    ip, Token, verify=False, vserver=""
                )
    #                return connect
    #     elif response.status_code == 403:
    #         # print("Invalid credentials or access if forbidden.")
    #         session.close()
    #     elif response.status_code == 200:
    #         session.close()
    #         connect = KlAkAdmServer.Create(ip, username, password, verify=False, vserver='')
    #        return connect
    else:
        session.close()
        connect = KlAkAdmServer.Create(ip, username, password, verify=False, vserver="")
    return connect

# Уточнил информацию у разработчиков. Коллеги предлагают сделать это посредством пары вызовов KSC Open API:
#
# TotpRegistration::GenerateSecret
#  (https://support.kaspersky.com/help/KSC/14.2/KSCAPI/a00590_af88eb4079f0de251b69bb9498ff69856.html#af88eb4079f0de251b69bb9498ff69856)
#
# wstring TotpRegistration::GenerateSecret | ( | [out] params | pSecret | ) |
#
# и
#
# TotpRegistration::SaveSecretForCurrentUser | ( | wstring | wstrSecretId,
# | | wstring | wstrValidationCode
# | | )
#
# или
#
# TotpUserSettings::ClearUserSecret
#
# (https://support.kaspersky.com/help/KSC/14.2/KSCAPI/a00591_a506a2c79f6b98ffc8af00e708d4b4e8d.html#a506a2c79f6b98ffc8af00e708d4b4e8d)
#
# TotpUserSettings::ClearUserSecret | ( | long | llTrusteeId | )

# def recreate_QR(UserName):
# #назначение пользователю KSC нового QR-кода
#     urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
#     ClearUserSecret(UserName)

# def convert_int_to_ip(n):
# # convert integer to IP4 address
# # IP4 addresses can be represented in big-endian byte order,
#     return socket.inet_ntoa(struct.pack('<I', n))

def Enumerate(oSrvView, wstrIteratorId):
    iRecordCount = oSrvView.GetRecordCount(wstrIteratorId).RetVal()
    # iStep = 200
    # iStart = 0
    # while iStart < iRecordCount:
    #     pRecords = oSrvView.GetRecordRange(wstrIteratorId, iStart, iStart + iStep).OutPar('pRecords')
    #     for oObj in pRecords['KLCSP_ITERATOR_ARRAY']:
    #         print('TrusteeId: ', oObj['ul_llTrusteeId'], ', DisplayName: ', oObj['ul_wstrDisplayName'])
    #     iStart += iStep + 1
    ul_llTrusteeId = 0
    if iRecordCount == 1:
        pRecords = oSrvView.GetRecordRange(wstrIteratorId, nStart=0, nEnd=1).OutPar('pRecords')
        for oObj in pRecords['KLCSP_ITERATOR_ARRAY']:
            ul_llTrusteeId = oObj['ul_llTrusteeId']
    oSrvView.ReleaseIterator(wstrIteratorId)
    return ul_llTrusteeId

def get_args():
# получим данные от пользователя через командную строку
    parser = argparse.ArgumentParser(formatter_class=argparse.RawDescriptionHelpFormatter, description=console.helpme)  # Initialize arguments parser
    parser.add_argument('-v', action='version', version='%(prog)s 1.0')
    parser.add_argument(  # Adding argument
        "-s",
        required=True,
        type=str,
        metavar="KSCip",
        help=console.help_s)
    parser.add_argument(  # Adding argument
        "-n",
        required=True,
        type=str,
        metavar="UserName",
        help=console.help_n)
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
#    print (inspect.getmodule(ClearUserSecret))
    args = get_args()
    KSCip = str(args.s)
    UserName = str(args.n)
    LogFile = args.l # для удобства сделаем alias
    KSCip = 'https://' + KSCip + ':13299'
    try:
        server = ConnectKSC_2FA_Token(KSCip)
    except Exception as e:
        LogFile.write("Ошибка подключения к KSC: {}\n".format(e.data))
        exit()
    if server:
        LogFile.write("Успешно подключился к {}\n".format(KSCip))
        oSrvView = KlAkSrvView(server)
        oFields2Return = KlAkArray(['ul_llTrusteeId', 'ul_wstrDisplayName'])
        oField2Order = KlAkArray([{'Name': 'ul_llTrusteeId', 'Asc': True}])
        wstrIteratorId = oSrvView.ResetIterator('GlobalUsersListSrvViewName', '(ul_wstrDisplayName = "' + username2changeQR + '")', oFields2Return, oField2Order, {},
                                                lifetimeSec=60 * 3).OutPar('wstrIteratorId')
        ul_llTrusteeId = Enumerate(oSrvView, wstrIteratorId)
        print(ul_llTrusteeId)
#        ClearUserSecret(ul_llTrusteeId)
        server.Disconnect()
    else:
        LogFile.write("Ошибка подключения к {}\n".format(KSCip))