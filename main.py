from KlAkOAPI.AdmServer import KlAkAdmServer
#from KlAkOAPI.TotpUserSettings import ClearUserSecret, IfCanClearUser2FaSecret
from KlAkOAPI.Params import KlAkParams, KlAkArray, KlAkParamsEncoder
from KlAkOAPI.SrvView import KlAkSrvView

#import inspect
import json
from KlAkOAPI.Params import KlAkParamsEncoder

import urllib3  #
import passwd   # файл с логинами/паролями, который в GIT не идёт
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
#username2changeQR = 'WIN-IOTUM83MVJE\OpenAPI_2FA_1'

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

def Enumerate(oSrvView, wstrIteratorId):
    iRecordCount = oSrvView.GetRecordCount(wstrIteratorId).RetVal()
    ul_llTrusteeId = -1
    iStep = 200
    iStart = 0
    result = []
    while iStart < iRecordCount:
        pRecords = oSrvView.GetRecordRange(wstrIteratorId, iStart, iStart + iStep).OutPar('pRecords')
        for oObj in pRecords['KLCSP_ITERATOR_ARRAY']:
            UserId = {}
            UserId[oObj['ul_wstrSamAccountName']] = oObj['ul_llTrusteeId']
#            print('TrusteeId: ', oObj['ul_llTrusteeId'], ', DisplayName: ', oObj['ul_wstrDisplayName'])
            result.append(UserId)
        iStart += iStep + 1
    # if iRecordCount == 1:
    #     pRecords = oSrvView.GetRecordRange(wstrIteratorId, nStart=0, nEnd=1).OutPar('pRecords')
    #     for oObj in pRecords['KLCSP_ITERATOR_ARRAY']:
    #         ul_llTrusteeId = oObj['ul_llTrusteeId']
    # oSrvView.ReleaseIterator(wstrIteratorId)
    #return ul_llTrusteeId
    return result

def FindUserId(server, strUsername):
    # Get user id by name

    oSrvView = KlAkSrvView(server)
    oFields2Return = KlAkArray(['ul_llTrusteeId', 'ul_wstrSamAccountName'])
    oField2Order = KlAkArray([{'Name': 'ul_llTrusteeId', 'Asc': True}])
    wstrIteratorId = oSrvView.ResetIterator('GlobalUsersListSrvViewName',
                                            '(ul_wstrSamAccountName = "' + strUsername + '")',
                                            oFields2Return,
                                            oField2Order,
                                            {},
                                            lifetimeSec=60 * 3).OutPar('wstrIteratorId')
    UsersId = Enumerate(oSrvView, wstrIteratorId)
    #llTrusteeId = Enumerate(oSrvView, wstrIteratorId)

    # oSrvView = KlAkSrvView(server)
    # wstrIteratorId = oSrvView.ResetIterator('GlobalUsersListSrvViewName',
    #                                         '(&(ul_wstrDisplayName=\"' + strUsername + '\")(ul_nVServer = 0))',
    #                                         ['ul_bTotpReigstered', 'ul_llTrusteeId', 'ul_wstrDisplayName'],
    #                                         [],
    #                                         {},
    #                                         lifetimeSec=60 * 5).OutPar('wstrIteratorId')
    # llTrusteeId = -1
    # if oSrvView.GetRecordCount(wstrIteratorId).RetVal() > 0:
    #     pRecords = oSrvView.GetRecordRange(wstrIteratorId, 0, 1).OutPar('pRecords')
    #     pRecordsArray = pRecords['KLCSP_ITERATOR_ARRAY']
    #     if pRecordsArray != None and len(pRecordsArray) > 0:
    #         llTrusteeId = pRecordsArray[0]['ul_llTrusteeId']    #Unique account ID
    #         bTotpReigstered = pRecordsArray[0]['ul_llTrusteeId']    #Is the 2FA secret registered for a user
    # oSrvView.ReleaseIterator(wstrIteratorId)

    # if llTrusteeId == -1:
    #     LogFile.write(f'Пользователь "{strUsername}" не найден\n')
    #     return
    #
    # return llTrusteeId

    if len(UsersId) == 0:
        LogFile.write(f'Пользователь "{strUsername}" не найден\n')
        return

    return UsersId

# заготовка аналога функции TotpUserSettings::ClearUserSecret 	( 	long  	llTrusteeId	)
# def GetUpdatesInfo(self, pFilter):
#     data = {'pFilter': pFilter}
#     response = self.server.session.post(url = self.server.Call((lambda: self.instance + '.' if self.instance != None and self.instance != '' else '')() + 'Updates.GetUpdatesInfo'), headers = KlAkBase.common_headers, data = json.dumps(data, cls = KlAkParamsEncoder))
#     return self.ParseResponse(response.status_code, response.text)

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
        # Get user id by name
        userName = 'WIN-IOTUM83MVJE\OpenAPI_2FA'
        userName = '*OpenAP*'
        UsersId = FindUserId(server, userName)
        #print(f'User name: {userName}, User id: {userId}')
        print(UsersId)

        # userName = 'WIN-IOTUM83MVJE\OpenAPI_2FA_1'
        # userId = FindUserId(server, userName)
        # print(f'User name: {userName}, User id: {userId}')

        # if userId != -1:
        #     # report to be generated
        #     nReportID = AddUserEffRightsReport(oReportManager, userId)
        #
        #     # create report
        #     download_filename = GenerateReport(server, oReportManager, nReportID)
        #     print('Now you can analyse report file: ', download_filename)




#        ClearUserSecret(ul_llTrusteeId)
        server.Disconnect()
    else:
        LogFile.write("Ошибка подключения к {}\n".format(KSCip))