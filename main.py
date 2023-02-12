import nvdlib
import datetime
import io
import sys

# run -- pip install nvdlib

# Initial CVE information
def cveMetaData():
    startIndex = nvdlib.cve.__get('startIndex')
    resultPerPage = nvdlib.cve.__get('resutlsPerPage')
    totalResults = nvdlib.cve.__get('totalResults')
    print('Start Index: ' + str(startIndex) + ' Results Per Page: '
          + str(resultPerPage) + ' Total Results: ' + str(totalResults))


# Get CVE by CVE id
def getCveByCveId(cveid):
    r = nvdlib.searchCVE(cveId=cveid)[0]
    print(r.v31severity + ' -' + str(r.v31score))
    print(r.descriptions[0].value)
    return r


# Get CVE's by Published time intervals
def getCveByPublishTimeIntervals(pubStart, pubEnd, keySearch, severity):
    # Gets list of CVE by Published start and end date.
    #   r = nvdlib.searchCVE(pubStartDate=pubStart, pubEndDate=pubEnd, key='d7ff5560-3545-4f85-b7f6-963dbd7755bc')

    # Gets list of CVE by local Published start and end date.
    #   end = datetime.datetime.now()
    #   start = end - datetime.timedelta(days=7)
    #   r = nvdlib.searchCVE(pubStartDate=start, pubEndDate=end, key='d7ff5560-3545-4f85-b7f6-963dbd7755bc')

    # Gets list of CVE's by local static parameters.
    r = nvdlib.searchCVE(pubStartDate=pubStart, pubEndDate=pubEnd,
                         keywordSearch='Microsoft Exchange', cvssV3Severity='Critical')
                        # ,key='d7ff5560-3545-4f85-b7f6-963dbd7755bc', delay=6)

    # Gets list of CVE by local Published start and end date without key
    #   r = nvdlib.searchCVE(pubStartDate='2021-10-08 00:00', pubEndDate='2021-12-01 00:00')
    return r


# Get a list of CVE by Severity
def getCveMatchVectorString(severity):
    r = nvdlib.searchCVE(cvssV3Severity=severity)
    return r


# Press the green button in the gutter to run the script.
if __name__ == '__main__':
    pubStart = '2021-10-08 00:00'
    pubEnd = '2021-12-01 00:00'
    keySearch = 'Microsoft Exchange'
    severity = 'Critical'
    key = 'd7ff5560-3545-4f85-b7f6-963dbd7755bc'

    print(' 1 = CVE by CVE Id')
    print(' 2 = CVE by Published Time Interval')
    print('3 = CVE by Vector')
    print("Select a CVE option: ")
    cveOption = str(input())

if cveOption == '1':
    cve = getCveByCveId('CVE-2021-26855')
    print(cve)
elif cveOption == '2':
    pubReturn = getCveByPublishTimeIntervals(pubStart, pubEnd,keySearch,severity)
    print(pubReturn)
elif cveOption == '3':
    cveVector = getCveMatchVectorString('HIGH')
    print(cveVector)
else:
    print("Invalid Option")
