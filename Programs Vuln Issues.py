import wget
import zipfile
import json
import textwrap
import os


Grab_NVD_Vuln_File = "https://nvd.nist.gov/feeds/json/cve/1.0/nvdcve-1.0-recent.json.zip"
wget.download(Grab_NVD_Vuln_File, "c:\TEMP\NVDCVE.json.zip")
Zipped_NVDCVE_File = zipfile.ZipFile("c:\TEMP\NVDCVE.json.zip", "r")
Zipped_NVDCVE_File.extractall("c:\TEMP")
Zipped_NVDCVE_File.close()
os.remove("c:\TEMP\NVDCVE.json.zip")


Security_Products = [u'cisco', u'f5', u'varonis', u'arcsight', u'Qualys']

with open('c:\TEMP\\nvdcve-1.0-recent.json') as NVDCVE_JSON:
    NVDCVE_JSON_Data = json.load(NVDCVE_JSON)
    Vendor_Version_Count = 0
    NVDCVE_Vendor_Data = {}
    NVDCVE_Info = {}
    NVDCVE_Vendor_Name = {}
    CVE_Count = 0
    NVDCVE_Row_Count = NVDCVE_JSON_Data[u'CVE_Items'].__len__()
    for NVDCVE_Current_Count in range(NVDCVE_Row_Count):
        try:
            Vendor_Version_Count = NVDCVE_JSON_Data[u'CVE_Items'][NVDCVE_Current_Count][u'cve'][u'affects'][u'vendor'] \
            [u'vendor_data'][0][u'product'][u'product_data'][0][u'version'][u'version_data']\
            [Vendor_Version_Count][u'version_value']
        except:
            Vendor_Version_Count = 0
        NVDCVE_Info[NVDCVE_Current_Count] = NVDCVE_JSON_Data[u'CVE_Items'][NVDCVE_Current_Count]
        NVDCVE_Vendor_Data[NVDCVE_Current_Count] = NVDCVE_Info[NVDCVE_Current_Count][u'cve'][u'affects'][u'vendor'] \
            [u'vendor_data']
        try:
            NVDCVE_Vendor_Name[NVDCVE_Current_Count] = NVDCVE_JSON_Data[u'CVE_Items'][NVDCVE_Current_Count][u'cve'] \
            [u'affects'][u'vendor'][u'vendor_data'][0][u'vendor_name']
        except:
            NVDCVE_Vendor_Name[NVDCVE_Current_Count] = ""
        for product_count in range(len(Security_Products)):
            try:
                if NVDCVE_Vendor_Name[NVDCVE_Current_Count] == Security_Products[product_count]:
                    print "\033[91m" + "\033[1m" + "Vendor: " + "\033[0m" + NVDCVE_Vendor_Name[ \
                        NVDCVE_Current_Count]

                    print "\033[1m" + "\033[91m" + "Product: " + "\033[0m" + \
                        NVDCVE_Info[NVDCVE_Current_Count][u'cve'][u'affects'][u'vendor'][u'vendor_data'][0] \
                        [u'product'][u'product_data'][0][u'product_name']

                    print "\033[91m" + "\033[1m" + "Exploitability: " + "\033[0m" + str(
                        NVDCVE_Info[NVDCVE_Current_Count][u'impact'][u'baseMetricV2'][u'exploitabilityScore'])

                    print "\033[91m" + "\033[1m" + "Version: " + "\033[0m" + NVDCVE_Info[NVDCVE_Current_Count][u'cve'] \
                        [u'affects'] \
                        [u'vendor'][u'vendor_data'][0][u'product'][u'product_data'][0][u'version'][ \
                        u'version_data'][0][u'version_value']

                    print "\033[91m" + "\033[1m" + "Published Date: " + "\033[0m" + NVDCVE_Info[NVDCVE_Current_Count][ \
                        u'publishedDate']

                    print "\033[91m" + "\033[1m" + "Published Date: " + "\033[0m" + NVDCVE_Info[NVDCVE_Current_Count][ \
                        u'lastModifiedDate']

                    print "\033[91m" + "\033[1m" + "Description: " + "\033[0m" + (textwrap.fill(NVDCVE_Info
                            [NVDCVE_Current_Count][u'cve'][u'description'][u'description_data']
                            [0][u'value'], 125))

                    print "\033[91m" + "\033[1m" + "Link to Description: " + "\033[0m" + \
                          NVDCVE_Info[NVDCVE_Current_Count][u'cve'][u'references'][u'reference_data'][0][u'url']

                    print ""

                    NVDCVE_Current_Count = NVDCVE_Current_Count + 1
                    CVE_Count = CVE_Count + 1
            except:
                NVDCVE_Current_Count = NVDCVE_Current_Count + 1
            continue
        NVDCVE_Current_Count = NVDCVE_Current_Count + 1
        continue
    print "\033[91m" + "\033[1m" + "Total Number of Exploits Found: " + "\033[0m",CVE_Count
    os.remove("c:\TEMP\nvdcve-1.0-recent.json")
exit()
