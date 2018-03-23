import subprocess
import os as os

# a function that gathers more information about a given IP Address
def gatherInformationOfIpA(ipToCheck, keepInformation=False):
    '''
    This functin gathers some information of an IP Address, like Organization, Country, Source of Information
    and the ASN. The command line funciton 'whois' is required
    :param ipToCheck: String with the IP Address, which is checked output
    :param keepInformation: true, if the parsed information should be stored in a file
    '''
    descr = []
    country = []
    source = []
    autSys = []
    nothingFound = False
    descrFound = False
    countryFound = False
    sourceFound = False
    inRange = False
    originFound = False
    ripe = False

    # execute 'whois' on the command line and save output to t
    t = subprocess.run(['whois', ipToCheck], stdout=subprocess.PIPE)

    # save generated output of shell command to a file
    with open("../../resources/output.txt", "w") as output:
        output.write(t.stdout.decode('utf-8'))

    # parse information, like Description, Country, Source and if found the ASN
    with open("../../resources/output.txt", "r", encoding="utf-8", errors='replace') as ripeDb:
        ipInfos = [line.split() for line in ripeDb if line.strip()]

        # check if IP is from RIPE
        for i, row in enumerate(ipInfos):
            if any("RIPE" in s for s in row) or any ("Ripe" in s for s in row):
                ripe = True
                break

        if ripe:
            # parse information about ip
            for i, row in enumerate(ipInfos):
                if any("inetnum" in s for s in row) and not inRange:
                    # check whether ipToCheck is in range of the current found inetnum or NetRange
                    if ipToCheck >= row[1] and ipToCheck <= row[3]:
                        inRange = True
                if any("descr:" in s for s in row) and not descrFound:
                    descr.extend(ipInfos[i][1:])
                    descrFound = True
                    continue
                if any("country:" in s for s in row) and not countryFound:
                    country.extend(ipInfos[i][1:])
                    countryFound = True
                    continue
                if any("source:" in s for s in row) and not sourceFound:
                    source.extend(ipInfos[i][1:])
                    sourceFound = True
                    continue
                if any("origin" in s for s in row) and not originFound:
                    autSys.extend(row[1:])
                    originFound = True
                    continue
                if inRange and descrFound and countryFound and sourceFound and originFound:
                    break
        else:
            # parse information about ip
            for i, row in enumerate(ipInfos):
                if any("inetnum" in s for s in row) or any("NetRange" in s for s in row) and not inRange:
                    # check whether ipToCheck is in range of the current found inetnum or NetRange
                    if ipToCheck >= row[1] and ipToCheck <= row[3]:
                        inRange = True
                if (any("descr:" in s for s in row) or any("Organization:" in s for s in row)) and not descrFound:
                    descr.extend(ipInfos[i][1:])
                    descrFound = True
                    continue
                if (any("country:" in s for s in row) or any("Country:" in s for s in row)) and not countryFound:
                    country.extend(ipInfos[i][1:])
                    countryFound = True
                    continue
                if (any("source:" in s for s in row) or any("Ref:" in s for s in row)) and not sourceFound:
                    source.extend(ipInfos[i][1:])
                    sourceFound = True
                    continue
                if (any("origin" in s for s in row) or any("OriginAS:" in s for s in row)) and not originFound:
                    autSys.extend(row[1:])
                    originFound = True
                    continue
                if inRange and descrFound and countryFound and sourceFound and originFound:
                    break

        if not descrFound and not countryFound and not sourceFound and not originFound and not inRange:
            nothingFound = True

    # print information (which use of this information is wanted? Output, Returned?)
    if not nothingFound:
        print("#############################################")
        print("More Information about", ipToCheck)
        print("Description: ", ' '.join(descr) if descr else "unknown")
        print("Country:     ", ' '.join(country) if country else "unknown")
        print("Source:      ", ' '.join(source) if source else "unknown")
        print("AS Number:   ", ' '.join(autSys) if autSys else "unknown")
        print("#############################################")
        print("\n")
    else:
        print("IP-Address", ipToCheck, "is not assigned by IANA yet\n")

    # in case it should be stored to a file
    if keepInformation and not nothingFound:
        with open("../../resources/information.txt", "w") as info:
            info.write("#############################################\n")
            info.write("More Information about" + ipToCheck + "\n")
            info.write("Description: ")
            info.write(' '.join(descr) + "\n" if descr else "unknown" + "\n")
            info.write("Country:     ")
            info.write(' '.join(country) + "\n" if country else "unknown" + "\n")
            info.write("Source:      ")
            info.write(' '.join(source) + "\n" if source else "unknown" + "\n")
            info.write("AS Number:   ")
            info.write(' '.join(autSys) + "\n" if autSys else "unknown" + "\n")
            info.write("#############################################\n")

    os.remove("../../resources/output.txt")
