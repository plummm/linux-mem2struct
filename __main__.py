import sys, os
sys.path.append(os.getcwd()) 

from translate import NetlinkTranslator

if __name__ == "__main__":
    tr = NetlinkTranslator(0x20000000, 0x20000080)
    print(tr.translate("./result.bin"))
