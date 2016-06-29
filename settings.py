from detector import Blacklist, CSBlacklist, EntropyDetect, PEiDComparison, APIDetection

DETECTORS = [
    # Blacklist(["604ad1939c67866df4a3e05d30bc45cc6ec3de3403bd1b5c286a45d5b7564859"]),
    # CSBlacklist(["df211b3880c676ece98a6cb3ef37153532db871e1bb0e17cd3172212fd5b7931"]),
    EntropyDetect(),
    # PEiDComparison(["UserDB.TXT"]),
    APIDetection(["VirtualAllocEx", "CreateRemoteThread", "VirtualAlloc", "GetModuleFileNameA", "LoadLibrary", "LoadLibraryA"], 3),
              ]
