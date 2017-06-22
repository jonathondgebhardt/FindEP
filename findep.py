# Locates entry point offset of a PE
	
import sys

ADDRESS_OF_ENTRY_POINT = 38
TWO_BYTES = 2

# Converts bytes object to string, includes preceding zeroes
def byte_to_address(byte):
    #Split bytes object in half
    msb = hex(byte[1])
    lsb = hex(byte[0])

    #Check if preceeding zeroes need to be added
    if (len(msb) == 3):
        msb = msb[0:2] + "0" + msb[2:]
    if (len(lsb) == 3):
        lsb = lsb[0:2] + "0" + lsb[2:]

    return str(msb)+str(lsb)[2:]

# Iterates through a Windows executable and returns 
def iterate_binary(file_name):
    # Parameters: r = reading, b = binary
    f = open(file_name, "rb")
    entry_point = 0
    
    try:
        byte = f.read(TWO_BYTES)
        # Look for address of IMAGE_OPTIONAL_HEADER struct
        while byte != "":
            if hex(byte[0]) == "0x50" and hex(byte[1]) == "0x45":
                # AddressOfEntryPoint is +28h (40d) but Windows is
                # little endian so we go 2 bytes before 
                print("Found \"PE\" at " + (hex((f.tell()) - TWO_BYTES)) + ", seeking file to entry point...")
                f.seek(f.tell() + ADDRESS_OF_ENTRY_POINT)
                entry_point = f.read(TWO_BYTES)
                break
            
            byte = f.read(2)

    finally:
        f.close()

    return entry_point
    
def main():
    # TODO: Add file verification
    file_name = sys.argv[1]
    if len(file_name) > 4:
        if file_name[len(file_name) - 3:] == "exe":
            print("Analyzing " + file_name + "...")
            entry_point = iterate_binary(file_name)
            print("Entry point: " + byte_to_address(entry_point))
        elif file_name[len(file_name) - 3:] == "txt":
            #TODO add file enumeration
            pass
        else:
            print("Invalid file format, must be txt or exe")

    else:
        print("Filename length too short")
    
main()
