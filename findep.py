# Locates entry point offset of a PE
	
import sys

ADDRESS_OF_ENTRY_POINT = 38
WORD = 4

# Converts bytes object to string, includes preceding zeroes
# TODO: Iterate through byte object, building string
def byte_to_address(byte):
    address = ""
    for b in byte:
        temp = str(hex(b))[2:]
        if len(temp) == 1:
            temp = "0" + temp
        address = temp + address

    return "0x" + str(address)


# Iterates through a Windows executable and returns 
def iterate_binary(file_name):
    # Parameters: r = reading, b = binary
    f = open(file_name, "rb")
    entry_point = 0
    
    try:
        byte = f.read(WORD)
        # Look for address of IMAGE_OPTIONAL_HEADER struct
        while byte != "":
            if hex(byte[0]) == "0x50" and hex(byte[1]) == "0x45":
                # AddressOfEntryPoint is +28h (40d) but Windows is
                # little endian so we go 2 bytes before 
                print("Found \"PE\" at " + (hex((f.tell()) - WORD)) + ", seeking file to entry point...")
                f.seek(f.tell() + ADDRESS_OF_ENTRY_POINT)
                entry_point = f.read(WORD)
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
