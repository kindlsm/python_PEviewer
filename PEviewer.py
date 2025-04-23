import pefile

def load_pe_file(file_path):
    pe = pefile.PE(file_path)
    return pe

def display_dos_header(pe):
    print("\nIMAGE_DOS_HEADER:")
    for attr, value in pe.DOS_HEADER.__dict__.items():
        if not attr.startswith('__'):
            try:
                print(f"{attr}: {hex(value)}")
            except TypeError:
                print(f"{attr}: {value}")

def display_nt_headers(pe):
    print("\nIMAGE_NT_HEADERS:")
    print(f"Signature: {hex(pe.NT_HEADERS.Signature)}")

def display_file_header(pe):
    print("\nIMAGE_FILE_HEADER:")
    for attr, value in pe.FILE_HEADER.__dict__.items():
        if not attr.startswith('__'):
            try:
                print(f"{attr}: {hex(value)}")
            except TypeError:
                print(f"{attr}: {value}")

def display_optional_header(pe):
    print("\nIMAGE_OPTIONAL_HEADER:")
    for attr, value in pe.OPTIONAL_HEADER.__dict__.items():
        if not attr.startswith('__'):
            try:
                print(f"{attr}: {hex(value)}")
            except TypeError:
                print(f"{attr}: {value}")

def display_section_headers(pe):
    print("\nSection Headers:")
    for idx, section in enumerate(pe.sections):
        print(f"{idx + 1}: {section.Name.decode().rstrip('\x00')}")

def analyze_section(pe, section_number):
    if section_number < 1 or section_number > len(pe.sections):
        print("잘못된 섹션 번호입니다.")
        return
    
    section = pe.sections[section_number - 1]
    print(f"\nAnalyzing Section {section_number}: {section.Name.decode().rstrip('\x00')}")
    print(f"Virtual Address: {hex(section.VirtualAddress)}")
    print(f"Virtual Size: {hex(section.Misc_VirtualSize)}")
    print(f"Raw Size: {hex(section.SizeOfRawData)}")
    print(f"Pointer to Raw Data: {hex(section.PointerToRawData)}")
    print(f"Pointer to Relocations: {hex(section.PointerToRelocations)}")
    print(f"Pointer to Line Numbers: {hex(section.PointerToLinenumbers)}")
    print(f"Number of Relocations: {hex(section.NumberOfRelocations)}")
    print(f"Number of Line Numbers: {hex(section.NumberOfLinenumbers)}")
    print(f"Characteristics: {hex(section.Characteristics)}")
    
    print("\nIMAGE_SECTION_HEADER details:")
    print(f"Name: {section.Name.decode().rstrip()}")
    print(f"VirtualSize: {hex(section.Misc_VirtualSize)}")
    print(f"VirtualAddress: {hex(section.VirtualAddress)}")
    print(f"SizeOfRawData: {hex(section.SizeOfRawData)}")
    print(f"PointerToRawData: {hex(section.PointerToRawData)}")
    print(f"PointerToRelocations: {hex(section.PointerToRelocations)}")
    print(f"PointerToLinenumbers: {hex(section.PointerToLinenumbers)}")
    print(f"NumberOfRelocations: {hex(section.NumberOfRelocations)}")
    print(f"NumberOfLinenumbers: {hex(section.NumberOfLinenumbers)}")
    print(f"Characteristics: {hex(section.Characteristics)}")

def main():
    file_path = input("파일 경로를 입력해주세요 : ")
    try:
        pe = load_pe_file(file_path)
        display_dos_header(pe)
        display_nt_headers(pe)
        display_file_header(pe)
        display_optional_header(pe)
        display_section_headers(pe)
        
        section_number_str = input("섹션 번호를 입력해주세요 : ")
        if not section_number_str.isdigit():
            print("섹션 번호는 숫자여야 합니다.")
            return
        section_number = int(section_number_str)
        
        analyze_section(pe, section_number)
        
    except FileNotFoundError:
        print("지정된 파일을 찾을 수 없습니다.")
    except pefile.PEFormatError:
        print("PE 파일이 아닙니다.")
    except ValueError as ve:
        print(f"입력 값에 문제가 있습니다: {ve}")
    except Exception as e:
        print(f"오류가 발생했습니다: {e}")

if __name__ == "__main__":
    main()
