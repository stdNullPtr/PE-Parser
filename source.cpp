#include <conio.h>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <vector>
#include <Windows.h>
#include <winnt.h>
#include <sstream>

using std::dec, std::uppercase, std::cout, std::cerr;
using std::string;

std::vector<char> readFile(const string& filename);

int main(int argc, char* argv[])
{
	if (argc > 1)
	{
		if (argc != 2)
		{
			cerr << "You must provide exactly 1 file argument.\n";
			return EXIT_FAILURE;
		}
	}
	else
	{
		cerr << "No files were provided.\n";
		return EXIT_FAILURE;
	}

	const string filePath{ argv[1] };

	cout << "File path: " << filePath << '\n';

	const auto fileContents{ readFile(filePath) };
	if (fileContents.empty())
	{
		cerr << "Failed to read file contents.\n";
		return EXIT_FAILURE;
	}

	auto hexStr = [](const auto& value)
		{
			std::stringstream ss;
			ss << std::hex << "0x" << std::uppercase << value;
			return ss.str();
		};

	const char* pFileContents{ fileContents.data() };

	const auto pDosHeader{ (IMAGE_DOS_HEADER*)pFileContents };
	if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
	{
		cerr << "DOS header begins with an invalid WORD: " << hexStr(pDosHeader->e_magic) << " should be: " << hexStr(IMAGE_DOS_SIGNATURE) << '\n';
		return EXIT_FAILURE;
	}

	const auto pPeHeaders{ (IMAGE_NT_HEADERS*)(pFileContents + pDosHeader->e_lfanew) };
	if (pPeHeaders->Signature != IMAGE_NT_SIGNATURE)
	{
		cerr << "PE header begins with an invalid LONG sig: " << hexStr(pPeHeaders->Signature) << " should be: " << hexStr(IMAGE_NT_SIGNATURE) << '\n';
		return EXIT_FAILURE;
	}

	cout << "DOS Header\n";
	cout << "  Magic number: " << hexStr(pDosHeader->e_magic) << '\n';
	cout << "  Magic number as string: " << string((CHAR*)&pDosHeader->e_magic, 2) << '\n';
	cout << "  Offset to PE header: " << hexStr(pDosHeader->e_lfanew) << '\n';
	cout << "PE header\n";
	cout << "  Signature\n";
	cout << "    Sig: " << hexStr(*(DWORD*)(pFileContents + pDosHeader->e_lfanew)) << '\n';
	cout << "    Sig string: " << (CHAR*)(pFileContents + pDosHeader->e_lfanew) << '\n';
	cout << "  File header\n";
	cout << "    Machine: " << hexStr(pPeHeaders->FileHeader.Machine) << '\n';
	cout << "    Number of sections: " << dec << uppercase << pPeHeaders->FileHeader.NumberOfSections << '\n';
	cout << "    Pointer to symbol table: " << hexStr(pPeHeaders->FileHeader.PointerToSymbolTable) << '\n';
	cout << "    Number of symbols: " << dec << uppercase << pPeHeaders->FileHeader.NumberOfSymbols << '\n';
	cout << "    Size of optional header: " << hexStr(pPeHeaders->FileHeader.SizeOfOptionalHeader) << '\n';
	cout << "    Characteristics: " << hexStr(pPeHeaders->FileHeader.Characteristics) << '\n';
	cout << "  Optional header\n";
	cout << "    Magic number: " << hexStr(pPeHeaders->OptionalHeader.Magic) << '\n';
	cout << "    Section Alignment: " << hexStr(pPeHeaders->OptionalHeader.SectionAlignment) << '\n';
	cout << "    File Alignment: " << hexStr(pPeHeaders->OptionalHeader.FileAlignment) << '\n';
	cout << "    Entry point: " << hexStr(pPeHeaders->OptionalHeader.AddressOfEntryPoint) << '\n';
	cout << "    Data directories: " << '\n';
	for (size_t i{ 0 }; i < std::size(pPeHeaders->OptionalHeader.DataDirectory); i++)
	{
		cout << "	DataDirectory[" << i << "] Size: " << hexStr(pPeHeaders->OptionalHeader.DataDirectory[i].Size) << '\n';
		cout << "	DataDirectory[" << i << "] VirtualAddress: " << hexStr(pPeHeaders->OptionalHeader.DataDirectory[i].VirtualAddress) << '\n';
	}

	const auto sectionHeaders{ (IMAGE_SECTION_HEADER*)(pPeHeaders + sizeof BYTE) };

	cout << "Section table\n";
	for (size_t i{ 0 }; i < pPeHeaders->FileHeader.NumberOfSections; i++)
	{
		const auto sectionHeader{ sectionHeaders[i] };
		cout << "  Section header #" << i << " \n";
		cout << "    Name " << string((CHAR*)sectionHeader.Name, std::size(sectionHeader.Name)) << " \n";
		cout << "    PhysicalAddress | VirtualSize " << hexStr(sectionHeader.Misc.PhysicalAddress) << " \n";
		cout << "    VirtualAddress " << hexStr(sectionHeader.VirtualAddress) << " \n";
		cout << "    SizeOfRawData " << hexStr(sectionHeader.SizeOfRawData) << " \n";
		cout << "    PointerToRawData " << hexStr(sectionHeader.PointerToRawData) << " \n";
		cout << "    PointerToRelocations " << hexStr(sectionHeader.PointerToRelocations) << " \n";
		//cout << "    PointerToLinenumbers " << hexStr(sectionHeader.PointerToLinenumbers) << " \n";
		cout << "    NumberOfRelocations " << sectionHeader.NumberOfRelocations << " \n";
		//cout << "    NumberOfLinenumbers " << sectionHeader.NumberOfLinenumbers << " \n";
		cout << "    Characteristics " << hexStr(sectionHeader.Characteristics) << " \n";
	}

	//cout << "Press any key to exit.\n";
	//while (!_kbhit());

	return EXIT_SUCCESS;
}

std::vector<char> readFile(const string& filename)
{
	std::ifstream file(filename, std::ios::binary);

	if (!file)
	{
		cerr << "Cannot open file: " << filename << '\n';
		return {};
	}

	// Seek to the end of the file to find its size
	file.seekg(0, std::ios::end);
	const size_t size{ (size_t)file.tellg() };
	file.seekg(0, std::ios::beg);

	std::vector<char> buffer(size);
	file.read(buffer.data(), size);

	return buffer;
}