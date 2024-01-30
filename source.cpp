#include <conio.h>
#include <fstream>
#include <iostream>
#include <vector>
#include <Windows.h>
#include <winnt.h>

using std::hex, std::dec, std::uppercase, std::cout, std::cerr;
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

	const char* pFileContents{ fileContents.data() };

	const IMAGE_DOS_HEADER* pDosHeader{ (IMAGE_DOS_HEADER*)pFileContents };
	if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
	{
		cerr << "DOS header begins with an invalid WORD: " << hex << "0x" << uppercase << pDosHeader->e_magic << " should be: 0x" << IMAGE_DOS_SIGNATURE << '\n';
		return EXIT_FAILURE;
	}

	const IMAGE_NT_HEADERS* pPeHeaders{ (IMAGE_NT_HEADERS*)(pFileContents + pDosHeader->e_lfanew) };

	if (pPeHeaders->Signature != IMAGE_NT_SIGNATURE)
	{
		cerr << "PE header begins with an invalid LONG sig: " << hex << "0x" << uppercase << pPeHeaders->Signature << " should be: 0x" << IMAGE_NT_SIGNATURE << '\n';
		return EXIT_FAILURE;
	}

	cout << "dosHeader.e_magic: " << hex << "0x" << uppercase << pDosHeader->e_magic << '\n';
	cout << "Offset to PE header: " << hex << "0x" << uppercase << pDosHeader->e_lfanew << '\n';
	cout << "PE header start: " << hex << "0x" << uppercase << pFileContents + pDosHeader->e_lfanew << '\n';
	cout << "File header | machine: " << hex << "0x" << uppercase << pPeHeaders->FileHeader.Machine << '\n';
	cout << "File header | number of sections: " << dec << uppercase << pPeHeaders->FileHeader.NumberOfSections << '\n';
	cout << "File header | pointer to symbol table: " << hex << "0x" << uppercase << pPeHeaders->FileHeader.PointerToSymbolTable << '\n';
	cout << "File header | number of symbols: " << dec << uppercase << pPeHeaders->FileHeader.NumberOfSymbols << '\n';
	cout << "File header | size of optional header: " << hex << "0x" << uppercase << pPeHeaders->FileHeader.SizeOfOptionalHeader << '\n';
	//todo check if its dll with characteristics and exit
	cout << "File header | characteristics: " << hex << "0x" << uppercase << pPeHeaders->FileHeader.Characteristics << '\n';
	cout << "Optional header magic number (typecasted): " << hex << "0x" << uppercase << pPeHeaders->OptionalHeader.Magic << '\n';
	cout << "Entry point: " << hex << "0x" << uppercase << pPeHeaders->OptionalHeader.AddressOfEntryPoint << '\n';

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