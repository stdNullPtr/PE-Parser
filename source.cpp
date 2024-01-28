#include <conio.h>
#include <fstream>
#include <iostream>
#include <vector>
#include <Windows.h>
#include <winnt.h>

using std::hex, std::dec, std::uppercase, std::cout, std::cerr;
using std::string;

std::vector<char> readFile(const string& filename);
string wordToString(const WORD& word);

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

	const IMAGE_DOS_HEADER dosHeader{ *(IMAGE_DOS_HEADER*)pFileContents };
	const string dosHeaderMagic{ wordToString(dosHeader.e_magic) };
	if (dosHeaderMagic != string{ "MZ" }) //IMAGE_DOS_SIGNATURE
	{
		cerr << "DOS header begins with an invalid WORD: " << dosHeader.e_magic << " string variant: " << dosHeaderMagic << '\n';
		return EXIT_FAILURE;
	}

	const LONG dosHeaderOffsetToPeHeader{ dosHeader.e_lfanew };
	const LONG* pPeHeaderStart{ ((LONG*)(pFileContents + dosHeaderOffsetToPeHeader)) };
	const LONG peHeaderStart{ *pPeHeaderStart };
	if (peHeaderStart != IMAGE_NT_SIGNATURE)
	{
		cerr << "PE header begins with an invalid LONG sig: 0x" << std::hex << peHeaderStart << " should be: 0x" << IMAGE_NT_SIGNATURE << '\n';
		return EXIT_FAILURE;
	}

	//or file header?
	const IMAGE_FILE_HEADER* pPeHeader{ (IMAGE_FILE_HEADER*)(pFileContents + dosHeaderOffsetToPeHeader + sizeof peHeaderStart) };

	cout << "dosHeader.e_magic as string: " << dosHeaderMagic << '\n';
	cout << "Offset to PE header: " << hex << "0x" << uppercase << dosHeaderOffsetToPeHeader << '\n';
	cout << "PE header start: " << hex << "0x" << uppercase << peHeaderStart << '\n';
	cout << "File header | machine: " << hex << "0x" << uppercase << pPeHeader->Machine << '\n';
	cout << "File header | number of sections: " << dec << uppercase << pPeHeader->NumberOfSections << '\n';
	cout << "File header | pointer to symbol table: " << hex << "0x" << uppercase << pPeHeader->PointerToSymbolTable << '\n';
	cout << "File header | number of symbols: " << dec << uppercase << pPeHeader->NumberOfSymbols << '\n';
	cout << "File header | size of optional header: " << hex << "0x" << uppercase << pPeHeader->SizeOfOptionalHeader << '\n';
	cout << "File header | characteristics: " << hex << "0x" << uppercase << pPeHeader->Characteristics << '\n';
	cout << "Optional header value (2 bytes, magic number): " << hex << "0x" << uppercase << *(WORD*)(pPeHeader + sizeof BYTE) << '\n'; // immediately after the pe header

	const IMAGE_OPTIONAL_HEADER* pOptionalHeader{ (IMAGE_OPTIONAL_HEADER*)(pPeHeader + sizeof BYTE) };
	cout << "Optional header magic number (typecasted): " << hex << "0x" << uppercase << pOptionalHeader->Magic << '\n';

	//cout << "Press any key to exit.\n";
	//while (!_kbhit());

	return EXIT_SUCCESS;
}

//TODO can endianness screw me over here?
// this function is just for fun, to explore a way to convert a word to a readable ascii string
string wordToString(const WORD& word)
{
	char buf[3];
	buf[0] = word & 0xFF;
	buf[1] = (word >> 8) & 0xFF;
	buf[2] = '\0';
	return string{ buf };
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