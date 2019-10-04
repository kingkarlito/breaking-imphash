/*
Copyright (c) 2019 Ateeq Sharfuddin, SCYTHE, Inc.

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated
documentation files(the "Software"), to deal in the Software without restriction, including without limitation the
rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit
persons to whom the Software is furnished to do so, subject to the following conditions :

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the
Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE
WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.IN NO EVENT SHALL THE AUTHORS OR
COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

*/

#include <SDKDDKVer.h>
#include <windows.h>
#include <stdio.h>
#include <string>
#include <vector>
#include <map>
#include <random>

#define gle GetLastError

DWORD Rva2Offset(DWORD rva, PIMAGE_SECTION_HEADER psh, PIMAGE_NT_HEADERS pnt)
{
    PIMAGE_SECTION_HEADER pSectionHeader;
    if (rva == 0)
    {
        return (rva);
    }

    pSectionHeader = psh;
    for (WORD i = 0; i < pnt->FileHeader.NumberOfSections; i++)
    {
        if (rva >= pSectionHeader->VirtualAddress &&
            rva < pSectionHeader->VirtualAddress + pSectionHeader->Misc.VirtualSize)
        {
            break;
        }

        pSectionHeader++;
    }

    return (rva - pSectionHeader->VirtualAddress + pSectionHeader->PointerToRawData);
}

BOOL UpdateImpHash(PBYTE pbPEBase, DWORD dwPEFileSize)
{
    PIMAGE_DOS_HEADER       pDOSHeader = (PIMAGE_DOS_HEADER)pbPEBase;
    PIMAGE_NT_HEADERS       pNTHeader = (PIMAGE_NT_HEADERS)(pbPEBase + pDOSHeader->e_lfanew);
    PIMAGE_SECTION_HEADER   pImageSectionHeader = IMAGE_FIRST_SECTION(pNTHeader);

    PCSTR pszModuleName;

    std::map<DWORD, DWORD> original_to_new;    

    PIMAGE_THUNK_DATA pOriginalFirstThunk;
    PIMAGE_THUNK_DATA pFirstThunk;
    PIMAGE_IMPORT_BY_NAME pImageImportByName;
    DWORD dwFirstThunk;

    if (pNTHeader->FileHeader.Machine != IMAGE_FILE_MACHINE_I386)
    {
        printf("Not a x86 PE file.");
        return FALSE;
    }

    // We need to find imports... we will reorder them.
    // IMAGE_DIRECTORY_ENTRY_IMPORT has original first thunk, and first thunk
    // first thunk VAs are in IMAGE_DIRECTORY_ENTRY_IAT. So, if we update first thunk when processing _IMPORT
    // we must not process _IAT.
    //
    // We need to update relocation table which are pointing to these first thunks.
    // This is because the instructions in .text will be in the form, assuming base is 0x400000:
    // call dword ptr [base + first thunk].
    // So, we need to update the relocs from base + first thunk to base + updated first thunk.

    if (pNTHeader->OptionalHeader.NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_IMPORT)
    {
        PBYTE offset = Rva2Offset(pNTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress,
                                  pImageSectionHeader, pNTHeader) + pbPEBase;
        PIMAGE_IMPORT_DESCRIPTOR pImageImportDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)offset;

        while (pImageImportDescriptor->Name != NULL)
        {
            std::vector<std::pair<DWORD, DWORD>> thunk_data;
            std::vector<std::pair<DWORD, DWORD>> thunk_data_copy;
            std::map<DWORD, std::string> names;

            pszModuleName = (PCHAR)((DWORD_PTR)pbPEBase + Rva2Offset(pImageImportDescriptor->Name, pImageSectionHeader,
                                                                     pNTHeader));


            pOriginalFirstThunk = (PIMAGE_THUNK_DATA)(pbPEBase + Rva2Offset(pImageImportDescriptor->OriginalFirstThunk,
                                                                            pImageSectionHeader, pNTHeader));
            dwFirstThunk = pImageImportDescriptor->FirstThunk;
            
            while (pOriginalFirstThunk->u1.AddressOfData != 0)
            {
                pFirstThunk = (PIMAGE_THUNK_DATA)(pbPEBase + Rva2Offset(dwFirstThunk, pImageSectionHeader, pNTHeader));

                if (pOriginalFirstThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG)
                {
                    printf("Ordinal: %d", IMAGE_ORDINAL(pOriginalFirstThunk->u1.Ordinal));
                }
                else
                {
                    pImageImportByName = (PIMAGE_IMPORT_BY_NAME)(pbPEBase +
                                            Rva2Offset(pOriginalFirstThunk->u1.AddressOfData,
                                                       pImageSectionHeader, pNTHeader));
                    printf("FT: %x OFT AddressOfData: %x Hint: %x Function: %s\n",
                        dwFirstThunk,
                        pOriginalFirstThunk->u1.AddressOfData,
                        pImageImportByName->Hint, 
                        pImageImportByName->Name);
                    thunk_data.push_back(std::make_pair(pOriginalFirstThunk->u1.AddressOfData, dwFirstThunk));
                    names[pOriginalFirstThunk->u1.AddressOfData] = pImageImportByName->Name;
                }

                pOriginalFirstThunk++;
                dwFirstThunk += sizeof(IMAGE_THUNK_DATA);
            }

            thunk_data_copy = thunk_data;
            printf("---------------------------\n");
            std::random_device rd;
            std::mt19937 g(rd());
            std::shuffle(thunk_data.begin(), thunk_data.end(), g);

            for (DWORD i = 0; i < thunk_data.size(); ++i)
            {
                //original_to_new[ thunk_data_copy[i].second ] = thunk_data[i].second;
                original_to_new[thunk_data[i].second] = thunk_data_copy[i].second;

                printf("replacing %s with %s\n", names[thunk_data_copy[i].first].c_str(), names[thunk_data[i].first].c_str());
            }


            pOriginalFirstThunk = (PIMAGE_THUNK_DATA)(pbPEBase +
                                        Rva2Offset(pImageImportDescriptor->OriginalFirstThunk,
                                                   pImageSectionHeader, pNTHeader));
            dwFirstThunk = pImageImportDescriptor->FirstThunk;
            DWORD i = 0;

            while (pOriginalFirstThunk->u1.AddressOfData != 0)
            {
                if (pOriginalFirstThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG)
                {
                    printf("Ordinal: %d", IMAGE_ORDINAL(pOriginalFirstThunk->u1.Ordinal));
                }
                else
                {
                    pFirstThunk = (PIMAGE_THUNK_DATA)(pbPEBase + Rva2Offset(dwFirstThunk,
                                                                            pImageSectionHeader, pNTHeader));

                    DWORD temp;
                    temp = pOriginalFirstThunk->u1.AddressOfData;
                    pOriginalFirstThunk->u1.AddressOfData = thunk_data[i].first;
                    temp = pFirstThunk->u1.AddressOfData;
                    pFirstThunk->u1.AddressOfData = thunk_data[i].first;                   

                    pImageImportByName = (PIMAGE_IMPORT_BY_NAME)(pbPEBase + 
                                            Rva2Offset(pOriginalFirstThunk->u1.AddressOfData, 
                                                       pImageSectionHeader, pNTHeader));
                    printf("AddressOfData: %x Hint: %x\n", pOriginalFirstThunk->u1.AddressOfData,
                                                           pImageImportByName->Hint);

                    i++;
                }
                pOriginalFirstThunk++;
                dwFirstThunk += sizeof(IMAGE_THUNK_DATA);
            }


            pImageImportDescriptor++;
        }
    }

    if (pNTHeader->OptionalHeader.NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_BASERELOC)
    {
        if (pNTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size > 0)
        {
            PIMAGE_BASE_RELOCATION relocation = (PIMAGE_BASE_RELOCATION)(pbPEBase +
                Rva2Offset(pNTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress,
                           pImageSectionHeader, pNTHeader));
            for (; relocation->VirtualAddress > 0; )
            {
                unsigned short *RelInfo = (unsigned short *)((unsigned char *)relocation + sizeof(IMAGE_BASE_RELOCATION));
                for (DWORD i = 0; i < ((relocation->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / 2); i++, RelInfo++)
                {
                    DWORD *patchAddrHL;
                    DWORD type, offset;
                    // the upper 4 bits define the type of relocation
                    type = *RelInfo >> 12;
                    // the lower 12 bits define the offset
                    offset = *RelInfo & 0xfff;
                    DWORD dest = (DWORD)(pbPEBase + Rva2Offset(relocation->VirtualAddress,
                                                               pImageSectionHeader, pNTHeader));
                    DWORD delta = dest - (DWORD)pbPEBase;

                    switch (type)
                    {
                    case IMAGE_REL_BASED_ABSOLUTE:
                        // skip relocation
                        //printf("absolute\n");
                        break;

                    case IMAGE_REL_BASED_HIGHLOW:
                    {
                        // change complete 32 bit address
                        //patchAddrHL = (DWORD *)(dest + offset);
                        //*patchAddrHL += (DWORD)delta;
                        patchAddrHL = (DWORD*)(dest + offset);


                        DWORD lookup = *patchAddrHL;
                        lookup -= pNTHeader->OptionalHeader.ImageBase;

                        auto locate = original_to_new.find(lookup);
                        if (locate != original_to_new.end())
                        {
                            *patchAddrHL = (locate->second + pNTHeader->OptionalHeader.ImageBase);

                            printf("updating %p from %x\n value: %x\n",
                                   patchAddrHL,
                                   *patchAddrHL,
                                   locate->second + pNTHeader->OptionalHeader.ImageBase);
                            
                        }

                        //*patchAddrHL += delta;
                    }
                        break;
                    default:
                        break;
                    }
                }
            
                relocation = (PIMAGE_BASE_RELOCATION)(((char *)relocation) + relocation->SizeOfBlock);
            }
        }
    }


    return TRUE;
}

void Usage()
{
    printf("Change the imphash of a 32-bit PE.\n\nIMPHASH input output\n\t"
           "Generate output with different imphash from input.\n");
}

int wmain(int argc, wchar_t ** argv)
{
    PCWSTR pszPEFilePath;
    PCWSTR pszUpdatedPEFilePath;
    DWORD le = NOERROR;

    if (argc < 3)
    {
        Usage();
    }
    else
    {
        pszPEFilePath = argv[1];
        pszUpdatedPEFilePath = argv[2];

        HANDLE hPEFile = CreateFile(pszPEFilePath, GENERIC_READ, FILE_SHARE_READ, NULL,
                                    OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        
        DWORD dwPEFileSize;
        PBYTE pbPEFile;
        DWORD dwProcessed;

        if (INVALID_HANDLE_VALUE == hPEFile)
        {
            le = gle();
            printf("Cannot open PE file %ls to read. le = %d\n", pszPEFilePath, le);
        }
        else
        {
            dwPEFileSize = GetFileSize(hPEFile, NULL);
            if (INVALID_FILE_SIZE == dwPEFileSize)
            {
                le = gle();
                printf("Cannot determine file size. le = %d\n", le);
            }
            else
            {
                pbPEFile = (PBYTE)malloc(dwPEFileSize);
                if (NULL == pbPEFile)
                {
                    DWORD le = ERROR_OUTOFMEMORY;
                    printf("Cannot allocate memory to load PE file. le=%d\n", le);
                }
                else
                {
                    if (ReadFile(hPEFile, pbPEFile, dwPEFileSize, &dwProcessed, NULL) && dwPEFileSize == dwProcessed)
                    {
                        if (UpdateImpHash(pbPEFile, dwPEFileSize))
                        {
                            HANDLE hOutput = CreateFile(pszUpdatedPEFilePath, GENERIC_WRITE, FILE_SHARE_READ, 
                                                        NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
                            if (INVALID_HANDLE_VALUE != hOutput)
                            {
                                if (WriteFile(hOutput, pbPEFile, dwPEFileSize, &dwProcessed, NULL) &&
                                    dwPEFileSize == dwProcessed)
                                {
                                    printf("Updated file %ls written.\n", pszUpdatedPEFilePath);
                                }
                                else
                                {
                                    le = gle();
                                    printf("WF failed, le=%d\n", le);
                                }

                                CloseHandle(hOutput);
                            }
                            else
                            {
                                printf("ERROR: Unable to open file to write\n");
                            }
                        }
                    }
                    else
                    {
                        DWORD le = gle();
                        printf("RF failed, le=%d; request != read\n", le);
                    }

                    free(pbPEFile);
                }
            }
        }
    }

    return le;
}