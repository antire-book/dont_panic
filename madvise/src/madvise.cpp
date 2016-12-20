#include <cstdlib>
#include <iostream>
#include <fstream>
#include <iomanip>
#include <cstring>
#include <elf.h>


/*
 * Parse the program headers and store the address/size of the first LOAD. Then walk
 * the section headers table looking for ".madvise_base_addr" and ".madvise_size"
 * where we'll store the address and size we pulled from the LOAD segment.
 *
 * \param[in,out] p_data the ELF binary
 * \return true if we found both .madvise sections
 */
bool add_advise_info(std::string& p_data)
{
    if (p_data[0] != 0x7f || p_data[1] != 'E' || p_data[2] != 'L' || p_data[3] != 'F')
    {
        return false;
    }

    Elf64_Ehdr* ehdr = reinterpret_cast<Elf64_Ehdr*>(&p_data[0]);
    Elf64_Shdr* sections = reinterpret_cast<Elf64_Shdr*>(&p_data[ehdr->e_shoff]);
    Elf64_Half sections_count = ehdr->e_shnum;
    if (sections_count == 0)
    {
        std::cerr << "[-] No section table" << std::endl;
        return false;
    }

    Elf64_Shdr* strings_header = reinterpret_cast<Elf64_Shdr*>(
        &p_data[ehdr->e_shoff] + (ehdr->e_shentsize * ehdr->e_shstrndx));
    const char* strings_table = &p_data[strings_header->sh_offset];

    Elf64_Phdr* phdr = reinterpret_cast<Elf64_Phdr*>(&p_data[ehdr->e_phoff]);
    uint32_t base_address = phdr->p_vaddr;
    uint32_t size = phdr->p_filesz;

    int found = 0;
    Elf64_Shdr* current = sections;
    for (int i = 0; i < sections_count; i++, current++)
    {
        std::string section_name(&strings_table[current->sh_name]);
        if (section_name.find(".madvise_base_addr") == 0)
        {
            memcpy(&p_data[0] + current->sh_offset, &base_address,
                   sizeof(base_address));
            found++;
        }
        else if (section_name.find(".madvise_size") == 0)
        {
            memcpy(&p_data[0] + current->sh_offset, &size, sizeof(size));
            found++;
        }
    }

    return (found == 2);
}

int main(int p_argc, char** p_argv)
{
    if (p_argc != 2)
    {
        std::cerr << "Usage: ./madvise <file path>" << std::endl;
        return EXIT_FAILURE;
    }

    std::ifstream inputFile(p_argv[1], std::ifstream::in | std::ifstream::binary);
    if (!inputFile.is_open() || !inputFile.good())
    {
        std::cerr << "Failed to open the provided file: " << p_argv[1] << std::endl;
        return EXIT_FAILURE;
    }

    std::string input((std::istreambuf_iterator<char>(inputFile)),
                      std::istreambuf_iterator<char>());
    inputFile.close();

    if(!add_advise_info(input))
    {
        return EXIT_FAILURE;
    }

    std::ofstream outputFile(p_argv[1], std::ofstream::out | std::ofstream::binary);
    if (!outputFile.is_open() || !outputFile.good())
    {
        std::cout << "Failed to wopen the provided file: " << p_argv[1] << std::endl;
        return EXIT_FAILURE;
    }

    outputFile.write(input.data(), input.length());
    outputFile.close();

    return EXIT_SUCCESS;
}
